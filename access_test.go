package main

// 访问控制硬验收：token 不可猜测、撤销即断、过期即拒、密码、封禁（自动/管理端）、
// 限流（会话风暴/拨号）、流量上限、并发流上限、状态持久化、溯源日志、中继无解密能力。

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestTokenUnguessable token 不可猜测：长度/字符集/熵来源（crypto/rand 16 字节）与唯一性
func TestTokenUnguessable(t *testing.T) {
	const n = 500
	seen := make(map[string]bool, n)
	posChars := make([]map[rune]bool, 22)
	for i := range posChars {
		posChars[i] = map[rune]bool{}
	}
	for i := 0; i < n; i++ {
		tok, err := newToken()
		if err != nil {
			t.Fatalf("生成 token 失败: %v", err)
		}
		if len(tok) != 22 {
			t.Fatalf("token 长度 %d，预期 22", len(tok))
		}
		if !validTokenFormat(tok) {
			t.Fatalf("token %q 含非法字符（仅允许 base64url 字符集）", tok)
		}
		if seen[tok] {
			t.Fatalf("token 重复: %s", tok)
		}
		seen[tok] = true
		raw, err := base64.RawURLEncoding.DecodeString(tok)
		if err != nil || len(raw) != 16 {
			t.Fatalf("token 不是 16 字节熵源的 base64url 编码: %v", err)
		}
		for j, r := range tok {
			posChars[j][r] = true
		}
	}
	// 分布性：前 21 位取值充分发散（熵来自 crypto/rand 而非固定模式的直接体现）；
	// 第 22 位（0 起算第 21 位）仅承载 16 字节的最后 2 个比特，4 种取值属 base64 编码固有
	for j, set := range posChars {
		minDistinct := 10
		if j == 21 {
			minDistinct = 3
		}
		if len(set) < minDistinct {
			t.Fatalf("token 第 %d 位取值仅 %d 种，分布异常", j, len(set))
		}
	}
}

// TestRelaySourceHasNoDecryptCapability 盲转不变量的结构性保障：
// 中继非测试源码不得引入任何分组密码/解密包
func TestRelaySourceHasNoDecryptCapability(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("读取源码目录失败: %v", err)
	}
	banned := []string{`"crypto/aes"`, `"crypto/cipher"`, `"crypto/des"`, `"crypto/rc4"`}
	checked := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		checked++
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("读取 %s 失败: %v", name, err)
		}
		for _, b := range banned {
			if strings.Contains(string(data), b) {
				t.Errorf("%s 引入 %s——中继必须保持盲转（无可解密路径）", name, b)
			}
		}
	}
	if checked == 0 {
		t.Fatal("未检查到任何中继源文件")
	}
}

// TestRevokeKillsInFlightStreams 撤销即在途流被终止、后续拨号被拒
func TestRevokeKillsInFlightStreams(t *testing.T) {
	h := startRelay(t, nil)
	block := func([]byte) []byte { time.Sleep(30 * time.Second); return nil }
	A := startSharer(t, h.addr, regOpts{handler: block})
	B, code := dialRecipient(t, h.addr, A.token, "instance-recipient-01", "")
	if code != "" {
		t.Fatalf("拨号被拒: %s", code)
	}
	if err := A.revoke(); err != nil {
		t.Fatalf("撤销失败: %v", err)
	}
	expectConnClosed(t, B, "在途收件人连接应随撤销被终止")
	if _, code := dialRecipient(t, h.addr, A.token, "instance-recipient-01", ""); code != "revoked" {
		t.Fatalf("撤销后拨号应被拒（revoked），得到 %q", code)
	}
	// 终态不可逆：重绑也被拒
	conn := rawDial(t, h.addr)
	defer func() { _ = conn.Close() }()
	_ = writeTestFrame(conn, frameHello, 0, mustJSON(helloPayload{
		Role: "sharer", Action: "bind", Token: A.token, InstanceID: "instance-sharer-0001",
	}))
	if fr, err := readTestFrame(conn, 5*time.Second); err != nil || fr.Type != frameError {
		t.Fatalf("撤销后重绑应被拒，得到 frame=%+v err=%v", fr, err)
	} else {
		var we wireErr
		_ = json.Unmarshal(fr.Payload, &we)
		if we.Code != "revoked" {
			t.Fatalf("重绑拒绝码 %q，预期 revoked", we.Code)
		}
	}
}

// TestExpiryKillSwitch 有效期到点即拒（kill-switch 定时器）：在途流断开、拨号/重绑均被拒
func TestExpiryKillSwitch(t *testing.T) {
	h := startRelay(t, func(c *Config) { c.SweepIntervalSec = 1 })
	block := func([]byte) []byte { time.Sleep(30 * time.Second); return nil }
	expire := int64(1)
	A := startSharer(t, h.addr, regOpts{expireSeconds: &expire, handler: block})
	B, code := dialRecipient(t, h.addr, A.token, "instance-recipient-01", "")
	if code != "" {
		t.Fatalf("过期前拨号被拒: %s", code)
	}
	// 定时扫描应拆掉在途流（1 秒有效期 + 1 秒扫描间隔）
	waitConnClosed(t, B, 6*time.Second, "过期后应断开在途流")
	if _, code := dialRecipient(t, h.addr, A.token, "instance-recipient-01", ""); code != "expired" {
		t.Fatalf("过期后拨号应被拒（expired），得到 %q", code)
	}
	// expireSeconds=0（原「无限期」）已停用：注册即拒（invalid_expire），会话不建立
	zero := int64(0)
	conn := rawDial(t, h.addr)
	_ = writeTestFrame(conn, frameHello, 0, mustJSON(helloPayload{
		Role: "sharer", Action: "register", InstanceID: "instance-sharer-0002",
		ExpireSeconds: &zero, Meta: defaultTestMeta(),
	}))
	zfr, zerr := readTestFrame(conn, 5*time.Second)
	_ = conn.Close()
	if zerr != nil || zfr.Type != frameError {
		t.Fatalf("expireSeconds=0 注册应被拒，得到 frame=%+v err=%v", zfr, zerr)
	}
	var zwe wireErr
	_ = json.Unmarshal(zfr.Payload, &zwe)
	if zwe.Code != "invalid_expire" {
		t.Fatalf("expireSeconds=0 注册拒绝码 %q，预期 invalid_expire", zwe.Code)
	}
	if !strings.Contains(zwe.Message, "无限期") {
		t.Fatalf("拒绝文案应说明无限期已停用: %q", zwe.Message)
	}
	// 会话不建立：在册会话中不得出现该实例的任何行（含终态行）
	h.relay.mu.Lock()
	leaked := 0
	for _, s := range h.relay.sessions {
		if s.InstanceID == "instance-sharer-0002" {
			leaked++
		}
	}
	h.relay.mu.Unlock()
	if leaked != 0 {
		t.Fatalf("被拒注册不应建立会话（发现在册行 %d 条）", leaked)
	}
}

// TestPasswordProtection 可选访问密码：无/错/对三态
func TestPasswordProtection(t *testing.T) {
	h := startRelay(t, nil)
	sum := sha256.Sum256([]byte("访问密码-测试"))
	hash := hex.EncodeToString(sum[:])
	key := newE2EKey()
	A := startSharer(t, h.addr, regOpts{passwordHash: hash, key: key})

	if _, code := dialRecipient(t, h.addr, A.token, "instance-recipient-01", ""); code != "bad_password" {
		t.Fatalf("无密码拨号应被拒（bad_password），得到 %q", code)
	}
	wrong := sha256.Sum256([]byte("错误密码"))
	if _, code := dialRecipient(t, h.addr, A.token, "instance-recipient-01", hex.EncodeToString(wrong[:])); code != "bad_password" {
		t.Fatalf("错密码拨号应被拒（bad_password），得到 %q", code)
	}
	B, code := dialRecipient(t, h.addr, A.token, "instance-recipient-01", hash)
	if code != "" {
		t.Fatalf("正确密码拨号被拒: %s", code)
	}
	defer func() { _ = B.Close() }()
	if _, _, err := recipientRoundTrip(B, key, []byte("with-password")); err != nil {
		t.Fatalf("带密码往返失败: %v", err)
	}
}

// TestReportAutoBan 举报链路：举报即撤销；同实例累计达阈值自动封禁（注册与拨号双双被拒）
func TestReportAutoBan(t *testing.T) {
	h := startRelay(t, func(c *Config) { c.AutoBanReportThreshold = 2 })
	const badInstance = "instance-bad-000001"
	A1 := startSharer(t, h.addr, regOpts{instanceID: badInstance})
	if code, _ := httpPostJSON(t, "http://"+h.addr+"/s/"+A1.token+"/report", "", nil); code != 200 {
		t.Fatalf("举报失败: %d", code)
	}
	if _, code := dialRecipient(t, h.addr, A1.token, "instance-recipient-01", ""); code != "revoked" {
		t.Fatalf("举报后拨号应被拒（revoked），得到 %q", code)
	}
	// 阈值 2：第二次举报触发自动封禁
	A2 := startSharer(t, h.addr, regOpts{instanceID: badInstance})
	if code, _ := httpPostJSON(t, "http://"+h.addr+"/s/"+A2.token+"/report", "", nil); code != 200 {
		t.Fatalf("第二次举报失败: %d", code)
	}
	// 被封禁实例不能再注册
	conn := rawDial(t, h.addr)
	_ = writeTestFrame(conn, frameHello, 0, mustJSON(helloPayload{
		Role: "sharer", Action: "register", InstanceID: badInstance,
		Meta: defaultTestMeta(),
	}))
	fr, err := readTestFrame(conn, 5*time.Second)
	_ = conn.Close()
	if err != nil || fr.Type != frameError {
		t.Fatalf("被封禁实例注册应被拒，得到 frame=%+v err=%v", fr, err)
	}
	var we wireErr
	_ = json.Unmarshal(fr.Payload, &we)
	if we.Code != "banned" {
		t.Fatalf("注册拒绝码 %q，预期 banned", we.Code)
	}
	// 被封禁实例作为收件人也拒
	A3 := startSharer(t, h.addr, regOpts{instanceID: "instance-good-00003"})
	if _, code := dialRecipient(t, h.addr, A3.token, badInstance, ""); code != "banned" {
		t.Fatalf("被封禁实例拨号应被拒（banned），得到 %q", code)
	}
	// 封禁同时撤销了该实例名下的活跃会话
	if _, code := dialRecipient(t, h.addr, A2.token, "instance-recipient-01", ""); code != "revoked" {
		t.Fatalf("封禁级联撤销后拨号应被拒（revoked），得到 %q", code)
	}
}

// TestAdminBanAndKillByIP 管理端处置：按 IP 封禁即时生效，解封恢复
func TestAdminBanAndKillByIP(t *testing.T) {
	const adminToken = "test-admin-token"
	h := startRelay(t, func(c *Config) { c.AdminToken = adminToken })
	A := startSharer(t, h.addr, regOpts{instanceID: "instance-admin-00001"})

	if code, body := httpPostJSON(t, "http://"+h.addr+"/admin/ban", adminToken, map[string]string{"ip": "127.0.0.1"}); code != 200 {
		t.Fatalf("管理端封禁失败: %d %s", code, body)
	}
	// 按 IP 封禁会级联撤销该 IP 注册的活跃会话（处置即时生效）——拨号返回 revoked
	if _, code := dialRecipient(t, h.addr, A.token, "instance-recipient-01", ""); code != "revoked" {
		t.Fatalf("封禁 IP 后拨号应被拒（级联撤销 revoked），得到 %q", code)
	}
	// 封禁名单已登记该 IP
	if _, body := httpGetWithToken(t, "http://"+h.addr+"/admin/bans", adminToken); !strings.Contains(body, "127.0.0.1") {
		t.Fatalf("封禁名单缺少该 IP: %s", body)
	}
	if code, _ := httpPostJSON(t, "http://"+h.addr+"/admin/unban", adminToken, map[string]string{"ip": "127.0.0.1"}); code != 200 {
		t.Fatalf("管理端解封失败: %d", code)
	}
	// 解封后新会话可正常注册与拨号（旧会话已被封禁级联撤销）
	A2 := startSharer(t, h.addr, regOpts{instanceID: "instance-admin-00002"})
	if _, code := dialRecipient(t, h.addr, A2.token, "instance-recipient-01", ""); code != "" {
		t.Fatalf("解封后拨号被拒: %s", code)
	}
	// 管理 API 鉴权：错令牌 401、未配置令牌的中继 404
	if code, _ := httpPostJSON(t, "http://"+h.addr+"/admin/ban", "wrong-token", map[string]string{"ip": "1.2.3.4"}); code != 401 {
		t.Fatalf("错令牌应 401，得到 %d", code)
	}
	h2 := startRelay(t, nil)
	if code, _ := httpPostJSON(t, "http://"+h2.addr+"/admin/ban", "any", map[string]string{"ip": "1.2.3.4"}); code != 404 {
		t.Fatalf("未配置管理令牌时应 404，得到 %d", code)
	}
}

// TestAdminKillSession 管理端终止会话：即时生效
func TestAdminKillSession(t *testing.T) {
	const adminToken = "test-admin-token"
	h := startRelay(t, func(c *Config) { c.AdminToken = adminToken })
	A := startSharer(t, h.addr, regOpts{})
	if code, _ := httpPostJSON(t, "http://"+h.addr+"/admin/kill", adminToken, map[string]string{"token": A.token}); code != 200 {
		t.Fatalf("管理端终止失败: %d", code)
	}
	if _, code := dialRecipient(t, h.addr, A.token, "instance-recipient-01", ""); code != "revoked" {
		t.Fatalf("管理端终止后拨号应被拒（revoked），得到 %q", code)
	}
}

// TestRegisterRateLimit 防会话风暴：单 IP 注册超限被拒
func TestRegisterRateLimit(t *testing.T) {
	h := startRelay(t, func(c *Config) { c.RegisterPerIPPerHour = 2 })
	startSharer(t, h.addr, regOpts{instanceID: "instance-rate-000001"})
	startSharer(t, h.addr, regOpts{instanceID: "instance-rate-000002"})
	conn := rawDial(t, h.addr)
	_ = writeTestFrame(conn, frameHello, 0, mustJSON(helloPayload{
		Role: "sharer", Action: "register", InstanceID: "instance-rate-000003", Meta: defaultTestMeta(),
	}))
	fr, err := readTestFrame(conn, 5*time.Second)
	_ = conn.Close()
	if err != nil || fr.Type != frameError {
		t.Fatalf("注册超限应被拒，得到 frame=%+v err=%v", fr, err)
	}
	var we wireErr
	_ = json.Unmarshal(fr.Payload, &we)
	if we.Code != "rate_limited" {
		t.Fatalf("注册拒绝码 %q，预期 rate_limited", we.Code)
	}
}

// TestDialRateLimit 拨号限流：每 IP 每分钟超限被拒
func TestDialRateLimit(t *testing.T) {
	h := startRelay(t, func(c *Config) { c.DialPerIPPerMinute = 3 })
	A := startSharer(t, h.addr, regOpts{})
	for i := 0; i < 3; i++ {
		conn, code := dialRecipient(t, h.addr, A.token, "instance-recipient-01", "")
		if code != "" {
			t.Fatalf("限流内拨号被拒: %s", code)
		}
		_ = conn.Close()
	}
	if _, code := dialRecipient(t, h.addr, A.token, "instance-recipient-01", ""); code != "rate_limited" {
		t.Fatalf("拨号限流应被拒（rate_limited），得到 %q", code)
	}
}

// TestStreamConcurrencyLimit 单会话并发流上限：第三个并发拉取被拒
func TestStreamConcurrencyLimit(t *testing.T) {
	h := startRelay(t, func(c *Config) { c.MaxStreamsPerSession = 2 })
	block := func([]byte) []byte { time.Sleep(30 * time.Second); return nil }
	A := startSharer(t, h.addr, regOpts{handler: block})
	hold := make([]net.Conn, 0, 2)
	defer func() {
		for _, c := range hold {
			_ = c.Close()
		}
	}()
	for i := 0; i < 2; i++ {
		conn, code := dialRecipient(t, h.addr, A.token, "instance-recipient-01", "")
		if code != "" {
			t.Fatalf("并发内拨号被拒: %s", code)
		}
		hold = append(hold, conn)
	}
	if _, code := dialRecipient(t, h.addr, A.token, "instance-recipient-01", ""); code != "limit" {
		t.Fatalf("超并发拉取应被拒（limit），得到 %q", code)
	}
}

// TestTrafficLimit 单会话流量字节上限：超限即在途断开、后续拨号被拒
func TestTrafficLimit(t *testing.T) {
	h := startRelay(t, func(c *Config) { c.MaxSessionTrafficBytes = 512 })
	key := newE2EKey()
	big := func([]byte) []byte { return make([]byte, 2048) } // 单帧响应即超限
	A := startSharer(t, h.addr, regOpts{key: key, handler: big})
	B, code := dialRecipient(t, h.addr, A.token, "instance-recipient-01", "")
	if code != "" {
		t.Fatalf("拨号被拒: %s", code)
	}
	// 传输超限：收件人连接被断开（读到断连而非完整响应）
	_ = writeTestFrame(B, frameData, recipientStreamID, gcmSeal(key, []byte("pull")))
	_ = writeTestFrame(B, frameStreamClose, recipientStreamID, nil)
	expectConnClosed(t, B, "流量超限应断开在途流")
	if _, code := dialRecipient(t, h.addr, A.token, "instance-recipient-02", ""); code != "limit" {
		t.Fatalf("流量超限后拨号应被拒（limit），得到 %q", code)
	}
}

// TestStatePersistenceAcrossRestart 撤销与活跃会话跨重启保持：终态不复活、活跃会话可重绑
func TestStatePersistenceAcrossRestart(t *testing.T) {
	dir := t.TempDir()
	stateFile := filepath.Join(dir, "state.json")
	newCfg := func(c *Config) { c.StateFile = stateFile }

	h1 := startRelay(t, newCfg)
	A1 := startSharer(t, h1.addr, regOpts{instanceID: "instance-persist-01"})
	A2 := startSharer(t, h1.addr, regOpts{instanceID: "instance-persist-02"})
	if code, _ := httpPostJSON(t, "http://"+h1.addr+"/s/"+A1.token+"/report", "", nil); code != 200 {
		t.Fatalf("举报失败: %d", code)
	}
	h1.stop()

	h2 := startRelay(t, newCfg)
	// 撤销状态跨重启保持
	if _, code := dialRecipient(t, h2.addr, A1.token, "instance-recipient-01", ""); code != "revoked" {
		t.Fatalf("重启后撤销会话应仍被拒（revoked），得到 %q", code)
	}
	// 活跃会话保留（隧道不保留）：拨号 offline，重绑后恢复
	if _, code := dialRecipient(t, h2.addr, A2.token, "instance-recipient-01", ""); code != "offline" {
		t.Fatalf("重启后活跃会话应 offline，得到 %q", code)
	}
	key := newE2EKey()
	startSharer(t, h2.addr, regOpts{key: key, action: "bind", token: A2.token})
	B, code := dialRecipient(t, h2.addr, A2.token, "instance-recipient-01", "")
	if code != "" {
		t.Fatalf("重启重绑后拨号被拒: %s", code)
	}
	defer func() { _ = B.Close() }()
	if _, _, err := recipientRoundTrip(B, key, []byte("after-restart")); err != nil {
		t.Fatalf("重启重绑后往返失败: %v", err)
	}
}

// TestLoadStateWarnsOnSuspectedStateLoss 状态丢失疑似告警：溯源目录留有活动痕迹而无会话
// 加载（状态文件缺失/零会话）时告警；正常加载与全新部署不告警
func TestLoadStateWarnsOnSuspectedStateLoss(t *testing.T) {
	captureWarn := func(t *testing.T) *bytes.Buffer {
		t.Helper()
		buf := &bytes.Buffer{}
		old := slog.Default()
		slog.SetDefault(slog.New(slog.NewTextHandler(buf, nil)))
		t.Cleanup(func() { slog.SetDefault(old) })
		return buf
	}
	seedTrace := func(t *testing.T, traceDir string) {
		t.Helper()
		if err := os.MkdirAll(traceDir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(traceDir, "trace-20261002.jsonl"), []byte("{}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	loadRelay := func(t *testing.T, stateFile, traceDir string) {
		t.Helper()
		cfg := defaultConfig()
		cfg.StateFile = stateFile
		cfg.TraceDir = traceDir
		cfg.sanitize()
		r := newRelay(cfg, newTraceLog(traceDir, cfg.TraceRetentionDays))
		if err := r.loadState(); err != nil {
			t.Fatalf("状态恢复失败: %v", err)
		}
	}

	t.Run("状态文件缺失且溯源目录有活动", func(t *testing.T) {
		dir := t.TempDir()
		traceDir := filepath.Join(dir, "log")
		seedTrace(t, traceDir)
		buf := captureWarn(t)
		loadRelay(t, filepath.Join(dir, "missing-state.json"), traceDir)
		if !strings.Contains(buf.String(), "疑似状态丢失") {
			t.Fatalf("状态文件缺失且溯源有活动应告警: %q", buf.String())
		}
	})
	t.Run("状态文件零会话且溯源目录有活动", func(t *testing.T) {
		dir := t.TempDir()
		traceDir := filepath.Join(dir, "log")
		seedTrace(t, traceDir)
		stateFile := filepath.Join(dir, "state.json")
		data, _ := json.Marshal(relayState{Version: 1})
		if err := os.WriteFile(stateFile, data, 0o644); err != nil {
			t.Fatal(err)
		}
		buf := captureWarn(t)
		loadRelay(t, stateFile, traceDir)
		if !strings.Contains(buf.String(), "疑似状态丢失") {
			t.Fatalf("零会话加载且溯源有活动应告警: %q", buf.String())
		}
	})
	t.Run("有会话加载不告警", func(t *testing.T) {
		dir := t.TempDir()
		traceDir := filepath.Join(dir, "log")
		seedTrace(t, traceDir)
		stateFile := filepath.Join(dir, "state.json")
		st := relayState{Version: 1, Sessions: []*Session{{Token: "abcdefghijklmnopqrstuv", Status: SessionActive}}}
		data, _ := json.Marshal(st)
		if err := os.WriteFile(stateFile, data, 0o644); err != nil {
			t.Fatal(err)
		}
		buf := captureWarn(t)
		loadRelay(t, stateFile, traceDir)
		if strings.Contains(buf.String(), "疑似状态丢失") {
			t.Fatalf("有会话加载不应告警: %q", buf.String())
		}
	})
	t.Run("全新部署不告警", func(t *testing.T) {
		dir := t.TempDir()
		buf := captureWarn(t)
		loadRelay(t, filepath.Join(dir, "state.json"), filepath.Join(dir, "log"))
		if strings.Contains(buf.String(), "疑似状态丢失") {
			t.Fatalf("全新部署（无溯源目录）不应告警: %q", buf.String())
		}
	})
}

// TestTraceLogRecordsFactsNotContent 溯源日志：记录 token/实例/IP/时间，不记内容
func TestTraceLogRecordsFactsNotContent(t *testing.T) {
	h := startRelay(t, nil)
	key := newE2EKey()
	A := startSharer(t, h.addr, regOpts{
		key:  key,
		meta: &shareMeta{Title: "溯源验证分享", WorkCount: 1, Source: "pixiv"},
	})
	B, code := dialRecipient(t, h.addr, A.token, "instance-recipient-99", "")
	if code != "" {
		t.Fatalf("拨号被拒: %s", code)
	}
	const secret = "TRACE-SECRET-CONTENT-绝不出现在日志"
	_, _, err := recipientRoundTrip(B, key, []byte(secret))
	if err != nil {
		t.Fatalf("往返失败: %v", err)
	}
	_ = B.Close()
	if code, _ := httpPostJSON(t, "http://"+h.addr+"/s/"+A.token+"/report", "", nil); code != 200 {
		t.Fatalf("举报失败: %d", code)
	}

	// 读取溯源日志文件
	files, err := filepath.Glob(filepath.Join(h.cfg.TraceDir, "trace-*.jsonl"))
	if err != nil || len(files) == 0 {
		t.Fatalf("溯源日志文件缺失: %v", err)
	}
	all := ""
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("读取溯源日志失败: %v", err)
		}
		all += string(data)
	}
	for _, want := range []string{A.token, "instance-sharer-0001", "instance-recipient-99", "127.0.0.1", `"register"`, `"dial"`, `"report"`} {
		if !strings.Contains(all, want) {
			t.Errorf("溯源日志缺少 %q", want)
		}
	}
	if strings.Contains(all, secret) {
		t.Error("溯源日志出现传输内容——违反「不记内容」红线")
	}
	// 每行均为合法 JSON 事件
	for _, line := range strings.Split(strings.TrimSpace(all), "\n") {
		if line == "" {
			continue
		}
		var ev traceEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("溯源日志行非 JSON: %q (%v)", line, err)
		}
		if ev.TS <= 0 || ev.Event == "" {
			t.Fatalf("溯源日志行缺时间或事件: %q", line)
		}
	}
}

// TestConcurrentRegistersAndDials 混合并发压力：注册+拨号+撤销并发下中继不崩溃且行为一致
func TestConcurrentRegistersAndDials(t *testing.T) {
	h := startRelay(t, func(c *Config) {
		c.RegisterGlobalPerHour = 1000
		c.RegisterPerIPPerHour = 1000
		c.DialPerIPPerMinute = 1000
	})
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			A := startSharer(t, h.addr, regOpts{instanceID: "instance-stress-" + string(rune('a'+i)) + "0001"})
			for j := 0; j < 3; j++ {
				conn, code := dialRecipient(t, h.addr, A.token, "instance-recipient-01", "")
				if code == "" {
					_ = conn.Close()
				}
			}
		}(i)
	}
	wg.Wait()
}

// TestSweepPrunesTerminalRows 终态剪枝四态：超 30 天保留期的终态行被剪枝且状态文件同轮更新；
// 30 天内的终态行、未盖终态时刻的终态行（生产路径不产生，仅守卫）与活跃行不剪
func TestSweepPrunesTerminalRows(t *testing.T) {
	h := startRelay(t, nil)
	r := h.relay
	now := time.Now()

	seedRow := func(tag, status string, endedAt int64) string {
		t.Helper()
		tok, err := newToken()
		if err != nil {
			t.Fatalf("生成 token 失败: %v", err)
		}
		s := &Session{
			Token: tok, InstanceID: "instance-prune-" + tag, RegIP: "127.0.0.1",
			CreatedAt: now.Add(-40 * 24 * time.Hour).UnixMilli(),
			Status:    status, EndedAt: endedAt,
		}
		s.ensureRT()
		r.mu.Lock()
		r.sessions[tok] = s
		r.mu.Unlock()
		return tok
	}
	oldRevoked := seedRow("old", SessionRevoked, now.Add(-31*24*time.Hour).UnixMilli()) // 超保留期 → 剪
	oldExpired := seedRow("oldexp", SessionExpired, now.Add(-31*24*time.Hour).UnixMilli())
	fresh := seedRow("fresh", SessionRevoked, now.Add(-29*24*time.Hour).UnixMilli()) // 保留期内 → 留
	noStamp := seedRow("nostamp", SessionRevoked, 0)                                 // 未盖终态时刻 → 留
	active := seedRow("act", SessionActive, 0)                                       // 活跃 → 永不剪

	r.sweepOnce(now)

	r.mu.Lock()
	_, gotOldRevoked := r.sessions[oldRevoked]
	_, gotOldExpired := r.sessions[oldExpired]
	_, gotFresh := r.sessions[fresh]
	_, gotNoStamp := r.sessions[noStamp]
	_, gotActive := r.sessions[active]
	r.mu.Unlock()
	if gotOldRevoked || gotOldExpired {
		t.Fatalf("超保留期终态行应被剪枝: revoked=%v expired=%v", gotOldRevoked, gotOldExpired)
	}
	if !gotFresh || !gotNoStamp {
		t.Fatalf("保留期内与未盖终态时刻的终态行不应被剪枝: fresh=%v noStamp=%v", gotFresh, gotNoStamp)
	}
	if !gotActive {
		t.Fatal("活跃行永不剪枝")
	}

	// 状态文件同轮更新：被剪 token 移出落盘快照，保留行仍在，版本维持 1
	data, err := os.ReadFile(h.cfg.StateFile)
	if err != nil {
		t.Fatalf("读取状态文件失败: %v", err)
	}
	var st relayState
	if err := json.Unmarshal(data, &st); err != nil {
		t.Fatalf("状态文件非 JSON: %v", err)
	}
	if st.Version != 1 {
		t.Fatalf("状态文件版本应维持 1: %d", st.Version)
	}
	onDisk := map[string]bool{}
	for _, s := range st.Sessions {
		onDisk[s.Token] = true
	}
	if onDisk[oldRevoked] || onDisk[oldExpired] {
		t.Fatal("被剪枝的 token 不应留在状态文件")
	}
	if !onDisk[fresh] || !onDisk[noStamp] || !onDisk[active] {
		t.Fatal("保留行应留在状态文件")
	}
}

// TestAdminBanStampsEndedAt 管理端封禁批量持锁直接置 revoked（绕开 killSession），
// 按 instanceId 与按 IP 两路的级联撤销均盖终态时刻（剪枝计时的起点）
func TestAdminBanStampsEndedAt(t *testing.T) {
	const adminToken = "test-admin-token"
	h := startRelay(t, func(c *Config) { c.AdminToken = adminToken })
	A := startSharer(t, h.addr, regOpts{instanceID: "instance-banstamp-01"})
	B := startSharer(t, h.addr, regOpts{instanceID: "instance-banstamp-02"})
	before := time.Now().UnixMilli()

	if code, body := httpPostJSON(t, "http://"+h.addr+"/admin/ban", adminToken, map[string]string{"instanceId": "instance-banstamp-01"}); code != 200 {
		t.Fatalf("按实例封禁失败: %d %s", code, body)
	}
	if code, body := httpPostJSON(t, "http://"+h.addr+"/admin/ban", adminToken, map[string]string{"ip": "127.0.0.1"}); code != 200 {
		t.Fatalf("按 IP 封禁失败: %d %s", code, body)
	}

	h.relay.mu.Lock()
	sa, sb := h.relay.sessions[A.token], h.relay.sessions[B.token]
	var endedA, endedB int64
	var statusA, statusB string
	if sa != nil {
		endedA, statusA = sa.EndedAt, sa.Status
	}
	if sb != nil {
		endedB, statusB = sb.EndedAt, sb.Status
	}
	h.relay.mu.Unlock()
	if statusA != SessionRevoked || endedA == 0 || endedA < before {
		t.Fatalf("按实例封禁的会话应置 revoked 且盖终态时刻: status=%q endedAt=%d", statusA, endedA)
	}
	if statusB != SessionRevoked || endedB == 0 || endedB < before {
		t.Fatalf("按 IP 封禁的会话应置 revoked 且盖终态时刻: status=%q endedAt=%d", statusB, endedB)
	}
}

// TestLoadStateBackfillsEndedAt 旧格式状态文件（终态行无 endedAt）：加载时补记当前时刻
// （自此宽限一个保留期后可剪枝）并即时落盘；活跃行与已有终态时刻的行不动
func TestLoadStateBackfillsEndedAt(t *testing.T) {
	dir := t.TempDir()
	stateFile := filepath.Join(dir, "state.json")
	traceDir := filepath.Join(dir, "log")
	const (
		tokRevoked = "abcdefghijklmnopqrstuv" // 终态缺 endedAt → 补
		tokActive  = "0123456789012345678901" // 活跃 → 不动
		tokStamped = "ABCDEFGHIJKLMNOPQRSTUV" // 已有终态时刻 → 不动
	)
	before := time.Now().UnixMilli()
	st := relayState{Version: 1, Sessions: []*Session{
		{Token: tokRevoked, Status: SessionRevoked, CreatedAt: before - 1},
		{Token: tokActive, Status: SessionActive, CreatedAt: before - 1},
		{Token: tokStamped, Status: SessionExpired, CreatedAt: before - 1, EndedAt: 42},
	}}
	data, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(stateFile, data, 0o644); err != nil {
		t.Fatal(err)
	}

	cfg := defaultConfig()
	cfg.StateFile = stateFile
	cfg.TraceDir = traceDir
	cfg.sanitize()
	r := newRelay(cfg, newTraceLog(traceDir, cfg.TraceRetentionDays))
	if err := r.loadState(); err != nil {
		t.Fatalf("状态恢复失败: %v", err)
	}
	r.mu.Lock()
	endedRevoked := r.sessions[tokRevoked].EndedAt
	endedActive := r.sessions[tokActive].EndedAt
	endedStamped := r.sessions[tokStamped].EndedAt
	r.mu.Unlock()
	after := time.Now().UnixMilli()
	if endedRevoked < before || endedRevoked > after {
		t.Fatalf("终态行缺 endedAt 应补记加载时刻 [%d,%d]: %d", before, after, endedRevoked)
	}
	if endedActive != 0 {
		t.Fatalf("活跃行不应被盖终态时刻: %d", endedActive)
	}
	if endedStamped != 42 {
		t.Fatalf("已有终态时刻不应被改写: %d", endedStamped)
	}

	// 补值已落盘（频繁重启不重置宽限钟），且版本维持 1（向后兼容）
	data2, err := os.ReadFile(stateFile)
	if err != nil {
		t.Fatal(err)
	}
	var st2 relayState
	if err := json.Unmarshal(data2, &st2); err != nil {
		t.Fatalf("状态文件非 JSON: %v", err)
	}
	if st2.Version != 1 {
		t.Fatalf("状态文件版本应维持 1: %d", st2.Version)
	}
	saved := false
	for _, s := range st2.Sessions {
		if s.Token == tokRevoked {
			saved = s.EndedAt == endedRevoked
		}
	}
	if !saved {
		t.Fatalf("补记的 endedAt 应已落盘: %d", endedRevoked)
	}
}

// TestConfigRejectsNonPositiveDefaultExpire 配置逃生口收口：defaultExpireSeconds 非正属显式误配
// （nil 注册将产生不到期会话），加载即报错拒绝启动；正数显式配置与缺省默认不受影响
func TestConfigRejectsNonPositiveDefaultExpire(t *testing.T) {
	dir := t.TempDir()
	writeCfg := func(content string) string {
		t.Helper()
		p := filepath.Join(dir, "config.json")
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	for _, bad := range []string{
		`{"defaultExpireSeconds": 0}`,
		`{"defaultExpireSeconds": -5}`,
		`{"listenAddr": ":1", "defaultExpireSeconds": 0}`,
	} {
		_, err := loadConfig(writeCfg(bad))
		if err == nil {
			t.Fatalf("配置 %s 应拒绝启动", bad)
		}
		if !strings.Contains(err.Error(), "defaultExpireSeconds") || !strings.Contains(err.Error(), "无限期") {
			t.Fatalf("报错应说明 defaultExpireSeconds 须为正数（无限期已停用）: %v", err)
		}
	}
	if _, err := loadConfig(writeCfg(`{"defaultExpireSeconds": 3600}`)); err != nil {
		t.Fatalf("正数配置不应报错: %v", err)
	}
	if _, err := loadConfig(filepath.Join(dir, "missing.json")); err != nil {
		t.Fatalf("配置文件缺失应取默认值启动: %v", err)
	}
}
