package main

// 合规核验（阶段5）：溯源日志字段集白名单（不记内容）、留存期限真实生效（清理单元 +
// 定时扫描接线端到端）、落地页合规件文案（ToS/隐私/举报流程/AGPL 源码披露 + 留存期
// 实际值渲染）。举报→撤销→实例封禁链路见 TestReportAutoBan（access_test.go），
// 端到端不可读性见 TestE2EBlindnessHardAcceptance（relay_e2e_test.go）——本文件只补缺口、不重复覆盖。

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestTraceLogFieldSetExcludesContent 溯源日志字段集白名单：每行 JSON 的键集合必须
// ⊆ {ts, event, token, instanceId, ip, detail}——结构上排除任何内容字段；传输明文负载不得出现在日志中
func TestTraceLogFieldSetExcludesContent(t *testing.T) {
	h := startRelay(t, nil)
	key := newE2EKey()
	A := startSharer(t, h.addr, regOpts{
		key:  key,
		meta: &shareMeta{Title: "合规字段集验证", WorkCount: 2, Source: "local"},
	})
	B, code := dialRecipient(t, h.addr, A.token, "instance-recipient-77", "")
	if code != "" {
		t.Fatalf("拨号被拒: %s", code)
	}
	const secret = "COMPLIANCE-FIELDSET-明文负载-绝不入日志"
	if _, _, err := recipientRoundTrip(B, key, []byte(secret)); err != nil {
		t.Fatalf("往返失败: %v", err)
	}
	_ = B.Close()
	if code, _ := httpPostJSON(t, "http://"+h.addr+"/s/"+A.token+"/report", "", nil); code != 200 {
		t.Fatalf("举报失败: %d", code)
	}

	files, err := filepath.Glob(filepath.Join(h.cfg.TraceDir, "trace-*.jsonl"))
	if err != nil || len(files) == 0 {
		t.Fatalf("溯源日志文件缺失: %v", err)
	}
	allowed := map[string]bool{
		"ts": true, "event": true, "token": true, "instanceId": true, "ip": true, "detail": true,
	}
	seenEvents := map[string]bool{}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("读取溯源日志失败: %v", err)
		}
		if strings.Contains(string(data), secret) {
			t.Errorf("%s 出现传输明文负载", f)
		}
		for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
			if line == "" {
				continue
			}
			var m map[string]any
			if err := json.Unmarshal([]byte(line), &m); err != nil {
				t.Fatalf("溯源日志行非 JSON: %q (%v)", line, err)
			}
			for k := range m {
				if !allowed[k] {
					t.Errorf("溯源日志出现白名单外字段 %q（行 %q）——字段集不得超出溯源事实范围", k, line)
				}
			}
			if ev, ok := m["event"].(string); ok {
				seenEvents[ev] = true
			}
		}
	}
	for _, ev := range []string{"register", "dial", "report"} {
		if !seenEvents[ev] {
			t.Errorf("溯源日志缺少事件 %q（已见事件集: %v）", ev, seenEvents)
		}
	}
}

// TestTraceRetentionCleanupUnit 留存期限清理（单元）：超留存期的按日文件被删除，
// 留存期内文件与非溯源命名文件不受影响
func TestTraceRetentionCleanupUnit(t *testing.T) {
	dir := t.TempDir()
	const retention = 30
	tl := newTraceLog(dir, retention)
	defer tl.close()

	now := time.Now()
	names := map[string]string{
		"超期（留存期+5 天）":         "trace-" + now.AddDate(0, 0, -(retention+5)).Format("20060102") + ".jsonl",
		"留存期内（retention-1 天）": "trace-" + now.AddDate(0, 0, -(retention-1)).Format("20060102") + ".jsonl",
		"当日":                  "trace-" + now.Format("20060102") + ".jsonl",
		"非溯源命名文本":             "notes.txt",
		"非日期形态溯源命名":           "trace-notadate.jsonl",
	}
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("{\"ts\":1,\"event\":\"register\"}\n"), 0o644); err != nil {
			t.Fatalf("预置文件失败: %v", err)
		}
	}

	tl.cleanup(now)

	if _, err := os.Stat(filepath.Join(dir, names["超期（留存期+5 天）"])); !os.IsNotExist(err) {
		t.Errorf("超期溯源文件未被清理: err=%v", err)
	}
	for _, key := range []string{"留存期内（retention-1 天）", "当日", "非溯源命名文本", "非日期形态溯源命名"} {
		if _, err := os.Stat(filepath.Join(dir, names[key])); err != nil {
			t.Errorf("不应删除的文件被删除（%s）: %v", key, err)
		}
	}
}

// TestTraceRetentionEnforcedViaSweep 留存期限真实生效（接线端到端）：预置超期溯源文件，
// 中继定时扫描（sweepLoop 首轮即触发清理）将其删除——留存期不只是配置声明，而是有清理动作兜底
func TestTraceRetentionEnforcedViaSweep(t *testing.T) {
	var traceDir string
	startRelay(t, func(c *Config) {
		c.TraceRetentionDays = 10
		c.SweepIntervalSec = 1
		traceDir = c.TraceDir
	})
	if err := os.MkdirAll(traceDir, 0o755); err != nil {
		t.Fatalf("创建溯源目录失败: %v", err)
	}
	now := time.Now()
	oldPath := filepath.Join(traceDir, "trace-"+now.AddDate(0, 0, -20).Format("20060102")+".jsonl")
	freshPath := filepath.Join(traceDir, "trace-"+now.Format("20060102")+".jsonl")
	for _, p := range []string{oldPath, freshPath} {
		if err := os.WriteFile(p, []byte("{\"ts\":1,\"event\":\"register\"}\n"), 0o644); err != nil {
			t.Fatalf("预置溯源文件失败: %v", err)
		}
	}

	deadline := time.Now().Add(6 * time.Second)
	for {
		_, err := os.Stat(oldPath)
		if os.IsNotExist(err) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("定时扫描未清理超期溯源日志——留存期限未真实生效")
		}
		time.Sleep(200 * time.Millisecond)
	}
	if _, err := os.Stat(freshPath); err != nil {
		t.Errorf("留存期内的当日溯源文件被误删: %v", err)
	}
}

// TestLandingPageComplianceCopy 落地页合规件：服务条款与免责声明、隐私声明（含留存期
// 默认值与当前配置实际值）、举报与处置流程、AGPL 源码获取链接；未知 token 的 404 页同样承载
func TestLandingPageComplianceCopy(t *testing.T) {
	h := startRelay(t, func(c *Config) { c.TraceRetentionDays = 42 })
	A := startSharer(t, h.addr, regOpts{})
	_, body := httpGet(t, "http://"+h.addr+"/s/"+A.token)
	for _, want := range []string{
		`id="disclaimer"`,
		"服务条款与免责声明", "隐私声明", "举报与处置流程", "源码获取（AGPL-3.0）",
		"盲转中继", "不存储", "无法读取", "无法审查",
		"举报即撤销", "自动封禁", "按 IP 封禁",
		"默认 183 天", "本实例当前配置 42 天",
		"instanceId", "来源 IP",
		"AGPL-3.0", "https://github.com/lvfeng-z/library-squirrel-relay",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("落地页合规文案缺少 %q", want)
		}
	}

	// 失效/未知链接的访客仍可见处置与隐私条款（404 页承载同一合规件）
	code, body404 := httpGet(t, "http://"+h.addr+"/s/AAAAAAAAAAAAAAAAAAAAAA")
	if code != 404 {
		t.Fatalf("未知 token 应 404，得到 %d", code)
	}
	for _, want := range []string{"服务条款与免责声明", "隐私声明", "本实例当前配置 42 天", "举报即撤销"} {
		if !strings.Contains(body404, want) {
			t.Errorf("404 落地页合规文案缺少 %q", want)
		}
	}
}
