package main

// 测试基建：隔离的中继实例（临时状态/溯源目录 + 随机端口）、分享方/收件人测试桩、
// AES-GCM 端到端加解密助手与录制代理——共同支撑「盲转」硬验收断言。
// 测试桩同时是线协议的参考客户端实现，与 PROTOCOL.md 一一对应。

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	if os.Getenv("RELAY_TEST_VERBOSE") == "" {
		slog.SetLogLoggerLevel(slog.LevelError)
	}
	os.Exit(m.Run())
}

// ---------- 中继实例 ----------

// testHarness 一次测试内的隔离中继实例
type testHarness struct {
	relay *Relay
	addr  string
	cfg   Config
	stop  func()
}

// testConfig 测试默认配置：保活与定时扫描拉长避免干扰，个别测试按需覆盖
func testConfig(t *testing.T) Config {
	t.Helper()
	cfg := defaultConfig()
	cfg.StateFile = filepath.Join(t.TempDir(), "state.json")
	cfg.TraceDir = filepath.Join(t.TempDir(), "log")
	cfg.TunnelKeepaliveSec = 3600
	cfg.TunnelKeepaliveTimeoutSec = 7200
	cfg.HandshakeTimeoutSec = 5
	cfg.RecipientIdleTimeoutSec = 60
	cfg.SniffTimeoutSec = 5
	cfg.SweepIntervalSec = 3600
	return cfg
}

// startRelay 启动隔离中继：真实单端口嗅探入口 + HTTP 面 + 定时扫描，全部走生产代码路径
func startRelay(t *testing.T, mutate func(*Config)) *testHarness {
	t.Helper()
	cfg := testConfig(t)
	if mutate != nil {
		mutate(&cfg)
	}
	cfg.sanitize()
	trace := newTraceLog(cfg.TraceDir, cfg.TraceRetentionDays)
	r := newRelay(cfg, trace)
	if err := r.loadState(); err != nil {
		t.Fatalf("状态恢复失败: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听失败: %v", err)
	}
	addr := ln.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	httpSrv := &http.Server{Handler: r.httpHandler(), ReadHeaderTimeout: 2 * time.Second}
	go runServer(ctx, ln, r, httpSrv)
	go r.sweepLoop(ctx)
	h := &testHarness{relay: r, addr: addr, cfg: cfg, stop: func() {
		cancel()
		_ = ln.Close()
		r.Close()
	}}
	t.Cleanup(h.stop)
	return h
}

// ---------- AES-GCM 端到端加密助手（仅存在于测试侧；中继源码不含任何解密能力） ----------

func newE2EKey() []byte {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}
	return key
}

// gcmSeal 加密：nonce(12) || 密文+认证标签
func gcmSeal(key, plaintext []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	return gcm.Seal(nonce, nonce, plaintext, nil)
}

// gcmOpen 解密（收件人侧能力）
func gcmOpen(key, blob []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(blob) < gcm.NonceSize() {
		return nil, errors.New("密文过短")
	}
	nonce, ct := blob[:gcm.NonceSize()], blob[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, nil)
}

// ---------- 帧读写助手 ----------

const testFrameMax = 1 << 20

func readTestFrame(conn net.Conn, timeout time.Duration) (frame, error) {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	return readFrame(conn, testFrameMax)
}

func writeTestFrame(conn net.Conn, typ byte, sid uint32, payload []byte) error {
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	return writeFrame(conn, typ, sid, payload)
}

// rawDial 裸连接（不发任何字节），供恶意输入与拒绝路径测试使用
func rawDial(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatalf("连接中继失败: %v", err)
	}
	return conn
}

// ---------- 分享方测试桩（隧道客户端：多路复用 + 端到端加解密） ----------

type stubSharer struct {
	t          *testing.T
	conn       net.Conn
	token      string
	key        []byte
	handler    func(req []byte) []byte
	ignorePing bool

	writeMu  sync.Mutex
	mu       sync.Mutex
	streams  map[uint32]chan []byte
	resultCh chan resultPayload // 控制操作应答（由 serve 循环统一读取，避免并发读连接）

	lastStreamInput  []byte // 最近一条流上收到的原始密文（请求方向）
	lastSealedOutput []byte // 最近一次加密后的响应密文（响应方向）
}

// regOpts 分享方注册/绑定选项
type regOpts struct {
	instanceID     string
	expireSeconds  *int64
	passwordHash   string
	meta           *shareMeta
	candidateAddrs []string
	key            []byte
	handler        func([]byte) []byte
	ignorePing     bool
	action         string // 空 = register；"bind" 时 token 必填
	token          string // bind 用
}

func defaultTestMeta() *shareMeta {
	return &shareMeta{Title: "测试分享", WorkCount: 3, Source: "pixiv"}
}

func (o regOpts) withDefaults() regOpts {
	if o.instanceID == "" {
		o.instanceID = "instance-sharer-0001"
	}
	if o.meta == nil && o.action != "bind" {
		o.meta = defaultTestMeta()
	}
	if o.handler == nil {
		o.handler = func(req []byte) []byte { return append([]byte("resp:"), req...) }
	}
	return o
}

// startSharer 建立分享方桩：连接中继（register 或 bind）、解析 WELCOME、进入隧道服务循环
func startSharer(t *testing.T, addr string, opts regOpts) *stubSharer {
	t.Helper()
	opts = opts.withDefaults()
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatalf("分享方连接中继失败: %v", err)
	}
	key := opts.key
	if key == nil {
		key = newE2EKey()
	}
	hello := helloPayload{
		Role: "sharer", Action: opts.action, Token: opts.token,
		InstanceID: opts.instanceID, PasswordHash: opts.passwordHash,
		ExpireSeconds: opts.expireSeconds, Meta: opts.meta,
		CandidateAddrs: opts.candidateAddrs,
	}
	if hello.Action == "" {
		hello.Action = "register"
	}
	if err := writeTestFrame(conn, frameHello, 0, mustJSON(hello)); err != nil {
		t.Fatalf("分享方发送 HELLO 失败: %v", err)
	}
	fr, err := readTestFrame(conn, 5*time.Second)
	if err != nil {
		t.Fatalf("分享方读应答失败: %v", err)
	}
	if fr.Type != frameWelcome {
		t.Fatalf("预期 WELCOME，得到 type=0x%02X payload=%s", fr.Type, fr.Payload)
	}
	var wl welcomePayload
	if err := json.Unmarshal(fr.Payload, &wl); err != nil {
		t.Fatalf("解析 WELCOME 失败: %v", err)
	}
	s := &stubSharer{
		t: t, conn: conn, key: key,
		handler: opts.handler, ignorePing: opts.ignorePing,
		streams:  map[uint32]chan []byte{},
		resultCh: make(chan resultPayload, 1),
	}
	if opts.action == "bind" {
		s.token = opts.token
	} else {
		s.token = wl.Token
	}
	go s.serve()
	return s
}

func (s *stubSharer) serve() {
	for {
		fr, err := readTestFrame(s.conn, 30*time.Second)
		if err != nil {
			return
		}
		switch fr.Type {
		case frameStreamOpen:
			ch := make(chan []byte, 8)
			s.mu.Lock()
			s.streams[fr.StreamID] = ch
			s.mu.Unlock()
			go s.serveStream(fr.StreamID, ch)
		case frameData:
			s.mu.Lock()
			ch := s.streams[fr.StreamID]
			s.mu.Unlock()
			if ch != nil {
				select {
				case ch <- fr.Payload:
				default:
				}
			}
		case frameStreamClose:
			s.mu.Lock()
			if ch, ok := s.streams[fr.StreamID]; ok {
				close(ch)
				delete(s.streams, fr.StreamID)
			}
			s.mu.Unlock()
		case framePing:
			if !s.ignorePing {
				_ = s.write(framePong, 0, nil)
			}
		case frameResult:
			var rp resultPayload
			if err := json.Unmarshal(fr.Payload, &rp); err == nil {
				select {
				case s.resultCh <- rp:
				default:
				}
			}
		}
	}
}

func (s *stubSharer) write(typ byte, sid uint32, payload []byte) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return writeTestFrame(s.conn, typ, sid, payload)
}

// serveStream 单流服务：解密请求 → handler → 加密响应 → 关流
func (s *stubSharer) serveStream(id uint32, ch chan []byte) {
	input, ok := <-ch
	if !ok {
		return
	}
	s.mu.Lock()
	s.lastStreamInput = append([]byte(nil), input...)
	s.mu.Unlock()
	plaintext, err := gcmOpen(s.key, input)
	if err != nil {
		s.t.Logf("分享方解密失败: %v", err)
		return
	}
	ct := gcmSeal(s.key, s.handler(plaintext))
	s.mu.Lock()
	s.lastSealedOutput = append([]byte(nil), ct...)
	s.mu.Unlock()
	_ = s.write(frameData, id, ct)
	_ = s.write(frameStreamClose, id, nil)
}

// revoke 发送撤销并等待 RESULT 应答（应答经 serve 循环统一读取后转入 resultCh）
func (s *stubSharer) revoke() error {
	if err := s.write(frameRevoke, 0, nil); err != nil {
		return err
	}
	select {
	case rp := <-s.resultCh:
		if rp.Action != "revoke" || !rp.OK {
			return fmt.Errorf("撤销应答异常: %+v", rp)
		}
		return nil
	case <-time.After(5 * time.Second):
		return errors.New("等待撤销应答超时")
	}
}

func (s *stubSharer) sealedOutput() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.lastSealedOutput...)
}

func (s *stubSharer) streamInput() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]byte(nil), s.lastStreamInput...)
}

// ---------- 收件人测试桩 ----------

// dialRecipient 拨号：成功返回连接；被拒返回非空错误码
func dialRecipient(t *testing.T, addr, token, instanceID, passwordHash string) (net.Conn, string) {
	t.Helper()
	if instanceID == "" {
		instanceID = "instance-recipient-01"
	}
	conn, err := net.DialTimeout("tcp", addr, 3*time.Second)
	if err != nil {
		t.Fatalf("收件人连接中继失败: %v", err)
	}
	hello := helloPayload{Role: "recipient", Token: token, InstanceID: instanceID, PasswordHash: passwordHash}
	if err := writeTestFrame(conn, frameHello, 0, mustJSON(hello)); err != nil {
		t.Fatalf("收件人发送 HELLO 失败: %v", err)
	}
	fr, err := readTestFrame(conn, 5*time.Second)
	if err != nil {
		t.Fatalf("收件人读应答失败: %v", err)
	}
	switch fr.Type {
	case frameWelcome:
		return conn, ""
	case frameError:
		var we wireErr
		_ = json.Unmarshal(fr.Payload, &we)
		_ = conn.Close()
		return nil, we.Code
	default:
		_ = conn.Close()
		t.Fatalf("预期 WELCOME/ERROR，得到 type=0x%02X", fr.Type)
		return nil, ""
	}
}

// recipientRoundTrip 单次端到端请求-响应：加密请求 → 发送 → 半关闭 → 收密文响应 → 解密。
// 返回收到的原始密文（供逐字节一致性断言）与解密后的明文。
func recipientRoundTrip(conn net.Conn, key, request []byte) (rawCT, response []byte, err error) {
	return recipientRoundTripCT(conn, key, gcmSeal(key, request))
}

// recipientRoundTripCT 发送测试方预先生成的密文（供盲转逐字节断言使用）
func recipientRoundTripCT(conn net.Conn, key, requestCT []byte) (rawCT, response []byte, err error) {
	if err := writeTestFrame(conn, frameData, recipientStreamID, requestCT); err != nil {
		return nil, nil, err
	}
	if err := writeTestFrame(conn, frameStreamClose, recipientStreamID, nil); err != nil {
		return nil, nil, err
	}
	var got []byte
	deadline := time.Now().Add(10 * time.Second)
	for {
		_ = conn.SetReadDeadline(deadline)
		fr, rerr := readFrame(conn, testFrameMax)
		if rerr != nil {
			return nil, nil, fmt.Errorf("读响应失败: %w", rerr)
		}
		switch fr.Type {
		case frameData:
			got = fr.Payload
		case frameStreamClose:
			if got == nil {
				return nil, nil, errors.New("流已关闭但未收到数据")
			}
			resp, derr := gcmOpen(key, got)
			if derr != nil {
				return got, nil, fmt.Errorf("解密失败: %w", derr)
			}
			return got, resp, nil
		case framePing:
			_ = writeTestFrame(conn, framePong, 0, nil)
		}
	}
}

// ---------- 断连断言 ----------

// expectConnClosed 断言连接已被对端关闭（EOF/复位），而非保持打开
func expectConnClosed(t *testing.T, conn net.Conn, hint string) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	_, err := conn.Read(buf)
	if err == nil {
		t.Fatalf("%s: 预期连接已关闭，但读到了数据", hint)
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("%s: 预期连接已关闭，但连接保持打开", hint)
	}
}

// waitConnClosed 在时限内轮询等待连接被对端关闭
func waitConnClosed(t *testing.T, conn net.Conn, max time.Duration, hint string) {
	t.Helper()
	deadline := time.Now().Add(max)
	for time.Now().Before(deadline) {
		_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		buf := make([]byte, 64)
		_, err := conn.Read(buf)
		if err != nil {
			var ne net.Error
			if !(errors.As(err, &ne) && ne.Timeout()) {
				return // 真实断连
			}
		}
	}
	t.Fatalf("%s: 等待连接关闭超时（%v）", hint, max)
}

// ---------- 录制代理（记录进入中继的全部字节，供盲转断言） ----------

type recordingProxy struct {
	target string
	ln     net.Listener
	mu     sync.Mutex
	buf    bytes.Buffer
	wg     sync.WaitGroup
}

func startRecordingProxy(t *testing.T, target string) *recordingProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("录制代理监听失败: %v", err)
	}
	p := &recordingProxy{target: target, ln: ln}
	go p.acceptLoop()
	t.Cleanup(func() { _ = ln.Close() })
	return p
}

func (p *recordingProxy) acceptLoop() {
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			return
		}
		up, err := net.DialTimeout("tcp", p.target, 3*time.Second)
		if err != nil {
			_ = conn.Close()
			continue
		}
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			go p.pump(conn, up)
			p.pump(up, conn)
		}()
	}
}

// pump 单向复制并把经过的字节录入捕获缓冲
func (p *recordingProxy) pump(src, dst net.Conn) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			p.mu.Lock()
			p.buf.Write(buf[:n])
			p.mu.Unlock()
			if _, werr := dst.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// snapshot 取当前已捕获的全部字节快照
func (p *recordingProxy) snapshot() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]byte(nil), p.buf.Bytes()...)
}

// ---------- HTTP 助手 ----------

func httpGet(t *testing.T, url string) (int, string) {
	t.Helper()
	return httpGetWithToken(t, url, "")
}

func httpGetWithToken(t *testing.T, url, adminToken string) (int, string) {
	t.Helper()
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatalf("构造请求失败: %v", err)
	}
	if adminToken != "" {
		req.Header.Set("X-Admin-Token", adminToken)
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("GET %s 失败: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatalf("读取响应体失败: %v", err)
	}
	return resp.StatusCode, string(body)
}

func httpPostJSON(t *testing.T, url, adminToken string, body any) (int, string) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("序列化请求体失败: %v", err)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest("POST", url, rd)
	if err != nil {
		t.Fatalf("构造请求失败: %v", err)
	}
	if adminToken != "" {
		req.Header.Set("X-Admin-Token", adminToken)
	}
	if rd != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("POST %s 失败: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatalf("读取响应体失败: %v", err)
	}
	return resp.StatusCode, string(b)
}
