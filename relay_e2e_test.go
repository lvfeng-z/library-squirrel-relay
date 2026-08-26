package main

// 硬验收：隧道互通、多收件人并发互不干扰、端到端加密正确性（决策14）、
// 分享方离线/重绑、保活超时。

import (
	"bytes"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestTunnelEndToEndRoundTrip 桩 A（分享方）经中继与桩 B（收件人）完成端到端加密的请求-响应
func TestTunnelEndToEndRoundTrip(t *testing.T) {
	h := startRelay(t, nil)
	key := newE2EKey()
	A := startSharer(t, h.addr, regOpts{key: key})
	if A.token == "" {
		t.Fatal("未取得 token")
	}
	B, code := dialRecipient(t, h.addr, A.token, "instance-recipient-01", "")
	if code != "" {
		t.Fatalf("拨号被拒: %s", code)
	}
	defer func() { _ = B.Close() }()
	rawCT, resp, err := recipientRoundTrip(B, key, []byte("hello-relay"))
	if err != nil {
		t.Fatalf("端到端往返失败: %v", err)
	}
	if string(resp) != "resp:hello-relay" {
		t.Fatalf("解密结果不符: %q", resp)
	}
	if bytes.Equal(rawCT, []byte("resp:hello-relay")) {
		t.Fatal("收件人收到的是明文，端到端加密未生效")
	}
}

// TestMultipleRecipientsConcurrent 多收件人并发各自拉取互不干扰：三个收件人同时拨号，
// 各自的请求得到各自的响应，无串流
func TestMultipleRecipientsConcurrent(t *testing.T) {
	h := startRelay(t, nil)
	key := newE2EKey()
	handler := func(req []byte) []byte { return append([]byte("data-for-"), req...) }
	A := startSharer(t, h.addr, regOpts{key: key, handler: handler})

	const n = 3
	var wg sync.WaitGroup
	errCh := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			conn, code := dialRecipient(t, h.addr, A.token, fmt.Sprintf("instance-recv-%02d", i), "")
			if code != "" {
				errCh <- fmt.Errorf("收件人 %d 拨号被拒: %s", i, code)
				return
			}
			defer func() { _ = conn.Close() }()
			req := fmt.Sprintf("reader-%d", i)
			_, resp, err := recipientRoundTrip(conn, key, []byte(req))
			if err != nil {
				errCh <- fmt.Errorf("收件人 %d 往返失败: %w", i, err)
				return
			}
			if want := "data-for-" + req; string(resp) != want {
				errCh <- fmt.Errorf("收件人 %d 数据串扰: got %q want %q", i, resp, want)
				return
			}
			errCh <- nil
		}(i)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatal(err)
		}
	}
}

// TestE2EBlindnessHardAcceptance 决策14 硬验收：录制代理捕获进入中继的全部字节——
// ①中继转发的字节与发送方所发密文逐字节一致（双向）；
// ②线路上不存在已知明文（密文性）；
// ③端到端密钥从不进入中继侧连接。
func TestE2EBlindnessHardAcceptance(t *testing.T) {
	h := startRelay(t, nil)
	proxy := startRecordingProxy(t, h.addr)
	key := newE2EKey()
	requestSecret := []byte("SECRET-REQUEST-明文请求-验收数据-0123456789")
	responseSecret := []byte("SECRET-RESPONSE-明文响应-验收数据-9876543210")
	handler := func([]byte) []byte { return responseSecret }
	A := startSharer(t, proxy.ln.Addr().String(), regOpts{key: key, handler: handler})

	B, code := dialRecipient(t, proxy.ln.Addr().String(), A.token, "instance-recipient-01", "")
	if code != "" {
		t.Fatalf("拨号被拒: %s", code)
	}
	// 测试方预先 seal 请求密文（nonce 受控），经录制代理原样送达
	requestCT := gcmSeal(key, requestSecret)
	rawCT, resp, err := recipientRoundTripCT(B, key, requestCT)
	if err != nil {
		t.Fatalf("端到端往返失败: %v", err)
	}
	if string(resp) != string(responseSecret) {
		t.Fatalf("解密结果与明文不符: %q", resp)
	}
	captured := proxy.snapshot()

	// ① 转发字节与密文逐字节一致（响应方向：收件人所收 == 分享方所发；请求方向同理）
	if !bytes.Equal(rawCT, A.sealedOutput()) {
		t.Fatal("响应方向：中继转发的字节与分享方所发密文不一致")
	}
	if !bytes.Equal(A.streamInput(), requestCT) {
		t.Fatal("请求方向：分享方收到的字节与收件人所发密文不一致")
	}
	// 密文确实穿过了中继（录制里可见密文字节）
	if !bytes.Contains(captured, A.sealedOutput()) || !bytes.Contains(captured, requestCT) {
		t.Fatal("密文未出现在中继侧字节流中，录制异常")
	}
	// ② 密文性：线路上不出现已知明文
	if bytes.Contains(captured, requestSecret) || bytes.Contains(captured, responseSecret) {
		t.Fatal("中继侧字节流中出现明文，端到端加密失效")
	}
	if bytes.Equal(rawCT, responseSecret) {
		t.Fatal("收件人收到的是明文")
	}
	// ③ 密钥不进中继侧连接
	if bytes.Contains(captured, key) {
		t.Fatal("端到端密钥出现在中继侧字节流中")
	}
}

// TestSharerOfflineDialRejectedAndLandingAlive 分享方离线：拨号被拒（offline），
// 落地页仍可访问（中继服务，与分享方在线与否无关）
func TestSharerOfflineDialRejectedAndLandingAlive(t *testing.T) {
	h := startRelay(t, nil)
	A := startSharer(t, h.addr, regOpts{})
	_ = A.conn.Close() // 模拟分享方关 App

	// 等隧道断开被中继感知（读循环报错 → tunnelDown）
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, code := dialRecipient(t, h.addr, A.token, "instance-recipient-01", "")
		if code == "offline" {
			break
		}
		if code != "" {
			t.Fatalf("预期 offline，得到 %s", code)
		}
		if time.Now().After(deadline) {
			t.Fatal("等待隧道断开超时")
		}
		time.Sleep(100 * time.Millisecond)
	}

	code, body := httpGet(t, "http://"+h.addr+"/s/"+A.token)
	if code != 200 {
		t.Fatalf("落地页状态码 %d", code)
	}
	if !strings.Contains(body, "测试分享") || !strings.Contains(body, "pixiv") {
		t.Fatal("落地页缺少预览元数据")
	}
}

// TestSharerRebind 分享方断线后凭 token 重绑：旧隧道被替换，拨号恢复可用
func TestSharerRebind(t *testing.T) {
	h := startRelay(t, nil)
	key := newE2EKey()
	A := startSharer(t, h.addr, regOpts{key: key})
	_ = A.conn.Close()

	// 等中继感知断线
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, code := dialRecipient(t, h.addr, A.token, "instance-recipient-01", "")
		if code == "offline" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("等待隧道断开超时")
		}
		time.Sleep(100 * time.Millisecond)
	}

	A2 := startSharer(t, h.addr, regOpts{key: key, action: "bind", token: A.token})
	_ = A2 // 隧道桩保持运行，其 serve 循环承载后续流服务
	B, code := dialRecipient(t, h.addr, A.token, "instance-recipient-01", "")
	if code != "" {
		t.Fatalf("重绑后拨号被拒: %s", code)
	}
	defer func() { _ = B.Close() }()
	_, resp, err := recipientRoundTrip(B, key, []byte("after-rebind"))
	if err != nil {
		t.Fatalf("重绑后往返失败: %v", err)
	}
	if string(resp) != "resp:after-rebind" {
		t.Fatalf("重绑后数据不符: %q", resp)
	}
}

// TestKeepaliveTimeoutKillsTunnel 隧道保活：分享方长时间无任何入帧（不回应 PING）即判死，
// 后续拨号返回 offline
func TestKeepaliveTimeoutKillsTunnel(t *testing.T) {
	h := startRelay(t, func(c *Config) {
		c.TunnelKeepaliveSec = 1
		c.TunnelKeepaliveTimeoutSec = 2
	})
	A := startSharer(t, h.addr, regOpts{ignorePing: true})

	deadline := time.Now().Add(6 * time.Second)
	for {
		conn, code := dialRecipient(t, h.addr, A.token, "instance-recipient-01", "")
		if code == "" {
			_ = conn.Close() // 立即释放流，避免占满并发上限
		}
		if code == "offline" {
			return
		}
		if code != "" {
			t.Fatalf("预期 offline，得到 %s", code)
		}
		if time.Now().After(deadline) {
			t.Fatal("保活超时未生效：隧道未被判定死亡")
		}
		time.Sleep(200 * time.Millisecond)
	}
}
