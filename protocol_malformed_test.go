package main

// 恶意输入硬验收：畸形帧/超长/夹带字段/越权路径一律拒绝且中继保持存活。
// 协议面封闭白名单：HELLO 字段集封闭（未知字段即拒），帧类型封闭（未知类型即断连）。

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

// rawFrameBytes 构造任意帧的原始字节（允许构造非法帧头）
func rawFrameBytes(typ byte, sid uint32, length uint32, payload []byte) []byte {
	buf := make([]byte, frameHeaderSize+len(payload))
	buf[0], buf[1] = protoMagic[0], protoMagic[1]
	buf[2] = protoVersion
	buf[3] = typ
	binary.BigEndian.PutUint32(buf[4:8], sid)
	binary.BigEndian.PutUint32(buf[8:12], length)
	copy(buf[frameHeaderSize:], payload)
	return buf
}

func writeRaw(t *testing.T, conn net.Conn, b []byte) {
	t.Helper()
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(b); err != nil {
		t.Fatalf("写原始字节失败: %v", err)
	}
}

// expectClosedSoon 断言连接被中继关闭（读到断连错误而非超时）
func expectClosedSoon(t *testing.T, conn net.Conn, name string) {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64)
	_, err := conn.Read(buf)
	if err == nil {
		t.Fatalf("%s: 预期断连，但读到数据", name)
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		t.Fatalf("%s: 预期断连，但连接保持打开", name)
	}
}

// TestMalformedFramesRejected 畸形帧/越权帧表驱动拒绝
func TestMalformedFramesRejected(t *testing.T) {
	h := startRelay(t, nil)

	recipientHello := `{"role":"recipient","token":"AAAAAAAAAAAAAAAAAAAAAA","instanceId":"instance-recipient-01"}`

	cases := []struct {
		name        string
		input       []byte
		wantErrCode string // 非空：先收 ERROR 帧再断连；空：直接断连
	}{
		{"首帧非 HELLO（DATA）", rawFrameBytes(frameData, 1, 4, []byte("abcd")), ""},
		{"首帧非 HELLO（PING）", rawFrameBytes(framePing, 0, 0, nil), ""},
		{"未知帧类型", rawFrameBytes(0x7F, 0, 0, nil), ""},
		{"版本不符", func() []byte {
			b := rawFrameBytes(frameHello, 0, 2, []byte("{}"))
			b[2] = 9
			return b
		}(), ""},
		{"控制帧带流号", rawFrameBytes(frameHello, 5, 2, []byte("{}")), ""},
		{"DATA 流号为 0", rawFrameBytes(frameData, 0, 4, []byte("abcd")), ""},
		{"超长负载声明", rawFrameBytes(frameData, 1, 0x00FFFFFF, nil), ""},
		{"HELLO 非法 JSON", rawFrameBytes(frameHello, 0, 3, []byte("xxx")), "malformed"},
		{"HELLO 尾随内容", rawFrameBytes(frameHello, 0, 5, []byte("{} {}")), "malformed"},
		{"HELLO 未知角色", rawFrameBytes(frameHello, 0, 15, []byte(`{"role":"admin"}`)), "malformed"},
		{"HELLO 夹带路径字段", append(rawFrameBytes(frameHello, 0, 0, nil)[:frameHeaderSize],
			[]byte(`{"role":"recipient","path":"/etc/passwd","instanceId":"instance-recipient-01"}`)...), "malformed"},
		{"HELLO 夹带密钥字段", append(rawFrameBytes(frameHello, 0, 0, nil)[:frameHeaderSize],
			[]byte(`{"role":"recipient","key":"topsecret","instanceId":"instance-recipient-01"}`)...), "malformed"},
		{"HELLO 非法 instanceId", rawFrameBytes(frameHello, 0, 33, []byte(`{"role":"recipient","instanceId":"x"}`)), "malformed"},
		{"HELLO 超长载荷", rawFrameBytes(frameHello, 0, 8192, make([]byte, 8192)), "malformed"},
		{"HELLO 作品名含控制字符", func() []byte {
			b := []byte(`{"role":"sharer","action":"register","instanceId":"instance-sharer-0001","meta":{"title":"t","workCount":1,"source":"s","worksName":["作品\n1"]}}`)
			return rawFrameBytes(frameHello, 0, uint32(len(b)), b)
		}(), "malformed"},
		{"HELLO 作品名单名超长", func() []byte {
			b := []byte(`{"role":"sharer","action":"register","instanceId":"instance-sharer-0001","meta":{"title":"t","workCount":1,"source":"s","worksName":["` + strings.Repeat("名", maxWorksNameLen+1) + `"]}}`)
			return rawFrameBytes(frameHello, 0, uint32(len(b)), b)
		}(), "malformed"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn := rawDial(t, h.addr)
			defer func() { _ = conn.Close() }()
			writeRaw(t, conn, tc.input)
			if tc.wantErrCode != "" {
				fr, err := readTestFrame(conn, 5*time.Second)
				if err != nil || fr.Type != frameError {
					t.Fatalf("预期 ERROR 帧，得到 type=0x%02X err=%v", fr.Type, err)
				}
				var we wireErr
				_ = json.Unmarshal(fr.Payload, &we)
				if we.Code != tc.wantErrCode {
					t.Fatalf("错误码 %q，预期 %q", we.Code, tc.wantErrCode)
				}
			}
			expectClosedSoon(t, conn, tc.name)
		})
	}

	// 会话内违规：合法 HELLO 后发送只有中继可发的 STREAM_OPEN → 断连
	t.Run("收件人发送 STREAM_OPEN", func(t *testing.T) {
		conn := rawDial(t, h.addr)
		defer func() { _ = conn.Close() }()
		writeRaw(t, conn, rawFrameBytes(frameHello, 0, uint32(len(recipientHello)), []byte(recipientHello)))
		if fr, err := readTestFrame(conn, 5*time.Second); err != nil || fr.Type != frameError {
			t.Fatalf("未知 token 应答 ERROR，得到 type=0x%02X err=%v", fr.Type, err)
		}
		writeRaw(t, conn, rawFrameBytes(frameStreamOpen, 1, 0, nil))
		expectClosedSoon(t, conn, "STREAM_OPEN 越权")
	})

	// 协议前缀 + 随机垃圾：一律断连
	t.Run("随机垃圾字节", func(t *testing.T) {
		rng := rand.New(rand.NewSource(42))
		for i := 0; i < 20; i++ {
			conn := rawDial(t, h.addr)
			garbage := make([]byte, 64)
			_, _ = rng.Read(garbage)
			garbage[0], garbage[1] = 'L', 'S'
			writeRaw(t, conn, garbage)
			expectClosedSoon(t, conn, fmt.Sprintf("随机垃圾 #%d", i))
			_ = conn.Close()
		}
	})

	// 全部拒绝之后：中继仍存活，合法注册与拨号照常
	key := newE2EKey()
	A := startSharer(t, h.addr, regOpts{key: key})
	B, code := dialRecipient(t, h.addr, A.token, "instance-recipient-01", "")
	if code != "" {
		t.Fatalf("恶意输入处置后合法拨号被拒: %s", code)
	}
	defer func() { _ = B.Close() }()
	if _, _, err := recipientRoundTrip(B, key, []byte("still-alive")); err != nil {
		t.Fatalf("恶意输入处置后往返失败: %v", err)
	}
}

// TestHTTPPathSafety HTTP 面路径安全：路径穿越/非法 token/未授权管理路径一律无内容返回
func TestHTTPPathSafety(t *testing.T) {
	h := startRelay(t, nil)
	A := startSharer(t, h.addr, regOpts{})

	// 路径穿越：被归一化为重定向（30x）或 404，绝不返回文件内容
	if status, body := rawHTTPGet(t, h.addr, "/../../etc/passwd"); status == 200 || strings.Contains(body, "root:") {
		t.Fatalf("路径穿越请求返回内容: status=%d body=%q", status, body)
	}
	// token 格式非法的落地页路径 → 404
	if status, _ := rawHTTPGet(t, h.addr, "/s/short"); status != 404 {
		t.Fatalf("非法 token 应 404，得到 %d", status)
	}
	if status, _ := rawHTTPGet(t, h.addr, "/s/"+A.token+"/../../admin"); status == 200 {
		t.Fatalf("嵌套穿越路径不应命中 200")
	}
	// 未配置管理令牌：管理面整体 404
	if status, _ := rawHTTPGet(t, h.addr, "/admin/sessions"); status != 404 {
		t.Fatalf("未授权管理路径应 404，得到 %d", status)
	}
}

// rawHTTPGet 裸 TCP 发送 HTTP 请求（绕过客户端路径归一化），返回状态码与主体
func rawHTTPGet(t *testing.T, addr, path string) (int, string) {
	t.Helper()
	conn := rawDial(t, addr)
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", path, addr)
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("发送 HTTP 请求失败: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("读取 HTTP 响应失败: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	return resp.StatusCode, string(buf[:n])
}
