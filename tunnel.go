package main

// 出站隧道：分享方的一条 TCP 连接复用 N 条虚拟流（frp 模式）。
// 中继在隧道上分配流 ID（STREAM_OPEN 通知分享方），把每条收件人连接的字节按流双向盲转——
// DATA 帧负载是分享方与收件人之间端到端加密的密文，中继只搬运、不解析、不落盘。

import (
	"errors"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// recipientStreamID 收件人连接上唯一一条流固定使用的流号（每条收件人连接 = 一条虚拟流）
const recipientStreamID uint32 = 1

// streamOutBuffer 每流写给收件人的帧缓冲深度（慢消费者保护：缓冲满即断流）
const streamOutBuffer = 128

var errTunnelClosed = errors.New("隧道已关闭")

// wireFrame 待写给某连接的一帧（中继侧出队形态）
type wireFrame struct {
	typ      byte
	streamID uint32
	payload  []byte
}

// tunnel 单条分享方隧道连接
type tunnel struct {
	relay *Relay
	token string
	conn  net.Conn

	writeMu sync.Mutex // 隧道连接写串行化（多流并发写帧）

	mu      sync.Mutex
	streams map[uint32]*tunnelStream
	nextID  uint32

	dead      atomic.Bool
	closed    chan struct{}
	closeOnce sync.Once

	lastActMills atomic.Int64 // 最近收到分享方帧的时刻（保活判定）
}

func newTunnel(r *Relay, token string, conn net.Conn) *tunnel {
	t := &tunnel{
		relay: r, token: token, conn: conn,
		streams: map[uint32]*tunnelStream{},
		closed:  make(chan struct{}),
	}
	t.lastActMills.Store(time.Now().UnixMilli())
	return t
}

// writeFrame 向隧道写一帧（互斥串行化 + 写超时）
func (t *tunnel) writeFrame(typ byte, streamID uint32, payload []byte) error {
	t.writeMu.Lock()
	defer t.writeMu.Unlock()
	_ = t.conn.SetWriteDeadline(time.Now().Add(t.relay.cfg.writeTimeout()))
	return writeFrame(t.conn, typ, streamID, payload)
}

// openStream 为一条收件人连接在隧道上开流：分配流 ID 并通知分享方。
// 成功后并发计数已递增；失败时清理半开状态并返回错误（调用方按 offline 处理）。
func (t *tunnel) openStream(s *Session) (*tunnelStream, error) {
	t.mu.Lock()
	if t.dead.Load() {
		t.mu.Unlock()
		return nil, errTunnelClosed
	}
	t.nextID++
	id := t.nextID
	st := newTunnelStream(t, s, id)
	t.streams[id] = st
	t.mu.Unlock()

	if err := t.writeFrame(frameStreamOpen, id, nil); err != nil {
		t.removeStream(st)
		return nil, errTunnelClosed
	}
	s.rt.activeStreams.Add(1)
	t.relay.globalStreams.Add(1)
	return st, nil
}

// removeStream 从隧道流表中摘除指定流（按指针同一性判定，幂等）
func (t *tunnel) removeStream(st *tunnelStream) {
	t.mu.Lock()
	if cur, ok := t.streams[st.id]; ok && cur == st {
		delete(t.streams, st.id)
	}
	t.mu.Unlock()
}

// streamByID 查询隧道上的活流
func (t *tunnel) streamByID(id uint32) *tunnelStream {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.streams[id]
}

// close 关闭隧道连接并终止全部在途流（幂等）
func (t *tunnel) close() {
	t.closeOnce.Do(func() {
		t.dead.Store(true)
		close(t.closed)
		_ = t.conn.Close() // 解除读循环阻塞
		t.teardownStreams()
	})
}

// teardownStreams 终止隧道上全部活流（通知分享方的 STREAM_CLOSE 会因连接已断而静默失败，属预期）
func (t *tunnel) teardownStreams() {
	t.mu.Lock()
	streams := make([]*tunnelStream, 0, len(t.streams))
	for _, s := range t.streams {
		streams = append(streams, s)
	}
	t.mu.Unlock()
	for _, s := range streams {
		s.shutdown(true)
	}
}

// serve 隧道读循环：处理分享方发来的帧，直到连接断开或隧道被关闭。
func (t *tunnel) serve() {
	defer t.relay.tunnelDown(t)
	go t.keepaliveLoop()
	cfg := t.relay.cfg
	for {
		_ = t.conn.SetReadDeadline(time.Now().Add(cfg.tunnelReadTimeout()))
		fr, err := readFrame(t.conn, cfg.MaxPayload)
		if err != nil {
			return
		}
		t.lastActMills.Store(time.Now().UnixMilli())
		switch fr.Type {
		case frameData:
			st := t.streamByID(fr.StreamID)
			if st == nil {
				continue // 流已结束或未知：丢弃迟到帧
			}
			if !t.relay.accountTraffic(st.session, len(fr.Payload)) {
				continue // 会话流量超限，会话与隧道正在被终止
			}
			if !st.deliver(fr.Payload) {
				// 收件人消费过慢或流已关：按慢消费者策略终止该流
				st.shutdown(true)
			}
		case frameStreamClose:
			if st := t.streamByID(fr.StreamID); st != nil {
				st.finishFromSharer()
			}
		case framePing:
			_ = t.writeFrame(framePong, 0, fr.Payload)
		case framePong:
			// lastAct 已在循环头刷新
		case frameRevoke:
			// 分享方撤销：终结会话但保留本隧道到应答写出后再收尾（由 defer tunnelDown 关闭）
			t.relay.revokeSession(t.token, "sharer", "分享方撤销", t)
			_ = t.writeFrame(frameResult, 0, mustJSON(resultPayload{OK: true, Action: "revoke"}))
			return
		default:
			// 分享方不得发送 HELLO/WELCOME/ERROR/STREAM_OPEN/RESULT
			return
		}
	}
}

// keepaliveLoop 周期向分享方发 PING；长时间无任何入帧即判定隧道死亡
func (t *tunnel) keepaliveLoop() {
	cfg := t.relay.cfg
	tick := time.NewTicker(cfg.tunnelKeepalive())
	defer tick.Stop()
	for {
		select {
		case <-t.closed:
			return
		case <-tick.C:
			if time.Since(time.UnixMilli(t.lastActMills.Load())) > cfg.tunnelReadTimeout() {
				slog.Info("隧道保活超时", "token", t.token)
				t.close()
				return
			}
			if err := t.writeFrame(framePing, 0, nil); err != nil {
				return
			}
		}
	}
}

// streamEnd 收件人连接读侧的结束方式
type streamEnd int

const (
	endClean streamEnd = iota // 收件人主动半关闭（STREAM_CLOSE）
	endAbort                  // 连接错误/超时/协议违规
)

// tunnelStream 隧道内的一条虚拟流，绑定一条收件人连接。
// out 由单写者 goroutine（writeLoop）消费，保证发给收件人的帧顺序与隧道到达顺序一致；
// writeLoop 退出时关闭连接并关闭 writerDone，供读侧在排空全部待写帧后再收尾。
type tunnelStream struct {
	tun     *tunnel
	session *Session
	id      uint32

	out          chan wireFrame // 待写给收件人连接的帧
	finished     chan struct{}  // 流收尾信号（writeLoop 排空后退出）
	writerDone   chan struct{}  // writeLoop 完全退出（含排空）的信号
	notifyOnce   sync.Once      // 向分享方转发 STREAM_CLOSE 的幂等闸
	shutdownOnce sync.Once
}

func newTunnelStream(t *tunnel, s *Session, id uint32) *tunnelStream {
	return &tunnelStream{
		tun: t, session: s, id: id,
		out:        make(chan wireFrame, streamOutBuffer),
		finished:   make(chan struct{}),
		writerDone: make(chan struct{}),
	}
}

// notifySharer 向分享方转发流结束（幂等）
func (st *tunnelStream) notifySharer() {
	st.notifyOnce.Do(func() {
		_ = st.tun.writeFrame(frameStreamClose, st.id, nil)
	})
}

// deliver 把隧道侧到达的数据帧投递给收件人写者。
// 返回 false 表示流已关或收件人消费过慢（缓冲满）——调用方应终止该流。
func (st *tunnelStream) deliver(payload []byte) bool {
	select {
	case <-st.finished:
		return false
	default:
	}
	select {
	case st.out <- wireFrame{typ: frameData, streamID: recipientStreamID, payload: payload}:
		return true
	default:
		return false // 缓冲满：收件人消费过慢
	}
}

// runRecipient 收件人连接主处理：WELCOME 已写出后启动写者与读者。
func (st *tunnelStream) runRecipient(conn net.Conn) {
	cfg := st.tun.relay.cfg
	go st.writeLoop(conn)
	res := st.readLoop(conn)
	if res == endClean {
		// 收件人半关闭（请求发完）：通知分享方后等待写者排空（分享方关流/隧道断开/超时均会结束等待）
		st.notifySharer()
		timer := time.NewTimer(cfg.recipientIdle())
		select {
		case <-st.writerDone:
			timer.Stop()
		case <-timer.C:
			// 分享方长时间未收尾：超时终止
		}
	}
	st.shutdown(true)
	_ = conn.Close()
}

// readLoop 收件人连接读循环：把收件人发来的密文帧转发进隧道
func (st *tunnelStream) readLoop(conn net.Conn) streamEnd {
	cfg := st.tun.relay.cfg
	for {
		_ = conn.SetReadDeadline(time.Now().Add(cfg.recipientIdle()))
		fr, err := readFrame(conn, cfg.MaxPayload)
		if err != nil {
			return endAbort
		}
		switch fr.Type {
		case frameData:
			if fr.StreamID != recipientStreamID {
				return endAbort
			}
			if !st.tun.relay.accountTraffic(st.session, len(fr.Payload)) {
				return endAbort // 会话流量超限，会话正在被终止
			}
			if err := st.tun.writeFrame(frameData, st.id, fr.Payload); err != nil {
				return endAbort
			}
		case frameStreamClose:
			if fr.StreamID != recipientStreamID {
				return endAbort
			}
			return endClean
		case framePing:
			select {
			case st.out <- wireFrame{typ: framePong}:
			case <-st.finished:
			default: // 缓冲满则丢弃 PONG（保活属尽力而为）
			}
		default:
			return endAbort // 收件人只允许 DATA/STREAM_CLOSE/PING
		}
	}
}

// writeLoop 收件人连接写循环：唯一写者，保证 WELCOME 之后的帧序。
// 任何退出路径都关闭连接——半关闭排空后收件人不应再收数据，读循环依赖此关闭解除阻塞。
func (st *tunnelStream) writeLoop(conn net.Conn) {
	defer func() {
		_ = conn.Close()
		close(st.writerDone)
	}()
	cfg := st.tun.relay.cfg
	for {
		select {
		case f := <-st.out:
			_ = conn.SetWriteDeadline(time.Now().Add(cfg.writeTimeout()))
			if err := writeFrame(conn, f.typ, f.streamID, f.payload); err != nil {
				st.shutdown(true)
				return
			}
		case <-st.finished:
			for { // 排空剩余缓冲后收尾
				select {
				case f := <-st.out:
					_ = conn.SetWriteDeadline(time.Now().Add(cfg.writeTimeout()))
					if err := writeFrame(conn, f.typ, f.streamID, f.payload); err != nil {
						return
					}
				default:
					return
				}
			}
		}
	}
}

// finishFromSharer 分享方主动结束流：把 STREAM_CLOSE 排入收件人写队列（数据排空后送达）并收尾
func (st *tunnelStream) finishFromSharer() {
	select {
	case st.out <- wireFrame{typ: frameStreamClose, streamID: recipientStreamID}:
	case <-st.finished:
	}
	st.shutdown(false)
}

// shutdown 流收尾：恰好一次地（可选）通知分享方、摘表、递减并发计数
func (st *tunnelStream) shutdown(notifySharer bool) {
	st.shutdownOnce.Do(func() {
		close(st.finished)
		if notifySharer {
			st.notifySharer()
		}
		st.tun.removeStream(st)
		st.session.rt.activeStreams.Add(-1)
		st.tun.relay.globalStreams.Add(-1)
	})
}
