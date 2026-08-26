package main

// 入口：加载配置、恢复状态、启动单端口服务。
// 单端口嗅探分流：连接前 2 字节为 "LS" 进入线协议（隧道/拨号），否则进入 HTTP（落地页/举报/管理）。
// TLS 归部署期反向代理（L4 TLS 终结后转发明文），代码不内置 TLS——见 PROTOCOL.md 部署说明。

import (
	"context"
	"flag"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

func main() {
	configPath := flag.String("config", "config.json", "配置文件路径（JSON，缺省文件或键用默认值）")
	flag.Parse()

	cfg, err := loadConfig(*configPath)
	if err != nil {
		slog.Error("配置加载失败", "err", err)
		os.Exit(1)
	}
	slog.SetLogLoggerLevel(parseLogLevel(cfg.LogLevel))

	trace := newTraceLog(cfg.TraceDir, cfg.TraceRetentionDays)
	trace.cleanup(time.Now())
	relay := newRelay(cfg, trace)
	if err := relay.loadState(); err != nil {
		slog.Warn("状态恢复失败，从空状态启动", "err", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	ln, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		slog.Error("监听失败", "addr", cfg.ListenAddr, "err", err)
		os.Exit(1)
	}

	go relay.sweepLoop(ctx)
	httpSrv := &http.Server{
		Handler:           relay.httpHandler(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	go runServer(ctx, ln, relay, httpSrv)

	slog.Info("中继已启动", "addr", cfg.ListenAddr)
	<-ctx.Done()
	slog.Info("收到退出信号，正在关闭")
	_ = ln.Close()
	relay.Close()
}

// runServer 接受循环 + 嗅探分发。关闭只依赖 ctx 取消与监听器关闭，通道不 close，避免发送侧竞态 panic。
func runServer(ctx context.Context, ln net.Listener, r *Relay, httpSrv *http.Server) {
	httpCh := make(chan net.Conn, 64)
	protoCh := make(chan net.Conn, 64)

	go func() {
		if err := httpSrv.Serve(&chanListener{ch: httpCh, ctx: ctx}); err != nil {
			slog.Debug("HTTP 服务退出", "err", err)
		}
	}()
	go func() {
		for {
			select {
			case c := <-protoCh:
				go r.HandleProtoConn(c)
			case <-ctx.Done():
				return
			}
		}
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			slog.Warn("接受连接失败", "err", err)
			continue
		}
		if int(r.conns.Load()) >= r.cfg.MaxConns {
			_ = conn.Close()
			continue
		}
		go dispatchConn(ctx, r, conn, httpCh, protoCh)
	}
}

// dispatchConn 嗅探连接前缀并分发：计数在包装后生效，连接关闭时由包装器递减
func dispatchConn(ctx context.Context, r *Relay, conn net.Conn, httpCh, protoCh chan net.Conn) {
	var head [2]byte
	_ = conn.SetReadDeadline(time.Now().Add(r.cfg.sniffTimeout()))
	_, err := io.ReadFull(conn, head[:])
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		_ = conn.Close()
		return
	}
	r.conns.Add(1)
	sc := &replayConn{Conn: &countedConn{Conn: conn, relay: r}}
	sc.push(head[:])
	if string(head[:]) == protoMagic {
		select {
		case protoCh <- sc:
		case <-ctx.Done():
			_ = sc.Close()
		}
		return
	}
	select {
	case httpCh <- sc:
	case <-ctx.Done():
		_ = sc.Close()
	}
}

// countedConn 连接包装：首次 Close 时递减全局连接计数（幂等）
type countedConn struct {
	net.Conn
	relay *Relay
	once  sync.Once
}

func (c *countedConn) Close() error {
	c.once.Do(func() { c.relay.conns.Add(-1) })
	return c.Conn.Close()
}

// replayConn 回放嗅探已读字节，后续读直达底层连接（HTTP 服务侧无感知）
type replayConn struct {
	net.Conn
	head []byte
}

func (c *replayConn) push(b []byte) { c.head = append(c.head, b...) }

func (c *replayConn) Read(p []byte) (int, error) {
	if len(c.head) > 0 {
		n := copy(p, c.head)
		c.head = c.head[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

// chanListener 从通道取连接的适配监听器（供 http.Server.Serve 消费嗅探后的 HTTP 连接）
type chanListener struct {
	ch  chan net.Conn
	ctx context.Context
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c, ok := <-l.ch:
		if !ok {
			return nil, net.ErrClosed
		}
		return c, nil
	case <-l.ctx.Done():
		return nil, net.ErrClosed
	}
}

func (l *chanListener) Close() error { return nil }

func (l *chanListener) Addr() net.Addr { return dummyAddr{} }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "tcp" }
func (dummyAddr) String() string  { return "chan-listener" }
