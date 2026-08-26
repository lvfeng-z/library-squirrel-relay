package main

// 中继核心：会话注册表、隧道汇聚表、访问控制编排、过期扫描。
// 盲转不变量：本文件与整个仓库只搬运端到端加密后的密文帧，不存在任何解密路径。

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Relay 中继核心状态
type Relay struct {
	cfg   Config
	trace *traceLog

	mu       sync.Mutex
	sessions map[string]*Session // token → 会话（含终态行，供撤销/过期语义与溯源）
	tunnels  map[string]*tunnel  // token → 活动隧道（分享方在线时存在）
	bans     banList

	regPerIP    *rateLimiter // 注册限流（每 IP）
	regGlobal   *rateLimiter // 注册限流（全局，防会话风暴）
	dialPerIP   *rateLimiter // 拨号/绑定限流（每 IP）
	reportPerIP *rateLimiter // 举报限流（每 IP）

	globalStreams atomic.Int64
	conns         atomic.Int64
	closed        atomic.Bool
}

func newRelay(cfg Config, trace *traceLog) *Relay {
	hour, minute := time.Hour, time.Minute
	return &Relay{
		cfg:         cfg,
		trace:       trace,
		sessions:    map[string]*Session{},
		tunnels:     map[string]*tunnel{},
		bans:        newBanList(),
		regPerIP:    newRateLimiter(cfg.RegisterPerIPPerHour, hour),
		regGlobal:   newRateLimiter(cfg.RegisterGlobalPerHour, hour),
		dialPerIP:   newRateLimiter(cfg.DialPerIPPerMinute, minute),
		reportPerIP: newRateLimiter(cfg.ReportPerIPPerHour, hour),
	}
}

// remoteIP 取连接对端 IP（去掉端口）
func remoteIP(conn net.Conn) string {
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return conn.RemoteAddr().String()
	}
	return host
}

// writeConnFrame 向客户端连接写一帧（带写超时）
func (r *Relay) writeConnFrame(conn net.Conn, typ byte, streamID uint32, payload []byte) error {
	_ = conn.SetWriteDeadline(time.Now().Add(r.cfg.writeTimeout()))
	return writeFrame(conn, typ, streamID, payload)
}

// HandleProtoConn 处理一条嗅探为线协议的连接：读 HELLO、按角色分流。
// 任何输入异常都以断连收场，绝不向上传播 panic。
func (r *Relay) HandleProtoConn(conn net.Conn) {
	defer func() {
		if p := recover(); p != nil {
			slog.Error("协议连接处理异常已恢复", "err", p)
		}
		_ = conn.Close()
	}()
	ip := remoteIP(conn)
	_ = conn.SetReadDeadline(time.Now().Add(r.cfg.handshakeTimeout()))
	fr, err := readFrame(conn, r.cfg.MaxPayload)
	if err != nil {
		return
	}
	if fr.Type != frameHello || fr.StreamID != 0 {
		return
	}
	if len(fr.Payload) > r.cfg.MaxHelloBytes {
		_ = r.writeConnFrame(conn, frameError, 0, mustJSON(wireErr{"malformed", "HELLO 载荷超长"}))
		return
	}
	h, err := decodeHello(fr.Payload)
	if err != nil {
		_ = r.writeConnFrame(conn, frameError, 0, mustJSON(wireErr{"malformed", "HELLO 载荷非法"}))
		return
	}
	switch h.Role {
	case "sharer":
		r.handleSharer(conn, h, ip)
	case "recipient":
		r.handleDial(conn, h, ip)
	default:
		_ = r.writeConnFrame(conn, frameError, 0, mustJSON(wireErr{"malformed", "未知角色"}))
	}
}

// handleSharer 分享方连接：注册新会话或重新绑定已有会话，随后进入隧道读循环
func (r *Relay) handleSharer(conn net.Conn, h helloPayload, ip string) {
	switch h.Action {
	case "register":
		r.handleRegister(conn, h, ip)
	case "bind":
		r.handleBind(conn, h, ip)
	default:
		_ = r.writeConnFrame(conn, frameError, 0, mustJSON(wireErr{"malformed", "未知 action"}))
	}
}

// handleRegister 注册新会话：全部输入校验通过后生成高熵 token，本连接转为该会话的隧道
func (r *Relay) handleRegister(conn net.Conn, h helloPayload, ip string) {
	reject := func(code, msg string) {
		_ = r.writeConnFrame(conn, frameError, 0, mustJSON(wireErr{code, msg}))
		r.trace.record("register_rejected", "", h.InstanceID, ip, code)
	}
	if !validInstanceID(h.InstanceID) {
		reject("malformed", "instanceId 格式非法")
		return
	}
	if !validPasswordHash(h.PasswordHash) {
		reject("malformed", "passwordHash 格式非法")
		return
	}
	if err := validateShareMeta(h.Meta); err != nil {
		reject("malformed", err.Error())
		return
	}
	if err := validateCandidateAddrs(h.CandidateAddrs); err != nil {
		reject("malformed", err.Error())
		return
	}
	if !r.regPerIP.allow(ip) || !r.regGlobal.allow("") {
		reject("rate_limited", "注册过于频繁")
		return
	}
	expiresAt, err := resolveExpireMS(h.ExpireSeconds, r.cfg, time.Now())
	if err != nil {
		reject("malformed", err.Error())
		return
	}

	r.mu.Lock()
	if r.bans.banned(h.InstanceID, ip) {
		r.mu.Unlock()
		reject("banned", "该实例或 IP 已被封禁")
		return
	}
	active := 0
	for _, s := range r.sessions {
		if s.Status == SessionActive {
			active++
		}
	}
	if active >= r.cfg.MaxSessions {
		r.mu.Unlock()
		reject("limit", "中继会话数已达上限")
		return
	}
	// 生成不与任何在册 token 冲突的新 token（含终态行，防复活歧义）
	var token string
	for i := 0; i < 8; i++ {
		cand, err := newToken()
		if err != nil {
			break
		}
		if _, exists := r.sessions[cand]; !exists {
			token = cand
			break
		}
	}
	if token == "" {
		r.mu.Unlock()
		reject("server_error", "token 生成失败")
		return
	}
	meta := shareMeta{}
	if h.Meta != nil {
		meta = *h.Meta
	}
	s := &Session{
		Token: token, InstanceID: h.InstanceID, RegIP: ip,
		PasswordHash:   h.PasswordHash,
		CreatedAt:      time.Now().UnixMilli(),
		ExpiresAt:      expiresAt,
		Status:         SessionActive,
		Meta:           meta,
		CandidateAddrs: h.CandidateAddrs,
	}
	s.ensureRT()
	r.sessions[token] = s
	t := newTunnel(r, token, conn)
	r.tunnels[token] = t
	r.saveStateLocked()
	r.mu.Unlock()

	r.trace.record("register", token, h.InstanceID, ip, "")
	slog.Info("会话注册", "token", token, "instanceId", h.InstanceID, "ip", ip)

	// WELCOME 写失败也必须进入 serve：由其 defer tunnelDown 统一摘表收尾，防止隧道悬挂
	_ = r.writeConnFrame(conn, frameWelcome, 0, mustJSON(welcomePayload{Token: token, ExpiresAt: expiresAt}))
	t.serve()
}

// handleBind 重新绑定：分享方隧道断开后凭 token 重连，替换旧隧道（在途流随旧隧道终止）
func (r *Relay) handleBind(conn net.Conn, h helloPayload, ip string) {
	reject := func(code, msg string) {
		_ = r.writeConnFrame(conn, frameError, 0, mustJSON(wireErr{code, msg}))
		r.trace.record("bind_rejected", h.Token, h.InstanceID, ip, code)
	}
	if !validInstanceID(h.InstanceID) {
		reject("malformed", "instanceId 格式非法")
		return
	}
	if !r.dialPerIP.allow(ip) {
		reject("rate_limited", "操作过于频繁")
		return
	}
	r.mu.Lock()
	s, ok := r.sessions[h.Token]
	if !ok {
		r.mu.Unlock()
		reject("not_found", "分享不存在")
		return
	}
	// 惰性过期：绑定时即判定，保持撤销/过期语义在重启后依然精确
	if s.Status == SessionActive && s.expired(time.Now()) {
		s.Status = SessionExpired
		r.saveStateLocked()
		r.mu.Unlock()
		r.killSession(h.Token, SessionExpired, keepNone)
		r.trace.record("expire", h.Token, s.InstanceID, "", "绑定惰性判定")
		reject("expired", "分享已过期")
		return
	}
	switch s.Status {
	case SessionRevoked:
		r.mu.Unlock()
		reject("revoked", "分享已被撤销")
		return
	case SessionExpired:
		r.mu.Unlock()
		reject("expired", "分享已过期")
		return
	}
	if s.rt.limited.Load() {
		r.mu.Unlock()
		reject("limit", "分享流量已达上限")
		return
	}
	if r.bans.banned(h.InstanceID, ip) {
		r.mu.Unlock()
		reject("banned", "该实例或 IP 已被封禁")
		return
	}
	old := r.tunnels[h.Token]
	t := newTunnel(r, h.Token, conn)
	r.tunnels[h.Token] = t
	r.mu.Unlock()

	if old != nil {
		old.close() // 旧隧道在途流一并终止
	}
	r.trace.record("bind", h.Token, h.InstanceID, ip, "")
	slog.Info("隧道重绑", "token", h.Token, "instanceId", h.InstanceID, "ip", ip)

	// WELCOME 写失败也必须进入 serve：由其 defer tunnelDown 统一摘表收尾
	_ = r.writeConnFrame(conn, frameWelcome, 0, mustJSON(welcomePayload{ExpiresAt: s.ExpiresAt}))
	t.serve()
}

// checkDialAccess 收件人拨号前的访问控制（统一持锁判定）
func (r *Relay) checkDialAccess(token, instanceID, ip, passwordHash string) (*Session, *tunnel, wireErr) {
	if !validTokenFormat(token) {
		return nil, nil, wireErr{"not_found", "分享不存在"}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.sessions[token]
	if !ok {
		return nil, nil, wireErr{"not_found", "分享不存在"}
	}
	if s.Status == SessionActive && s.expired(time.Now()) {
		s.Status = SessionExpired
		r.saveStateLocked()
		r.trace.record("expire", token, s.InstanceID, "", "拨号惰性判定")
		if t := r.tunnels[token]; t != nil {
			delete(r.tunnels, token)
			go t.close()
		}
	}
	switch s.Status {
	case SessionRevoked:
		return nil, nil, wireErr{"revoked", "分享已被撤销"}
	case SessionExpired:
		return nil, nil, wireErr{"expired", "分享已过期"}
	}
	if s.rt.limited.Load() {
		return nil, nil, wireErr{"limit", "分享流量已达上限"}
	}
	if r.bans.banned(instanceID, ip) {
		return nil, nil, wireErr{"banned", "该实例或 IP 已被封禁"}
	}
	if s.PasswordHash != "" && !samePasswordHash(s.PasswordHash, passwordHash) {
		return nil, nil, wireErr{"bad_password", "访问密码错误"}
	}
	t, ok := r.tunnels[token]
	if !ok || t.dead.Load() {
		return nil, nil, wireErr{"offline", "分享方不在线"}
	}
	if int(s.rt.activeStreams.Load()) >= r.cfg.MaxStreamsPerSession {
		return nil, nil, wireErr{"limit", "该分享的并发拉取数已达上限"}
	}
	if int(r.globalStreams.Load()) >= r.cfg.MaxGlobalStreams {
		return nil, nil, wireErr{"limit", "中继并发流数已达上限"}
	}
	return s, t, wireErr{}
}

// handleDial 收件人拨号：校验访问控制后在隧道上开流，整条连接作为一条虚拟流盲转
func (r *Relay) handleDial(conn net.Conn, h helloPayload, ip string) {
	defer func() {
		if p := recover(); p != nil {
			slog.Error("拨号处理异常已恢复", "err", p)
		}
		_ = conn.Close()
	}()
	reject := func(e wireErr) {
		_ = r.writeConnFrame(conn, frameError, 0, mustJSON(e))
		r.trace.record("dial_rejected", h.Token, h.InstanceID, ip, e.Code)
	}
	if !validInstanceID(h.InstanceID) {
		reject(wireErr{"malformed", "instanceId 格式非法"})
		return
	}
	if !validPasswordHash(h.PasswordHash) {
		reject(wireErr{"malformed", "passwordHash 格式非法"})
		return
	}
	if !r.dialPerIP.allow(ip) {
		reject(wireErr{"rate_limited", "拨号过于频繁"})
		return
	}
	s, t, werr := r.checkDialAccess(h.Token, h.InstanceID, ip, h.PasswordHash)
	if werr.Code != "" {
		reject(werr)
		return
	}
	st, err := t.openStream(s)
	if err != nil {
		reject(wireErr{"offline", "分享方不在线"})
		return
	}
	if err := r.writeConnFrame(conn, frameWelcome, 0, mustJSON(welcomePayload{})); err != nil {
		st.shutdown(true)
		return
	}
	r.trace.record("dial", h.Token, h.InstanceID, ip, "")
	st.runRecipient(conn)
}

// keepNone killSession 不保留任何隧道的标记值
var keepNone *tunnel

// killSession 终止会话：置终态、从隧道表摘除并关闭隧道（在途流随隧道终止）、落盘。
// keepTunnel 指定的隧道不在本次关闭（撤销应答写出前需保持连接可用，由其读循环 defer 收尾）。
// 返回受影响的会话（token 未知时返回 nil）。
func (r *Relay) killSession(token, newStatus string, keepTunnel *tunnel) *Session {
	var victim *tunnel
	var s *Session
	r.mu.Lock()
	if cur, ok := r.sessions[token]; ok {
		s = cur
		if s.Status == SessionActive {
			s.Status = newStatus
		}
	}
	if t, ok := r.tunnels[token]; ok {
		delete(r.tunnels, token)
		if t != keepTunnel {
			victim = t
		}
	}
	if s != nil {
		r.saveStateLocked()
	}
	r.mu.Unlock()
	if victim != nil {
		victim.close()
	}
	return s
}

// revokeSession 撤销会话（分享方/举报/管理端共用入口），处置即时生效
func (r *Relay) revokeSession(token, actor, detail string, keepTunnel *tunnel) *Session {
	s := r.killSession(token, SessionRevoked, keepTunnel)
	if s != nil {
		r.trace.record("revoke", token, s.InstanceID, "", actor+": "+detail)
		slog.Info("会话撤销", "token", token, "actor", actor)
	}
	return s
}

// tunnelDown 隧道断开后的收尾：从隧道表摘除（按指针同一性，防误删重绑后的新隧道）并关闭。
// 会话本身保留，分享方可凭 token 重新绑定。
func (r *Relay) tunnelDown(t *tunnel) {
	r.mu.Lock()
	if cur, ok := r.tunnels[t.token]; ok && cur == t {
		delete(r.tunnels, t.token)
	}
	r.mu.Unlock()
	t.close()
}

// accountTraffic 累计会话流量；超限时会话被终止（在途流一并断开），返回 false 表示该流必须立即放弃
func (r *Relay) accountTraffic(s *Session, n int) bool {
	limit := r.cfg.MaxSessionTrafficBytes
	if limit <= 0 {
		return true
	}
	total := s.rt.traffic.Add(int64(n))
	if total > limit {
		if s.rt.limited.CompareAndSwap(false, true) {
			r.killSession(s.Token, SessionActive, keepNone) // 状态保持 active，仅运行时受限
			r.trace.record("traffic_limited", s.Token, s.InstanceID, "", "")
			slog.Info("会话流量超限", "token", s.Token, "limit", limit)
		}
		return false
	}
	return true
}

// reportSession 举报处理：立即撤销会话并累计实例被举报次数；达阈值自动封禁该实例并撤销其全部活跃会话。
// 返回 "ok" 或 "not_found"。
func (r *Relay) reportSession(token, reporterIP string) string {
	now := time.Now()
	r.mu.Lock()
	s, ok := r.sessions[token]
	if !ok {
		r.mu.Unlock()
		return "not_found"
	}
	if s.Status == SessionActive {
		s.Status = SessionRevoked
		s.ReportCount++
	}
	var cascade []string
	total := r.reportCountForInstanceLocked(s.InstanceID)
	if s.Status == SessionRevoked && r.cfg.AutoBanReportThreshold > 0 && total >= r.cfg.AutoBanReportThreshold {
		if _, wasBanned := r.bans.Instances[s.InstanceID]; !wasBanned {
			r.bans.Instances[s.InstanceID] = now.UnixMilli()
			slog.Info("实例多次被举报，自动封禁", "instanceId", s.InstanceID, "reports", total)
		}
		for tok2, s2 := range r.sessions {
			if s2.InstanceID == s.InstanceID && s2.Status == SessionActive {
				s2.Status = SessionRevoked
				cascade = append(cascade, tok2)
			}
		}
	}
	var victims []*tunnel
	for _, tok := range append([]string{token}, cascade...) {
		if t := r.tunnels[tok]; t != nil {
			delete(r.tunnels, tok)
			victims = append(victims, t)
		}
	}
	r.saveStateLocked()
	r.mu.Unlock()

	for _, t := range victims {
		t.close()
	}
	r.trace.record("report", token, s.InstanceID, reporterIP, "举报即撤销")
	return "ok"
}

// reportCountForInstanceLocked 统计某实例名下全部会话的累计被举报次数（须持 r.mu）
func (r *Relay) reportCountForInstanceLocked(instanceID string) int {
	total := 0
	for _, s := range r.sessions {
		if s.InstanceID == instanceID {
			total += s.ReportCount
		}
	}
	return total
}

// sweepLoop 周期扫描：到期会话的 kill-switch 处置、限流器与溯源日志清理
func (r *Relay) sweepLoop(ctx context.Context) {
	tick := time.NewTicker(r.cfg.sweepInterval())
	defer tick.Stop()
	var lastCleanup time.Time
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-tick.C:
			r.sweepOnce(now)
			if now.Sub(lastCleanup) > time.Hour {
				lastCleanup = now
				r.regPerIP.prune(now)
				r.regGlobal.prune(now)
				r.dialPerIP.prune(now)
				r.reportPerIP.prune(now)
				r.trace.cleanup(now)
			}
		}
	}
}

// sweepOnce 单轮扫描：把到有效期终点的活跃会话置为过期并拆隧道（在途流一并断开）
func (r *Relay) sweepOnce(now time.Time) {
	type victim struct {
		token      string
		instanceID string
		tun        *tunnel
	}
	var victims []victim
	r.mu.Lock()
	for tok, s := range r.sessions {
		if s.Status == SessionActive && s.expired(now) {
			s.Status = SessionExpired
			t := r.tunnels[tok]
			delete(r.tunnels, tok)
			victims = append(victims, victim{tok, s.InstanceID, t})
		}
	}
	if len(victims) > 0 {
		r.saveStateLocked()
	}
	r.mu.Unlock()
	for _, v := range victims {
		if v.tun != nil {
			v.tun.close()
		}
		r.trace.record("expire", v.token, v.instanceID, "", "定时扫描")
		slog.Info("会话到期失效", "token", v.token)
	}
}

// sessionForPage 落地页查询：返回会话（做惰性过期判定），未知返回 nil
func (r *Relay) sessionForPage(token string) *Session {
	if !validTokenFormat(token) {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	s, ok := r.sessions[token]
	if !ok {
		return nil
	}
	if s.Status == SessionActive && s.expired(time.Now()) {
		s.Status = SessionExpired
		r.saveStateLocked()
		if t := r.tunnels[token]; t != nil {
			delete(r.tunnels, token)
			go t.close()
		}
		r.trace.record("expire", token, s.InstanceID, "", "落地页惰性判定")
	}
	return s
}

// Close 中继停机：关闭全部隧道与溯源日志
func (r *Relay) Close() {
	r.closed.Store(true)
	r.mu.Lock()
	tuns := make([]*tunnel, 0, len(r.tunnels))
	for _, t := range r.tunnels {
		tuns = append(tuns, t)
	}
	r.tunnels = map[string]*tunnel{}
	r.mu.Unlock()
	for _, t := range tuns {
		t.close()
	}
	r.trace.close()
}
