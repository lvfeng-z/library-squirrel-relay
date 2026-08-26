package main

// HTTP 面：落地页（仅文字元数据）、举报入口、管理 API（封禁/撤销/查询）、健康检查。
// 落地页由中继服务——分享方离线时页面仍可访问；页面不含任何图像（预览最小化）。
// HTML 经 html/template 渲染，元数据自动转义防注入。

import (
	"crypto/subtle"
	_ "embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"
)

//go:embed web/index.html
var landingHTML string

var landingTmpl = template.Must(template.New("landing").Parse(landingHTML))

// pageStatus 会话在落地页上的展示状态
func pageStatus(s *Session) string {
	switch {
	case s.Status == SessionRevoked:
		return "revoked"
	case s.Status == SessionExpired:
		return "expired"
	case s.rt.limited.Load():
		return "limited"
	default:
		return "active"
	}
}

var pageStatusText = map[string]string{
	"revoked": "分享已被撤销（分享方撤销或经举报处置）。",
	"expired": "分享已过期。",
	"limited": "分享流量已达上限。",
}

// pageData 落地页模板数据
type pageData struct {
	Title             string
	Found             bool // 会话是否存在（不存在时不渲染元数据区）
	WorkCount         int64
	Source            string
	CreatedAtText     string
	ExpiresAtText     string // 空 = 长期有效
	Active            bool
	Status            string // active/revoked/expired/limited/unknown（模板 CSS 类）
	StatusText        string
	DeepLink          string // library-squirrel://share/{relay}/{token}
	ReportURL         string
	DownloadURL       string
	RetentionDaysText string // 隐私声明的溯源日志留存期文案（默认值 + 当前配置实际值）
}

// retentionDaysText 溯源日志留存期文案：默认值取 defaultConfig，当前值取本实例配置
// （经 sanitize 下限保护），两者并列展示——隐私声明承诺的期限即本实例真实生效的期限
func (c Config) retentionDaysText() string {
	return fmt.Sprintf("默认 %d 天，本实例当前配置 %d 天", defaultConfig().TraceRetentionDays, c.TraceRetentionDays)
}

// httpHandler 组装中继 HTTP 路由
func (r *Relay) httpHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("GET /s/{token}", r.serveLanding)
	mux.HandleFunc("POST /s/{token}/report", r.serveReport)
	mux.HandleFunc("POST /admin/kill", r.adminAuth(r.adminKill))
	mux.HandleFunc("POST /admin/ban", r.adminAuth(r.adminBan))
	mux.HandleFunc("POST /admin/unban", r.adminAuth(r.adminUnban))
	mux.HandleFunc("GET /admin/sessions", r.adminAuth(r.adminSessions))
	mux.HandleFunc("GET /admin/bans", r.adminAuth(r.adminBans))
	return r.securityHeaders(mux)
}

// securityHeaders 通用安全响应头
func (r *Relay) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'")
		next.ServeHTTP(w, req)
	})
}

// clientIP 提取 HTTP 请求来源 IP（TrustProxyHeaders 开启时优先取 X-Forwarded-For 首段）
func (r *Relay) clientIP(req *http.Request) string {
	if r.cfg.TrustProxyHeaders {
		if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			return strings.TrimSpace(parts[0])
		}
	}
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return req.RemoteAddr
	}
	return host
}

// relayAddrOf 对外服务地址：配置 PublicAddr 优先，否则按请求 Host 推导
func (r *Relay) relayAddrOf(req *http.Request) string {
	if r.cfg.PublicAddr != "" {
		return r.cfg.PublicAddr
	}
	return req.Host
}

// serveLanding 落地页：GET /s/{token}
func (r *Relay) serveLanding(w http.ResponseWriter, req *http.Request) {
	token := req.PathValue("token")
	s := r.sessionForPage(token)
	data := pageData{
		Title:             "分享不存在",
		Found:             false,
		Status:            "unknown",
		StatusText:        "分享不存在或已失效。",
		RetentionDaysText: r.cfg.retentionDaysText(),
	}
	if s != nil {
		status := pageStatus(s)
		data = pageData{
			Title:             s.Meta.Title,
			Found:             true,
			WorkCount:         s.Meta.WorkCount,
			Source:            s.Meta.Source,
			CreatedAtText:     formatMills(s.CreatedAt),
			Active:            status == "active",
			Status:            status,
			StatusText:        pageStatusText[status],
			DeepLink:          fmt.Sprintf("library-squirrel://share/%s/%s", r.relayAddrOf(req), token),
			ReportURL:         fmt.Sprintf("/s/%s/report", token),
			DownloadURL:       r.cfg.DownloadURL,
			RetentionDaysText: r.cfg.retentionDaysText(),
		}
		if s.ExpiresAt > 0 {
			data.ExpiresAtText = formatMills(s.ExpiresAt)
		}
		if data.Title == "" {
			data.Title = "未命名分享"
		}
		if data.Source == "" {
			data.Source = "未标注"
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if s == nil {
		w.WriteHeader(http.StatusNotFound)
	}
	if err := landingTmpl.Execute(w, data); err != nil {
		slog.Error("落地页渲染失败", "err", err)
	}
}

func formatMills(ms int64) string {
	return time.UnixMilli(ms).Format("2006-01-02 15:04")
}

// serveReport 举报入口：POST /s/{token}/report —— 举报即撤销会话，处置即时生效
func (r *Relay) serveReport(w http.ResponseWriter, req *http.Request) {
	token := req.PathValue("token")
	// 丢弃请求体（不接受内容陈述，防接口被当作任意数据承载面）
	_, _ = io.Copy(io.Discard, io.LimitReader(req.Body, 4096))
	ip := r.clientIP(req)
	if !validTokenFormat(token) {
		http.NotFound(w, req)
		return
	}
	if !r.reportPerIP.allow(ip) {
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"ok": false, "error": "举报过于频繁"})
		return
	}
	switch r.reportSession(token, ip) {
	case "not_found":
		http.NotFound(w, req)
	default:
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "revoked": true})
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// adminAuth 管理 API 鉴权：X-Admin-Token 常量时间比对；未配置令牌时整个管理面返回 404
func (r *Relay) adminAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		if r.cfg.AdminToken == "" {
			http.NotFound(w, req)
			return
		}
		got := req.Header.Get("X-Admin-Token")
		if got == "" || subtle.ConstantTimeCompare([]byte(got), []byte(r.cfg.AdminToken)) != 1 {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"ok": false, "error": "管理令牌错误"})
			return
		}
		next(w, req)
	}
}

// adminKill 终止指定会话：POST /admin/kill {"token":"..."}
func (r *Relay) adminKill(w http.ResponseWriter, req *http.Request) {
	var body struct {
		Token string `json:"token"`
	}
	if err := decodeJSONBody(req, &body); err != nil || !validTokenFormat(body.Token) {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "参数非法"})
		return
	}
	if r.revokeSession(body.Token, "admin", "管理端终止", keepNone) == nil {
		writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "分享不存在"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// adminBan 封禁实例或 IP：POST /admin/ban {"instanceId":"..."} 或 {"ip":"..."}
func (r *Relay) adminBan(w http.ResponseWriter, req *http.Request) {
	var body struct {
		InstanceID string `json:"instanceId"`
		IP         string `json:"ip"`
	}
	if err := decodeJSONBody(req, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "参数非法"})
		return
	}
	r.mu.Lock()
	now := time.Now().UnixMilli()
	var victims []string
	if body.InstanceID != "" {
		r.bans.Instances[body.InstanceID] = now
		for tok, s := range r.sessions {
			if s.InstanceID == body.InstanceID && s.Status == SessionActive {
				s.Status = SessionRevoked
				victims = append(victims, tok)
			}
		}
	}
	if body.IP != "" {
		r.bans.IPs[body.IP] = now
		for tok, s := range r.sessions {
			if s.RegIP == body.IP && s.Status == SessionActive {
				s.Status = SessionRevoked
				victims = append(victims, tok)
			}
		}
	}
	var tuns []*tunnel
	for _, tok := range victims {
		if t := r.tunnels[tok]; t != nil {
			delete(r.tunnels, tok)
			tuns = append(tuns, t)
		}
	}
	if body.InstanceID != "" || body.IP != "" {
		r.saveStateLocked()
	}
	r.mu.Unlock()
	for _, t := range tuns {
		t.close()
	}
	if body.InstanceID == "" && body.IP == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "参数非法"})
		return
	}
	r.trace.record("ban", "", body.InstanceID, body.IP, "管理端封禁")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "revoked": victims})
}

// adminUnban 解除封禁：POST /admin/unban {"instanceId":"..."} 或 {"ip":"..."}
func (r *Relay) adminUnban(w http.ResponseWriter, req *http.Request) {
	var body struct {
		InstanceID string `json:"instanceId"`
		IP         string `json:"ip"`
	}
	if err := decodeJSONBody(req, &body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "参数非法"})
		return
	}
	r.mu.Lock()
	if body.InstanceID != "" {
		delete(r.bans.Instances, body.InstanceID)
	}
	if body.IP != "" {
		delete(r.bans.IPs, body.IP)
	}
	r.saveStateLocked()
	r.mu.Unlock()
	r.trace.record("unban", "", body.InstanceID, body.IP, "管理端解封")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// adminSessions 会话清单（运营处置面）：GET /admin/sessions
func (r *Relay) adminSessions(w http.ResponseWriter, _ *http.Request) {
	type row struct {
		Token          string    `json:"token"`
		InstanceID     string    `json:"instanceId"`
		Status         string    `json:"status"`
		Online         bool      `json:"online"`
		ActiveStreams  int64     `json:"activeStreams"`
		TrafficBytes   int64     `json:"trafficBytes"`
		CreatedAt      int64     `json:"createdAt"`
		ExpiresAt      int64     `json:"expiresAt"`
		ReportCount    int       `json:"reportCount"`
		Meta           shareMeta `json:"meta"`
		CandidateAddrs []string  `json:"candidateAddrs"`
	}
	r.mu.Lock()
	rows := make([]row, 0, len(r.sessions))
	for tok, s := range r.sessions {
		_, online := r.tunnels[tok]
		rows = append(rows, row{
			Token: tok, InstanceID: s.InstanceID, Status: s.Status,
			Online:        online,
			ActiveStreams: s.rt.activeStreams.Load(),
			TrafficBytes:  s.rt.traffic.Load(),
			CreatedAt:     s.CreatedAt, ExpiresAt: s.ExpiresAt,
			ReportCount: s.ReportCount, Meta: s.Meta,
			CandidateAddrs: s.CandidateAddrs,
		})
	}
	r.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"sessions": rows})
}

// adminBans 封禁名单：GET /admin/bans
func (r *Relay) adminBans(w http.ResponseWriter, _ *http.Request) {
	r.mu.Lock()
	bans := r.bans
	r.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"instances": bans.Instances, "ips": bans.IPs})
}

// decodeJSONBody 解析有上限的 JSON 请求体
func decodeJSONBody(req *http.Request, v any) error {
	body, err := io.ReadAll(io.LimitReader(req.Body, 4096))
	if err != nil {
		return err
	}
	if len(body) == 0 {
		return fmt.Errorf("请求体为空")
	}
	return json.Unmarshal(body, v)
}
