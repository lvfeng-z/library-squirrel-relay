package main

// 会话模型与状态持久化：会话是分享方在中继登记的一次分享的全部账目。
// 持久化字段经状态文件（JSON 快照）保存，重启后撤销/过期/封禁等处置状态依然有效；
// 运行时字段（流量计数、并发流数、在线隧道）不持久化，重启即重置。

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync/atomic"
	"time"
)

// 会话状态（终态不可逆：撤销/过期后不可复活，分享方需重新发布新会话）
const (
	SessionActive  = "active"
	SessionRevoked = "revoked"
	SessionExpired = "expired"
)

// Session 分享会话
type Session struct {
	Token          string     `json:"token"`                    // 高熵随机 token（访问凭证）
	InstanceID     string     `json:"instanceId"`               // 分享方设备绑定实例 ID（溯源锚点）
	RegIP          string     `json:"regIp"`                    // 注册来源 IP（处置面：按 IP 精准封禁）
	PasswordHash   string     `json:"passwordHash,omitempty"`   // 可选访问密码的 sha256 hex（空=无密码）
	CreatedAt      int64      `json:"createdAt"`                // 注册时刻 unix 毫秒
	ExpiresAt      int64      `json:"expiresAt"`                // 到期时刻 unix 毫秒（0=无限期）
	Status         string     `json:"status"`                   // active / revoked / expired
	Meta           shareMeta  `json:"meta"`                     // 落地页文字元数据
	CandidateAddrs []string   `json:"candidateAddrs,omitempty"` // V2 直连候选地址（预留位，本期仅存储不消费）
	ReportCount    int        `json:"reportCount"`              // 该会话累计被举报次数
	rt             *sessionRT // 运行时态（不持久化）
}

// sessionRT 会话运行时态：中继进程内存中的计数与标记
type sessionRT struct {
	traffic       atomic.Int64 // 中继转发的字节累计（双向 DATA 负载，重启清零）
	limited       atomic.Bool  // 流量超限标记（处置：拒绝后续拨号，重启后按需重新累计）
	activeStreams atomic.Int64 // 当前并发流数
}

func newSessionRT() *sessionRT { return &sessionRT{} }

// ensureRT 加载持久化状态后补建运行时态
func (s *Session) ensureRT() *sessionRT {
	if s.rt == nil {
		s.rt = newSessionRT()
	}
	return s.rt
}

// expired 会话是否已到有效期终点（ExpiresAt=0 表示无限期）
func (s *Session) expired(now time.Time) bool {
	return s.ExpiresAt > 0 && now.UnixMilli() >= s.ExpiresAt
}

// validateShareMeta 校验落地页文字元数据（长度与控制字符，防注入/防滥用承载）
func validateShareMeta(m *shareMeta) error {
	if m == nil {
		return nil
	}
	if runeLenOf(m.Title) > 200 {
		return fmt.Errorf("标题过长（上限 200 字符）")
	}
	if runeLenOf(m.Source) > 100 {
		return fmt.Errorf("来源过长（上限 100 字符）")
	}
	if m.WorkCount < 0 || m.WorkCount > 1_000_000_000 {
		return fmt.Errorf("作品数非法")
	}
	if hasControlChars(m.Title) || hasControlChars(m.Source) {
		return fmt.Errorf("元数据含控制字符")
	}
	return nil
}

func runeLenOf(s string) int {
	n := 0
	for range s {
		n++
	}
	return n
}

func hasControlChars(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return true
		}
	}
	return false
}

// validateCandidateAddrs 校验 V2 直连候选地址（预留位：仅校验形态后存储，本期不消费）
func validateCandidateAddrs(addrs []string) error {
	if len(addrs) > 8 {
		return fmt.Errorf("候选地址数量超限（上限 8）")
	}
	for _, a := range addrs {
		if !validCandidateAddr(a) {
			return fmt.Errorf("候选地址 %q 形态非法", a)
		}
	}
	return nil
}

// resolveExpireMS 解析注册有效期：nil=用中继默认；0=无限期；>0=自定义秒数（超上限截断到上限）
func resolveExpireMS(in *int64, cfg Config, now time.Time) (int64, error) {
	if in == nil {
		if cfg.DefaultExpireSeconds <= 0 {
			return 0, nil
		}
		return now.Add(time.Duration(cfg.DefaultExpireSeconds) * time.Second).UnixMilli(), nil
	}
	if *in < 0 {
		return 0, fmt.Errorf("expireSeconds 不能为负")
	}
	if *in == 0 {
		return 0, nil
	}
	secs := *in
	if cfg.MaxExpireSeconds > 0 && secs > cfg.MaxExpireSeconds {
		secs = cfg.MaxExpireSeconds
	}
	return now.Add(time.Duration(secs) * time.Second).UnixMilli(), nil
}

// relayState 状态持久化文件结构（会话 + 封禁名单整体快照）
type relayState struct {
	Version  int        `json:"version"`
	Sessions []*Session `json:"sessions"`
	Bans     banList    `json:"bans"`
}

// loadState 启动时恢复会话与封禁状态。
// 文件损坏时不阻断启动：把损坏文件改名旁路保存后从空状态运行（处置连续性优先于数据找回）。
func (r *Relay) loadState() error {
	data, err := os.ReadFile(r.cfg.StateFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var st relayState
	if err := json.Unmarshal(data, &st); err != nil {
		backup := fmt.Sprintf("%s.corrupt-%d", r.cfg.StateFile, time.Now().UnixMilli())
		if err2 := os.Rename(r.cfg.StateFile, backup); err2 == nil {
			slog.Warn("状态文件损坏，已旁路保存并从空状态启动", "backup", backup)
		}
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessions = map[string]*Session{}
	for _, s := range st.Sessions {
		if s == nil || !validTokenFormat(s.Token) {
			continue
		}
		if s.Status == "" {
			s.Status = SessionActive
		}
		s.ensureRT()
		r.sessions[s.Token] = s
	}
	if st.Bans.Instances == nil {
		st.Bans.Instances = map[string]int64{}
	}
	if st.Bans.IPs == nil {
		st.Bans.IPs = map[string]int64{}
	}
	r.bans = st.Bans
	return nil
}

// saveStateLocked 原子落盘当前状态（临时文件 + rename；须持 r.mu 调用）
func (r *Relay) saveStateLocked() {
	st := relayState{Version: 1, Bans: r.bans}
	for _, s := range r.sessions {
		st.Sessions = append(st.Sessions, s)
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		slog.Error("状态序列化失败", "err", err)
		return
	}
	tmp := r.cfg.StateFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		slog.Error("状态写入失败", "file", tmp, "err", err)
		return
	}
	if err := os.Rename(tmp, r.cfg.StateFile); err != nil {
		slog.Error("状态落盘改名失败", "file", r.cfg.StateFile, "err", err)
	}
}
