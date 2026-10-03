package main

// 配置：JSON 配置文件覆盖默认值（文件不存在或某键缺省时用默认值）。
// 全部配置键与默认值见 PROTOCOL.md「配置参考」。秒/字节类字段一律用整数，仓库不引入第三方依赖。

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"
)

// Config 中继运行配置
type Config struct {
	ListenAddr  string `json:"listenAddr"`  // 监听地址（线协议与 HTTP 单口嗅探共用）
	PublicAddr  string `json:"publicAddr"`  // 对外服务地址 host[:port]（深链用）；空=按请求 Host 推导
	DownloadURL string `json:"downloadUrl"` // 落地页「未安装应用」兜底下载链接
	AdminToken  string `json:"adminToken"`  // 管理 API 令牌；空=禁用管理 API
	LogLevel    string `json:"logLevel"`    // debug | info | warn | error

	StateFile          string `json:"stateFile"`          // 会话与封禁状态持久化文件
	TraceDir           string `json:"traceDir"`           // 溯源日志目录
	TraceRetentionDays int    `json:"traceRetentionDays"` // 溯源日志留存天数

	DefaultExpireSeconds int64 `json:"defaultExpireSeconds"` // 注册未指定有效期时的默认秒数
	MaxExpireSeconds     int64 `json:"maxExpireSeconds"`     // 自定义有效期上限秒数（0=不设上限）

	MaxSessions            int   `json:"maxSessions"`            // 活跃会话数上限
	MaxStreamsPerSession   int   `json:"maxStreamsPerSession"`   // 单会话并发流上限
	MaxGlobalStreams       int   `json:"maxGlobalStreams"`       // 全局并发流上限
	MaxSessionTrafficBytes int64 `json:"maxSessionTrafficBytes"` // 单会话流量字节上限（0=不限）
	MaxConns               int   `json:"maxConns"`               // 全局连接数上限（线协议+HTTP 合计）

	MaxPayload    int `json:"maxPayload"`    // 单帧负载上限（字节）
	MaxHelloBytes int `json:"maxHelloBytes"` // HELLO 载荷上限（字节，且不得大于 MaxPayload）

	HandshakeTimeoutSec       int `json:"handshakeTimeoutSec"`       // HELLO 握手超时
	WriteTimeoutSec           int `json:"writeTimeoutSec"`           // 单帧写超时
	TunnelKeepaliveSec        int `json:"tunnelKeepaliveSec"`        // 隧道保活探测间隔
	TunnelKeepaliveTimeoutSec int `json:"tunnelKeepaliveTimeoutSec"` // 隧道无任何入帧的超时
	RecipientIdleTimeoutSec   int `json:"recipientIdleTimeoutSec"`   // 收件人连接空闲读超时
	SniffTimeoutSec           int `json:"sniffTimeoutSec"`           // 单口嗅探读取前缀的超时
	SweepIntervalSec          int `json:"sweepIntervalSec"`          // 过期扫描间隔

	RegisterPerIPPerHour  int `json:"registerPerIPPerHour"`  // 每 IP 每小时注册上限
	RegisterGlobalPerHour int `json:"registerGlobalPerHour"` // 全局每小时注册上限
	DialPerIPPerMinute    int `json:"dialPerIPPerMinute"`    // 每 IP 每分钟拨号（含 bind）上限
	ReportPerIPPerHour    int `json:"reportPerIPPerHour"`    // 每 IP 每小时举报上限

	AutoBanReportThreshold int `json:"autoBanReportThreshold"` // 同一实例累计被举报达到该次数后自动封禁

	TrustProxyHeaders bool `json:"trustProxyHeaders"` // 信任 X-Forwarded-For（经反向代理部署时开启）
}

// defaultConfig 默认配置（有效期默认与上限均为 30 天；溯源日志留存 183 天 ≈ 6 个月）
func defaultConfig() Config {
	return Config{
		ListenAddr:                "0.0.0.0:9527",
		LogLevel:                  "info",
		StateFile:                 "state.json",
		TraceDir:                  "log",
		TraceRetentionDays:        183,
		DefaultExpireSeconds:      30 * 24 * 3600,
		MaxExpireSeconds:          30 * 24 * 3600,
		MaxSessions:               1000,
		MaxStreamsPerSession:      8,
		MaxGlobalStreams:          512,
		MaxSessionTrafficBytes:    64 << 30,
		MaxConns:                  2048,
		MaxPayload:                32 << 10,
		MaxHelloBytes:             4 << 10,
		HandshakeTimeoutSec:       15,
		WriteTimeoutSec:           30,
		TunnelKeepaliveSec:        30,
		TunnelKeepaliveTimeoutSec: 75,
		RecipientIdleTimeoutSec:   600,
		SniffTimeoutSec:           10,
		SweepIntervalSec:          10,
		RegisterPerIPPerHour:      5,
		RegisterGlobalPerHour:     60,
		DialPerIPPerMinute:        60,
		ReportPerIPPerHour:        10,
		AutoBanReportThreshold:    3,
		TrustProxyHeaders:         false,
	}
}

// loadConfig 从 JSON 配置文件加载配置：文件不存在时整体用默认值，存在时缺省键保持默认值
func loadConfig(path string) (Config, error) {
	cfg := defaultConfig()
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, err
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("解析配置文件 %s: %w", path, err)
	}
	cfg.sanitize()
	if err := cfg.validate(); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// sanitize 对关键下限做兜底修正，避免零值/负值配置破坏运行不变量
func (c *Config) sanitize() {
	floor := func(v *int, min int) {
		if *v < min {
			*v = min
		}
	}
	floor(&c.MaxPayload, 1024)
	floor(&c.MaxHelloBytes, 512)
	if c.MaxHelloBytes > c.MaxPayload {
		c.MaxHelloBytes = c.MaxPayload
	}
	floor(&c.MaxSessions, 1)
	floor(&c.MaxStreamsPerSession, 1)
	floor(&c.MaxGlobalStreams, 1)
	floor(&c.MaxConns, 16)
	floor(&c.HandshakeTimeoutSec, 1)
	floor(&c.WriteTimeoutSec, 1)
	floor(&c.TunnelKeepaliveSec, 1)
	floor(&c.TunnelKeepaliveTimeoutSec, 1)
	floor(&c.RecipientIdleTimeoutSec, 1)
	floor(&c.SniffTimeoutSec, 1)
	floor(&c.SweepIntervalSec, 1)
	if c.TraceRetentionDays < 1 {
		c.TraceRetentionDays = 1
	}
}

// validate 显式误配校验：此类配置不做兜底修正，直接报错拒绝启动。
// defaultExpireSeconds 非正 = 配置侧逃生口——注册未指定有效期（nil）将产生不到期会话，
// 违背「取消无限期」定案（resolveExpireMS 已拒绝显式 0，此处收口默认值侧）。
func (c Config) validate() error {
	if c.DefaultExpireSeconds <= 0 {
		return fmt.Errorf("defaultExpireSeconds 须为正数（无限期已停用）")
	}
	return nil
}

// 各超时的 time.Duration 换算
func (c Config) handshakeTimeout() time.Duration {
	return time.Duration(c.HandshakeTimeoutSec) * time.Second
}
func (c Config) writeTimeout() time.Duration { return time.Duration(c.WriteTimeoutSec) * time.Second }
func (c Config) tunnelKeepalive() time.Duration {
	return time.Duration(c.TunnelKeepaliveSec) * time.Second
}
func (c Config) tunnelReadTimeout() time.Duration {
	return time.Duration(c.TunnelKeepaliveTimeoutSec) * time.Second
}
func (c Config) recipientIdle() time.Duration {
	return time.Duration(c.RecipientIdleTimeoutSec) * time.Second
}
func (c Config) sniffTimeout() time.Duration  { return time.Duration(c.SniffTimeoutSec) * time.Second }
func (c Config) sweepInterval() time.Duration { return time.Duration(c.SweepIntervalSec) * time.Second }

// parseLogLevel 解析日志级别配置
func parseLogLevel(s string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
