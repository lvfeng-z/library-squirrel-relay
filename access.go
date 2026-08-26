package main

// 访问控制原语：token 生成与格式校验、访问密码哈希比较、封禁名单、滑动窗口限流。
// 端到端加密密钥从不经过中继——本文件与整个仓库不引入任何分组密码/解密能力。

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"regexp"
	"sync"
	"time"
)

var (
	// tokenRe token 字符集与长度：base64url（字母数字、-、_），22 字符 = 16 字节熵源编码
	tokenRe = regexp.MustCompile(`^[A-Za-z0-9_-]{22}$`)
	// instanceIDRe 设备绑定实例 ID：客户端自报，8..128 字符，字母数字与连字符
	instanceIDRe = regexp.MustCompile(`^[A-Za-z0-9-]{8,128}$`)
	// passwordHashRe 访问密码哈希：hex(sha256)，64 个小写十六进制字符
	passwordHashRe = regexp.MustCompile(`^[0-9a-f]{64}$`)
	// candidateAddrRe V2 直连候选地址（预留）：可打印 ASCII，长度受限，仅存储不消费
	candidateAddrRe = regexp.MustCompile(`^[\x21-\x7E]{1,253}$`)
)

func validTokenFormat(t string) bool   { return tokenRe.MatchString(t) }
func validInstanceID(s string) bool    { return instanceIDRe.MatchString(s) }
func validPasswordHash(s string) bool  { return s == "" || passwordHashRe.MatchString(s) }
func validCandidateAddr(s string) bool { return candidateAddrRe.MatchString(s) }

// newToken 生成分享 token：16 字节 crypto/rand → base64url 无填充（22 字符，128 bit 熵，不可猜测）
func newToken() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// samePasswordHash 常量时间比较两个访问密码哈希，避免时序侧信道
func samePasswordHash(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// banList 封禁名单：按设备实例 ID 与来源 IP 两个维度（多次被举报的实例自动进入）
type banList struct {
	Instances map[string]int64 `json:"instances"` // instanceId → 封禁时刻 unix 毫秒
	IPs       map[string]int64 `json:"ips"`       // IP → 封禁时刻 unix 毫秒
}

func newBanList() banList {
	return banList{Instances: map[string]int64{}, IPs: map[string]int64{}}
}

func (b *banList) banned(instanceID, ip string) bool {
	if instanceID != "" {
		if _, ok := b.Instances[instanceID]; ok {
			return true
		}
	}
	if ip != "" {
		if _, ok := b.IPs[ip]; ok {
			return true
		}
	}
	return false
}

// rateLimiter 滑动窗口限流器（内存态，重启清零）。limit<=0 表示不限。
type rateLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	events map[string][]time.Time
}

func newRateLimiter(limit int, window time.Duration) *rateLimiter {
	if limit <= 0 {
		return nil
	}
	return &rateLimiter{limit: limit, window: window, events: map[string][]time.Time{}}
}

// allow 记录一次事件并判定是否放行
func (l *rateLimiter) allow(key string) bool {
	if l == nil {
		return true
	}
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	events := l.events[key]
	fresh := events[:0]
	for _, ts := range events {
		if now.Sub(ts) < l.window {
			fresh = append(fresh, ts)
		}
	}
	if len(fresh) >= l.limit {
		l.events[key] = fresh
		return false
	}
	l.events[key] = append(fresh, now)
	return true
}

// prune 清理全部窗口外的过期事件，限制内存占用
func (l *rateLimiter) prune(now time.Time) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	for k, events := range l.events {
		fresh := events[:0]
		for _, ts := range events {
			if now.Sub(ts) < l.window {
				fresh = append(fresh, ts)
			}
		}
		if len(fresh) == 0 {
			delete(l.events, k)
		} else {
			l.events[k] = fresh
		}
	}
}
