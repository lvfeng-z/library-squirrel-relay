package main

// 会话级溯源日志：JSONL 追加写，按日切文件，超留存期清理。
// 只记录会话维度的事实（时间/事件/token/设备实例 ID/来源 IP），永不记录内容字节。

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

// traceEvent 单条溯源记录
type traceEvent struct {
	TS         int64  `json:"ts"`                   // unix 毫秒
	Event      string `json:"event"`                // 事件类型（register/bind/dial/revoke/report/expire/ban/…）
	Token      string `json:"token,omitempty"`      // 会话 token
	InstanceID string `json:"instanceId,omitempty"` // 设备绑定实例 ID（客户端自报）
	IP         string `json:"ip,omitempty"`         // 来源 IP
	Detail     string `json:"detail,omitempty"`     // 补充说明（拒绝码/操作方等）
}

// traceFileRe 溯源日志文件名形态（trace-YYYYMMDD.jsonl）
var traceFileRe = regexp.MustCompile(`^trace-\d{8}\.jsonl$`)

// traceLog 溯源日志：按日切文件，句柄随日期重建
type traceLog struct {
	dir           string
	retentionDays int

	mu  sync.Mutex
	day string
	f   *os.File
}

func newTraceLog(dir string, retentionDays int) *traceLog {
	return &traceLog{dir: dir, retentionDays: retentionDays}
}

// record 追加一条溯源记录
func (t *traceLog) record(event, token, instanceID, ip, detail string) {
	if t == nil {
		return
	}
	now := time.Now()
	line, err := json.Marshal(traceEvent{
		TS: now.UnixMilli(), Event: event, Token: token,
		InstanceID: instanceID, IP: ip, Detail: detail,
	})
	if err != nil {
		slog.Error("溯源记录序列化失败", "event", event, "err", err)
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := t.ensureFileLocked(now); err != nil {
		slog.Error("溯源日志写入不可用", "err", err)
		return
	}
	if _, err := t.f.Write(append(line, '\n')); err != nil {
		slog.Error("溯源日志写入失败", "err", err)
	}
}

// ensureFileLocked 确保当日文件句柄就绪（须持锁调用）
func (t *traceLog) ensureFileLocked(now time.Time) error {
	day := now.Format("20060102")
	if t.f != nil && t.day == day {
		return nil
	}
	if t.f != nil {
		t.f.Close()
	}
	if err := os.MkdirAll(t.dir, 0o755); err != nil {
		return fmt.Errorf("创建溯源日志目录: %w", err)
	}
	f, err := os.OpenFile(filepath.Join(t.dir, "trace-"+day+".jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("打开溯源日志文件: %w", err)
	}
	t.f, t.day = f, day
	return nil
}

// cleanup 删除超过留存期的溯源日志文件
func (t *traceLog) cleanup(now time.Time) {
	if t == nil {
		return
	}
	entries, err := os.ReadDir(t.dir)
	if err != nil {
		return // 目录尚不存在视为无留存物
	}
	cutoff := now.AddDate(0, 0, -t.retentionDays).Format("20060102")
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !traceFileRe.MatchString(name) {
			continue
		}
		day := name[len("trace-") : len(name)-len(".jsonl")]
		if day < cutoff {
			if err := os.Remove(filepath.Join(t.dir, name)); err != nil {
				slog.Warn("溯源日志清理失败", "file", name, "err", err)
			} else {
				slog.Info("溯源日志超留存期已清理", "file", name)
			}
		}
	}
}

// close 关闭日志句柄
func (t *traceLog) close() {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.f != nil {
		t.f.Close()
		t.f = nil
	}
}
