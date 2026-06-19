package parser

import (
	"testing"
	"time"

	"logaggregator/internal/config"
	"logaggregator/internal/logpull"
)

func TestNormalizeLevel(t *testing.T) {
	tests := []struct {
		input    string
		expected LogLevel
	}{
		{"INFO", LevelInfo},
		{"WARN", LevelWarn},
		{"WARNING", LevelWarn},
		{"ERROR", LevelError},
		{"FATAL", LevelFatal},
		{"DEBUG", LevelDebug},
		{"UNKNOWN", LevelUnknown},
		{"", LevelUnknown},
	}

	for _, tt := range tests {
		result := NormalizeLevel(tt.input)
		if result != tt.expected {
			t.Errorf("NormalizeLevel(%q) = %q, 期望 %q", tt.input, result, tt.expected)
		}
	}
}

func TestParseLogs(t *testing.T) {
	now := time.Now()
	window := 15

	cfg := &config.Config{
		TimeWindow: window,
		LevelPattern: `\b(INFO|WARN|WARNING|ERROR|FATAL|DEBUG)\b`,
		TimeFormats: []config.TimeFormat{
			{Regex: `\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}`, Layout: "2006-01-02T15:04:05", Group: 0},
		},
		Detection: config.DetectionRules{},
	}

	recentTime := now.Add(-5 * time.Minute).Format("2006-01-02T15:04:05")
	oldTime := now.Add(-30 * time.Minute).Format("2006-01-02T15:04:05")

	rawEntries := []logpull.RawLogEntry{
		{
			ServerName: "server1",
			Host:       "192.168.1.1",
			FilePath:   "/var/log/app/app.log",
			Line:       recentTime + " INFO Server started successfully",
			LineNumber: 1,
		},
		{
			ServerName: "server1",
			Host:       "192.168.1.1",
			FilePath:   "/var/log/app/app.log",
			Line:       recentTime + " ERROR Database connection failed: timeout",
			LineNumber: 2,
		},
		{
			ServerName: "server2",
			Host:       "192.168.1.2",
			FilePath:   "/var/log/app/app.log",
			Line:       recentTime + " WARN High memory usage detected",
			LineNumber: 3,
		},
		{
			ServerName: "server1",
			Host:       "192.168.1.1",
			FilePath:   "/var/log/app/app.log",
			Line:       oldTime + " INFO This log is too old and should be filtered",
			LineNumber: 4,
		},
		{
			ServerName: "server1",
			Host:       "192.168.1.1",
			FilePath:   "/var/log/app/app.log",
			Line:       "This line has no timestamp and no level",
			LineNumber: 5,
		},
	}

	parsed := ParseLogs(rawEntries, cfg)

	if len(parsed) < 3 {
		t.Errorf("期望至少3条日志（过滤掉旧的），但得到 %d 条", len(parsed))
	}

	hasInfo := false
	hasError := false
	hasWarn := false
	for _, entry := range parsed {
		switch entry.Level {
		case LevelInfo:
			hasInfo = true
			if !entry.HasTime {
				t.Error("INFO日志应该有时间戳")
			}
		case LevelError:
			hasError = true
		case LevelWarn:
			hasWarn = true
		}
	}

	if !hasInfo {
		t.Error("未找到INFO级别的日志")
	}
	if !hasError {
		t.Error("未找到ERROR级别的日志")
	}
	if !hasWarn {
		t.Error("未找到WARN级别的日志")
	}

	for i := 1; i < len(parsed); i++ {
		if parsed[i].Timestamp.Before(parsed[i-1].Timestamp) {
			t.Error("日志未按时间戳排序")
		}
	}

	t.Logf("解析测试通过，得到 %d 条日志", len(parsed))
}
