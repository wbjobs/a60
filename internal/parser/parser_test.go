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

func TestTimeOffsetAdjustment(t *testing.T) {
	now := time.Now().UTC()
	window := 15

	cfg := &config.Config{
		TimeWindow:   window,
		LevelPattern: `\b(INFO|WARN|WARNING|ERROR|FATAL|DEBUG)\b`,
		TimeFormats: []config.TimeFormat{
			{Regex: `\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}`, Layout: "2006-01-02T15:04:05", Group: 0},
		},
		Detection: config.DetectionRules{},
	}

	recentTime := now.Add(-5 * time.Minute).UTC()
	recentTimeStr := recentTime.Format("2006-01-02T15:04:05")

	offset := 8 * time.Second

	rawEntries := []logpull.RawLogEntry{
		{
			ServerName: "server-slow",
			Host:       "192.168.1.1",
			FilePath:   "/var/log/app/app.log",
			Line:       recentTimeStr + " INFO Slow server log entry",
			LineNumber: 1,
			TimeOffset: offset,
		},
		{
			ServerName: "server-normal",
			Host:       "192.168.1.2",
			FilePath:   "/var/log/app/app.log",
			Line:       recentTimeStr + " INFO Normal server log entry",
			LineNumber: 2,
			TimeOffset: 0,
		},
	}

	parsed := ParseLogs(rawEntries, cfg)

	if len(parsed) != 2 {
		t.Fatalf("期望2条日志，实际得到 %d 条", len(parsed))
	}

	var slowEntry, normalEntry *ParsedLogEntry
	for i := range parsed {
		if parsed[i].ServerName == "server-slow" {
			slowEntry = &parsed[i]
		} else if parsed[i].ServerName == "server-normal" {
			normalEntry = &parsed[i]
		}
	}

	if slowEntry == nil || normalEntry == nil {
		t.Fatal("未找到预期的日志条目")
	}

	if slowEntry.TimeOffset != offset {
		t.Errorf("server-slow 的时间偏移应为 %v，实际为 %v", offset, slowEntry.TimeOffset)
	}

	origUnix := slowEntry.OrigTimestamp.Unix()
	expectedOrigUnix := recentTime.Truncate(time.Second).Unix()
	if origUnix != expectedOrigUnix {
		t.Errorf("原始时间戳不正确，期望Unix时间 %d，实际 %d",
			expectedOrigUnix, origUnix)
	}

	expectedAdjustedUnix := recentTime.Add(-offset).Truncate(time.Second).Unix()
	adjustedUnix := slowEntry.Timestamp.Unix()
	if adjustedUnix != expectedAdjustedUnix {
		t.Errorf("调整后的时间戳不正确，期望Unix时间 %d，实际 %d",
			expectedAdjustedUnix, adjustedUnix)
	}

	if normalEntry.TimeOffset != 0 {
		t.Errorf("server-normal 的时间偏移应为 0，实际为 %v", normalEntry.TimeOffset)
	}

	if normalEntry.Timestamp.Unix() != normalEntry.OrigTimestamp.Unix() {
		t.Error("无偏移时，调整后的时间戳应等于原始时间戳")
	}

	if slowEntry.Timestamp.Unix() >= normalEntry.Timestamp.Unix() {
		t.Error("经过时间偏移调整后，server-slow 的日志应该排在 server-normal 之前")
	}

	if parsed[0].ServerName != "server-slow" {
		t.Errorf("排序后第一条应该是 server-slow，实际是 %s", parsed[0].ServerName)
	}

	t.Logf("时间偏移测试通过 | 偏移量: %v | 原始时间: %v | 调整后时间: %v",
		offset, slowEntry.OrigTimestamp.Format("15:04:05"), slowEntry.Timestamp.Format("15:04:05"))
}
