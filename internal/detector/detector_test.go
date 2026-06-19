package detector

import (
	"testing"
	"time"

	"logaggregator/internal/config"
	"logaggregator/internal/parser"
)

func TestDetectAnomalies(t *testing.T) {
	now := time.Now()

	entries := []parser.ParsedLogEntry{
		{
			ServerName: "server1",
			Timestamp:  now.Add(-10 * time.Minute),
			HasTime:    true,
			Level:      parser.LevelInfo,
			RawLine:    "2024-01-15T10:00:00 INFO Request processed successfully",
		},
		{
			ServerName: "server1",
			Timestamp:  now.Add(-9 * time.Minute),
			HasTime:    true,
			Level:      parser.LevelError,
			RawLine:    "2024-01-15T10:01:00 ERROR Database connection refused to mysql",
		},
		{
			ServerName: "server1",
			Timestamp:  now.Add(-8 * time.Minute),
			HasTime:    true,
			Level:      parser.LevelError,
			RawLine:    "2024-01-15T10:02:00 ERROR SQLException: deadlock detected",
		},
		{
			ServerName: "server2",
			Timestamp:  now.Add(-7 * time.Minute),
			HasTime:    true,
			Level:      parser.LevelError,
			RawLine:    "2024-01-15T10:03:00 ERROR Connection timeout after 30s",
		},
		{
			ServerName: "server2",
			Timestamp:  now.Add(-6 * time.Minute),
			HasTime:    true,
			Level:      parser.LevelWarn,
			RawLine:    "2024-01-15T10:04:00 WARN OutOfMemory warning in heap",
		},
		{
			ServerName: "server1",
			Timestamp:  now.Add(-5 * time.Minute),
			HasTime:    true,
			Level:      parser.LevelInfo,
			RawLine:    "2024-01-15T10:05:00 INFO 401 Unauthorized access attempt",
		},
	}

	rules := config.DetectionRules{
		KeywordMatches: []config.KeywordRule{
			{
				Name:     "数据库异常",
				Keywords: []string{"Connection refused", "deadlock", "SQLException", "timeout"},
				Color:    "red",
			},
			{
				Name:     "内存问题",
				Keywords: []string{"OutOfMemory", "OOM"},
				Color:    "purple",
			},
			{
				Name:     "鉴权失败",
				Keywords: []string{"401 Unauthorized", "authentication failed"},
				Color:    "yellow",
			},
		},
		ConsecutiveLevels: []config.ConsecutiveLevelRule{
			{
				Name:  "连续ERROR告警",
				Level: "ERROR",
				Count: 3,
			},
			{
				Name:  "连续WARN警告",
				Level: "WARN",
				Count: 5,
			},
		},
	}

	detectedEntries, alerts := DetectAnomalies(entries, rules)

	keywordAlertCount := 0
	consecutiveAlertCount := 0
	for _, a := range alerts {
		switch a.Type {
		case "keyword_match":
			keywordAlertCount++
		case "consecutive_level":
			consecutiveAlertCount++
		}
	}

	t.Logf("关键词告警数: %d", keywordAlertCount)
	t.Logf("连续级别告警数: %d", consecutiveAlertCount)
	t.Logf("总告警数: %d", len(alerts))

	if consecutiveAlertCount < 1 {
		t.Error("期望至少检测到一个连续ERROR告警，但未检测到")
	}

	foundConsecutiveRule := false
	for i, entry := range detectedEntries {
		for _, rule := range entry.MatchedRules {
			if rule == "连续ERROR告警" {
				foundConsecutiveRule = true
				t.Logf("条目[%d]匹配连续ERROR规则: %s", i, entry.RawLine[:50])
			}
		}
	}

	if !foundConsecutiveRule {
		t.Error("期望在日志条目中找到连续ERROR规则标记")
	}

	keywordMatchedEntries := 0
	for _, entry := range detectedEntries {
		for _, rule := range entry.MatchedRules {
			if rule == "数据库异常" || rule == "内存问题" || rule == "鉴权失败" {
				keywordMatchedEntries++
				break
			}
		}
	}

	t.Logf("匹配关键词的条目数: %d", keywordMatchedEntries)
	if keywordMatchedEntries < 4 {
		t.Errorf("期望至少4条日志匹配关键词规则，实际只有 %d 条", keywordMatchedEntries)
	}

	for i, entry := range detectedEntries {
		t.Logf("条目[%d] level=%s 规则=%v 告警=%v 内容=%s",
			i, entry.Level, entry.MatchedRules, entry.IsAlert,
			truncateString(entry.RawLine, 60))
	}

	t.Log("异常检测测试完成")
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func TestItoa(t *testing.T) {
	tests := []struct {
		input    int
		expected string
	}{
		{0, "0"},
		{1, "1"},
		{123, "123"},
		{999, "999"},
		{-42, "-42"},
		{1000, "1000"},
	}

	for _, tt := range tests {
		result := itoa(tt.input)
		if result != tt.expected {
			t.Errorf("itoa(%d) = %q, 期望 %q", tt.input, result, tt.expected)
		}
	}
}
