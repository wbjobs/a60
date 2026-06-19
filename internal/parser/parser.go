package parser

import (
	"fmt"
	"regexp"
	"sort"
	"time"

	"logaggregator/internal/config"
	"logaggregator/internal/logpull"
)

type LogLevel string

const (
	LevelDebug   LogLevel = "DEBUG"
	LevelInfo    LogLevel = "INFO"
	LevelWarn    LogLevel = "WARN"
	LevelWarning LogLevel = "WARNING"
	LevelError   LogLevel = "ERROR"
	LevelFatal   LogLevel = "FATAL"
	LevelUnknown LogLevel = "UNKNOWN"
)

type ParsedLogEntry struct {
	ServerName   string
	Host         string
	FilePath     string
	LineNumber   int64
	RawLine      string
	Timestamp    time.Time
	OrigTimestamp time.Time
	HasTime      bool
	Level        LogLevel
	Message      string
	MatchedRules []string
	IsAlert      bool
	TimeOffset   time.Duration
}

func NormalizeLevel(level string) LogLevel {
	switch level {
	case "INFO":
		return LevelInfo
	case "WARN", "WARNING":
		return LevelWarn
	case "ERROR":
		return LevelError
	case "FATAL":
		return LevelFatal
	case "DEBUG":
		return LevelDebug
	default:
		return LevelUnknown
	}
}

func ParseLogs(rawEntries []logpull.RawLogEntry, cfg *config.Config) []ParsedLogEntry {
	var compiledTimeRegexes []*regexp.Regexp
	for _, tf := range cfg.TimeFormats {
		re, err := regexp.Compile(tf.Regex)
		if err == nil {
			compiledTimeRegexes = append(compiledTimeRegexes, re)
		}
	}

	levelRegex, _ := regexp.Compile(cfg.LevelPattern)

	parsed := make([]ParsedLogEntry, 0, len(rawEntries))
	cutoff := time.Now().Add(-time.Duration(cfg.TimeWindow) * time.Minute)

	offsetInfo := make(map[string]time.Duration)

	for _, raw := range rawEntries {
		entry := ParsedLogEntry{
			ServerName: raw.ServerName,
			Host:       raw.Host,
			FilePath:   raw.FilePath,
			LineNumber: raw.LineNumber,
			RawLine:    raw.Line,
			Message:    raw.Line,
			TimeOffset: raw.TimeOffset,
		}

		if raw.TimeOffset != 0 {
			offsetInfo[raw.ServerName] = raw.TimeOffset
		}

		for i, tf := range cfg.TimeFormats {
			if i < len(compiledTimeRegexes) {
				match := compiledTimeRegexes[i].FindStringSubmatch(raw.Line)
				if match != nil && len(match) > tf.Group {
					timeStr := match[tf.Group]
					if t, err := time.Parse(tf.Layout, timeStr); err == nil {
						if t.Year() == 0 || t.Year() < 2000 {
							now := time.Now()
							t = time.Date(now.Year(), t.Month(), t.Day(),
								t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), now.Location())
						}
						entry.OrigTimestamp = t
						if raw.TimeOffset != 0 {
							entry.Timestamp = t.Add(-raw.TimeOffset)
						} else {
							entry.Timestamp = t
						}
						entry.HasTime = true
						break
					}
				}
			}
		}

		if !entry.HasTime {
			now := time.Now()
			entry.Timestamp = now
			entry.OrigTimestamp = now
		}

		if !entry.Timestamp.Before(cutoff) {
			if levelRegex != nil {
				if match := levelRegex.FindStringSubmatch(raw.Line); match != nil && len(match) > 0 {
					entry.Level = NormalizeLevel(match[1])
				} else {
					entry.Level = LevelUnknown
				}
			}
			parsed = append(parsed, entry)
		}
	}

	if len(offsetInfo) > 0 {
		fmt.Println()
		fmt.Println("🕐 时间偏移应用情况:")
		for server, offset := range offsetInfo {
			fmt.Printf("   %-20s: %v\n", server, offset)
		}
		fmt.Println()
	}

	sort.Slice(parsed, func(i, j int) bool {
		return parsed[i].Timestamp.Before(parsed[j].Timestamp)
	})

	return parsed
}
