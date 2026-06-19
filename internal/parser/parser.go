package parser

import (
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
	ServerName  string
	Host        string
	FilePath    string
	LineNumber  int64
	RawLine     string
	Timestamp   time.Time
	HasTime     bool
	Level       LogLevel
	Message     string
	MatchedRules []string
	IsAlert     bool
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

	for _, raw := range rawEntries {
		entry := ParsedLogEntry{
			ServerName: raw.ServerName,
			Host:       raw.Host,
			FilePath:   raw.FilePath,
			LineNumber: raw.LineNumber,
			RawLine:    raw.Line,
			Message:    raw.Line,
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
						entry.Timestamp = t
						entry.HasTime = true
						break
					}
				}
			}
		}

		if !entry.HasTime {
			entry.Timestamp = time.Now()
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

	sort.Slice(parsed, func(i, j int) bool {
		return parsed[i].Timestamp.Before(parsed[j].Timestamp)
	})

	return parsed
}
