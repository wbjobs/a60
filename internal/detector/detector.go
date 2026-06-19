package detector

import (
	"strings"

	"logaggregator/internal/config"
	"logaggregator/internal/parser"
)

func DetectAnomalies(entries []parser.ParsedLogEntry, rules config.DetectionRules) ([]parser.ParsedLogEntry, []Alert) {
	var alerts []Alert

	for i := range entries {
		for _, kwRule := range rules.KeywordMatches {
			for _, kw := range kwRule.Keywords {
				if strings.Contains(strings.ToLower(entries[i].RawLine), strings.ToLower(kw)) {
					entries[i].MatchedRules = append(entries[i].MatchedRules, kwRule.Name)
					entries[i].IsAlert = true
					alerts = append(alerts, Alert{
						Type:     "keyword_match",
						RuleName: kwRule.Name,
						Message:  "发现关键词: " + kw,
						Entry:    &entries[i],
						Severity: getSeverityFromLevel(entries[i].Level),
					})
				}
			}
		}
	}

	for _, consRule := range rules.ConsecutiveLevels {
		targetLevel := parser.NormalizeLevel(consRule.Level)
		count := 0
		var lastStartIdx = -1

		for i := range entries {
			if entries[i].Level == targetLevel {
				if count == 0 {
					lastStartIdx = i
				}
				count++
				if count >= consRule.Count {
					for j := lastStartIdx; j <= i; j++ {
						alreadyMatched := false
						for _, r := range entries[j].MatchedRules {
							if r == consRule.Name {
								alreadyMatched = true
								break
							}
						}
						if !alreadyMatched {
							entries[j].MatchedRules = append(entries[j].MatchedRules, consRule.Name)
							entries[j].IsAlert = true
						}
					}
					if count == consRule.Count {
						alerts = append(alerts, Alert{
							Type:     "consecutive_level",
							RuleName: consRule.Name,
							Message:  "连续 " + consRule.Level + " 次数达到阈值: " + itoa(consRule.Count),
							Entry:    &entries[i],
							Severity: "HIGH",
						})
					}
				}
			} else {
				count = 0
				lastStartIdx = -1
			}
		}
	}

	return entries, alerts
}

type Alert struct {
	Type     string
	RuleName string
	Message  string
	Entry    *parser.ParsedLogEntry
	Severity string
}

func getSeverityFromLevel(level parser.LogLevel) string {
	switch level {
	case parser.LevelError, parser.LevelFatal:
		return "HIGH"
	case parser.LevelWarn:
		return "MEDIUM"
	default:
		return "LOW"
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	var buf [20]byte
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
