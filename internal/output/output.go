package output

import (
	"fmt"
	"os"
	"strings"

	"logaggregator/internal/config"
	"logaggregator/internal/detector"
	"logaggregator/internal/parser"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorWhite  = "\033[37m"
	bgRed       = "\033[41m"
	bgYellow    = "\033[43m"
	bold        = "\033[1m"
)

var levelColors = map[parser.LogLevel]string{
	parser.LevelInfo:    colorGreen,
	parser.LevelWarn:    colorYellow,
	parser.LevelWarning: colorYellow,
	parser.LevelError:   colorRed,
	parser.LevelFatal:   bgRed + colorWhite,
	parser.LevelDebug:   colorBlue,
	parser.LevelUnknown: colorCyan,
}

var ruleColors = map[string]string{
	"red":    colorRed,
	"green":  colorGreen,
	"yellow": colorYellow,
	"blue":   colorBlue,
	"purple": colorPurple,
	"cyan":   colorCyan,
}

func getColorForRule(colorName string) string {
	if c, ok := ruleColors[strings.ToLower(colorName)]; ok {
		return c
	}
	return colorPurple
}

func formatTimestamp(t parser.ParsedLogEntry) string {
	if t.HasTime {
		return t.Timestamp.Format("2006-01-02 15:04:05")
	}
	return "????-??-?? ??:??:??"
}

func applyKeywordHighlight(line string, rules []config.KeywordRule, useColor bool) string {
	if !useColor {
		return line
	}
	result := line
	for _, rule := range rules {
		colorCode := getColorForRule(rule.Color)
		for _, kw := range rule.Keywords {
			idx := strings.Index(strings.ToLower(result), strings.ToLower(kw))
			for idx != -1 {
				matched := result[idx : idx+len(kw)]
				before := result[:idx]
				after := result[idx+len(kw):]
				result = before + colorCode + bold + matched + colorReset + after
				nextIdx := idx + len(kw) + len(colorCode) + len(bold) + len(colorReset)
				rest := result[nextIdx:]
				findIdx := strings.Index(strings.ToLower(rest), strings.ToLower(kw))
				if findIdx == -1 {
					break
				}
				idx = nextIdx + findIdx
			}
		}
	}
	return result
}

func PrintLogs(entries []parser.ParsedLogEntry, alerts []detector.Alert, cfg *config.Config) {
	useColor := cfg.Output.ColorEnabled && isTerminal()

	fmt.Println()
	fmt.Println(strings.Repeat("=", 80))
	fmt.Println("  日志聚合报告")
	fmt.Printf("  总条目: %d  |  告警数: %d\n", len(entries), len(alerts))
	fmt.Println(strings.Repeat("=", 80))
	fmt.Println()

	if len(alerts) > 0 {
		PrintAlerts(alerts, useColor)
		fmt.Println()
		fmt.Println(strings.Repeat("-", 80))
		fmt.Println("  详细日志:")
		fmt.Println(strings.Repeat("-", 80))
		fmt.Println()
	}

	for _, entry := range entries {
		printSingleEntry(entry, cfg, useColor)
	}

	fmt.Println()
	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf("  日志输出完成 | 共 %d 条\n", len(entries))
	fmt.Println(strings.Repeat("=", 80))
}

func printSingleEntry(entry parser.ParsedLogEntry, cfg *config.Config, useColor bool) {
	ts := formatTimestamp(entry)
	level := string(entry.Level)
	if len(level) < 7 {
		level = level + strings.Repeat(" ", 7-len(level))
	}

	var parts []string

	if cfg.Output.ShowHostPrefix {
		hostPart := fmt.Sprintf("[%s]", entry.ServerName)
		if useColor {
			hostPart = colorCyan + hostPart + colorReset
		}
		parts = append(parts, hostPart)
	}

	tsPart := ts
	if useColor {
		tsPart = colorWhite + tsPart + colorReset
	}
	parts = append(parts, tsPart)

	levelPart := fmt.Sprintf("[%s]", level)
	if useColor {
		if c, ok := levelColors[entry.Level]; ok {
			levelPart = c + bold + levelPart + colorReset
		}
	}
	parts = append(parts, levelPart)

	alertTag := ""
	if entry.IsAlert {
		alertTag = " ⚠ "
		if useColor {
			alertTag = colorYellow + bold + alertTag + colorReset
		}
	}
	ruleTags := ""
	if len(entry.MatchedRules) > 0 {
		ruleTags = " {" + strings.Join(entry.MatchedRules, ", ") + "}"
		if useColor {
			ruleTags = colorPurple + ruleTags + colorReset
		}
	}

	message := entry.RawLine
	if useColor && len(cfg.Detection.KeywordMatches) > 0 {
		message = applyKeywordHighlight(message, cfg.Detection.KeywordMatches, useColor)
	}

	if entry.IsAlert && useColor {
		prefix := strings.Join(parts, " ")
		fmt.Printf("%s%s%s  %s\n", prefix, alertTag, ruleTags, message)
	} else {
		prefix := strings.Join(parts, " ")
		fmt.Printf("%s%s%s  %s\n", prefix, alertTag, ruleTags, message)
	}
}

func PrintAlerts(alerts []detector.Alert, useColor bool) {
	fmt.Println(strings.Repeat("-", 80))
	title := "  ⚠  检测到异常告警 (" + itoaD(len(alerts)) + ")"
	if useColor {
		title = colorRed + bold + title + colorReset
	}
	fmt.Println(title)
	fmt.Println(strings.Repeat("-", 80))

	for i, alert := range alerts {
		severity := alert.Severity
		var sevStr string
		if useColor {
			switch severity {
			case "HIGH":
				sevStr = bgRed + colorWhite + " 高 " + colorReset
			case "MEDIUM":
				sevStr = bgYellow + " 中 " + colorReset
			default:
				sevStr = colorYellow + " 低 " + colorReset
			}
		} else {
			sevStr = "[" + severity + "]"
		}

		entryInfo := ""
		if alert.Entry != nil {
			entryInfo = fmt.Sprintf(" | %s | [%s]",
				alert.Entry.Timestamp.Format("15:04:05"),
				alert.Entry.ServerName)
		}

		fmt.Printf("  %d. %s 规则: %s | %s%s\n",
			i+1, sevStr, alert.RuleName, alert.Message, entryInfo)
	}
}

func isTerminal() bool {
	fi, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (fi.Mode() & os.ModeCharDevice) != 0
}

func itoaD(n int) string {
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

func PrintSummary(entries []parser.ParsedLogEntry) {
	levelCount := make(map[parser.LogLevel]int)
	serverCount := make(map[string]int)
	alertCount := 0

	for _, e := range entries {
		levelCount[e.Level]++
		serverCount[e.ServerName]++
		if e.IsAlert {
			alertCount++
		}
	}

	fmt.Println()
	fmt.Println("📊 统计摘要:")
	fmt.Println("  按日志级别:")
	for level, count := range levelCount {
		fmt.Printf("    %-8s: %d\n", level, count)
	}
	fmt.Println("  按服务器:")
	for server, count := range serverCount {
		fmt.Printf("    %-20s: %d\n", server, count)
	}
	fmt.Printf("  告警条目: %d\n", alertCount)
	fmt.Println()
}
