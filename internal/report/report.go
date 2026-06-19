package report

import (
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"logaggregator/internal/config"
	"logaggregator/internal/detector"
	"logaggregator/internal/parser"
)

type ReportData struct {
	Title            string
	GeneratedAt      time.Time
	TimeRangeStart   time.Time
	TimeRangeEnd     time.Time
	TotalLogs        int
	TotalAlerts      int
	AlertLogs        int
	ServerStats      []ServerStat
	LevelStats       []LevelStat
	RuleStats        []RuleStat
	TimeDistribution []TimeBucket
	AlertDetails     []AlertDetail
	RawLogs          []parser.ParsedLogEntry
	IncludeRaw       bool
	IncludeCharts    bool
}

type ServerStat struct {
	Name       string
	TotalLogs  int
	AlertLogs  int
	Alerts     int
	AlertRate  float64
}

type LevelStat struct {
	Level string
	Count int
	Color string
	Percent float64
}

type RuleStat struct {
	RuleName string
	Count    int
	Severity string
}

type TimeBucket struct {
	Time       string
	Count      int
	AlertCount int
	Height     string
	AlertHeight string
	LeftPos    string
}

type AlertDetail struct {
	ID         int
	Timestamp  time.Time
	Server     string
	Level      string
	RuleName   string
	Message    string
	RawLine    string
	Severity   string
}

var levelColors = map[string]string{
	"INFO":    "success",
	"WARN":    "warning",
	"WARNING": "warning",
	"ERROR":   "danger",
	"FATAL":   "danger",
	"DEBUG":   "info",
	"UNKNOWN": "secondary",
}

var levelBarColors = map[string]string{
	"INFO":    "#28a745",
	"WARN":    "#ffc107",
	"WARNING": "#ffc107",
	"ERROR":   "#dc3545",
	"FATAL":   "#dc3545",
	"DEBUG":   "#17a2b8",
	"UNKNOWN": "#6c757d",
}

var severityColors = map[string]string{
	"HIGH":   "danger",
	"MEDIUM": "warning",
	"LOW":    "info",
}

func GenerateReport(
	entries []parser.ParsedLogEntry,
	alerts []detector.Alert,
	cfg *config.Config,
) (string, error) {
	reportData := buildReportData(entries, alerts, cfg)

	outputPath := cfg.Report.OutputPath
	if dir := filepath.Dir(outputPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return "", fmt.Errorf("创建报告目录失败: %w", err)
		}
	}

	file, err := os.Create(outputPath)
	if err != nil {
		return "", fmt.Errorf("创建报告文件失败: %w", err)
	}
	defer file.Close()

	funcMap := template.FuncMap{
		"formatTime": func(t time.Time) string {
			return t.Format("2006-01-02 15:04:05")
		},
		"severityClass": func(s string) string {
			if c, ok := severityColors[s]; ok {
				return c
			}
			return "secondary"
		},
		"levelClass": func(l string) string {
			if c, ok := levelColors[l]; ok {
				return c
			}
			return "secondary"
		},
		"levelBarColor": func(l string) string {
			if c, ok := levelBarColors[l]; ok {
				return c
			}
			return "#6c757d"
		},
		"toLower": strings.ToLower,
		"escapeHTML": func(s string) template.HTML {
			return template.HTML(template.HTMLEscapeString(s))
		},
		"safeHTML": func(s string) template.HTML {
			return template.HTML(s)
		},
		"formatFloat": func(f float64) string {
			return fmt.Sprintf("%.1f", f)
		},
		"toString": func(v interface{}) string {
			return fmt.Sprintf("%v", v)
		},
	}

	tmpl, err := template.New("report").Funcs(funcMap).Parse(htmlTemplate)
	if err != nil {
		return "", fmt.Errorf("解析HTML模板失败: %w", err)
	}

	if err := tmpl.Execute(file, reportData); err != nil {
		return "", fmt.Errorf("生成HTML报告失败: %w", err)
	}

	absPath, _ := filepath.Abs(outputPath)
	return absPath, nil
}

func buildReportData(
	entries []parser.ParsedLogEntry,
	alerts []detector.Alert,
	cfg *config.Config,
) ReportData {
	now := time.Now()
	timeWindow := time.Duration(cfg.TimeWindow) * time.Minute
	startTime := now.Add(-timeWindow)

	alertEntryCount := 0
	for _, e := range entries {
		if e.IsAlert {
			alertEntryCount++
		}
	}

	serverMap := make(map[string]*ServerStat)
	for _, s := range cfg.Servers {
		serverMap[s.Name] = &ServerStat{Name: s.Name}
	}

	levelMap := make(map[string]int)
	ruleMap := make(map[string]int)
	ruleSeverity := make(map[string]string)

	for _, entry := range entries {
		if stat, ok := serverMap[entry.ServerName]; ok {
			stat.TotalLogs++
			if entry.IsAlert {
				stat.AlertLogs++
			}
		} else {
			serverMap[entry.ServerName] = &ServerStat{
				Name:      entry.ServerName,
				TotalLogs: 1,
				AlertLogs: boolToInt(entry.IsAlert),
			}
		}
		levelMap[string(entry.Level)]++
		for _, rule := range entry.MatchedRules {
			ruleMap[rule]++
		}
	}

	for _, alert := range alerts {
		if alert.Entry != nil {
			if stat, ok := serverMap[alert.Entry.ServerName]; ok {
				stat.Alerts++
			}
		}
		ruleMap[alert.RuleName]++
		ruleSeverity[alert.RuleName] = alert.Severity
	}

	for _, s := range serverMap {
		if s.TotalLogs > 0 {
			s.AlertRate = float64(s.AlertLogs) / float64(s.TotalLogs) * 100
		}
	}

	serverStats := make([]ServerStat, 0, len(serverMap))
	for _, s := range serverMap {
		serverStats = append(serverStats, *s)
	}
	sort.Slice(serverStats, func(i, j int) bool {
		return serverStats[i].TotalLogs > serverStats[j].TotalLogs
	})

	totalLogs := len(entries)
	levelStats := make([]LevelStat, 0, len(levelMap))
	for level, count := range levelMap {
		percent := 0.0
		if totalLogs > 0 {
			percent = float64(count) / float64(totalLogs) * 100
		}
		levelStats = append(levelStats, LevelStat{
			Level:   level,
			Count:   count,
			Color:   levelColors[level],
			Percent: percent,
		})
	}
	sort.Slice(levelStats, func(i, j int) bool {
		return levelStats[i].Count > levelStats[j].Count
	})

	ruleStats := make([]RuleStat, 0, len(ruleMap))
	for rule, count := range ruleMap {
		ruleStats = append(ruleStats, RuleStat{
			RuleName: rule,
			Count:    count,
			Severity: ruleSeverity[rule],
		})
	}
	sort.Slice(ruleStats, func(i, j int) bool {
		return ruleStats[i].Count > ruleStats[j].Count
	})

	timeDist := buildTimeDistribution(entries, startTime, now)

	alertDetails := make([]AlertDetail, 0, len(alerts))
	for i, alert := range alerts {
		if alert.Entry != nil {
			alertDetails = append(alertDetails, AlertDetail{
				ID:        i + 1,
				Timestamp: alert.Entry.Timestamp,
				Server:    alert.Entry.ServerName,
				Level:     string(alert.Entry.Level),
				RuleName:  alert.RuleName,
				Message:   alert.Message,
				RawLine:   alert.Entry.RawLine,
				Severity:  alert.Severity,
			})
		}
	}

	return ReportData{
		Title:            cfg.Report.Title,
		GeneratedAt:      now,
		TimeRangeStart:   startTime,
		TimeRangeEnd:     now,
		TotalLogs:        totalLogs,
		TotalAlerts:      len(alerts),
		AlertLogs:        alertEntryCount,
		ServerStats:      serverStats,
		LevelStats:       levelStats,
		RuleStats:        ruleStats,
		TimeDistribution: timeDist,
		AlertDetails:     alertDetails,
		RawLogs:          entries,
		IncludeRaw:       cfg.Report.IncludeRaw,
		IncludeCharts:    cfg.Report.IncludeCharts,
	}
}

func buildTimeDistribution(entries []parser.ParsedLogEntry, start, end time.Time) []TimeBucket {
	bucketCount := 24
	duration := end.Sub(start)
	if duration <= 0 {
		return make([]TimeBucket, 0)
	}
	bucketDuration := duration / time.Duration(bucketCount)

	maxCount := 1
	buckets := make([]TimeBucket, bucketCount)
	for i := 0; i < bucketCount; i++ {
		bucketStart := start.Add(time.Duration(i) * bucketDuration)
		buckets[i].Time = bucketStart.Format("15:04")
	}

	for _, entry := range entries {
		if entry.Timestamp.Before(start) || entry.Timestamp.After(end) {
			continue
		}
		offset := entry.Timestamp.Sub(start)
		idx := int(offset / bucketDuration)
		if idx >= bucketCount {
			idx = bucketCount - 1
		}
		if idx < 0 {
			idx = 0
		}
		buckets[idx].Count++
		if entry.IsAlert {
			buckets[idx].AlertCount++
		}
		if buckets[idx].Count > maxCount {
			maxCount = buckets[idx].Count
		}
	}

	barMaxHeight := 200
	for i := range buckets {
		if maxCount > 0 {
			height := int(float64(buckets[i].Count) / float64(maxCount) * float64(barMaxHeight))
			if height < 2 && buckets[i].Count > 0 {
				height = 2
			}
			buckets[i].Height = fmt.Sprintf("%dpx", height)

			alertHeight := 0
			if buckets[i].AlertCount > 0 {
				alertHeight = int(float64(buckets[i].AlertCount) / float64(maxCount) * float64(barMaxHeight))
				if alertHeight < 2 {
					alertHeight = 2
				}
			}
			buckets[i].AlertHeight = fmt.Sprintf("%dpx", alertHeight)
		}
		buckets[i].LeftPos = fmt.Sprintf("%.4f%%", float64(i)/float64(bucketCount)*100)
	}

	return buckets
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{.Title}}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f7fa; color: #333; padding: 20px; }
        .container { max-width: 1400px; margin: 0 auto; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 12px; margin-bottom: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .header h1 { font-size: 28px; margin-bottom: 10px; }
        .header .meta { opacity: 0.9; font-size: 14px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }
        .stat-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); border-left: 4px solid #667eea; }
        .stat-card .label { font-size: 13px; color: #666; margin-bottom: 8px; }
        .stat-card .value { font-size: 32px; font-weight: bold; color: #333; }
        .stat-card.alert { border-left-color: #e74c3c; }
        .stat-card.warning { border-left-color: #f39c12; }
        .card { background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); margin-bottom: 20px; overflow: hidden; }
        .card-header { padding: 15px 20px; border-bottom: 1px solid #eee; font-weight: 600; font-size: 16px; background: #fafbfc; }
        .card-body { padding: 20px; }
        table { width: 100%; border-collapse: collapse; }
        table th, table td { padding: 12px; text-align: left; border-bottom: 1px solid #eee; }
        table th { background: #f8f9fa; font-weight: 600; font-size: 13px; color: #555; }
        table tr:hover { background: #f8f9fa; }
        .badge { display: inline-block; padding: 4px 10px; border-radius: 20px; font-size: 12px; font-weight: 600; }
        .badge-success { background: #d4edda; color: #155724; }
        .badge-warning { background: #fff3cd; color: #856404; }
        .badge-danger { background: #f8d7da; color: #721c24; }
        .badge-info { background: #d1ecf1; color: #0c5460; }
        .badge-secondary { background: #e2e3e5; color: #383d41; }
        .chart-container { min-height: 280px; position: relative; }
        .bar-chart { display: flex; align-items: flex-end; height: 220px; gap: 3px; padding: 10px 0 30px 0; position: relative; }
        .bar { flex: 1; background: linear-gradient(to top, #667eea, #764ba2); border-radius: 3px 3px 0 0; position: relative; transition: opacity 0.3s; }
        .bar:hover { opacity: 0.8; }
        .bar-label { position: absolute; bottom: -18px; left: 50%; transform: translateX(-50%); font-size: 10px; color: #999; white-space: nowrap; }
        .alert-bar-overlay { position: absolute; bottom: 0; height: 0; background: linear-gradient(to top, #e74c3c, #c0392b); border-radius: 3px 3px 0 0; pointer-events: none; }
        .legend { display: flex; gap: 20px; margin-bottom: 15px; font-size: 13px; color: #666; }
        .legend-item { display: flex; align-items: center; gap: 5px; }
        .severity-dot { display: inline-block; width: 10px; height: 10px; border-radius: 50%; margin-right: 6px; }
        .severity-high { background: #e74c3c; }
        .severity-medium { background: #f39c12; }
        .severity-low { background: #3498db; }
        .tabs { display: flex; border-bottom: 2px solid #eee; margin-bottom: 20px; }
        .tab { padding: 12px 24px; cursor: pointer; border-bottom: 3px solid transparent; margin-bottom: -2px; font-weight: 600; color: #666; transition: all 0.3s; }
        .tab.active { color: #667eea; border-bottom-color: #667eea; }
        .tab:hover { color: #667eea; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        .alert-item { padding: 15px; border-left: 4px solid #e74c3c; margin-bottom: 10px; background: #fff5f5; border-radius: 0 4px 4px 0; }
        .alert-item.medium { border-left-color: #f39c12; background: #fffcf0; }
        .alert-item.low { border-left-color: #3498db; background: #f0f8ff; }
        .alert-item .alert-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; flex-wrap: wrap; gap: 10px; }
        .alert-item .alert-time { font-size: 13px; color: #666; font-family: monospace; }
        .alert-item .alert-server { font-size: 13px; color: #666; }
        .alert-item .alert-message { font-size: 14px; color: #333; margin-bottom: 5px; }
        .alert-item .alert-raw { font-size: 12px; color: #888; font-family: monospace; background: #f8f8f8; padding: 8px; border-radius: 4px; overflow-x: auto; }
        .log-entry { font-family: monospace; font-size: 12px; padding: 8px 12px; border-bottom: 1px solid #f0f0f0; }
        .log-entry:hover { background: #f8f9fa; }
        .log-time { color: #888; }
        .log-server { color: #007bff; margin-right: 10px; }
        .search-box { margin-bottom: 15px; }
        .search-box input { width: 100%; padding: 10px 15px; border: 1px solid #ddd; border-radius: 4px; font-size: 14px; }
        .pagination { display: flex; justify-content: center; gap: 5px; margin-top: 20px; }
        .pagination button { padding: 8px 16px; border: 1px solid #ddd; background: white; border-radius: 4px; cursor: pointer; }
        .pagination button.active { background: #667eea; color: white; border-color: #667eea; }
        .pagination button:disabled { opacity: 0.5; cursor: not-allowed; }
        .progress-bar { height: 8px; background: #e9ecef; border-radius: 4px; overflow: hidden; }
        .progress-bar-fill { height: 100%; background: linear-gradient(90deg, #667eea, #764ba2); }
        .level-bar { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }
        .level-bar .name { width: 90px; font-size: 13px; }
        .level-bar .count { width: 70px; text-align: right; font-size: 13px; font-weight: 600; }
        .footer { text-align: center; padding: 20px; color: #999; font-size: 13px; }
        .no-alerts { text-align: center; color: #888; padding: 40px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📊 {{.Title}}</h1>
            <div class="meta">
                生成时间: {{formatTime .GeneratedAt}} |
                时间范围: {{formatTime .TimeRangeStart}} - {{formatTime .TimeRangeEnd}}
            </div>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="label">日志总条数</div>
                <div class="value">{{.TotalLogs}}</div>
            </div>
            <div class="stat-card alert">
                <div class="label">异常告警数</div>
                <div class="value">{{.TotalAlerts}}</div>
            </div>
            <div class="stat-card warning">
                <div class="label">含异常日志</div>
                <div class="value">{{.AlertLogs}}</div>
            </div>
            <div class="stat-card">
                <div class="label">监控服务器</div>
                <div class="value">{{len .ServerStats}}</div>
            </div>
        </div>

        <div class="tabs">
            <div class="tab active" onclick="switchTab('overview')">📈 概览</div>
            <div class="tab" onclick="switchTab('alerts')">⚠️ 异常详情</div>
            {{if .IncludeRaw}}
            <div class="tab" onclick="switchTab('logs')">📋 原始日志</div>
            {{end}}
        </div>

        <div id="tab-overview" class="tab-content active">
            {{if .IncludeCharts}}
            <div class="card">
                <div class="card-header">📊 时间分布</div>
                <div class="card-body">
                    <div class="legend">
                        <div class="legend-item"><span class="severity-dot"></span> 总日志数</div>
                        <div class="legend-item"><span class="severity-dot severity-high"></span> 异常日志数</div>
                    </div>
                    <div class="chart-container">
                        <div class="bar-chart">
                            {{range .TimeDistribution}}
                            <div class="bar" style="height: {{.Height}};">
                                <div class="bar-label">{{.Time}}</div>
                                {{if gt .AlertCount 0}}
                                <div class="alert-bar-overlay" style="left: {{.LeftPos}}; height: {{.AlertHeight}};"></div>
                                {{end}}
                            </div>
                            {{end}}
                        </div>
                    </div>
                </div>
            </div>
            {{end}}

            <div class="card">
                <div class="card-header">🖥️ 服务器统计</div>
                <div class="card-body">
                    <table>
                        <thead>
                            <tr>
                                <th>服务器</th>
                                <th>总日志数</th>
                                <th>异常日志</th>
                                <th>告警次数</th>
                                <th>异常率</th>
                            </tr>
                        </thead>
                        <tbody>
                            {{range .ServerStats}}
                            <tr>
                                <td><strong>{{.Name}}</strong></td>
                                <td>{{.TotalLogs}}</td>
                                <td>{{.AlertLogs}}</td>
                                <td>{{.Alerts}}</td>
                                <td>
                                    {{if gt .TotalLogs 0}}
                                    <div class="progress-bar" style="max-width: 150px;">
                                        <div class="progress-bar-fill" style="width: {{.AlertRate}}%;"></div>
                                    </div>
                                    <small>{{formatFloat .AlertRate}}%</small>
                                    {{end}}
                                </td>
                            </tr>
                            {{end}}
                        </tbody>
                    </table>
                </div>
            </div>

            <div class="card">
                <div class="card-header">🏷️ 日志级别分布</div>
                <div class="card-body">
                    {{range .LevelStats}}
                    <div class="level-bar">
                        <span class="name">
                            <span class="badge badge-{{.Color}}">{{.Level}}</span>
                        </span>
                        <div class="progress-bar" style="flex: 1;">
                            <div class="progress-bar-fill" style="width: {{.Percent}}%; background: {{levelBarColor .Level}};"></div>
                        </div>
                        <span class="count">{{.Count}} ({{formatFloat .Percent}}%)</span>
                    </div>
                    {{end}}
                </div>
            </div>

            <div class="card">
                <div class="card-header">🚨 告警规则统计</div>
                <div class="card-body">
                    <table>
                        <thead>
                            <tr>
                                <th>规则名称</th>
                                <th>严重程度</th>
                                <th>触发次数</th>
                            </tr>
                        </thead>
                        <tbody>
                            {{range .RuleStats}}
                            <tr>
                                <td><strong>{{.RuleName}}</strong></td>
                                <td>
                                    {{if .Severity}}
                                    <span class="severity-dot severity-{{toLower .Severity}}"></span>
                                    <span class="badge badge-{{severityClass .Severity}}">{{.Severity}}</span>
                                    {{else}}
                                    -
                                    {{end}}
                                </td>
                                <td>{{.Count}}</td>
                            </tr>
                            {{end}}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <div id="tab-alerts" class="tab-content">
            <div class="card">
                <div class="card-header">🚨 异常告警详情 ({{len .AlertDetails}} 条)</div>
                <div class="card-body">
                    {{if .AlertDetails}}
                    {{range .AlertDetails}}
                    <div class="alert-item {{toLower .Severity}}">
                        <div class="alert-header">
                            <div>
                                <span class="severity-dot severity-{{toLower .Severity}}"></span>
                                <strong>#{{.ID}}</strong>
                                <span class="badge badge-{{severityClass .Severity}}">{{.Severity}}</span>
                                <span class="badge badge-{{levelClass .Level}}">{{.Level}}</span>
                                <strong>{{.RuleName}}</strong>
                            </div>
                            <div>
                                <span class="alert-server">[{{.Server}}]</span>
                                <span class="alert-time">{{formatTime .Timestamp}}</span>
                            </div>
                        </div>
                        <div class="alert-message">{{.Message}}</div>
                        <div class="alert-raw">{{escapeHTML .RawLine}}</div>
                    </div>
                    {{end}}
                    {{else}}
                    <div class="no-alerts">
                        ✅ 太棒了！在当前时间窗口内没有检测到任何异常。
                    </div>
                    {{end}}
                </div>
            </div>
        </div>

        {{if .IncludeRaw}}
        <div id="tab-logs" class="tab-content">
            <div class="card">
                <div class="card-header">📋 原始日志 ({{len .RawLogs}} 条)</div>
                <div class="card-body">
                    <div class="search-box">
                        <input type="text" id="logSearch" placeholder="搜索日志内容..." onkeyup="filterLogs()">
                    </div>
                    <div id="logContainer">
                        {{range $index, $entry := .RawLogs}}
                        <div class="log-entry" data-line="{{$entry.RawLine}}" data-index="{{$index}}">
                            <span class="log-time">{{formatTime $entry.Timestamp}}</span>
                            <span class="log-server">[{{$entry.ServerName}}]</span>
                            <span class="badge badge-{{levelClass (toString $entry.Level)}}">{{$entry.Level}}</span>
                            {{if $entry.IsAlert}}
                            <span class="badge badge-danger">⚠️ ALERT</span>
                            {{end}}
                            <span>{{escapeHTML $entry.RawLine}}</span>
                        </div>
                        {{end}}
                    </div>
                    <div class="pagination" id="pagination"></div>
                </div>
            </div>
        </div>
        {{end}}

        <div class="footer">
            由 logaggregator 生成 | © 2026
        </div>
    </div>

    <script>
        function switchTab(tabName) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            event.target.classList.add('active');
            document.getElementById('tab-' + tabName).classList.add('active');
            if (tabName === 'logs') {
                setupPagination();
            }
        }

        function filterLogs() {
            const search = document.getElementById('logSearch').value.toLowerCase();
            document.querySelectorAll('.log-entry').forEach(entry => {
                const text = entry.getAttribute('data-line').toLowerCase();
                entry.style.display = text.includes(search) ? '' : 'none';
            });
            currentPage = 1;
            setupPagination();
        }

        const pageSize = 100;
        let currentPage = 1;

        function setupPagination() {
            const container = document.getElementById('logContainer');
            if (!container) return;

            const entries = Array.from(container.querySelectorAll('.log-entry')).filter(e => e.style.display !== 'none');
            const totalPages = Math.ceil(entries.length / pageSize);

            entries.forEach((e, i) => {
                const page = Math.floor(i / pageSize) + 1;
                const search = document.getElementById('logSearch').value.toLowerCase();
                const matches = e.getAttribute('data-line').toLowerCase().includes(search);
                e.style.display = (page === currentPage && matches) ? 'block' : 'none';
            });

            const pagination = document.getElementById('pagination');
            if (!pagination) return;
            pagination.innerHTML = '';

            if (totalPages <= 1) return;

            const prevBtn = document.createElement('button');
            prevBtn.textContent = '上一页';
            prevBtn.disabled = currentPage === 1;
            prevBtn.onclick = () => { currentPage--; setupPagination(); };
            pagination.appendChild(prevBtn);

            const maxVisible = 5;
            let start = Math.max(1, currentPage - Math.floor(maxVisible / 2));
            let end = Math.min(totalPages, start + maxVisible - 1);
            if (end - start + 1 < maxVisible) {
                start = Math.max(1, end - maxVisible + 1);
            }

            for (let i = start; i <= end; i++) {
                const btn = document.createElement('button');
                btn.textContent = i;
                btn.className = i === currentPage ? 'active' : '';
                btn.onclick = (function(page) { return function() { currentPage = page; setupPagination(); }; })(i);
                pagination.appendChild(btn);
            }

            const nextBtn = document.createElement('button');
            nextBtn.textContent = '下一页';
            nextBtn.disabled = currentPage === totalPages;
            nextBtn.onclick = () => { currentPage++; setupPagination(); };
            pagination.appendChild(nextBtn);
        }

        document.addEventListener('DOMContentLoaded', () => {
            setupPagination();
        });
    </script>
</body>
</html>
`
