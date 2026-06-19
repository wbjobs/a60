package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"logaggregator/internal/config"
	"logaggregator/internal/detector"
	"logaggregator/internal/logpull"
	"logaggregator/internal/output"
	"logaggregator/internal/parser"
	"logaggregator/internal/report"
	"logaggregator/internal/watch"
)

var (
	version = "1.0.0"
)

type GlobalFlags struct {
	configPath  string
	timeWindow  int
	noColor     bool
	verbose     bool
	onlyAlerts  bool
}

func main() {
	if len(os.Args) < 2 {
		printMainUsage()
		os.Exit(1)
	}

	subcommand := os.Args[1]

	switch subcommand {
	case "pull":
		runPull(os.Args[2:])
	case "report":
		runReport(os.Args[2:])
	case "watch":
		runWatch(os.Args[2:])
	case "-h", "--help", "help":
		printMainUsage()
	case "-v", "--version", "version":
		fmt.Printf("logaggregator v%s\n", version)
	case "--gen-config":
		if len(os.Args) < 3 {
			fmt.Fprintf(os.Stderr, "错误: 请指定生成配置文件的路径\n\n")
			printMainUsage()
			os.Exit(1)
		}
		if err := generateExampleConfig(os.Args[2]); err != nil {
			fmt.Fprintf(os.Stderr, "生成配置文件失败: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✅ 已生成示例配置文件: %s\n", os.Args[2])
	default:
		fmt.Fprintf(os.Stderr, "错误: 未知的子命令 '%s'\n\n", subcommand)
		printMainUsage()
		os.Exit(1)
	}
}

func printMainUsage() {
	fmt.Fprintf(os.Stderr, `日志聚合与异常检测工具 v%s

用法:
  logaggregator <子命令> [选项]

子命令:
  pull    一次性拉取并分析日志（默认行为）
  report  拉取日志并生成HTML报告
  watch   持续监控模式，实时告警

全局选项:
  -h, --help              显示帮助
  -v, --version           显示版本号
      --gen-config <路径> 生成示例配置文件

示例:
  logaggregator pull -c config.yaml
  logaggregator report -c config.yaml -o report.html
  logaggregator watch -c config.yaml --daemon
  logaggregator --gen-config config.yaml

`, version)
}

func parseGlobalFlags(args []string, name string) (*GlobalFlags, *flag.FlagSet) {
	var (
		configPath  string
		timeWindow  int
		noColor     bool
		verbose     bool
		onlyAlerts  bool
		showHelp    bool
	)

	fs := flag.NewFlagSet(name, flag.ExitOnError)
	fs.StringVar(&configPath, "config", "", "配置文件路径 (YAML/JSON)")
	fs.StringVar(&configPath, "c", "", "配置文件路径 (简写)")
	fs.IntVar(&timeWindow, "window", 0, "覆盖配置中的时间窗口（分钟）")
	fs.IntVar(&timeWindow, "w", 0, "覆盖配置中的时间窗口（简写）")
	fs.BoolVar(&noColor, "no-color", false, "禁用彩色输出")
	fs.BoolVar(&verbose, "verbose", false, "显示详细调试信息")
	fs.BoolVar(&onlyAlerts, "alerts-only", false, "只显示告警信息")
	fs.BoolVar(&showHelp, "help", false, "显示帮助")
	fs.BoolVar(&showHelp, "h", false, "显示帮助 (简写)")

	fs.Usage = func() {
		switch name {
		case "pull":
			printPullUsage(fs)
		case "report":
			printReportUsage(fs)
		case "watch":
			printWatchUsage(fs)
		default:
			printMainUsage()
		}
	}

	fs.Parse(args)

	if showHelp {
		fs.Usage()
		os.Exit(0)
	}

	if configPath == "" {
		fmt.Fprintf(os.Stderr, "错误: 必须指定配置文件路径\n\n")
		fs.Usage()
		os.Exit(1)
	}

	return &GlobalFlags{
		configPath: configPath,
		timeWindow: timeWindow,
		noColor:    noColor,
		verbose:    verbose,
		onlyAlerts: onlyAlerts,
	}, fs
}

func loadConfig(gf *GlobalFlags) (*config.Config, context.Context, context.CancelFunc) {
	cfg, err := config.LoadConfig(gf.configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "加载配置失败: %v\n", err)
		os.Exit(1)
	}

	if gf.timeWindow > 0 {
		cfg.TimeWindow = gf.timeWindow
	}

	if gf.noColor {
		cfg.Output.ColorEnabled = false
	}

	ctx, cancel := context.WithCancel(context.Background())

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\n正在中断...")
		cancel()
	}()

	if gf.verbose {
		fmt.Printf("🔧 配置加载成功\n")
		fmt.Printf("   服务器数量: %d\n", len(cfg.Servers))
		fmt.Printf("   时间窗口: %d 分钟\n", cfg.TimeWindow)
		fmt.Printf("   检测规则: 关键词=%d, 连续级别=%d\n",
			len(cfg.Detection.KeywordMatches),
			len(cfg.Detection.ConsecutiveLevels))
		fmt.Println()
	}

	return cfg, ctx, cancel
}

func processLogs(cfg *config.Config, ctx context.Context, gf *GlobalFlags) ([]parser.ParsedLogEntry, []detector.Alert) {
	startTime := time.Now()

	rawEntries, err := logpull.PullAllServers(ctx, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "拉取日志失败: %v\n", err)
		os.Exit(1)
	}

	if gf.verbose {
		fmt.Printf("\n📥 拉取完成，共 %d 条原始日志\n", len(rawEntries))
	}

	parsedEntries := parser.ParseLogs(rawEntries, cfg)
	if gf.verbose {
		fmt.Printf("📝 解析完成，共 %d 条日志符合时间窗口\n", len(parsedEntries))
	}

	detectedEntries, alerts := detector.DetectAnomalies(parsedEntries, cfg.Detection)
	if gf.verbose {
		fmt.Printf("🔍 检测完成，发现 %d 条告警\n", len(alerts))
	}

	if gf.onlyAlerts {
		alertEntries := make([]parser.ParsedLogEntry, 0)
		for _, e := range detectedEntries {
			if e.IsAlert {
				alertEntries = append(alertEntries, e)
			}
		}
		detectedEntries = alertEntries
	}

	elapsed := time.Since(startTime)
	if gf.verbose {
		fmt.Printf("⏱  处理耗时: %v\n", elapsed.Round(time.Millisecond))
	}

	return detectedEntries, alerts
}

func runPull(args []string) {
	gf, _ := parseGlobalFlags(args, "pull")
	cfg, ctx, cancel := loadConfig(gf)
	defer cancel()

	detectedEntries, alerts := processLogs(cfg, ctx, gf)

	output.PrintLogs(detectedEntries, alerts, cfg)
	output.PrintSummary(detectedEntries)
}

func runReport(args []string) {
	gf, fs := parseGlobalFlags(args, "report")

	var outputPath string
	fs.StringVar(&outputPath, "output", "", "报告输出路径 (覆盖配置文件中的设置)")
	fs.StringVar(&outputPath, "o", "", "报告输出路径 (简写)")
	fs.Parse(args)

	cfg, ctx, cancel := loadConfig(gf)
	defer cancel()

	if outputPath != "" {
		cfg.Report.OutputPath = outputPath
	}

	detectedEntries, alerts := processLogs(cfg, ctx, gf)

	fmt.Printf("📊 正在生成HTML报告...\n")
	reportPath, err := report.GenerateReport(detectedEntries, alerts, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "生成报告失败: %v\n", err)
		os.Exit(1)
	}

	absPath, _ := filepath.Abs(reportPath)
	fmt.Printf("✅ 报告已生成: %s\n", absPath)
	fmt.Println()
	output.PrintSummary(detectedEntries)
}

func runWatch(args []string) {
	gf, fs := parseGlobalFlags(args, "watch")

	var (
		interval int
		daemon   bool
		pidFile  string
		logFile  string
	)

	fs.IntVar(&interval, "interval", 0, "拉取间隔秒数 (覆盖配置文件中的设置)")
	fs.IntVar(&interval, "i", 0, "拉取间隔秒数 (简写)")
	fs.BoolVar(&daemon, "daemon", false, "以后台模式运行")
	fs.BoolVar(&daemon, "d", false, "以后台模式运行 (简写)")
	fs.StringVar(&pidFile, "pid-file", "", "PID文件路径 (覆盖配置文件中的设置)")
	fs.StringVar(&logFile, "log-file", "", "日志文件路径 (覆盖配置文件中的设置)")
	fs.Parse(args)

	cfg, ctx, cancel := loadConfig(gf)
	defer cancel()

	if interval > 0 {
		cfg.Watch.IntervalSeconds = interval
	}
	if daemon {
		cfg.Watch.Daemon = daemon
	}
	if pidFile != "" {
		cfg.Watch.PidFile = pidFile
	}
	if logFile != "" {
		cfg.Watch.LogFile = logFile
	}

	if err := watch.Daemonize(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "启动后台模式失败: %v\n", err)
		os.Exit(1)
	}

	watcher := watch.NewWatcher(cfg)
	defer watcher.Stop()

	if err := watcher.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "监控运行失败: %v\n", err)
		os.Exit(1)
	}
}

func printPullUsage(fs *flag.FlagSet) {
	fmt.Fprintf(os.Stderr, `一次性拉取并分析日志

用法:
  logaggregator pull [选项]

选项:
  -c, --config <路径>     指定配置文件路径 (YAML/JSON)
  -w, --window <分钟>     覆盖时间窗口（最近N分钟）
      --no-color          禁用彩色输出
      --alerts-only       只显示告警信息
      --verbose           显示详细调试信息
  -h, --help              显示帮助

示例:
  logaggregator pull -c config.yaml
  logaggregator pull -c config.json -w 30 --no-color

`)
}

func printReportUsage(fs *flag.FlagSet) {
	fmt.Fprintf(os.Stderr, `拉取日志并生成HTML报告

用法:
  logaggregator report [选项]

选项:
  -c, --config <路径>     指定配置文件路径 (YAML/JSON)
  -w, --window <分钟>     覆盖时间窗口（最近N分钟）
  -o, --output <路径>     报告输出路径 (覆盖配置)
      --no-color          禁用彩色输出
      --alerts-only       只显示告警信息
      --verbose           显示详细调试信息
  -h, --help              显示帮助

示例:
  logaggregator report -c config.yaml
  logaggregator report -c config.yaml -o /var/www/report.html

`)
}

func printWatchUsage(fs *flag.FlagSet) {
	fmt.Fprintf(os.Stderr, `持续监控模式，实时告警

用法:
  logaggregator watch [选项]

选项:
  -c, --config <路径>     指定配置文件路径 (YAML/JSON)
  -i, --interval <秒>     拉取间隔秒数 (覆盖配置)
  -d, --daemon            以后台模式运行
      --pid-file <路径>   PID文件路径 (覆盖配置)
      --log-file <路径>   日志文件路径 (覆盖配置)
  -w, --window <分钟>     首次拉取的时间窗口
      --no-color          禁用彩色输出
      --verbose           显示详细调试信息
  -h, --help              显示帮助

示例:
  logaggregator watch -c config.yaml
  logaggregator watch -c config.yaml -i 10
  logaggregator watch -c config.yaml --daemon --pid-file /var/run/logagg.pid

`)
}

func generateExampleConfig(path string) error {
	ext := filepath.Ext(path)
	var content string
	switch ext {
	case ".yaml", ".yml":
		content = yamlExample()
	case ".json":
		content = jsonExample()
	default:
		content = yamlExample()
	}

	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return err
		}
	}

	return os.WriteFile(path, []byte(content), 0644)
}

func yamlExample() string {
	return `# 日志聚合工具配置示例
# 时间窗口：拉取最近多少分钟内的日志
time_window_minutes: 15

# 日志级别匹配正则表达式
level_pattern: '\b(INFO|WARN|WARNING|ERROR|FATAL|DEBUG)\b'

# 时间戳格式配置（按顺序尝试匹配）
time_formats:
  - regex: '\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}'
    layout: '2006-01-02T15:04:05'
    group: 0
  - regex: '\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}'
    layout: '2006/01/02 15:04:05'
    group: 0
  - regex: '[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}'
    layout: 'Jan  2 15:04:05'
    group: 0

# 服务器列表
servers:
  - name: web-server-1
    host: 192.168.1.101
    port: 22
    user: appuser
    password: your_password
    # 或者使用密钥文件认证
    # key_file: ~/.ssh/id_rsa
    # 连接重试次数（可选，默认2次）
    connect_retries: 2
    # 连接超时秒数（可选，默认10秒）
    connect_timeout_seconds: 10
    # 自动探测与该服务器的时间偏移（可选，默认false）
    auto_time_sync: false
    # 手动设置时间偏移秒数（可选，正数表示服务器比本地快，负数表示慢）
    # time_offset_seconds: -5
    log_paths:
      - /var/log/app/*.log
      - /var/log/nginx/*.log

  - name: web-server-2
    host: 192.168.1.102
    port: 22
    user: appuser
    key_file: ~/.ssh/deploy_key
    connect_retries: 3
    connect_timeout_seconds: 15
    auto_time_sync: true
    log_paths:
      - /var/log/app/*.log

  - name: db-server
    host: 192.168.1.201
    port: 22
    user: dba
    password: secure_pass
    # 手动设置时间偏移（比本地慢8秒）
    auto_time_sync: false
    time_offset_seconds: -8
    log_paths:
      - /var/log/mysql/*.log

# 异常检测规则
detection:
  # 关键词匹配规则：包含指定关键词就高亮/告警
  keyword_matches:
    - name: 数据库异常
      keywords:
        - Connection refused
        - timeout
        - deadlock
        - SQLException
      color: red

    - name: 内存问题
      keywords:
        - OutOfMemory
        - OOM
        - memory leak
      color: purple

    - name: 鉴权失败
      keywords:
        - 401 Unauthorized
        - 403 Forbidden
        - invalid token
        - authentication failed
      color: yellow

  # 连续级别规则：同一级别连续出现N次就告警
  consecutive_levels:
    - name: 连续ERROR告警
      level: ERROR
      count: 3

    - name: 连续WARN警告
      level: WARN
      count: 5

# 输出配置
output:
  show_host_prefix: true
  color_enabled: true

# 报告配置
report:
  output_path: log_report.html
  title: 日志异常检测报告
  include_charts: true
  include_raw_logs: true

# 监控配置
watch:
  interval_seconds: 30
  daemon: false
  pid_file: logaggregator.pid
  log_file: logaggregator.log
  # 告警命令，支持以下变量替换:
  # {{severity}}, {{rule}}, {{message}}, {{server}}, {{level}}, {{timestamp}}
  # alert_command: 'echo "[{{severity}}] {{rule}} on {{server}}: {{message}}" | mail -s "Log Alert" admin@example.com'
`
}

func jsonExample() string {
	return `{
  "time_window_minutes": 15,
  "level_pattern": "\\b(INFO|WARN|WARNING|ERROR|FATAL|DEBUG)\\b",
  "time_formats": [
    {
      "regex": "\\d{4}-\\d{2}-\\d{2}[T ]\\d{2}:\\d{2}:\\d{2}",
      "layout": "2006-01-02T15:04:05",
      "group": 0
    },
    {
      "regex": "\\d{4}/\\d{2}/\\d{2} \\d{2}:\\d{2}:\\d{2}",
      "layout": "2006/01/02 15:04:05",
      "group": 0
    }
  ],
  "servers": [
    {
      "name": "web-server-1",
      "host": "192.168.1.101",
      "port": 22,
      "user": "appuser",
      "password": "your_password",
      "connect_retries": 2,
      "connect_timeout_seconds": 10,
      "auto_time_sync": false,
      "log_paths": [
        "/var/log/app/*.log",
        "/var/log/nginx/*.log"
      ]
    },
    {
      "name": "web-server-2",
      "host": "192.168.1.102",
      "port": 22,
      "user": "appuser",
      "key_file": "~/.ssh/deploy_key",
      "connect_retries": 3,
      "connect_timeout_seconds": 15,
      "auto_time_sync": true,
      "log_paths": [
        "/var/log/app/*.log"
      ]
    },
    {
      "name": "db-server",
      "host": "192.168.1.201",
      "port": 22,
      "user": "dba",
      "password": "secure_pass",
      "auto_time_sync": false,
      "time_offset_seconds": -8,
      "log_paths": [
        "/var/log/mysql/*.log"
      ]
    }
  ],
  "detection": {
    "keyword_matches": [
      {
        "name": "数据库异常",
        "keywords": [
          "Connection refused",
          "timeout",
          "deadlock",
          "SQLException"
        ],
        "color": "red"
      },
      {
        "name": "内存问题",
        "keywords": [
          "OutOfMemory",
          "OOM",
          "memory leak"
        ],
        "color": "purple"
      }
    ],
    "consecutive_levels": [
      {
        "name": "连续ERROR告警",
        "level": "ERROR",
        "count": 3
      },
      {
        "name": "连续WARN警告",
        "level": "WARN",
        "count": 5
      }
    ]
  },
  "output": {
    "show_host_prefix": true,
    "color_enabled": true
  },
  "report": {
    "output_path": "log_report.html",
    "title": "日志异常检测报告",
    "include_charts": true,
    "include_raw_logs": true
  },
  "watch": {
    "interval_seconds": 30,
    "daemon": false,
    "pid_file": "logaggregator.pid",
    "log_file": "logaggregator.log",
    "alert_command": ""
  }
}
`
}
