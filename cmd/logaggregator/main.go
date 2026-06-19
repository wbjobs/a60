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
)

var (
	version = "1.0.0"
)

func main() {
	var (
		configPath   string
		timeWindow   int
		showVersion  bool
		noColor      bool
		showHelp     bool
		verbose      bool
		onlyAlerts   bool
		generateCfg  string
	)

	flag.StringVar(&configPath, "config", "", "配置文件路径 (YAML/JSON)")
	flag.StringVar(&configPath, "c", "", "配置文件路径 (简写)")
	flag.IntVar(&timeWindow, "window", 0, "覆盖配置中的时间窗口（分钟）")
	flag.IntVar(&timeWindow, "w", 0, "覆盖配置中的时间窗口（简写）")
	flag.BoolVar(&showVersion, "version", false, "显示版本号")
	flag.BoolVar(&showVersion, "v", false, "显示版本号 (简写)")
	flag.BoolVar(&noColor, "no-color", false, "禁用彩色输出")
	flag.BoolVar(&showHelp, "help", false, "显示帮助")
	flag.BoolVar(&showHelp, "h", false, "显示帮助 (简写)")
	flag.BoolVar(&verbose, "verbose", false, "显示详细调试信息")
	flag.BoolVar(&onlyAlerts, "alerts-only", false, "只显示告警信息")
	flag.StringVar(&generateCfg, "gen-config", "", "生成示例配置文件 (指定路径，如 config.yaml)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `日志聚合与异常检测工具 v%s

用法:
  logaggregator -config <配置文件> [选项]

选项:
  -c, --config <路径>     指定配置文件路径 (YAML/JSON)
  -w, --window <分钟>     覆盖时间窗口（最近N分钟）
      --no-color          禁用彩色输出
      --alerts-only       只显示告警信息
  -v, --version           显示版本号
  -h, --help              显示帮助
      --verbose           显示详细调试信息
      --gen-config <路径> 生成示例配置文件

示例:
  logaggregator -c config.yaml
  logaggregator -c config.json -w 30 --no-color
  logaggregator --gen-config config.yaml

`, version)
	}

	flag.Parse()

	if showHelp {
		flag.Usage()
		return
	}

	if showVersion {
		fmt.Printf("logaggregator v%s\n", version)
		return
	}

	if generateCfg != "" {
		if err := generateExampleConfig(generateCfg); err != nil {
			fmt.Fprintf(os.Stderr, "生成配置文件失败: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("✅ 已生成示例配置文件: %s\n", generateCfg)
		return
	}

	if configPath == "" {
		fmt.Fprintf(os.Stderr, "错误: 必须指定配置文件路径\n\n")
		flag.Usage()
		os.Exit(1)
	}

	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "加载配置失败: %v\n", err)
		os.Exit(1)
	}

	if timeWindow > 0 {
		cfg.TimeWindow = timeWindow
	}

	if noColor {
		cfg.Output.ColorEnabled = false
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\n正在中断...")
		cancel()
	}()

	if verbose {
		fmt.Printf("🔧 配置加载成功\n")
		fmt.Printf("   服务器数量: %d\n", len(cfg.Servers))
		fmt.Printf("   时间窗口: %d 分钟\n", cfg.TimeWindow)
		fmt.Printf("   检测规则: 关键词=%d, 连续级别=%d\n",
			len(cfg.Detection.KeywordMatches),
			len(cfg.Detection.ConsecutiveLevels))
		fmt.Println()
	}

	startTime := time.Now()

	rawEntries, err := logpull.PullAllServers(ctx, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "拉取日志失败: %v\n", err)
		os.Exit(1)
	}

	if verbose {
		fmt.Printf("\n📥 拉取完成，共 %d 条原始日志\n", len(rawEntries))
	}

	parsedEntries := parser.ParseLogs(rawEntries, cfg)
	if verbose {
		fmt.Printf("📝 解析完成，共 %d 条日志符合时间窗口\n", len(parsedEntries))
	}

	detectedEntries, alerts := detector.DetectAnomalies(parsedEntries, cfg.Detection)
	if verbose {
		fmt.Printf("🔍 检测完成，发现 %d 条告警\n", len(alerts))
	}

	if onlyAlerts {
		alertEntries := make([]parser.ParsedLogEntry, 0)
		for _, e := range detectedEntries {
			if e.IsAlert {
				alertEntries = append(alertEntries, e)
			}
		}
		detectedEntries = alertEntries
	}

	output.PrintLogs(detectedEntries, alerts, cfg)
	output.PrintSummary(detectedEntries)

	elapsed := time.Since(startTime)
	fmt.Printf("⏱  总耗时: %v\n", elapsed.Round(time.Millisecond))
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
    log_paths:
      - /var/log/app/*.log
      - /var/log/nginx/*.log

  - name: web-server-2
    host: 192.168.1.102
    port: 22
    user: appuser
    key_file: ~/.ssh/deploy_key
    log_paths:
      - /var/log/app/*.log

  - name: db-server
    host: 192.168.1.201
    port: 22
    user: dba
    password: secure_pass
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
      "log_paths": [
        "/var/log/app/*.log"
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
  }
}
`
}
