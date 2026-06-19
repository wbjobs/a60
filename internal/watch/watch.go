package watch

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"logaggregator/internal/config"
	"logaggregator/internal/detector"
	"logaggregator/internal/logpull"
	"logaggregator/internal/output"
	"logaggregator/internal/parser"
)

type WatchState struct {
	mu              sync.Mutex
	lastPullTime    time.Time
	serverLastLines map[string]map[string]int64
}

func NewWatchState() *WatchState {
	return &WatchState{
		lastPullTime:    time.Now(),
		serverLastLines: make(map[string]map[string]int64),
	}
}

func (s *WatchState) SetLastPullTime(t time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastPullTime = t
}

func (s *WatchState) GetLastPullTime() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastPullTime
}

func (s *WatchState) SetServerLastLine(serverName, filePath string, lineNum int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.serverLastLines[serverName]; !ok {
		s.serverLastLines[serverName] = make(map[string]int64)
	}
	s.serverLastLines[serverName][filePath] = lineNum
}

func (s *WatchState) GetServerLastLine(serverName, filePath string) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if serverMap, ok := s.serverLastLines[serverName]; ok {
		return serverMap[filePath]
	}
	return 0
}

type Watcher struct {
	cfg    *config.Config
	state  *WatchState
	stopCh chan struct{}
	wg     sync.WaitGroup
}

func NewWatcher(cfg *config.Config) *Watcher {
	return &Watcher{
		cfg:    cfg,
		state:  NewWatchState(),
		stopCh: make(chan struct{}),
	}
}

func (w *Watcher) Stop() {
	close(w.stopCh)
	w.wg.Wait()
}

func (w *Watcher) Run(ctx context.Context) error {
	interval := time.Duration(w.cfg.Watch.IntervalSeconds) * time.Second
	fmt.Printf("🔍 启动监控模式，每 %v 拉取一次增量日志...\n", interval)
	fmt.Println("   按 Ctrl+C 退出")
	fmt.Println()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	if err := w.doPull(ctx, true); err != nil {
		fmt.Printf("⚠  首次拉取失败: %v\n", err)
	}

	for {
		select {
		case <-ctx.Done():
			fmt.Println("\n收到退出信号，正在停止...")
			return nil
		case <-w.stopCh:
			fmt.Println("\n监控已停止")
			return nil
		case <-ticker.C:
			if err := w.doPull(ctx, false); err != nil {
				fmt.Printf("⚠  拉取失败: %v\n", err)
			}
		}
	}
}

func (w *Watcher) doPull(ctx context.Context, isFirst bool) error {
	_ = w.calculateWindow(isFirst)

	rawEntries, err := logpull.PullAllServers(ctx, w.cfg)
	if err != nil {
		return fmt.Errorf("拉取日志失败: %w", err)
	}

	w.state.SetLastPullTime(time.Now())

	parsedEntries := parser.ParseLogs(rawEntries, w.cfg)

	if len(parsedEntries) == 0 {
		if !isFirst {
			now := time.Now().Format("2006-01-02 15:04:05")
			fmt.Printf("[%s] ✓ 没有新的日志\n", now)
		}
		return nil
	}

	detectedEntries, alerts := detector.DetectAnomalies(parsedEntries, w.cfg.Detection)

	if !isFirst {
		newAlerts := w.filterNewAlerts(alerts)
		if len(newAlerts) > 0 {
			now := time.Now().Format("2006-01-02 15:04:05")
			fmt.Println()
			fmt.Println(strings.Repeat("=", 80))
			fmt.Printf("🚨 [%s] 发现 %d 条新告警！\n", now, len(newAlerts))
			fmt.Println(strings.Repeat("=", 80))
			output.PrintLogs(detectedEntries, newAlerts, w.cfg)
			fmt.Println()

			for _, alert := range newAlerts {
				w.executeAlertCommand(alert)
			}
		} else {
			now := time.Now().Format("2006-01-02 15:04:05")
			fmt.Printf("[%s] ✓ 拉取 %d 条日志，无新告警\n", now, len(detectedEntries))
		}
	} else {
		fmt.Printf("📊 首次拉取完成，共 %d 条日志，%d 条告警\n", len(detectedEntries), len(alerts))
		if len(alerts) > 0 {
			output.PrintLogs(detectedEntries, alerts, w.cfg)
		}
		fmt.Println()
	}

	return nil
}

func (w *Watcher) calculateWindow(isFirst bool) time.Duration {
	if isFirst {
		return time.Duration(w.cfg.TimeWindow) * time.Minute
	}

	lastPull := w.state.GetLastPullTime()
	elapsed := time.Since(lastPull)

	baseWindow := time.Duration(w.cfg.Watch.IntervalSeconds) * time.Second
	if elapsed > baseWindow {
		baseWindow = elapsed
	}

	return baseWindow + 10*time.Second
}

func (w *Watcher) filterNewAlerts(alerts []detector.Alert) []detector.Alert {
	var newAlerts []detector.Alert
	threshold := w.state.GetLastPullTime()

	for _, alert := range alerts {
		if alert.Entry != nil && alert.Entry.Timestamp.After(threshold) {
			newAlerts = append(newAlerts, alert)
		}
	}

	return newAlerts
}

func (w *Watcher) executeAlertCommand(alert detector.Alert) {
	if w.cfg.Watch.AlertCommand == "" {
		return
	}

	cmdStr := w.cfg.Watch.AlertCommand

	if alert.Entry != nil {
		cmdStr = strings.ReplaceAll(cmdStr, "{{severity}}", alert.Severity)
		cmdStr = strings.ReplaceAll(cmdStr, "{{rule}}", alert.RuleName)
		cmdStr = strings.ReplaceAll(cmdStr, "{{message}}", alert.Message)
		cmdStr = strings.ReplaceAll(cmdStr, "{{server}}", alert.Entry.ServerName)
		cmdStr = strings.ReplaceAll(cmdStr, "{{level}}", string(alert.Entry.Level))
		cmdStr = strings.ReplaceAll(cmdStr, "{{timestamp}}", alert.Entry.Timestamp.Format(time.RFC3339))
	}

	go func(cmd string) {
		fmt.Printf("⚡ 执行告警命令: %s\n", cmd)
		var execCmd *exec.Cmd
		if isWindows() {
			execCmd = exec.Command("cmd", "/C", cmd)
		} else {
			execCmd = exec.Command("sh", "-c", cmd)
		}
		output, err := execCmd.CombinedOutput()
		if err != nil {
			fmt.Printf("⚠  告警命令执行失败: %v\n输出: %s\n", err, string(output))
		}
	}(cmdStr)
}

func Daemonize(cfg *config.Config) error {
	if !cfg.Watch.Daemon {
		return nil
	}

	if isWindows() {
		fmt.Println("⚠  Windows平台暂不支持daemon模式，将以前台模式运行")
		cfg.Watch.Daemon = false
		return nil
	}

	fmt.Printf("🔄 以后台模式启动...\n")

	if cfg.Watch.PidFile != "" {
		pid := os.Getpid()
		if err := os.WriteFile(cfg.Watch.PidFile, []byte(fmt.Sprintf("%d", pid)), 0644); err != nil {
			return fmt.Errorf("写入PID文件失败: %w", err)
		}
		fmt.Printf("   PID文件: %s\n", cfg.Watch.PidFile)
	}

	if cfg.Watch.LogFile != "" {
		logFile, err := os.OpenFile(cfg.Watch.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return fmt.Errorf("打开日志文件失败: %w", err)
		}
		defer logFile.Close()

		os.Stdout = logFile
		os.Stderr = logFile
		fmt.Printf("   日志文件: %s\n", cfg.Watch.LogFile)
	}

	return nil
}

func isWindows() bool {
	return os.PathSeparator == '\\'
}
