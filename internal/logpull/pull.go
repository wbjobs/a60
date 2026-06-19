package logpull

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"logaggregator/internal/config"
	sshclient "logaggregator/internal/ssh"
)

type RawLogEntry struct {
	ServerName string
	Host       string
	FilePath   string
	Line       string
	LineNumber int64
	TimeOffset time.Duration
}

func PullLogsFromServer(ctx context.Context, server config.ServerConfig, window time.Duration) ([]RawLogEntry, error) {
	var authMethod string
	if server.KeyFile != "" {
		authMethod = "密钥文件: " + server.KeyFile
	} else if server.Password != "" {
		authMethod = "密码认证"
	} else {
		authMethod = "未指定"
	}

	client, err := sshclient.NewClient(
		server.Name,
		server.Host,
		server.Port,
		server.User,
		server.Password,
		server.KeyFile,
		server.ConnectRetries,
		server.ConnectTimeout,
	)
	if err != nil {
		return nil, fmt.Errorf("[%s] ❌ 创建SSH客户端失败: %w (认证方式: %s)", server.Name, err, authMethod)
	}

	if err := client.Connect(); err != nil {
		return nil, fmt.Errorf("[%s] ❌ %w", server.Name, err)
	}
	defer client.Close()

	var timeOffset time.Duration
	if server.AutoTimeSync {
		fmt.Printf("[%s] 正在自动探测时间偏移...\n", server.Name)
		offset, err := client.GetTimeOffset()
		if err != nil {
			fmt.Printf("[%s] ⚠  自动时间同步失败: %v，将使用手动配置或0偏移\n", server.Name, err)
		} else {
			timeOffset = offset
		}
	}

	if server.TimeOffsetSec != 0 {
		manualOffset := time.Duration(server.TimeOffsetSec) * time.Second
		fmt.Printf("[%s] 使用手动时间偏移: %v\n", server.Name, manualOffset)
		if server.AutoTimeSync && timeOffset != 0 {
			fmt.Printf("[%s] 注意: 手动偏移覆盖自动探测的偏移 %v\n", server.Name, timeOffset)
		}
		timeOffset = manualOffset
	}

	cutoffTime := time.Now().Add(-window)
	adjustedCutoff := cutoffTime.Add(-timeOffset)
	cutoffStr := adjustedCutoff.Format("2006-01-02 15:04:05")
	if timeOffset != 0 {
		fmt.Printf("[%s] 拉取 %s 之后的日志（本地时间 %s，已应用时间偏移 %v）...\n",
			server.Name, cutoffStr, cutoffTime.Format("2006-01-02 15:04:05"), timeOffset)
	} else {
		fmt.Printf("[%s] 拉取 %s 之后的日志...\n", server.Name, cutoffStr)
	}

	var allEntries []RawLogEntry
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, logPath := range server.LogPaths {
		wg.Add(1)
		go func(path string) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				fmt.Printf("[%s] ⚠  拉取路径 %s 被中断\n", server.Name, path)
				return
			default:
			}
			entries, err := pullFromPath(client, server, path, adjustedCutoff, timeOffset)
			if err != nil {
				fmt.Printf("[%s] ⚠  拉取路径 %s 失败: %v\n", server.Name, path, err)
				return
			}
			mu.Lock()
			allEntries = append(allEntries, entries...)
			mu.Unlock()
		}(logPath)
	}

	wg.Wait()
	return allEntries, nil
}

func pullFromPath(client *sshclient.SSHClient, server config.ServerConfig, path string, cutoff time.Time, timeOffset time.Duration) ([]RawLogEntry, error) {
	findCmd := fmt.Sprintf(`find %s -type f -newermt "%s" 2>/dev/null`, path, cutoff.Format("2006-01-02 15:04:05"))
	files, err := client.RunCommand(findCmd)
	if err != nil {
		findCmdFallback := fmt.Sprintf(`ls -1 %s 2>/dev/null | head -20`, path)
		files, err = client.RunCommand(findCmdFallback)
		if err != nil {
			return nil, fmt.Errorf("查找日志文件失败: %w", err)
		}
	}

	fileLines := splitNonEmptyLines(files)
	var entries []RawLogEntry

	for _, filePath := range fileLines {
		select {
		case <-context.Background().Done():
			return entries, nil
		default:
		}

		fileEntries, err := tailAndFilterFile(client, server.Name, server.Host, filePath, cutoff, timeOffset)
		if err != nil {
			fmt.Printf("[%s] ⚠  读取文件 %s 失败: %v\n", server.Name, filePath, err)
			continue
		}
		entries = append(entries, fileEntries...)
	}

	return entries, nil
}

func tailAndFilterFile(client *sshclient.SSHClient, serverName, host, filePath string, cutoff time.Time, timeOffset time.Duration) ([]RawLogEntry, error) {
	cmd := fmt.Sprintf(`tail -n 10000 %s 2>/dev/null`, filePath)
	output, err := client.RunCommand(cmd)
	if err != nil {
		reader, err := client.RunCommandWithPipe(cmd)
		if err != nil {
			return nil, err
		}
		return readFromReader(reader, serverName, host, filePath, cutoff, timeOffset)
	}
	return readFromString(output, serverName, host, filePath, cutoff, timeOffset)
}

func readFromString(content, serverName, host, filePath string, cutoff time.Time, timeOffset time.Duration) ([]RawLogEntry, error) {
	var entries []RawLogEntry
	scanner := bufio.NewScanner(strReader(content))
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024*10)
	var lineNum int64
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		entries = append(entries, RawLogEntry{
			ServerName: serverName,
			Host:       host,
			FilePath:   filePath,
			Line:       line,
			LineNumber: lineNum,
			TimeOffset: timeOffset,
		})
	}
	if err := scanner.Err(); err != nil {
		return entries, fmt.Errorf("扫描文件内容失败: %w", err)
	}
	return entries, nil
}

func readFromReader(reader io.Reader, serverName, host, filePath string, cutoff time.Time, timeOffset time.Duration) ([]RawLogEntry, error) {
	var entries []RawLogEntry
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024*10)
	var lineNum int64
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		entries = append(entries, RawLogEntry{
			ServerName: serverName,
			Host:       host,
			FilePath:   filePath,
			Line:       line,
			LineNumber: lineNum,
			TimeOffset: timeOffset,
		})
	}
	if err := scanner.Err(); err != nil {
		return entries, fmt.Errorf("读取管道失败: %w", err)
	}
	return entries, nil
}

func splitNonEmptyLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' || s[i] == '\r' {
			if i > start {
				line := s[start:i]
				if len(line) > 0 {
					lines = append(lines, line)
				}
			}
			if s[i] == '\r' && i+1 < len(s) && s[i+1] == '\n' {
				i++
			}
			start = i + 1
		}
	}
	if start < len(s) {
		line := s[start:]
		if len(line) > 0 {
			lines = append(lines, line)
		}
	}
	return lines
}

type stringReaderImpl struct {
	s string
	i int
}

func (r *stringReaderImpl) Read(p []byte) (n int, err error) {
	if r.i >= len(r.s) {
		return 0, io.EOF
	}
	n = copy(p, r.s[r.i:])
	r.i += n
	return n, nil
}

func strReader(s string) io.Reader {
	return &stringReaderImpl{s: s}
}

func PullAllServers(ctx context.Context, cfg *config.Config) ([]RawLogEntry, error) {
	window := time.Duration(cfg.TimeWindow) * time.Minute
	var allEntries []RawLogEntry
	var mu sync.Mutex
	var wg sync.WaitGroup

	successCount := 0
	failCount := 0
	totalServers := len(cfg.Servers)

	fmt.Println()
	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf("  开始从 %d 台服务器拉取日志（时间窗口: %d 分钟）\n", totalServers, cfg.TimeWindow)
	fmt.Println(strings.Repeat("=", 80))
	fmt.Println()

	for _, server := range cfg.Servers {
		wg.Add(1)
		go func(s config.ServerConfig) {
			defer wg.Done()

			select {
			case <-ctx.Done():
				fmt.Printf("[%s] ⚠  任务被中断，跳过\n", s.Name)
				return
			default:
			}

			fmt.Printf("[%s] 正在连接 %s:%d...\n", s.Name, s.Host, s.Port)
			entries, err := PullLogsFromServer(ctx, s, window)
			if err != nil {
				fmt.Println()
				fmt.Printf("❌ [%s] 拉取失败: %v\n", s.Name, err)
				fmt.Println()
				mu.Lock()
				failCount++
				mu.Unlock()
				return
			}
			mu.Lock()
			allEntries = append(allEntries, entries...)
			successCount++
			mu.Unlock()
			fmt.Printf("✅ [%s] 拉取完成，共 %d 条原始日志\n", s.Name, len(entries))
		}(server)
	}

	wg.Wait()

	fmt.Println()
	fmt.Println(strings.Repeat("-", 80))
	fmt.Printf("  拉取完成 | 成功: %d/%d | 失败: %d/%d | 总日志: %d 条\n",
		successCount, totalServers, failCount, totalServers, len(allEntries))
	fmt.Println(strings.Repeat("-", 80))
	fmt.Println()

	if failCount > 0 && successCount == 0 {
		return nil, fmt.Errorf("所有 %d 台服务器拉取日志全部失败", totalServers)
	}

	if failCount > 0 {
		fmt.Printf("⚠  注意: %d 台服务器拉取失败，但已获取 %d 台服务器的数据，继续处理...\n",
			failCount, successCount)
		fmt.Println()
	}

	return allEntries, nil
}
