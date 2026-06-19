package logpull

import (
	"bufio"
	"context"
	"fmt"
	"io"
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
}

func PullLogsFromServer(ctx context.Context, server config.ServerConfig, window time.Duration) ([]RawLogEntry, error) {
	var authMethod string
	if server.KeyFile != "" {
		authMethod = server.KeyFile
	} else {
		authMethod = server.Password
	}

	client, err := sshclient.NewClient(server.Name, server.Host, server.Port, server.User, server.Password, server.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("[%s] 创建SSH客户端失败: %w (auth: %s)", server.Name, err, authMethod)
	}
	if err := client.Connect(); err != nil {
		return nil, err
	}
	defer client.Close()

	cutoffTime := time.Now().Add(-window)
	cutoffStr := cutoffTime.Format("2006-01-02 15:04:05")
	fmt.Printf("[%s] 拉取 %s 之后的日志...\n", server.Name, cutoffStr)

	var allEntries []RawLogEntry
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, logPath := range server.LogPaths {
		wg.Add(1)
		go func(path string) {
			defer wg.Done()
			entries, err := pullFromPath(client, server, path, cutoffTime)
			if err != nil {
				fmt.Printf("[%s] 警告: 拉取路径 %s 失败: %v\n", server.Name, path, err)
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

func pullFromPath(client *sshclient.SSHClient, server config.ServerConfig, path string, cutoff time.Time) ([]RawLogEntry, error) {
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

		fileEntries, err := tailAndFilterFile(client, server.Name, server.Host, filePath, cutoff)
		if err != nil {
			fmt.Printf("[%s] 警告: 读取文件 %s 失败: %v\n", server.Name, filePath, err)
			continue
		}
		entries = append(entries, fileEntries...)
	}

	return entries, nil
}

func tailAndFilterFile(client *sshclient.SSHClient, serverName, host, filePath string, cutoff time.Time) ([]RawLogEntry, error) {
	cmd := fmt.Sprintf(`tail -n 10000 %s 2>/dev/null`, filePath)
	output, err := client.RunCommand(cmd)
	if err != nil {
		reader, err := client.RunCommandWithPipe(cmd)
		if err != nil {
			return nil, err
		}
		return readFromReader(reader, serverName, host, filePath, cutoff)
	}
	return readFromString(output, serverName, host, filePath, cutoff)
}

func readFromString(content, serverName, host, filePath string, cutoff time.Time) ([]RawLogEntry, error) {
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
		})
	}
	if err := scanner.Err(); err != nil {
		return entries, fmt.Errorf("扫描文件内容失败: %w", err)
	}
	return entries, nil
}

func readFromReader(reader io.Reader, serverName, host, filePath string, cutoff time.Time) ([]RawLogEntry, error) {
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
	errCh := make(chan error, len(cfg.Servers))

	for _, server := range cfg.Servers {
		wg.Add(1)
		go func(s config.ServerConfig) {
			defer wg.Done()
			entries, err := PullLogsFromServer(ctx, s, window)
			if err != nil {
				errCh <- err
				return
			}
			mu.Lock()
			allEntries = append(allEntries, entries...)
			mu.Unlock()
			fmt.Printf("[%s] 拉取完成，共 %d 条原始日志\n", s.Name, len(entries))
		}(server)
	}

	wg.Wait()
	close(errCh)

	hasError := false
	for err := range errCh {
		fmt.Printf("错误: %v\n", err)
		hasError = true
	}

	if len(allEntries) == 0 && hasError {
		return nil, fmt.Errorf("所有服务器拉取日志失败")
	}

	return allEntries, nil
}
