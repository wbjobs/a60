package ssh

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

type SSHClient struct {
	Config        *ssh.ClientConfig
	Host          string
	Port          int
	ServerName    string
	client        *ssh.Client
	connectRetries int
	connectTimeout time.Duration
}

func NewClient(serverName, host string, port int, user, password, keyFile string, retries int, timeoutSec int) (*SSHClient, error) {
	authMethods := []ssh.AuthMethod{}

	if keyFile != "" {
		key, err := os.ReadFile(keyFile)
		if err != nil {
			return nil, fmt.Errorf("读取密钥文件失败: %w", err)
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("解析私钥失败: %w", err)
		}
		authMethods = append(authMethods, ssh.PublicKeys(signer))
	}

	if password != "" {
		authMethods = append(authMethods, ssh.Password(password))
	}

	if len(authMethods) == 0 {
		return nil, fmt.Errorf("必须提供密码或密钥文件")
	}

	if retries <= 0 {
		retries = 2
	}
	if timeoutSec <= 0 {
		timeoutSec = 10
	}

	config := &ssh.ClientConfig{
		User:            user,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         time.Duration(timeoutSec) * time.Second,
	}

	return &SSHClient{
		Config:         config,
		Host:           host,
		Port:           port,
		ServerName:     serverName,
		connectRetries: retries,
		connectTimeout: time.Duration(timeoutSec) * time.Second,
	}, nil
}

func (s *SSHClient) Connect() error {
	addr := fmt.Sprintf("%s:%d", s.Host, s.Port)
	var lastErr error

	for attempt := 1; attempt <= s.connectRetries+1; attempt++ {
		client, err := ssh.Dial("tcp", addr, s.Config)
		if err == nil {
			s.client = client
			if attempt > 1 {
				fmt.Printf("[%s] 连接成功（第 %d 次尝试）\n", s.ServerName, attempt)
			}
			return nil
		}
		lastErr = err

		if attempt <= s.connectRetries {
			waitTime := time.Duration(attempt) * 2 * time.Second
			fmt.Printf("[%s] 连接失败（第 %d/%d 次尝试）: %v，%v 后重试...\n",
				s.ServerName, attempt, s.connectRetries+1, err, waitTime)
			time.Sleep(waitTime)
		}
	}

	return fmt.Errorf("连接SSH服务器 %s(%s) 失败（经过 %d 次尝试）: %w",
		s.ServerName, addr, s.connectRetries+1, lastErr)
}

func (s *SSHClient) Close() error {
	if s.client != nil {
		return s.client.Close()
	}
	return nil
}

func (s *SSHClient) RunCommand(cmd string) (string, error) {
	if s.client == nil {
		if err := s.Connect(); err != nil {
			return "", err
		}
	}

	session, err := s.client.NewSession()
	if err != nil {
		return "", fmt.Errorf("创建会话失败: %w", err)
	}
	defer session.Close()

	output, err := session.CombinedOutput(cmd)
	if err != nil {
		return string(output), fmt.Errorf("执行命令失败: %w, 输出: %s", err, string(output))
	}
	return string(output), nil
}

func (s *SSHClient) RunCommandWithPipe(cmd string) (io.Reader, error) {
	if s.client == nil {
		if err := s.Connect(); err != nil {
			return nil, err
		}
	}

	session, err := s.client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("创建会话失败: %w", err)
	}

	pipe, err := session.StdoutPipe()
	if err != nil {
		session.Close()
		return nil, fmt.Errorf("创建标准输出管道失败: %w", err)
	}

	session.Stderr = session.Stdout

	if err := session.Start(cmd); err != nil {
		session.Close()
		return nil, fmt.Errorf("启动命令失败: %w", err)
	}

	go func() {
		session.Wait()
		session.Close()
	}()

	return pipe, nil
}

func (s *SSHClient) GetRemoteTime() (time.Time, error) {
	if s.client == nil {
		if err := s.Connect(); err != nil {
			return time.Time{}, err
		}
	}

	output, err := s.RunCommand("date +%s.%N")
	if err != nil {
		return time.Time{}, fmt.Errorf("获取远程时间失败: %w", err)
	}

	output = strings.TrimSpace(output)
	parts := strings.Split(output, ".")
	if len(parts) != 2 {
		return time.Time{}, fmt.Errorf("无法解析远程时间输出: %s", output)
	}

	sec, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("解析秒数失败: %w", err)
	}

	nsecStr := parts[1]
	if len(nsecStr) > 9 {
		nsecStr = nsecStr[:9]
	} else if len(nsecStr) < 9 {
		nsecStr = nsecStr + strings.Repeat("0", 9-len(nsecStr))
	}

	nsec, err := strconv.ParseInt(nsecStr, 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("解析纳秒失败: %w", err)
	}

	return time.Unix(sec, nsec), nil
}

func (s *SSHClient) GetTimeOffset() (time.Duration, error) {
	localBefore := time.Now()
	remoteTime, err := s.GetRemoteTime()
	if err != nil {
		return 0, err
	}
	localAfter := time.Now()

	latency := localAfter.Sub(localBefore) / 2
	estimatedLocalAtRemote := localBefore.Add(latency)
	offset := remoteTime.Sub(estimatedLocalAtRemote)

	fmt.Printf("[%s] 时间校准: 本地=%s, 远程=%s, 偏移=%v (估计网络延迟=%v)\n",
		s.ServerName,
		estimatedLocalAtRemote.Format("15:04:05.000"),
		remoteTime.Format("15:04:05.000"),
		offset,
		latency)

	return offset, nil
}
