package ssh

import (
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
)

type SSHClient struct {
	Config     *ssh.ClientConfig
	Host       string
	Port       int
	ServerName string
	client     *ssh.Client
}

func NewClient(serverName, host string, port int, user, password, keyFile string) (*SSHClient, error) {
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

	config := &ssh.ClientConfig{
		User:            user,
		Auth:            authMethods,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	return &SSHClient{
		Config:     config,
		Host:       host,
		Port:       port,
		ServerName: serverName,
	}, nil
}

func (s *SSHClient) Connect() error {
	addr := fmt.Sprintf("%s:%d", s.Host, s.Port)
	client, err := ssh.Dial("tcp", addr, s.Config)
	if err != nil {
		return fmt.Errorf("连接SSH服务器 %s(%s) 失败: %w", s.ServerName, addr, err)
	}
	s.client = client
	return nil
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
