package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type ServerConfig struct {
	Name            string   `yaml:"name" json:"name"`
	Host            string   `yaml:"host" json:"host"`
	Port            int      `yaml:"port" json:"port"`
	User            string   `yaml:"user" json:"user"`
	Password        string   `yaml:"password,omitempty" json:"password,omitempty"`
	KeyFile         string   `yaml:"key_file,omitempty" json:"key_file,omitempty"`
	LogPaths        []string `yaml:"log_paths" json:"log_paths"`
	TimeOffsetSec   int      `yaml:"time_offset_seconds,omitempty" json:"time_offset_seconds,omitempty"`
	AutoTimeSync    bool     `yaml:"auto_time_sync,omitempty" json:"auto_time_sync,omitempty"`
	ConnectRetries  int      `yaml:"connect_retries,omitempty" json:"connect_retries,omitempty"`
	ConnectTimeout  int      `yaml:"connect_timeout_seconds,omitempty" json:"connect_timeout_seconds,omitempty"`
}

type TimeFormat struct {
	Regex   string `yaml:"regex" json:"regex"`
	Layout  string `yaml:"layout" json:"layout"`
	Group   int    `yaml:"group" json:"group"`
}

type KeywordRule struct {
	Name     string   `yaml:"name" json:"name"`
	Keywords []string `yaml:"keywords" json:"keywords"`
	Color    string   `yaml:"color" json:"color"`
}

type ConsecutiveLevelRule struct {
	Name     string `yaml:"name" json:"name"`
	Level    string `yaml:"level" json:"level"`
	Count    int    `yaml:"count" json:"count"`
}

type DetectionRules struct {
	KeywordMatches     []KeywordRule         `yaml:"keyword_matches" json:"keyword_matches"`
	ConsecutiveLevels  []ConsecutiveLevelRule `yaml:"consecutive_levels" json:"consecutive_levels"`
}

type Config struct {
	Servers      []ServerConfig   `yaml:"servers" json:"servers"`
	TimeWindow   int              `yaml:"time_window_minutes" json:"time_window_minutes"`
	TimeFormats  []TimeFormat     `yaml:"time_formats" json:"time_formats"`
	LevelPattern string           `yaml:"level_pattern" json:"level_pattern"`
	Detection    DetectionRules   `yaml:"detection" json:"detection"`
	Output       OutputConfig     `yaml:"output" json:"output"`
}

type OutputConfig struct {
	ShowHostPrefix bool `yaml:"show_host_prefix" json:"show_host_prefix"`
	ColorEnabled   bool `yaml:"color_enabled" json:"color_enabled"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %w", err)
	}

	ext := strings.ToLower(filepath.Ext(path))
	var cfg Config

	switch ext {
	case ".yaml", ".yml":
		err = yaml.Unmarshal(data, &cfg)
	case ".json":
		err = json.Unmarshal(data, &cfg)
	default:
		return nil, fmt.Errorf("不支持的配置文件格式: %s，仅支持 .yaml/.yml/.json", ext)
	}

	if err != nil {
		return nil, fmt.Errorf("解析配置文件失败: %w", err)
	}

	if err := validateAndSetDefaults(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func validateAndSetDefaults(cfg *Config) error {
	if len(cfg.Servers) == 0 {
		return fmt.Errorf("配置中没有定义任何服务器")
	}

	if cfg.TimeWindow <= 0 {
		cfg.TimeWindow = 15
	}

	if cfg.LevelPattern == "" {
		cfg.LevelPattern = `\b(INFO|WARN|WARNING|ERROR|FATAL|DEBUG)\b`
	}

	for i := range cfg.Servers {
		s := &cfg.Servers[i]
		if s.Host == "" {
			return fmt.Errorf("服务器[%d]缺少host字段", i)
		}
		if s.Port == 0 {
			s.Port = 22
		}
		if s.User == "" {
			return fmt.Errorf("服务器[%s]缺少user字段", s.Name)
		}
		if s.Name == "" {
			s.Name = s.Host
		}
		if len(s.LogPaths) == 0 {
			s.LogPaths = []string{"/var/log/app/*.log"}
		}
		if s.ConnectRetries <= 0 {
			s.ConnectRetries = 2
		}
		if s.ConnectTimeout <= 0 {
			s.ConnectTimeout = 10
		}
	}

	if len(cfg.TimeFormats) == 0 {
		cfg.TimeFormats = []TimeFormat{
			{Regex: `\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}`, Layout: "2006-01-02T15:04:05", Group: 0},
			{Regex: `\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}`, Layout: "2006/01/02 15:04:05", Group: 0},
			{Regex: `\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}`, Layout: "02/Jan/2006:15:04:05", Group: 0},
			{Regex: `[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}`, Layout: "Jan  2 15:04:05", Group: 0},
		}
	}

	if !cfg.Output.ColorEnabled {
		cfg.Output.ColorEnabled = true
	}
	if cfg.Output.ShowHostPrefix {
		cfg.Output.ShowHostPrefix = true
	}

	return nil
}
