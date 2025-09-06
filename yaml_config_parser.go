package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

var AppConfig Config

type Config struct {
	DataMonitorLogLevel              string            `yaml:"datamonitor_log_level"`
	DataMonitorLogFile               string            `yaml:"datamonitor_log_file"`
	DataMonitorHookedFunctions       string            `yaml:"datamonitor_hooked_functions"`
	DataMonitorRedactedTextClipboard bool              `yaml:"datamonitor_redacted_text_clipboard"`
	DataMonitorHTTPForwardEvents     HttpForwardEvents `yaml:"datamonitor_http_forward_events"`
}

type HttpForwardEvents struct {
	Enabled               bool               `yaml:"enabled"`
	DataBatchSendInterval int                `yaml:"data_batch_send_interval"`
	URL                   string             `yaml:"url"`
	Headers               *map[string]string `yaml:"headers"`
}

func LoadConfig(configPath string) error {
	absConfigPath, err := filepath.Abs(configPath)
	if err != nil {
		return fmt.Errorf("failed to get absolute path for config file '%s': %w", configPath, err)
	}

	configData, err := os.ReadFile(absConfigPath)
	if err != nil {
		return fmt.Errorf("failed to read config file '%s': %w", absConfigPath, err)
	}

	err = yaml.Unmarshal(configData, &AppConfig)
	if err != nil {
		return fmt.Errorf("failed to unmarshal config data from '%s': %w", absConfigPath, err)
	}

	if AppConfig.DataMonitorLogLevel == "" {
		AppConfig.DataMonitorLogLevel = "LOGLEVEL_INFO"
	}

	AppConfig.DataMonitorLogLevel = strings.ToUpper(AppConfig.DataMonitorLogLevel)

	return nil
}
