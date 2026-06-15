package config

import (
	"encoding/json"
	"os"
	"strings"
	"sync"
)

// Config holds the persistent settings for LAN Sentinel
type Config struct {
	ScanIntervalSeconds int               `json:"scan_interval_seconds"`
	EnableNotifications bool              `json:"enable_notifications"`
	AuthorizedDevices   map[string]string `json:"authorized_devices"` // MAC address -> Alias
}

var (
	configLock sync.RWMutex
	configFile = "config.json"
)

// LoadConfig loads configuration from config.json or returns default values
func LoadConfig() (*Config, error) {
	configLock.RLock()
	defer configLock.RUnlock()

	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		// Return default configuration
		return &Config{
			ScanIntervalSeconds: 30,
			EnableNotifications: true,
			AuthorizedDevices:   make(map[string]string),
		}, nil
	}

	data, err := os.ReadFile(configFile)
	if err != nil {
		return nil, err
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	// Normalize keys in AuthorizedDevices map to lowercase MACs
	normalizedAuth := make(map[string]string)
	for mac, alias := range config.AuthorizedDevices {
		normalizedAuth[strings.ToLower(mac)] = alias
	}
	config.AuthorizedDevices = normalizedAuth

	return &config, nil
}

// SaveConfig writes the configuration to config.json
func SaveConfig(config *Config) error {
	configLock.Lock()
	defer configLock.Unlock()

	// Ensure keys are lowercase
	normalizedAuth := make(map[string]string)
	for mac, alias := range config.AuthorizedDevices {
		normalizedAuth[strings.ToLower(mac)] = alias
	}
	config.AuthorizedDevices = normalizedAuth

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(configFile, data, 0644)
}
