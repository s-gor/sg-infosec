package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultBasePath      = "/infosec/"
	defaultListenSocket  = "/run/sg-infosec-web/web.sock"
	defaultControlSocket = "/run/sg-infosec/control.sock"
	defaultStatePath     = "/var/lib/sg-infosec/web/auth.json"
	defaultSessionTTL    = 8 * time.Hour
)

type Config struct {
	BasePath      string
	ListenSocket  string
	ControlSocket string
	StatePath     string
	SessionTTL    time.Duration
}

func LoadFromEnv() (Config, error) {
	cfg := Config{BasePath: valueOrDefault("SG_INFOSEC_WEB_BASE_PATH", defaultBasePath), ListenSocket: valueOrDefault("SG_INFOSEC_WEB_SOCKET", defaultListenSocket), ControlSocket: valueOrDefault("SG_INFOSEC_CONTROL_SOCKET", defaultControlSocket), StatePath: valueOrDefault("SG_INFOSEC_WEB_STATE", defaultStatePath), SessionTTL: defaultSessionTTL}
	if value := strings.TrimSpace(os.Getenv("SG_INFOSEC_WEB_SESSION_TTL")); value != "" {
		ttl, err := time.ParseDuration(value)
		if err != nil {
			return Config{}, fmt.Errorf("parse session lifetime: %w", err)
		}
		cfg.SessionTTL = ttl
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func (c Config) Validate() error {
	if c.BasePath == "/" || !strings.HasPrefix(c.BasePath, "/") || !strings.HasSuffix(c.BasePath, "/") || strings.Contains(c.BasePath, "//") || strings.Contains(c.BasePath, "..") || strings.ContainsAny(c.BasePath, "?#") {
		return fmt.Errorf("web base path must be a non-root absolute path ending in slash")
	}
	for name, value := range map[string]string{"web socket": c.ListenSocket, "control socket": c.ControlSocket, "state path": c.StatePath} {
		if !filepath.IsAbs(value) {
			return fmt.Errorf("%s path must be absolute", name)
		}
	}
	if c.SessionTTL < 5*time.Minute || c.SessionTTL > 24*time.Hour {
		return fmt.Errorf("session lifetime must be between 5 minutes and 24 hours")
	}
	return nil
}

func valueOrDefault(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}
