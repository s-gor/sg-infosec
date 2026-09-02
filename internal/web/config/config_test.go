package config

import (
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	for _, key := range []string{
		"SG_INFOSEC_WEB_BASE_PATH",
		"SG_INFOSEC_WEB_SOCKET",
		"SG_INFOSEC_CONTROL_SOCKET",
		"SG_INFOSEC_WEB_STATE",
		"SG_INFOSEC_WEB_SESSION_TTL",
	} {
		t.Setenv(key, "")
	}
	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BasePath != "/infosec/" {
		t.Fatalf("base path=%q", cfg.BasePath)
	}
	if cfg.ListenSocket != "/run/sg-infosec/web.sock" {
		t.Fatalf("listen socket=%q", cfg.ListenSocket)
	}
	if cfg.ControlSocket != "/run/sg-infosec/control.sock" {
		t.Fatalf("control socket=%q", cfg.ControlSocket)
	}
	if cfg.StatePath != "/var/lib/sg-infosec/web/auth.json" {
		t.Fatalf("state path=%q", cfg.StatePath)
	}
	if cfg.SessionTTL != 8*time.Hour {
		t.Fatalf("session ttl=%s", cfg.SessionTTL)
	}
}

func TestLoadOverrides(t *testing.T) {
	t.Setenv("SG_INFOSEC_WEB_BASE_PATH", "/infosec/")
	t.Setenv("SG_INFOSEC_WEB_SOCKET", "/tmp/web.sock")
	t.Setenv("SG_INFOSEC_CONTROL_SOCKET", "/tmp/control.sock")
	t.Setenv("SG_INFOSEC_WEB_STATE", "/tmp/auth.json")
	t.Setenv("SG_INFOSEC_WEB_SESSION_TTL", "30m")
	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ListenSocket != "/tmp/web.sock" || cfg.ControlSocket != "/tmp/control.sock" || cfg.StatePath != "/tmp/auth.json" || cfg.SessionTTL != 30*time.Minute {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

func TestLoadRejectsUnsafeConfig(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value string
	}{
		{name: "base without leading slash", key: "SG_INFOSEC_WEB_BASE_PATH", value: "infosec/"},
		{name: "base without trailing slash", key: "SG_INFOSEC_WEB_BASE_PATH", value: "/infosec"},
		{name: "root base", key: "SG_INFOSEC_WEB_BASE_PATH", value: "/"},
		{name: "relative web socket", key: "SG_INFOSEC_WEB_SOCKET", value: "web.sock"},
		{name: "relative control socket", key: "SG_INFOSEC_CONTROL_SOCKET", value: "control.sock"},
		{name: "relative state", key: "SG_INFOSEC_WEB_STATE", value: "auth.json"},
		{name: "short session", key: "SG_INFOSEC_WEB_SESSION_TTL", value: "4m"},
		{name: "long session", key: "SG_INFOSEC_WEB_SESSION_TTL", value: "25h"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, key := range []string{
				"SG_INFOSEC_WEB_BASE_PATH",
				"SG_INFOSEC_WEB_SOCKET",
				"SG_INFOSEC_CONTROL_SOCKET",
				"SG_INFOSEC_WEB_STATE",
				"SG_INFOSEC_WEB_SESSION_TTL",
			} {
				t.Setenv(key, "")
			}
			t.Setenv(test.key, test.value)
			if _, err := LoadFromEnv(); err == nil {
				t.Fatalf("accepted %s=%q", test.key, test.value)
			}
		})
	}
}
