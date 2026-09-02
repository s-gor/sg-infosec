package tests

import (
	"os/exec"
	"path/filepath"
	"testing"
)

func TestStandaloneWebSystemdIsUnprivilegedAndSocketOnly(t *testing.T) {
	unit := readRepositoryFile(t, "packaging/systemd/sg-infosec-web.service")
	requireContains(t, unit,
		"User=sg-infosec-web",
		"Group=sg-infosec-web",
		"SupplementaryGroups=sg-infosec",
		"Requires=sg-infosec.service",
		"ExecStart=/usr/local/sbin/sg-infosec-web",
		"Environment=SG_INFOSEC_WEB_BASE_PATH=/infosec/",
		"Environment=SG_INFOSEC_WEB_SOCKET=/run/sg-infosec/web.sock",
		"Environment=SG_INFOSEC_CONTROL_SOCKET=/run/sg-infosec/control.sock",
		"Environment=SG_INFOSEC_WEB_STATE=/var/lib/sg-infosec/web/auth.json",
		"RestrictAddressFamilies=AF_UNIX",
		"NoNewPrivileges=true",
		"ProtectSystem=strict",
		"CapabilityBoundingSet=",
		"AmbientCapabilities=",
	)
	requireNotContains(t, unit, "User=root", "User=sg-infosec\n", "AF_INET", "AF_INET6", "CAP_NET_ADMIN")
}

func TestStandaloneWebHasDedicatedCoreAuthorizationSource(t *testing.T) {
	source := readRepositoryFile(t, "packaging/sources.d/standalone-web.yaml")
	requireContains(t, source,
		"source_id: sg-infosec-web",
		"user: sg-infosec-web",
		"group: sg-infosec-web",
		"  - check_decisions",
		"  - read_admin",
		"  - write_admin",
	)
	requireNotContains(t, source, "user: root", "user: sg-infosec\n")
}

func TestStandaloneWebNginxUsesDedicatedHTTPSPortAndWebSocketOnly(t *testing.T) {
	config := readRepositoryFile(t, "packaging/nginx/sg-infosec-web.conf")
	requireContains(t, config,
		"listen 64443 ssl",
		"location /infosec/",
		"/run/sg-infosec/web.sock",
		"proxy_set_header X-Real-IP $remote_addr",
		"ssl_protocols TLSv1.2 TLSv1.3",
	)
	requireNotContains(t, config,
		"/run/sg-infosec/control.sock",
		"/run/sg-infosec/enforcer.sock",
		"proxy_pass http://127.0.0.1",
		"listen 80",
		"listen 443",
	)
}

func TestStandaloneWebInstallerIsPinnedIndependentAndSelfVerifying(t *testing.T) {
	installer := readRepositoryFile(t, "install-standalone-web-from-github.sh")
	requireContains(t, installer,
		"set -Eeuo pipefail",
		"^[0-9a-f]{40}$",
		"install-from-github.sh",
		"sg-infosec-web",
		"groupadd --system \"$WEB_GROUP\"",
		"useradd --system",
		"usermod -a -G sg-infosec \"$WEB_USER\"",
		"usermod -a -G \"$WEB_GROUP\" www-data",
		"standalone-web.yaml",
		"nginx -t",
		"--ensure-setup-code",
		"https://127.0.0.1:64443/infosec/",
		"systemctl is-active --quiet sg-infosec-web.service",
	)
	requireNotContains(t, installer,
		"curl | bash",
		"restart sg-gateway.service",
		"try-restart sg-gateway.service",
		"/run/sg-infosec/control.sock:;",
	)
	command := exec.Command("bash", "-n", filepath.Join(repositoryRoot(t), "install-standalone-web-from-github.sh"))
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("installer shell syntax failed: %v\n%s", err, output)
	}
}
