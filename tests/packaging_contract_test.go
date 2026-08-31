package tests

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, current, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test path")
	}
	return filepath.Dir(filepath.Dir(current))
}

func readRepositoryFile(t *testing.T, name string) string {
	t.Helper()
	content, err := os.ReadFile(filepath.Join(repositoryRoot(t), name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return string(content)
}

func requireContains(t *testing.T, text string, values ...string) {
	t.Helper()
	for _, value := range values {
		if !strings.Contains(text, value) {
			t.Errorf("missing contract %q", value)
		}
	}
}

func requireNotContains(t *testing.T, text string, values ...string) {
	t.Helper()
	for _, value := range values {
		if strings.Contains(text, value) {
			t.Errorf("forbidden contract %q", value)
		}
	}
}

func TestSystemdServiceIsUnixOnlyAndUnprivileged(t *testing.T) {
	service := readRepositoryFile(t, "packaging/systemd/sg-infosec.service")
	requireContains(t, service,
		"User=sg-infosec",
		"Group=sg-infosec",
		"After=local-fs.target systemd-tmpfiles-setup.service sg-infosec-enforcer.service",
		"StateDirectory=sg-infosec",
		"StateDirectoryMode=0750",
		"ExecStartPre=/usr/local/sbin/sg-infosecd --config /etc/sg-infosec/sg-infosec.yaml --check-config",
		"ExecStart=/usr/local/sbin/sg-infosecd --config /etc/sg-infosec/sg-infosec.yaml",
		"RestrictAddressFamilies=AF_UNIX",
		"NoNewPrivileges=true",
		"ProtectSystem=strict",
		"ReadWritePaths=/run/sg-infosec /var/lib/sg-infosec",
		"CapabilityBoundingSet=",
		"AmbientCapabilities=",
	)
	requireNotContains(t, service, "User=root", "CAP_NET_ADMIN", "AF_INET", "AF_INET6", "RuntimeDirectory=sg-infosec")
}

func TestTmpfilesCreatesNarrowRuntimeAndPersistentDirectories(t *testing.T) {
	tmpfiles := readRepositoryFile(t, "packaging/tmpfiles.d/sg-infosec.conf")
	requireContains(t, tmpfiles,
		"d /run/sg-infosec 0750 root sg-infosec -",
		"a+ /run/sg-infosec - - - - u:sg-infosec:rwx,g::rx,m::rwx",
		"d /var/lib/sg-infosec 0750 sg-infosec sg-infosec -",
		"d /etc/sg-infosec 0750 root sg-infosec -",
		"d /etc/sg-infosec/sources.d 0750 root sg-infosec -",
		"d /etc/sg-infosec/policies.d 0750 root sg-infosec -",
	)
	requireNotContains(t, tmpfiles, "d /run/sg-infosec 0750 sg-infosec sg-infosec -")
}

func TestInstallerPreservesConfigAndGrantsGatewaySocketAccess(t *testing.T) {
	installer := readRepositoryFile(t, "packaging/install.sh")
	requireContains(t, installer,
		"set -Eeuo pipefail",
		"groupadd --system \"$SERVICE_GROUP\"",
		"useradd --system",
		"install_if_missing",
		"usermod -a -G \"$SERVICE_GROUP\" sg-gateway",
		"systemd-tmpfiles --create \"$TMPFILES_PATH\"",
		"systemctl enable sg-infosec-enforcer.service sg-infosec.service sg-infosec-ssh-agent.service",
		"systemctl start sg-infosec-enforcer.service",
		"systemctl start sg-infosec.service",
		"systemctl start sg-infosec-ssh-agent.service",
		"group membership takes effect after the next planned sg-gateway.service restart",
	)
	requireNotContains(t, installer, "curl ", "wget ", "sed -i", "iptables", "nft ", "try-restart sg-gateway.service", "restart sg-gateway.service")
}

func TestUninstallerPreservesStateUnlessPurgeIsExplicit(t *testing.T) {
	uninstaller := readRepositoryFile(t, "packaging/uninstall.sh")
	requireContains(t, uninstaller,
		"set -Eeuo pipefail",
		"--purge",
		"systemctl disable --now sg-infosec-ssh-agent.service",
		"systemctl disable --now sg-infosec.service sg-infosec-enforcer.service",
		"\"$SSH_AGENT_PATH\"",
		"\"$SSH_AGENT_UNIT_PATH\"",
		"if (( PURGE )); then",
		`rm -rf -- "$CONFIG_ROOT" "$STATE_ROOT" "$RUNTIME_ROOT"`,
	)
	requireNotContains(t, uninstaller, `"$ENFORCER_PATH" --purge-owned-table || true`)
}

func TestPackagedSourcesSeparateGatewayAndLocalRootAdmin(t *testing.T) {
	gateway := readRepositoryFile(t, "config/example/sources.d/sg-gateway.yaml")
	admin := readRepositoryFile(t, "config/example/sources.d/local-admin.yaml")
	requireContains(t, gateway,
		"source_id: sg-gateway",
		"user: sg-gateway",
		"  - check_decisions",
	)
	requireNotContains(t, gateway, "read_admin", "write_admin")
	requireContains(t, admin,
		"source_id: local-admin",
		"user: root",
		"  - read_admin",
		"  - write_admin",
		"  - check_decisions",
	)
}

func TestInstallerAndUninstallerAreRepeatableInDestdir(t *testing.T) {
	root := repositoryRoot(t)
	temporary := t.TempDir()
	fakeBin := filepath.Join(temporary, "bin")
	if err := os.MkdirAll(fakeBin, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"sg-infosecd", "sg-infosecctl", "sg-infosec-enforcerd", "sg-infosec-ssh-agent"} {
		path := filepath.Join(fakeBin, name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	destdir := filepath.Join(temporary, "root")
	environment := append(os.Environ(),
		"DESTDIR="+destdir,
		"SG_INFOSEC_DAEMON_SOURCE="+filepath.Join(fakeBin, "sg-infosecd"),
		"SG_INFOSEC_CTL_SOURCE="+filepath.Join(fakeBin, "sg-infosecctl"),
		"SG_INFOSEC_ENFORCER_SOURCE="+filepath.Join(fakeBin, "sg-infosec-enforcerd"),
		"SG_INFOSEC_SSH_AGENT_SOURCE="+filepath.Join(fakeBin, "sg-infosec-ssh-agent"),
	)
	run := func(script string, args ...string) {
		t.Helper()
		command := exec.Command("bash", append([]string{filepath.Join(root, script)}, args...)...)
		command.Env = environment
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("%s failed: %v\n%s", script, err, output)
		}
	}

	run("packaging/install.sh")
	configPath := filepath.Join(destdir, "etc/sg-infosec/sg-infosec.yaml")
	const marker = "preserve-this-config\n"
	if err := os.WriteFile(configPath, []byte(marker), 0o640); err != nil {
		t.Fatal(err)
	}
	run("packaging/install.sh")
	content, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(content) != marker {
		t.Fatalf("installer overwrote existing config: %q", content)
	}
	for _, path := range []string{
		"usr/local/sbin/sg-infosecd",
		"usr/local/sbin/sg-infosecctl",
		"usr/local/sbin/sg-infosec-enforcerd",
		"usr/local/sbin/sg-infosec-ssh-agent",
		"etc/systemd/system/sg-infosec.service",
		"etc/systemd/system/sg-infosec-enforcer.service",
		"etc/systemd/system/sg-infosec-ssh-agent.service",
		"usr/lib/tmpfiles.d/sg-infosec.conf",
		"etc/sg-infosec/sources.d/local-admin.yaml",
		"etc/sg-infosec/policies.d/ssh.yaml",
	} {
		if _, err := os.Stat(filepath.Join(destdir, path)); err != nil {
			t.Errorf("missing installed path %s: %v", path, err)
		}
	}

	run("packaging/uninstall.sh")
	if _, err := os.Stat(configPath); err != nil {
		t.Fatalf("ordinary uninstall removed config: %v", err)
	}
	if _, err := os.Stat(filepath.Join(destdir, "usr/local/sbin/sg-infosecd")); !os.IsNotExist(err) {
		t.Fatalf("ordinary uninstall kept daemon: %v", err)
	}
	if _, err := os.Stat(filepath.Join(destdir, "usr/local/sbin/sg-infosec-ssh-agent")); !os.IsNotExist(err) {
		t.Fatalf("ordinary uninstall kept SSH agent: %v", err)
	}

	run("packaging/install.sh")
	run("packaging/uninstall.sh", "--purge")
	if _, err := os.Stat(filepath.Join(destdir, "etc/sg-infosec")); !os.IsNotExist(err) {
		t.Fatalf("purge kept configuration: %v", err)
	}
	if _, err := os.Stat(filepath.Join(destdir, "var/lib/sg-infosec")); !os.IsNotExist(err) {
		t.Fatalf("purge kept state: %v", err)
	}
}

func TestEnforcerServiceIsRootButNarrowlyCapabilityBound(t *testing.T) {
	service := readRepositoryFile(t, "packaging/systemd/sg-infosec-enforcer.service")
	requireContains(t, service,
		"User=root",
		"Group=sg-infosec",
		"After=network-pre.target systemd-tmpfiles-setup.service",
		"ExecStart=/usr/local/sbin/sg-infosec-enforcerd --service-user sg-infosec",
		"CapabilityBoundingSet=CAP_NET_ADMIN",
		"AmbientCapabilities=CAP_NET_ADMIN",
		"RestrictAddressFamilies=AF_UNIX AF_NETLINK",
		"NoNewPrivileges=true",
		"ProtectSystem=strict",
		"ReadWritePaths=/run/sg-infosec",
	)
	requireNotContains(t, service, "Group=root", "AF_INET", "AF_INET6", "CAP_SYS_ADMIN", "CAP_DAC_OVERRIDE", "RuntimeDirectory=sg-infosec")
	core := readRepositoryFile(t, "packaging/systemd/sg-infosec.service")
	requireContains(t, core, "Requires=sg-infosec-enforcer.service")
}
