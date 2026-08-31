package tests

import "testing"

func TestSSHCollectorBuildPackagingAndPolicyContracts(t *testing.T) {
	makefile := readRepositoryFile(t, "Makefile")
	requireContains(t, makefile,
		"bin/sg-infosec-ssh-agent",
		"./cmd/sg-infosec-ssh-agent",
	)

	policy := readRepositoryFile(t, "config/example/policies.d/ssh.yaml")
	requireContains(t, policy,
		"policy_id: local-ssh-login",
		"event_type: auth.failed",
		"scope: ssh",
		"source_id: local-admin",
		"threshold: 5",
		"window: 10m",
		"base_duration: 30m",
		"max_duration: 24h",
		"backend: nftables",
	)

	unit := readRepositoryFile(t, "packaging/systemd/sg-infosec-ssh-agent.service")
	requireContains(t, unit,
		"After=sg-infosec.service",
		"Requires=sg-infosec.service",
		"ExecStart=/usr/local/sbin/sg-infosec-ssh-agent",
		"RestrictAddressFamilies=AF_UNIX",
		"NoNewPrivileges=true",
		"ProtectSystem=strict",
		"CapabilityBoundingSet=",
		"AmbientCapabilities=",
	)
	requireNotContains(t, unit,
		"CAP_NET_ADMIN",
		"AF_INET",
		"AF_INET6",
		"ExecStart=/bin/sh",
		"ExecStart=/usr/bin/bash",
	)
}

func TestSSHCollectorLifecyclePreservesSSHAndGateway(t *testing.T) {
	installer := readRepositoryFile(t, "packaging/install.sh")
	requireContains(t, installer,
		"SG_INFOSEC_SSH_AGENT_SOURCE",
		"/usr/local/sbin/sg-infosec-ssh-agent",
		"sg-infosec-ssh-agent.service",
		"config/example/policies.d/ssh.yaml",
		"install_if_missing",
	)

	uninstaller := readRepositoryFile(t, "packaging/uninstall.sh")
	requireContains(t, uninstaller,
		"systemctl disable --now sg-infosec-ssh-agent.service",
		"sg-infosec-ssh-agent",
	)

	bootstrap := readRepositoryFile(t, "install-from-github.sh")
	requireContains(t, bootstrap,
		"bin/sg-infosec-ssh-agent",
		"systemctl start sg-infosec-ssh-agent.service",
		"systemctl is-active --quiet sg-infosec-ssh-agent.service",
	)
	requireNotContains(t, installer+uninstaller+bootstrap,
		"sshd_config",
		"pam.d/sshd",
		"restart ssh.service",
		"restart sshd.service",
		"restart sg-gateway.service",
		"try-restart sg-gateway.service",
	)
}

func TestSSHCollectorIsPartOfPermanentSmoke(t *testing.T) {
	systemdSmoke := readRepositoryFile(t, "scripts/smoke-systemd-install.sh")
	requireContains(t, systemdSmoke,
		"sg-infosec-ssh-agent.service",
		"/usr/local/sbin/sg-infosec-ssh-agent",
	)

	cleanSmoke := readRepositoryFile(t, "scripts/smoke-install-from-github.sh")
	requireContains(t, cleanSmoke,
		"systemctl is-active --quiet sg-infosec-ssh-agent.service",
		"sg-infosecctl overview",
	)
}
