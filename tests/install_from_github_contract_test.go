package tests

import "testing"

func TestInstallFromGitHubRequiresPinnedCommitAndBootstrapsHost(t *testing.T) {
	installer := readRepositoryFile(t, "install-from-github.sh")
	requireContains(t, installer,
		"set -Eeuo pipefail",
		"SG InfoSec source commit must be a full 40-character SHA",
		"SG_INFOSEC_FORCE_GO_INSTALL",
		"ca-certificates",
		"curl",
		"git",
		"build-essential",
		"pkg-config",
		"libsqlite3-dev",
		"go1.24.12.linux-amd64.tar.gz",
		"bddf8e653c82429aea7aec2520774e79925d4bb929fe20e67ecc00dd5af44c50",
		"go1.24.12.linux-arm64.tar.gz",
		"4e02e2979e53b40f3666bba9f7e5ea0b99ea5156e0824b343fd054742c25498d",
		"git fetch --depth=1 origin \"$SOURCE_SHA\"",
		"test \"$(git rev-parse HEAD)\" = \"$SOURCE_SHA\"",
		"make build",
		"SG_INFOSEC_NO_START=1 ./packaging/install.sh",
		"systemctl start sg-infosec-enforcer.service",
		"systemctl start sg-infosec.service",
		"sg-infosecctl health",
		"sg-infosecctl nft status",
	)
	requireNotContains(t, installer,
		"restart sg-gateway.service",
		"try-restart sg-gateway.service",
		"systemctl restart sg-gateway",
		"curl | sh",
	)
}

func TestREADMEUsesThePinnedCleanInstallEntrypoint(t *testing.T) {
	readme := readRepositoryFile(t, "README.md")
	requireContains(t, readme,
		"## Install on a clean Debian or Ubuntu host",
		`SHA="<published-full-commit-sha>"`,
		`https://raw.githubusercontent.com/s-gor/sg-infosec/${SHA}/install-from-github.sh`,
		`sudo bash -s -- "$SHA"`,
		"The SHA appears twice intentionally",
		"does not restart SG-Gateway",
	)
}

func TestCleanInstallSmokeIsPartOfThePermanentGate(t *testing.T) {
	smoke := readRepositoryFile(t, "scripts/smoke-install-from-github.sh")
	requireContains(t, smoke,
		"packaging/uninstall.sh\" --purge",
		"SG_INFOSEC_REPOSITORY_URL=\"file://$SOURCE_REPOSITORY\"",
		"SG_INFOSEC_FORCE_GO_INSTALL=1",
		"/usr/local/go/bin/go env GOVERSION",
		"go1.24.12",
		"install-from-github.sh\" \"$SOURCE_SHA\"",
		"systemctl is-active --quiet sg-infosec-enforcer.service",
		"systemctl is-active --quiet sg-infosec.service",
		"/run/sg-infosec/enforcer.sock",
		"/run/sg-infosec/control.sock",
		"/run/sg-infosec/events.sock",
		"preserve-clean-install-marker",
		"clean install bootstrap smoke passed",
	)

	workflow := readRepositoryFile(t, ".github/workflows/enforcer-gate.yml")
	requireContains(t, workflow,
		"Run clean install bootstrap smoke",
		"bash scripts/smoke-install-from-github.sh",
	)
}
