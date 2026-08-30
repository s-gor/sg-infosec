package tests

import "testing"

func TestPermanentGateRunsSystemdInstallationSmoke(t *testing.T) {
	workflow := readRepositoryFile(t, ".github/workflows/enforcer-gate.yml")
	requireContains(t, workflow,
		"Run real systemd installation smoke",
		"bash scripts/smoke-systemd-install.sh",
	)
}
