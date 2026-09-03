package tests

import "testing"

func TestStandaloneWebRealInstallSmokeIsInReleaseGate(t *testing.T) {
	smoke := readRepositoryFile(t, "scripts/smoke-standalone-web-install.sh")
	requireContains(t, smoke,
		"install-standalone-web-from-github.sh",
		"SG_INFOSEC_REPOSITORY_URL=\"file://$ROOT_DIR\"",
		"12345678\\n12345678\\n",
		"Login: admin",
		"systemctl is-active --quiet sg-infosec-web.service",
		"https://127.0.0.1:64443/infosec/login",
		"https://127.0.0.1:64443/infosec/decisions",
		"standalone web install smoke passed",
	)
	requireNotContains(t, smoke,
		"/infosec/setup",
		"One-time setup code",
	)
	workflow := readRepositoryFile(t, ".github/workflows/enforcer-gate.yml")
	requireContains(t, workflow,
		"Run standalone web installation smoke",
		"bash scripts/smoke-standalone-web-install.sh",
	)
}
