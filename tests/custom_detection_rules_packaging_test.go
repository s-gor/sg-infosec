package tests

import "testing"

func TestCustomDetectionRulesAreInstalledWithoutOverwritingOperatorState(t *testing.T) {
	installer := readRepositoryFile(t, "packaging/install.sh")
	example := readRepositoryFile(t, "config/example/detection-rules.json")
	app := readRepositoryFile(t, "internal/app/app.go")
	unit := readRepositoryFile(t, "packaging/systemd/sg-infosec.service")

	requireContains(t, installer,
		"config/example/detection-rules.json",
		"$CONFIG_ROOT/detection-rules.json",
		"install_if_missing",
	)
	requireContains(t, app,
		"SG_INFOSEC_DETECTION_RULES",
		"detection.DefaultRulesPath",
		"detection.LoadRuleSet",
	)
	requireContains(t, unit,
		"Environment=SG_INFOSEC_DETECTION_RULES=/etc/sg-infosec/detection-rules.json",
		"ExecStartPre=/usr/local/sbin/sg-infosecd --config /etc/sg-infosec/sg-infosec.yaml --check-config",
	)
	requireContains(t, example, "\"rules\": []")
}
