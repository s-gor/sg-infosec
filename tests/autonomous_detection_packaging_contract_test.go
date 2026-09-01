package tests

import "testing"

func TestAutonomousDetectorHasReadOnlyJournalAccessAndIsEnabledByDefault(t *testing.T) {
	service := readRepositoryFile(t, "packaging/systemd/sg-infosec.service")
	requireContains(t, service,
		"After=local-fs.target systemd-tmpfiles-setup.service sg-infosec-enforcer.service",
		"After=systemd-journald.service",
		"SupplementaryGroups=systemd-journal",
		"Environment=SG_INFOSEC_AUTONOMOUS_DETECTION=1",
		"User=sg-infosec",
		"CapabilityBoundingSet=",
		"RestrictAddressFamilies=AF_UNIX",
	)
	requireNotContains(t, service,
		"User=root",
		"CAP_DAC_READ_SEARCH",
		"CAP_SYSLOG",
		"AF_INET",
		"AF_INET6",
	)
}
