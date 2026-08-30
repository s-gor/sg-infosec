package tests

import "testing"

func TestEnforcerRuntimeDirectoryPermissions(t *testing.T) {
	tmpfiles := readRepositoryFile(t, "packaging/tmpfiles.d/sg-infosec.conf")
	requireContains(t, tmpfiles,
		"d /run/sg-infosec 0750 root sg-infosec -",
		"a+ /run/sg-infosec - - - - u:sg-infosec:rwx,g::rx,m::rwx",
	)
	requireNotContains(t, tmpfiles,
		"d /run/sg-infosec 0750 sg-infosec sg-infosec -",
	)

	service := readRepositoryFile(t, "packaging/systemd/sg-infosec-enforcer.service")
	requireContains(t, service,
		"User=root",
		"Group=sg-infosec",
		"ReadWritePaths=/run/sg-infosec",
	)
	requireNotContains(t, service,
		"Group=root",
		"CAP_DAC_OVERRIDE",
	)
}
