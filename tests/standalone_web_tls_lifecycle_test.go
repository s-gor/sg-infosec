package tests

import (
	"os/exec"
	"path/filepath"
	"testing"
)

func TestStandaloneWebTLSLifecycleContract(t *testing.T) {
	installer := readRepositoryFile(t, "install-standalone-web-from-github.sh")
	requireContains(t, installer,
		`WEB_DOMAIN="${SG_INFOSEC_WEB_DOMAIN:-}"`,
		"tls_pair_valid()",
		"disable_invalid_enabled_site()",
		"configure_nginx_site()",
		`[[ -r "$certificate" && -s "$certificate" ]]`,
		`readlink -f -- "$certificate"`,
		`/etc/letsencrypt/live/$WEB_DOMAIN/fullchain.pem`,
		`/etc/letsencrypt/live/$WEB_DOMAIN/privkey.pem`,
		"nginx -t",
		"HTTPS web UI is temporarily disabled",
	)
	requireNotContains(t, installer,
		"openssl req -x509",
		"certbot certonly",
		"certbot delete",
		"listen 443",
	)

	config := readRepositoryFile(t, "packaging/nginx/sg-infosec-web.conf")
	requireContains(t, config, "listen 64443 ssl")
	requireNotContains(t, config, "listen 443")

	uninstaller := readRepositoryFile(t, "packaging/uninstall.sh")
	requireContains(t, uninstaller,
		"/etc/nginx/sites-enabled/sg-infosec-web.conf",
		"/etc/nginx/sites-available/sg-infosec-web.conf",
		"nginx -t",
	)
	requireNotContains(t, uninstaller,
		"rm -rf /etc/letsencrypt",
		"rm -rf -- /etc/letsencrypt",
		"certbot delete",
	)
}

func TestStandaloneWebBrokenLetsEncryptSmokeCoversRealRegression(t *testing.T) {
	smoke := readRepositoryFile(t, "scripts/smoke-standalone-web-install.sh")
	requireContains(t, smoke,
		"itsec.opik.net",
		"/etc/letsencrypt/live/$TEST_DOMAIN/fullchain.pem",
		"/etc/letsencrypt/live/$TEST_DOMAIN/privkey.pem",
		"broken LetsEncrypt symlink",
		"nginx -t unexpectedly passed with broken InfoSec TLS",
		"SG_INFOSEC_WEB_DOMAIN=\"$TEST_DOMAIN\"",
		"InfoSec HTTPS site remained enabled without a readable TLS pair",
		"nginx -t",
		"listen 443 ssl",
		"listen 64443 ssl",
		"coexistence smoke passed",
	)

	command := exec.Command("bash", "-n", filepath.Join(repositoryRoot(t), "scripts/smoke-standalone-web-install.sh"))
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("standalone web smoke shell syntax failed: %v\n%s", err, output)
	}
}
