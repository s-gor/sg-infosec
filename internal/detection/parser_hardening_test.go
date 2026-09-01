package detection

import (
	"testing"
	"time"
)

func TestParseHTTPDoesNotTreatNormalGatewayConfigurationRoutesAsScans(t *testing.T) {
	t.Parallel()
	for _, path := range []string{"/config", "/api/config", "/backup", "/api/backups", "/admin/settings"} {
		record := JournalRecord{
			Unit:       "nginx.service",
			Identifier: "nginx",
			Message:    `203.0.113.44 - - [01/Sep/2026:10:00:00 +0000] "GET ` + path + ` HTTP/1.1" 200 153 "-" "browser"`,
			OccurredAt: time.Now().UTC(),
		}
		if findings := Parse(record); len(findings) != 0 {
			t.Fatalf("ordinary path %q produced findings: %#v", path, findings)
		}
	}
}

func TestParseHTTPRecognizesReviewedAdministrativeAttackPaths(t *testing.T) {
	t.Parallel()
	for _, path := range []string{"/.git/config", "/wp-login.php", "/actuator/env", "/cgi-bin/test", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "/../../etc/passwd"} {
		record := JournalRecord{
			Unit:       "nginx.service",
			Identifier: "nginx",
			Message:    `198.51.100.4 - - [01/Sep/2026:10:00:00 +0000] "GET ` + path + ` HTTP/1.1" 404 0 "-" "scanner"`,
			OccurredAt: time.Now().UTC(),
		}
		if findings := Parse(record); len(findings) != 1 || findings[0].Category != CategoryHTTPAdminProbe {
			t.Fatalf("attack path %q was not recognized: %#v", path, findings)
		}
	}
}
