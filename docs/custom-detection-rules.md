# Custom journal detection rules

SG InfoSec includes reviewed built-in parsers for OpenSSH, Nginx and SG-Gateway. Additional local log formats can be mapped into the same bounded correlator through `/etc/sg-infosec/detection-rules.json`.

The installer creates an empty file only when it is missing. Existing operator rules are never overwritten during installation or update.

## Schema

```json
{
  "rules": [
    {
      "id": "custom-panel-auth",
      "unit_pattern": "^custom-panel\\.service$",
      "identifier_pattern": "^custom-panel$",
      "message_pattern": "^LOGIN_FAIL ip=(?P<ip>[^ ]+) user=(?P<subject>[^ ]+)$",
      "category": "gateway.auth_failed",
      "service": "sg-gateway"
    }
  ]
}
```

`message_pattern` is required and must contain a named `ip` capture. An optional named `subject` capture is hashed before it enters correlation state. The raw message and raw subject are not persisted.

Supported categories:

- `ssh.auth_failed`;
- `ssh.invalid_user`;
- `http.admin_probe`;
- `gateway.auth_failed`;
- `gateway.api_auth_failed`.

Supported services:

- `ssh`;
- `http`;
- `sg-gateway`.

`unit_pattern` and `identifier_pattern` are optional. Rules are limited to 256, each expression is limited to 1024 bytes, duplicate IDs are rejected and unknown fields fail configuration validation.

## Processing

Custom findings enter the same per-IP sliding windows as built-in findings. Duplicate built-in/custom findings for the same IP, category, service and subject are counted once. Existing thresholds, allowlists, escalation, audit and backend isolation remain in force.

An invalid rules file prevents SG InfoSec from starting instead of silently disabling the intended protection. A missing rules file is treated as an empty set.

A different path can be selected with:

```ini
Environment=SG_INFOSEC_DETECTION_RULES=/path/to/detection-rules.json
```

After changing rules, validate and restart SG InfoSec during a maintenance window:

```bash
sudo sg-infosecd --config /etc/sg-infosec/sg-infosec.yaml --check-config
sudo systemctl restart sg-infosec.service
```
