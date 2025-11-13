# Enlogic PDU CLI

Minimal, scriptable CLI for Enlogic/ePDU devices. Python 3.9+ (RHEL 8/9, Ubuntu 22.04/24.04).

## Install
```bash
tar xzf enlogic_cli_split_rhel_ubuntu.tar.gz
cd enlogic_cli_split
bash install_enlogic_cli.sh
```

Wrapper will be at `~/.local/bin/enlogic_cli`.

## Sample config
See `enlogic.ini.sample` and `enlogic-hosts.sample.ini`. Use `enlogic_cli setup` to create/update your config.

## Actions
- `help` — global help or `help <action>`
- `setup` — interactive config writer
- `validate` — validate `~/.enlogic.ini` and hosts file
- `show` — list outlets; includes lock status; `--port` or `--label` for a single outlet
- `on` / `off` — power control (XHR)
- `lock` / `unlock` — super-admin outlet locking (Redfish)
- `reboot`, `on_delay`, `off_delay`, `reboot_delay` — single-port variants

### Output formats
`--format table|json|csv` (CSV goes to stdout; use `--csv-header` to control headers).

### Reliability options (power + lock actions)
- `--retry-ports N` — retry failed outlets up to **N** times.
- `--retry-wait SECS` — wait between retries.
- `--retry-ports-once` — shorthand for one retry.

### TLS/protocol
- `--http` / `--https` (default HTTPS)
- `--insecure` to skip TLS verify, `--secure` to enforce
- `--timeout`, `--retries`, `--backoff`

## Exit codes
| Code | Meaning |
|---:|---|
| 0 | Success |
| 2 | Usage error |
| 3 | Config/hosts error |
| 4 | Auth/permission (401/403) |
| 5 | Network/TLS error |
| 6 | Device/Redfish error |
| 7 | Partial success (some ports succeeded, some failed) |
| 8 | I/O error |
| 9 | Timeout |
| 10 | Unexpected error |

## Examples
```bash
# Validate
enlogic_cli validate --format json --strict

# Show + JSON
enlogic_cli --host 10.0.0.10 show --format json

# Show one outlet
enlogic_cli --host 10.0.0.10 show --port 8

# Power with retries
enlogic_cli --host 10.0.0.10 --user admin --password pass on --port 3 5 --retry-ports 2 --retry-wait 0.5

# Lock with retries (super-admin)
enlogic_cli --host 10.0.0.10 --super-user super --super-password pass lock --port 3 --retry-ports 3
```

## Help
```bash
enlogic_cli --help
enlogic_cli help
enlogic_cli help show
```
