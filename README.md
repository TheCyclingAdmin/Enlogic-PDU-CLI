# Enlogic PDU CLI

Minimal, scriptable CLI for Enlogic/ePDU devices. Python 3.9+ (RHEL 8/9, Ubuntu 22.04/24.04).

## Install
```bash
tar xzf enlogic_cli_split_rhel_ubuntu.tar.gz
cd enlogic_cli_split
bash install_enlogic_cli.sh
```

Wrapper will be at `~/.local/bin/enlogic-cli`.

## Sample config
See `enlogic.ini.sample` and `enlogic-hosts.sample.ini` in this repo. Use `enlogic-cli setup` to create/update your config.

## Actions
- `setup` — interactive config writer
- `validate` — validate `~/.enlogic.ini` and hosts file
- `show` / `list` — list outlets; includes lock status
- `get` — fetch one outlet by `--port` or `--label`
- `on` / `off` — power control (HTTP/XHR path)
- `lock` / `unlock` — super-admin outlet locking (Redfish)
- `reboot`, `on_delay`, `off_delay`, `reboot_delay` — single-port variants
- `batch` — read-only list across many hosts

### Output formats
`--format table|json|csv` (CSV goes to stdout; use `--csv-header` to control headers).

### Reliability options (power + lock actions)
- `--retry-ports N` — retry failed outlets up to N times.
- `--retry-wait SECS` — wait between retries.
- `--retry-ports-once` — shorthand for one retry.

### TLS/protocol and perf
- `--http` / `--https` (default HTTPS)
- `--insecure` to skip TLS verify, `--secure` to enforce
- `--timeout`, `--retries`, `--backoff`
- `--parallel` for `batch`

## Exit codes
| Code | Meaning |
|---:|---|
| 0 | Success |
| 2 | Usage error (bad/missing flags, invalid target for `get`/`show`) |
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
enlogic-cli validate --format json --strict

# Show + JSON
enlogic-cli --host 10.0.0.10 show --format json

# Get one outlet
enlogic-cli --host 10.0.0.10 get --port 8

# Power with retries
enlogic-cli --host 10.0.0.10 --user admin --password pass on --port 3 5 --retry-ports 2 --retry-wait 0.5

# Lock with retries (super-admin)
enlogic-cli --host 10.0.0.10 --super-user super --super-password pass lock --port 3 --retry-ports 3

# Batch CSV
enlogic-cli --user admin --password pass batch --hosts rackA 10.0.0.11 --format csv > /tmp/pdu.csv
```
