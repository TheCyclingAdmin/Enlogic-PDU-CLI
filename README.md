# Enlogic PDU CLI

A fast, scriptable CLI to **list/get** outlet status and **control** outlets (`on/off/reboot/...`) on Enlogic PDUs.
Supports **batch** actions across many hosts, **parallelism**, **CSV exports**, **JSON**, and **file logging**.

## Features
- Globals-first CLI: `... --user ... --host ... <action> [flags]`
- Actions:
  - `examples` — print practical scenarios
  - `readme` — print this README
  - `setup` — write defaults to an INI config
  - `hosts` — show nicknames from `[hosts]`
  - `list` — table of all outlets (sortable)
  - `get` — show one outlet by `--port` or `--label`
  - `on/off` — one or many `--port`, or `--all`
  - `reboot`, `on_delay`, `off_delay`, `reboot_delay` — single `--port`
  - `batch` — run `on/off/reboot/.../list/get` across many PDUs in parallel
- Output:
  - Human tables by default
  - `--json` rows include `index,date,time`
  - `--csv <path>` rows include `index,date,time`; safe-append if header matches
- Networking/reliability:
  - `--timeout`, `--retries`, `--backoff`
  - `--insecure/--secure`, `--http/--https`
  - `--parallel` for batch concurrency
- Logging:
  - `--log-file <path>` writes logs including the **full command**

## Install
```bash
python3 -m pip install requests urllib3
```

## Examples
> Print these anytime:
> ```
> enlogic_cli.py examples
> ```


# Examples

# 1) First-time setup (writes defaults; prompts if missing)
enlogic_cli.py setup --config ~/.enlogic.ini

# 2) List all outlets (HTTPS, self-signed)
enlogic_cli.py --user admin --password pass --insecure --host 10.0.0.10 list

# 3) Get a single outlet by number or label
enlogic_cli.py --user admin --password pass --insecure --host 10.0.0.10 get --port 8
enlogic_cli.py --user admin --password pass --insecure --host 10.0.0.10 get --label "PSU1"

# 4) Turn ON multiple ports on a single PDU, then show full table
enlogic_cli.py --user admin --password pass --insecure --host 10.0.0.10 on --port 3 5 7

# 5) Turn OFF ALL outlets on a single PDU
enlogic_cli.py --user admin --password pass --insecure --host 10.0.0.10 off --all

# 6) Batch reboot a specific port across many hosts with parallelism and timeout
enlogic_cli.py --user admin --password pass --insecure --parallel 10 --timeout 5 \
  batch reboot --hosts 10.0.0.10 10.0.0.11 --port 8

# 7) Batch list ALL ports using a host file; export to CSV and log command/results
enlogic_cli.py --user admin --password pass --insecure \
  --log-file /tmp/pdu.log \
  batch list --host-file hosts.txt --all --csv /tmp/pdu.csv

# 8) JSON for scripting
enlogic_cli.py --user admin --password pass --insecure --host 10.0.0.10 list --json

# 9) Use nicknames from config [hosts] and per-host PDU IDs
# INI:
# [hosts]   lab.pdu1 = 10.0.0.10
# [pduid]   lab.pdu1 = 2
enlogic_cli.py --user admin --password pass --insecure --host lab.pdu1 list

# 10) Force HTTP (no TLS) and verify TLS explicitly
enlogic_cli.py --user admin --password pass --http   --host 10.0.0.10 list
enlogic_cli.py --user admin --password pass --secure --host 10.0.0.10 list


## Config
Run `enlogic_cli.py --config-help` to see the full annotated INI example.

## Exit Codes
- `0` success
- `1` usage/validation error
- `2` HTTP error
- `3` unexpected runtime error
