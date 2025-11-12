# =========================================
# file: enlogic_text.py
# =========================================
"""
Static text & helpers for help/readme/examples to keep CLI lean.
Compatible with Python 3.9+ (RHEL 8/9, Ubuntu 22.04/24.04).
"""

from typing import Dict, List

README_TEXT = """\
# Enlogic PDU CLI

Scriptable CLI to list/get outlet status and control outlets (on/off/reboot) on Enlogic iPDU.
Includes **Super Admin Outlet Locking** (`lock` / `unlock`) and a **Lock** column in all outlet listings.

Highlights:
- HTTPS with retry/backoff, colorized tables, CSV/JSON output (`--format table|json|csv`)
- Per-host nicknames and PDU-IDs via config; batch mode across many hosts
- Super-admin creds stored under `[superadmin]` in the INI
- Tested on Python 3.9+ typical of RHEL 8/9 and Ubuntu 22.04/24.04
"""

CONFIG_HELP = """\
Config file (INI). Default: ~/.enlogic.ini

[auth]
user = <username>
password = <password>

[superadmin]
# optional; used for outlet locking via Redfish
user = <super admin username>
password = <super admin password>

[defaults]
http = false           # true -> use http://, false -> https://
insecure = false       # true -> skip TLS verification, false -> verify TLS
pduid = 1
low_bank_max = 24
timeout = 10.0
retries = 3
backoff = 0.5

[hosts]
# nick -> ip or hostname
lab.pdu1 = 10.0.0.10

[pduid]
# per-host PDU id override (nickname or IP)
lab.pdu1 = 2
"""

EXAMPLES_TEXT = """\
# Examples

# Show config help / README / examples
enlogic_cli.py --config-help
enlogic_cli.py readme
enlogic_cli.py examples

# List all outlets (HTTPS, self-signed)
enlogic_cli.py --user admin --password pass --insecure --host 10.0.0.10 list

# Same but JSON/CSV (for scripting)
enlogic_cli.py --host 10.0.0.10 --user admin --password pass list --format json
enlogic_cli.py --host 10.0.0.10 --user admin --password pass list --format csv > /tmp/pdu.csv

# List using super-admin creds (ensures lock visibility)
enlogic_cli.py --host 10.0.0.10 --super-user super --super-password pass list --use-super

# Get a single outlet by number or label (JSON for scripts)
enlogic_cli.py --host 10.0.0.10 --user admin --password pass get --port 8 --format json
enlogic_cli.py --host 10.0.0.10 --user admin --password pass get --label "PSU1"

# Turn ON multiple ports
enlogic_cli.py --host 10.0.0.10 --user admin --password pass on --port 3 5 7

# Turn OFF ALL outlets on a single PDU
enlogic_cli.py --host 10.0.0.10 --user admin --password pass off --all

# Lock / Unlock ports (super admin)
enlogic_cli.py --host 10.0.0.10 lock --port 3 5 --super-user super --super-password pass
enlogic_cli.py --host 10.0.0.10 unlock --all --super-user super --super-password pass

# Config via setup (writes to ~/.enlogic.ini)
enlogic_cli.py setup --user admin --password pass --https --secure
enlogic_cli.py setup --super-user superadmin --super-password '********'

# Nicknames from config and per-host PDU IDs
# INI:
# [hosts]   lab.pdu1 = 10.0.0.10
# [pduid]   lab.pdu1 = 2
enlogic_cli.py --host lab.pdu1 --user admin --password pass list

# Batch against many hosts (read-only listing showcase)
enlogic_cli.py --user u --password p --insecure batch --hosts 10.0.0.10 10.0.0.11 --json
"""

def examples_for(action: str) -> List[str]:
    prog = "enlogic_cli.py"
    mapping: Dict[str, List[str]] = {
        "list": [
            f"{prog} --host 10.0.0.10 list",
            f"{prog} --host myrack list --sort name",
            f"{prog} --host myrack list --format json",
            f"{prog} --host 10.0.0.10 --super-user su --super-password sp list --use-super",
        ],
        "get": [
            f"{prog} --host 10.0.0.10 get --port 8",
            f"{prog} --host 10.0.0.10 get --label PSU1",
            f"{prog} --host 10.0.0.10 get --port 8 --format json",
        ],
        "on": [
            f"{prog} --host 10.0.0.10 on --port 3 5 7",
            f"{prog} --host 10.0.0.10 on --all",
        ],
        "off": [
            f"{prog} --host 10.0.0.10 off --port 3 5 7",
            f"{prog} --host 10.0.0.10 off --all",
        ],
        "lock": [
            f"{prog} --host 10.0.0.10 lock --port 3 5 7 --super-user su --super-password sp",
            f"{prog} --host 10.0.0.10 lock --all --super-user su --super-password sp",
        ],
        "unlock": [
            f"{prog} --host 10.0.0.10 unlock --port 3 5 7 --super-user su --super-password sp",
            f"{prog} --host 10.0.0.10 unlock --all --super-user su --super-password sp",
        ],
        "batch": [
            f"{prog} --user u --password p --insecure batch --hosts 10.0.0.10 10.0.0.11 --json",
        ],
    }
    return mapping.get(action, [f"{prog} examples", f"{prog} readme"])

def action_descriptions() -> Dict[str, str]:
    return {
        "hosts": "Show host nicknames configured under [hosts] in the INI.",
        "setup": "Interactive config writer. Supports --super-user/--super-password to write [superadmin].",
        "examples": "Print common CLI examples.",
        "readme": "Print a short README for this CLI.",
        "list": "List outlets with Name, State, and Lock column. Use --use-super to list with super-admin creds. Formats: table/json/csv.",
        "get": "Show a single outlet by --port or by --label; includes Lock column. Formats: table/json/csv.",
        "on": "Turn outlet(s) ON (by --port ... or --all). After action, results are shown (table/json/csv).",
        "off": "Turn outlet(s) OFF (by --port ... or --all). After action, results are shown (table/json/csv).",
        "lock": "Lock outlet(s) (requires super-admin). Results shown in chosen format.",
        "unlock": "Unlock outlet(s) (requires super-admin). Results shown in chosen format.",
        "reboot": "Immediate reboot of a single --port. Results shown in chosen format.",
        "on_delay": "Turn ON with configured delay (single --port). Results shown in chosen format.",
        "off_delay": "Turn OFF with configured delay (single --port). Results shown in chosen format.",
        "reboot_delay": "Reboot with configured delay (single --port). Results shown in chosen format.",
        "batch": "Run a read-only listing across many PDUs in parallel. Formats: table/json/csv.",
    }
