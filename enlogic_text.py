# =========================================
# file: enlogic_text.py
# =========================================
from typing import Dict, List

EXAMPLES_TEXT = """        # Examples

enlogic_cli.py --config-help
enlogic_cli.py examples

# Validate configs
enlogic_cli.py validate
enlogic_cli.py validate --hosts rackA rackB 10.0.0.10 --format json --strict

# Show (combined list/get)
enlogic_cli.py --host 10.0.0.10 show
enlogic_cli.py --host 10.0.0.10 show --port 8
enlogic_cli.py --host 10.0.0.10 show --format json

# Legacy list/get
enlogic_cli.py --host 10.0.0.10 list
enlogic_cli.py --host 10.0.0.10 get --port 3

# Power control with retries
enlogic_cli.py --host 10.0.0.10 --user admin --password pass on  --port 3 5 --retry-ports 2 --retry-wait 0.5
enlogic_cli.py --host 10.0.0.10 --user admin --password pass off --all --retry-ports-once

# Lock/unlock with retries
enlogic_cli.py --host 10.0.0.10 --super-user super --super-password pass lock   --port 3 5 --retry-ports 3 --retry-wait 1.0
enlogic_cli.py --host 10.0.0.10 --super-user super --super-password pass unlock --all --format json --retry-ports-once

# Batch listing
enlogic_cli.py --user admin --password pass batch --hosts rackA 10.0.0.11 --format csv > /tmp/pdu-batch.csv
"""

def examples_for(action: str) -> list:
    prog = "enlogic_cli.py"
    mapping: Dict[str, list] = {
        "validate": [
            f"{prog} validate",
            f"{prog} validate --hosts rackA rackB 10.0.0.10",
            f"{prog} -c ~/.enlogic.ini validate --format json"
        ],
        "show": [
            f"{prog} --host 10.0.0.10 show",
            f"{prog} --host 10.0.0.10 show --port 8",
            f"{prog} --host 10.0.0.10 show --format json",
        ],
        "list": [
            f"{prog} --host 10.0.0.10 list",
            f"{prog} --host myrack list --sort name",
        ],
        "get": [
            f"{prog} --host 10.0.0.10 get --port 8",
            f"{prog} --host 10.0.0.10 get --label PSU1",
        ],
        "on": [
            f"{prog} --host 10.0.0.10 on --port 3 5 7",
            f"{prog} --host 10.0.0.10 on --port 3 5 --retry-ports 2 --retry-wait 0.5",
        ],
        "off": [
            f"{prog} --host 10.0.0.10 off --port 3 5 7",
            f"{prog} --host 10.0.0.10 off --all --retry-ports-once",
        ],
        "lock": [
            f"{prog} --host 10.0.0.10 lock --port 3 5 7 --super-user su --super-password sp",
            f"{prog} --host 10.0.0.10 lock --port 3 5 --retry-ports 2 --retry-wait 0.5 --super-user su --super-password sp",
        ],
        "unlock": [
            f"{prog} --host 10.0.0.10 unlock --port 3 5 7 --super-user su --super-password sp",
            f"{prog} --host 10.0.0.10 unlock --port 3 5 --retry-ports-once --super-user su --super-password sp",
        ],
        "batch": [
            f"{prog} --user u --password p --insecure batch --hosts rackA 10.0.0.11 --json",
        ],
    }
    return mapping.get(action, [f"{prog} examples"])

def action_descriptions() -> Dict[str, str]:
    return {
        "setup": "Interactive config writer. Adds/updates [superadmin], hosts_file, and defaults.",
        "examples": "Print common CLI examples.",
        "validate": "Validate main config and hosts file; report errors and suggestions.",
        "show": "Unified viewer: list all outlets or target one via --port/--label; includes Lock. Formats: table/json/csv.",
        "list": "List outlets with Name, State, Lock (legacy alias of show).",
        "get": "Get a single outlet by --port or --label (legacy alias of show).",
        "on": "Turn outlet(s) ON (by --port ... or --all). Formats: table/json/csv.",
        "off": "Turn outlet(s) OFF (by --port ... or --all). Formats: table/json/csv.",
        "lock": "Lock outlet(s) (requires super-admin). Formats: table/json/csv.",
        "unlock": "Unlock outlet(s) (requires super-admin). Formats: table/json/csv.",
        "reboot": "Immediate reboot of a single --port. Formats: table/json/csv.",
        "on_delay": "Turn ON with configured delay (single --port). Formats: table/json/csv.",
        "off_delay": "Turn OFF with configured delay (single --port). Formats: table/json/csv.",
        "reboot_delay": "Reboot with configured delay (single --port). Formats: table/json/csv.",
        "batch": "Run a read-only listing across many PDUs in parallel. Formats: table/json/csv.",
    }
