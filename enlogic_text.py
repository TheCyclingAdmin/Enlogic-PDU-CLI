from typing import Dict, List

EXAMPLES_TEXT = """        # Examples

# Show (lists all or single with --port/--label)
enlogic_cli --host 10.0.0.10 show
enlogic_cli --host 10.0.0.10 show --port 8 --format json

# Power control with retries
enlogic_cli --host 10.0.0.10 --user admin --password pass on  --port 3 5 --retry-ports 2 --retry-wait 0.5
enlogic_cli --host 10.0.0.10 --user admin --password pass off --all --retry-ports-once

# Lock/unlock with retries (super-admin)
enlogic_cli --host 10.0.0.10 --super-user super --super-password pass lock   --port 3 --retry-ports 3 --retry-wait 1
enlogic_cli --host 10.0.0.10 --super-user super --super-password pass unlock --all --format json

# Validate configs
enlogic_cli validate --format json --strict

# Setup interactively
enlogic_cli setup
"""

def examples_for(action: str) -> list:
    prog = "enlogic_cli"
    mapping: Dict[str, list] = {
        "help": [
            f"{prog} --help",
            f"{prog} help",
            f"{prog} help show",
        ],
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
        "reboot": [
            f"{prog} --host 10.0.0.10 reboot --port 8 --user admin --password pass",
        ],
        "setup": [
            f"{prog} setup",
        ],
    }
    return mapping.get(action, [f"{prog} --help"])

def action_descriptions() -> Dict[str, str]:
    return {
        "help": "Show help for the CLI or a specific action.",
        "setup": "Interactive config writer. Adds/updates [superadmin], hosts_file, and defaults.",
        "validate": "Validate main config and hosts file; report errors and suggestions.",
        "show": "List outlets (or target one via --port/--label) including Lock. Formats: table/json/csv.",
        "on": "Turn outlet(s) ON (by --port ... or --all). Formats: table/json/csv.",
        "off": "Turn outlet(s) OFF (by --port ... or --all). Formats: table/json/csv.",
        "lock": "Lock outlet(s) (requires super-admin). Formats: table/json/csv.",
        "unlock": "Unlock outlet(s) (requires super-admin). Formats: table/json/csv.",
        "reboot": "Immediate reboot of a single --port. Formats: table/json/csv.",
        "on_delay": "Turn ON with configured delay (single --port). Formats: table/json/csv.",
        "off_delay": "Turn OFF with configured delay (single --port). Formats: table/json/csv.",
        "reboot_delay": "Reboot with configured delay (single --port). Formats: table/json/csv.",
    }
