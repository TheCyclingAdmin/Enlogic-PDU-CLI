# =========================================
# file: enlogic_cli.py
# =========================================
#!/usr/bin/env python3
"""
Entrypoint: argument parsing, help/readme/examples wiring, and action dispatch.
Compatible with Python 3.9+ (RHEL 8/9, Ubuntu 22.04/24.04).
"""

from __future__ import annotations

import argparse
import sys
from typing import Optional

from requests.auth import HTTPBasicAuth

import enlogic_core as core
import enlogic_text as text

# ---- Helpers ----
def _prog() -> str:
    return "enlogic_cli.py"

def _combine_tls_flags(insecure: Optional[bool], secure: Optional[bool]) -> Optional[bool]:
    if insecure is None and secure is None: return None
    if insecure and secure: return None
    return True if insecure else False if secure else None

def _combine_scheme_flags(http: Optional[bool], https: Optional[bool]) -> Optional[bool]:
    if http is None and https is None: return None
    if http and https: return None
    return True if http else False if https else None

# ---- Parsers ----
def build_global_parser() -> argparse.ArgumentParser:
    desc_lines = [
        "Enlogic PDU CLI — globals first, then action.",
        "",
        "Actions:",
    ]
    for k, v in text.action_descriptions().items():
        desc_lines.append(f"  {k:12s} {v}")
    desc_lines.append("")
    desc_lines.append("Tip: run 'examples' and 'readme' for usage.")
    p = argparse.ArgumentParser(
        add_help=True,
        allow_abbrev=False,
        description="\n".join(desc_lines),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    p.add_argument("-c","--config", help=f"Config file (default: {core.DEFAULT_CFG} if present)")
    p.add_argument("-H","--host", help="Target host (IP or DNS). May be a nickname defined in [hosts].")
    p.add_argument("-u","--user", help="Username (falls back to [auth] user)")
    p.add_argument("-P","--password", help="Password (falls back to [auth] password)")
    p.add_argument("--super-user", dest="super_user", help="Super admin user (falls back to [superadmin] user)")
    p.add_argument("--super-password", dest="super_password", help="Super admin password (falls back to [superadmin] password)")
    p.add_argument("-k","--insecure", action="store_true", default=None, help="Skip TLS verification")
    p.add_argument("--secure", dest="secure", action="store_true", default=None, help="Verify TLS")
    p.add_argument("-x","--http", action="store_true", default=None, help="Use HTTP instead of HTTPS")
    p.add_argument("--https", dest="https", action="store_true", default=None, help="Force HTTPS (default)")
    p.add_argument("-d","--pduid", type=int, help="PDU ID override (falls back to [defaults] pduid)")
    p.add_argument("--low-bank-max", type=int, help="Outlet1 bank size (default 24; second bank beyond this)")
    p.add_argument("--timeout", type=float, help=f"HTTP timeout seconds (default {core.DEFAULT_TIMEOUT})")
    p.add_argument("--retries", type=int, help=f"HTTP retries (default {core.DEFAULT_RETRIES})")
    p.add_argument("--backoff", type=float, help=f"HTTP backoff factor (default {core.DEFAULT_BACKOFF})")
    p.add_argument("--parallel", type=int, help=f"Batch parallelism (default {core.DEFAULT_PARALLEL})")
    p.add_argument("--debug", action="store_true", help="Verbose debug to stderr")
    p.add_argument("--config-help", action="store_true", help="Print INI config help and exit")
    p.add_argument("--csv-header", choices=["never","auto","always"], default="auto",
                   help="CSV header policy: never write, auto-detect (default), or always write before rows")
    p.add_argument("--format", choices=["table","json","csv"], default="table",
                   help="Output format for commands that support it (table/json/csv). CSV is written to stdout; --csv-header applies.")
    p.add_argument("action", nargs="?", choices=list(text.action_descriptions().keys()), help="Command to run")
    return p

def build_action_parser(action: str) -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog=f"{_prog()} {action}", add_help=True, allow_abbrev=False,
                                 description=text.action_descriptions().get(action, action),
                                 formatter_class=argparse.RawTextHelpFormatter)
    if action in ("hosts","setup","examples","readme"):
        pass
    elif action == "list":
        ap.add_argument("--sort", choices=["outlet","name"], default="outlet", help="Sort by outlet number or name")
        ap.add_argument("--no-color", action="store_true", help="Disable color in table output")
        ap.add_argument("--csv", help="(Optional) Also append table rows to this CSV path")
        ap.add_argument("--use-super", action="store_true", help="Use super-admin creds for listing (ensures lock visibility)")
    elif action == "get":
        ap.add_argument("--port", type=int, help="Outlet number")
        ap.add_argument("--label", help="Exact outlet label to match")
        ap.add_argument("--no-color", action="store_true", help="Disable color in table output")
        ap.add_argument("--csv", help="(Optional) Also append selected outlet row to this CSV path")
        ap.add_argument("--use-super", action="store_true", help="Use super-admin creds for GET (ensures lock visibility)")
    elif action in ("on","off","lock","unlock"):
        mx = ap.add_mutually_exclusive_group(required=True)
        mx.add_argument("--port", nargs="+", type=int, help="One or more outlet numbers")
        mx.add_argument("--all", action="store_true", help="Operate on ALL outlets")
        ap.add_argument("--sort", choices=["outlet","name"], default="outlet", help="Sort when showing result table")
        ap.add_argument("--no-color", action="store_true", help="Disable color in table output")
        ap.add_argument("--csv", help="(Optional) Also append resulting table rows to this CSV path")
    elif action in ("reboot","on_delay","off_delay","reboot_delay"):
        ap.add_argument("--port", type=int, required=True, help="Single outlet to operate on")
        ap.add_argument("--no-color", action="store_true", help="Disable color in table output")
        ap.add_argument("--csv", help="(Optional) Also append selected outlet row to this CSV path")
    elif action == "batch":
        ap.add_argument("--hosts", nargs="+", required=True, help="List of hosts to act on")
        ap.add_argument("--no-color", action="store_true", help="Disable color in table output")
    return ap

# ---- Dispatch ----
def main() -> None:
    gparser = build_global_parser()
    raw = sys.argv[1:]
    if not raw:
        gparser.print_help(); sys.exit(0)

    # Split globals vs action args
    try:
        idx = next(i for i,a in enumerate(raw) if not a.startswith("-"))
        global_argv, rest = raw[:idx], raw[idx+1:]
        action = raw[idx]
    except StopIteration:
        global_argv, rest, action = raw, [], None

    gargs = gparser.parse_args(global_argv)
    if gargs.config_help:
        print(text.CONFIG_HELP); sys.exit(0)
    if not action:
        gparser.print_help(); sys.exit(0)

    aparser = build_action_parser(action)
    aargs = aparser.parse_args(rest)

    # Build config + defaults
    cfg = core.AppConfig(gargs.config)
    d = cfg.defaults()
    insecure_flag = d.insecure if _combine_tls_flags(gargs.insecure, gargs.secure) is None else bool(gargs.insecure)
    scheme_http = d.http if _combine_scheme_flags(gargs.http, gargs.https) is None else bool(gargs.http)
    low_bank_max = gargs.low_bank_max if gargs.low_bank_max is not None else d.low_bank_max
    timeout = gargs.timeout if gargs.timeout is not None else d.timeout
    retries = gargs.retries if gargs.retries is not None else d.retries
    backoff = gargs.backoff if gargs.backoff is not None else d.backoff

    # Simple actions
    if action == "examples":
        print(text.EXAMPLES_TEXT); sys.exit(0)
    if action == "readme":
        print(text.README_TEXT); sys.exit(0)
    if action == "hosts":
        hmap = cfg.hosts_map()
        if not hmap: print("No hosts configured in [hosts]."); sys.exit(0)
        width = max(len(k) for k in hmap)
        for k,v in sorted(hmap.items()): print(f"{k.ljust(width)} -> {v}")
        sys.exit(0)
    if action == "setup":
        # Interactive; write [auth]/[defaults] and optionally [superadmin]
        cur = cfg.cfg
        cur_user = cur.get("auth","user", fallback="")
        user = gargs.user or (input(f"Username [{cur_user}]: ") or cur_user)
        pw = gargs.password or (input("Password: ") if not cur.get("auth","password", fallback="") else cur.get("auth","password"))
        http = scheme_http
        insecure = insecure_flag
        core.write_config(cfg.path, user=user, password=pw, http=http, insecure=insecure)
        if gargs.super_user and gargs.super_password:
            core.write_super_to_config(cfg.path, gargs.super_user, gargs.super_password)
        print(f"Wrote config: {cfg.path}")
        print(text.CONFIG_HELP)
        sys.exit(0)

    # Actions requiring host
    if not gargs.host:
        print("Error: --host is required for this action.")
        ex = text.examples_for(action)
        if ex:
            print("\nExamples:")
            for e in ex: print(f"  {e}")
        sys.exit(2)

    # Resolve host & base URL
    host_ip, _ = cfg.resolve_host_label(gargs.host)
    pduid_lookup = cfg.pduid_map().get(gargs.host) or cfg.pduid_map().get(host_ip)
    pduid = gargs.pduid if gargs.pduid is not None else (pduid_lookup or d.pduid)
    base = f"{'http' if scheme_http else 'https'}://{host_ip}"
    client = core.PDUClient(base, insecure=insecure_flag, timeout=timeout, retries=retries, backoff=backoff, debug=gargs.debug)

    # Auth (normal and super)
    user, pw = cfg.get_auth(gargs.user, gargs.password)
    su, sp = cfg.get_super_auth(gargs.super_user, gargs.super_password)

    # Determine output format
    out_format = gargs.format

    # Dispatch
    if action == "list":
        if not (user and pw) and not (su and sp and getattr(aargs, "use_super", False)):
            print("Error: provide --user/--password or add [auth] to config; or --use-super with super creds.")
            sys.exit(2)
        # choose auth (super when requested)
        if getattr(aargs, "use_super", False) and su and sp:
            auth = HTTPBasicAuth(su, sp)
        else:
            auth = HTTPBasicAuth(user or "", pw or "")
        core.list_action(gargs.host, pduid, base, client, auth, sort=aargs.sort, out_format=out_format, no_color=aargs.no_color,
                         csv_path=getattr(aargs, "csv", None), csv_header=gargs.csv_header)
        sys.exit(0)

    if action == "get":
        # choose auth (super when requested)
        if getattr(aargs, "use_super", False):
            if not (su and sp):
                print("Error: --use-super requires --super-user/--super-password (or [superadmin])."); sys.exit(2)
            auth = HTTPBasicAuth(su, sp)
        else:
            if not (user and pw):
                print("Error: provide --user/--password or add [auth] to config."); sys.exit(2)
            auth = HTTPBasicAuth(user, pw)
        core.get_action(aargs.port, aargs.label, gargs.host, pduid, base, client, auth,
                        out_format=out_format, no_color=aargs.no_color, csv_path=getattr(aargs, "csv", None), csv_header=gargs.csv_header)
        sys.exit(0)

    if action in ("on","off"):
        if not user or not pw: print("Error: provide --user/--password or add [auth] to config."); sys.exit(2)
        auth = HTTPBasicAuth(user, pw)
        act = core.PowerAction.ON if action=="on" else core.PowerAction.OFF
        ports = aargs.port or []
        core.on_off_action(act, ports, aargs.all, gargs.host, base, pduid, client, user, pw, auth, low_bank_max,
                           sort=aargs.sort, out_format=out_format, no_color=aargs.no_color,
                           csv_path=getattr(aargs, "csv", None), csv_header=gargs.csv_header)
        sys.exit(0)

    if action in ("lock","unlock"):
        # Prefer superadmin if available; else error
        su_user = su
        su_pw = sp
        if not su_user or not su_pw:
            print("Error: super admin credentials missing. Add [superadmin] user/password to config or pass via --super-user/--super-password.")
            sys.exit(2)
        auth = HTTPBasicAuth(su_user, su_pw)
        core.lock_unlock_action(locked=(action=="lock"), ports=aargs.port or [], all_flag=aargs.all,
                                host=gargs.host, base=base, pduid=pduid, client=client, auth_basic=auth,
                                sort=aargs.sort, out_format=out_format, no_color=aargs.no_color,
                                csv_path=getattr(aargs, "csv", None), csv_header=gargs.csv_header)
        sys.exit(0)

    if action in ("reboot","on_delay","off_delay","reboot_delay"):
        if not user or not pw: print("Error: provide --user/--password or add [auth] to config."); sys.exit(2)
        auth = HTTPBasicAuth(user, pw)
        m = {
            "reboot": core.PowerAction.REBOOT,
            "on_delay": core.PowerAction.ON_DELAY,
            "off_delay": core.PowerAction.OFF_DELAY,
            "reboot_delay": core.PowerAction.REBOOT_DELAY,
        }
        core.on_off_action(m[action], [aargs.port], False, gargs.host, base, pduid, client, user, pw, auth, low_bank_max,
                           sort="outlet", out_format=out_format, no_color=aargs.no_color,
                           csv_path=getattr(aargs, "csv", None), csv_header=gargs.csv_header)
        sys.exit(0)

    if action == "batch":
        if not user or not pw: print("Error: provide --user/--password or add [auth] to config."); sys.exit(2)
        build_params = dict(
            user=user, password=pw, http=scheme_http, insecure=insecure_flag, timeout=timeout, retries=retries,
            backoff=backoff, debug=gargs.debug, parallel=(gargs.parallel or core.DEFAULT_PARALLEL), pduid=gargs.pduid
        )
        core.batch_list(aargs.hosts, build_params, cfg, out_format=out_format, json_out=(out_format=="json"), no_color=aargs.no_color)
        sys.exit(0)

    # Fallback
    print("Unknown action.")
    sys.exit(2)

if __name__ == "__main__":
    main()
