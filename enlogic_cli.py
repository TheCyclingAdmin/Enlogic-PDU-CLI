#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, os, sys
from typing import Optional
from requests.auth import HTTPBasicAuth
import enlogic_core as core
import enlogic_text as text
import enlogic_errors as err

def _prog() -> str: return "enlogic_cli"

def _combine_tls_flags(insecure: Optional[bool], secure: Optional[bool]) -> Optional[bool]:
    if insecure is None and secure is None: return None
    if insecure and secure: return None
    return True if insecure else False if secure else None

def _combine_scheme_flags(http: Optional[bool], https: Optional[bool]) -> Optional[bool]:
    if http is None and https is None: return None
    if http and https: return None
    return True if http else False if https else None

def build_global_parser() -> argparse.ArgumentParser:
    desc_lines = ["Enlogic PDU CLI — globals first, then action.", "", "Actions:"]
    for k, v in text.action_descriptions().items():
        desc_lines.append(f"  {k:12s} {v}")
    desc_lines.append("")
    desc_lines.append("Tip: run '--help' or 'help' for usage.")
    p = argparse.ArgumentParser(add_help=True, allow_abbrev=False,
                                description="\n".join(desc_lines),
                                formatter_class=argparse.RawTextHelpFormatter)
    p.add_argument("-c","--config", help=f"Config file (default: {core.DEFAULT_CFG} if present)")
    p.add_argument("-H","--host", help="Target host (IP or DNS). May be a nickname resolved from hosts_file.")
    p.add_argument("-u","--user", help="Username (falls back to [auth] user)")
    p.add_argument("-P","--password", help="Password (falls back to [auth] password)")
    p.add_argument("--super-user", dest="super_user", help="Super admin user (falls back to [superadmin] user)")
    p.add_argument("--super-password", dest="super_password", help="Super admin password (falls back to [superadmin] password)")
    p.add_argument("-k","--insecure", action="store_true", default=None, help="Skip TLS verification")
    p.add_argument("--secure", dest="secure", action="store_true", default=None, help="Verify TLS")
    p.add_argument("-x","--http", action="store_true", default=None, help="Use HTTP instead of HTTPS")
    p.add_argument("--https", dest="https", action="store_true", default=None, help="Force HTTPS (default)")
    p.add_argument("-d","--pduid", type=int, help="PDU ID override (falls back to [defaults] pduid)")
    p.add_argument("--low-bank-max", type=int, help="Manual bank1 size (auto-detected by default)")
    p.add_argument("--timeout", type=float, help=f"HTTP timeout seconds (default {core.DEFAULT_TIMEOUT})")
    p.add_argument("--retries", type=int, help=f"HTTP retries (default {core.DEFAULT_RETRIES})")
    p.add_argument("--backoff", type=float, help=f"HTTP backoff factor (default {core.DEFAULT_BACKOFF})")
    p.add_argument("--debug", action="store_true", help="Verbose debug to stderr")
    p.add_argument("--config-help", action="store_true", help="Print INI config help and exit")
    p.add_argument("--csv-header", choices=["never","auto","always"], default="auto",
                   help="CSV header policy: never write, auto-detect (default), or always write before rows")
    p.add_argument("--format", choices=["table","json","csv"], default="table",
                   help="Output format (table/json/csv). CSV writes to stdout; --csv-header applies.")
    p.add_argument("action", nargs="?", choices=list(text.action_descriptions().keys()), help="Command to run")
    return p

def build_action_parser(action: str) -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog=f"{_prog()} {action}", add_help=True, allow_abbrev=False,
                                 description=text.action_descriptions().get(action, action),
                                 formatter_class=argparse.RawTextHelpFormatter)
    add_format = lambda p: p.add_argument("--format", choices=["table","json","csv"], help="Output format override for this action")
    if action in ("setup","validate","help"):
        if action == "validate":
            ap.add_argument("--hosts", nargs="*", help="Optional list of hosts/nicknames to verify resolution")
            ap.add_argument("--strict", action="store_true", help="Treat warnings as errors (non-zero exit)")
            ap.add_argument("--no-color", action="store_true", help="Disable color in table output")
            add_format(ap)
        elif action == "help":
            ap.add_argument("topic", nargs="?", help="Optional command to show help for")
    elif action in ("show",):
        ap.add_argument("--sort", choices=["outlet","name"], default="outlet", help="Sort by outlet number or name")
        ap.add_argument("--no-color", action="store_true", help="Disable color in table output")
        ap.add_argument("--csv", help="(Optional) Also append table rows to this CSV path")
        ap.add_argument("--port", type=int, help="Target a single outlet by number")
        ap.add_argument("--label", help="Target a single outlet by exact label")
        ap.add_argument("--use-super", action="store_true", help="Force super-admin creds for reading")
        ap.add_argument("--no-super", action="store_true", help="Force normal creds for reading (override defaults)")
        add_format(ap)
    elif action in ("on","off","lock","unlock"):
        mx = ap.add_mutually_exclusive_group(required=True)
        mx.add_argument("--port", nargs="+", type=int, help="One or more outlet numbers")
        mx.add_argument("--all", action="store_true", help="Operate on ALL outlets")
        ap.add_argument("--sort", choices=["outlet","name"], default="outlet", help="Sort when showing result table")
        ap.add_argument("--no-color", action="store_true", help="Disable color in table output")
        ap.add_argument("--csv", help="(Optional) Also append resulting table rows to this CSV path")
        ap.add_argument("--retry-ports", type=int, default=0, help="Retry failed ports up to N times")
        ap.add_argument("--retry-ports-once", action="store_true", help="Retry failed ports once (compat)")
        ap.add_argument("--retry-wait", type=float, default=0.0, help="Seconds to wait between retries")
        add_format(ap)
    elif action in ("reboot","on_delay","off_delay","reboot_delay"):
        ap.add_argument("--port", type=int, required=True, help="Single outlet to operate on")
        ap.add_argument("--no-color", action="store_true", help="Disable color in table output")
        ap.add_argument("--csv", help="(Optional) Also append selected outlet row to this CSV path")
        ap.add_argument("--retry-ports", type=int, default=0, help="Retry failed operation up to N times")
        ap.add_argument("--retry-ports-once", action="store_true", help="Retry failed operation once (compat)")
        ap.add_argument("--retry-wait", type=float, default=0.0, help="Seconds to wait between retries")
        add_format(ap)
    return ap

def main() -> None:
    gparser = build_global_parser()
    raw = sys.argv[1:]
    if not raw:
        gparser.print_help(); err.exit_with(err.ExitCode.OK)

    actions = set(text.action_descriptions().keys())
    idx = next((i for i, a in enumerate(raw) if a in actions), None)
    if idx is None:
        global_argv, rest, action = raw, [], None
    else:
        global_argv, rest, action = raw[:idx], raw[idx+1:], raw[idx]

    gargs = gparser.parse_args(global_argv)
    if gargs.config_help:
        print("""        Config file (INI). Default: ~/.enlogic.ini

[auth]
user = <username>
password = <password>

[superadmin]
user = <super username>
password = <super password>

[defaults]
http = false
insecure = false
pduid = 1
low_bank_max = 24
auto_bank = true
hosts_file = ~/.enlogic-hosts.ini
use_super_for_read = true
timeout = 10.0
retries = 3
backoff = 0.5

[pduid]
# rackA = 2
""")
        err.exit_with(err.ExitCode.OK)
    if not action:
        gparser.print_help(); err.exit_with(err.ExitCode.OK)

    if action == "help":
        sub = rest[0] if rest else None
        if not sub:
            gparser.print_help(); err.exit_with(err.ExitCode.OK)
        else:
            aparser = build_action_parser(sub)
            aparser.print_help(); err.exit_with(err.ExitCode.OK)

    aparser = build_action_parser(action)
    aargs = aparser.parse_args(rest)

    if action == "validate":
        from configparser import NoSectionError, NoOptionError
        cfg = core.AppConfig(gargs.config)
        issues = []
        def add_issue(comp, field, level, message, suggest):
            issues.append({"component": comp, "field": field, "level": level, "message": message, "suggest": suggest})

        if not os.path.exists(cfg.path):
            add_issue("config", "path", "error", f"Config not found: {cfg.path}",
                      "Copy enlogic.ini.sample to ~/.enlogic.ini or run `enlogic_cli setup`.")
        else:
            user = cfg.cfg.get("auth","user", fallback="")
            pw = cfg.cfg.get("auth","password", fallback="")
            if not user:
                add_issue("config", "[auth].user", "error", "Missing username", "Run `enlogic_cli setup` or set [auth].user.")
            if not pw:
                add_issue("config", "[auth].password", "error", "Missing password", "Run `enlogic_cli setup` or set [auth].password (chmod 600).")

            def _check_bool(opt):
                try: cfg.cfg.getboolean("defaults", opt)
                except (ValueError, NoOptionError, NoSectionError):
                    val = cfg.cfg.get("defaults", opt, fallback="<missing>")
                    add_issue("config", f"[defaults].{opt}", "warning", f"Invalid/missing boolean: {val}",
                              f"Use true/false; run `enlogic_cli setup` to set {opt}.")
            def _check_int(opt, minval=0):
                try:
                    v = cfg.cfg.getint("defaults", opt)
                    if v < minval:
                        add_issue("config", f"[defaults].{opt}", "warning", f"Value {v} < {minval}", f"Increase {opt} to >= {minval}.")
                except (ValueError, NoOptionError, NoSectionError):
                    val = cfg.cfg.get("defaults", opt, fallback="<missing>")
                    add_issue("config", f"[defaults].{opt}", "warning", f"Invalid/missing int: {val}", f"Set a valid integer via `enlogic_cli setup`.")
            _check_bool("http"); _check_bool("insecure"); _check_bool("auto_bank"); _check_bool("use_super_for_read")
            _check_int("pduid", 1); _check_int("low_bank_max", 1); _check_int("retries", 0)
            try:
                v = cfg.cfg.getfloat("defaults","timeout"); 
                if v <= 0: add_issue("config", "[defaults].timeout", "warning", f"Timeout {v} <= 0", "Use a positive timeout.")
            except Exception:
                add_issue("config", "[defaults].timeout", "warning", "Invalid/missing float", "Set with `enlogic_cli setup`.")
            try:
                v = cfg.cfg.getfloat("defaults","backoff"); 
                if v < 0: add_issue("config", "[defaults].backoff", "warning", f"Backoff {v} < 0", "Use a non-negative backoff.")
            except Exception:
                add_issue("config", "[defaults].backoff", "warning", "Invalid/missing float", "Set with `enlogic_cli setup`.")

            hosts_file = cfg.cfg.get("defaults","hosts_file", fallback=core.DEFAULT_HOSTS_FILE)
            hf_expanded = os.path.expanduser(hosts_file)
            if not os.path.exists(hf_expanded):
                add_issue("hosts", "hosts_file", "warning", f"Hosts file missing: {hf_expanded}",
                          "Copy enlogic-hosts.sample.ini to ~/.enlogic-hosts.ini or update hosts_file path.")
            else:
                hmap = cfg.hosts_map()
                if not hmap:
                    add_issue("hosts", "[hosts]", "warning", "No host nicknames found", "Add entries under [hosts] in the hosts file.")

            try:
                use_s = cfg.cfg.getboolean("defaults","use_super_for_read")
            except Exception:
                use_s = False
            su = cfg.cfg.get("superadmin","user", fallback="")
            sp = cfg.cfg.get("superadmin","password", fallback="")
            if use_s and (not su or not sp):
                add_issue("config", "[superadmin]", "warning",
                          "use_super_for_read=true but superadmin credentials are missing",
                          "Run `enlogic_cli setup` and add super-admin credentials.")

        thosts = getattr(aargs, "hosts", None) or []
        if thosts:
            hmap = cfg.hosts_map()
            import re as _re
            ip_re = _re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
            for h in thosts:
                if h in hmap: continue
                if "." not in h and not ip_re.match(h):
                    issues.append({"component":"hosts","field":h,"level":"warning",
                                   "message":"Not found in hosts file; treating as literal host",
                                   "suggest":"Add it under [hosts] or use the IP/FQDN directly."})

        out_format = getattr(aargs, "format", None) or gargs.format
        if out_format == "json":
            print(json.dumps({"ok": not any(i["level"]=="error" for i in issues),
                              "strict": bool(getattr(aargs, "strict", False)),
                              "issues": issues}, indent=2))
        else:
            print("\nValidation report\n")
            print("Component | Field              | Level   | Message                                     | Suggestion")
            print("----------+--------------------+---------+---------------------------------------------+------------------------------")
            if not issues:
                print("config    | all                | ok      | No issues detected                           | -")
            else:
                for i in issues:
                    comp = f"{i['component']:<9}"
                    field = f"{i['field']:<18}"
                    level = f"{i['level']:<7}"
                    msg = f"{i['message']:<43}"
                    sug = f"{i['suggest']:<28}"
                    print(f"{comp} | {field} | {level} | {msg} | {sug}")
            print()

        if issues and getattr(aargs,"strict", False): err.exit_with(err.ExitCode.CONFIG)
        if any(i["level"]=="error" for i in issues): err.exit_with(err.ExitCode.CONFIG)
        err.exit_with(err.ExitCode.OK)

    # Build config + defaults for other actions
    dcfg = core.AppConfig(gargs.config)
    d = dcfg.defaults()
    insecure_flag = d.insecure if _combine_tls_flags(gargs.insecure, gargs.secure) is None else bool(gargs.insecure)
    scheme_http = d.http if _combine_scheme_flags(gargs.http, gargs.https) is None else bool(gargs.http)
    timeout = gargs.timeout if gargs.timeout is not None else d.timeout
    retries = gargs.retries if gargs.retries is not None else d.retries
    backoff = gargs.backoff if gargs.backoff is not None else d.backoff

    if action == "setup":
        import getpass
        cur = dcfg.cfg
        cur_user = cur.get("auth","user", fallback="")
        user = gargs.user or (input(f"Username [{cur_user}]: ") or cur_user)
        if gargs.password:
            pw = gargs.password
        else:
            existing_pw = cur.get("auth","password", fallback="")
            prompt = "Password (leave blank to keep existing): " if existing_pw else "Password: "
            pw = getpass.getpass(prompt)
            if not pw and existing_pw: pw = existing_pw
        def _ask_bool(prompt, default):
            ans = input(f"{prompt} [{'Y/n' if default else 'y/N'}]: ").strip().lower()
            if ans in ("y","yes"): return True
            if ans in ("n","no"): return False
            return default
        http = _ask_bool("Default to HTTP (not HTTPS)?", d.http)
        insecure = _ask_bool("Skip TLS verification by default?", d.insecure)
        try:
            def_pduid = int(input(f"Default PDU ID [{d.pduid}]: ") or d.pduid)
        except Exception:
            def_pduid = d.pduid
        auto_bank = _ask_bool("Auto-detect bank split (LOW_BANK_MAX) from device?", d.auto_bank)
        try:
            lbm_in = input(f"Manual low_bank_max (used when auto_bank=false) [{d.low_bank_max}]: ").strip()
            def_lbm = int(lbm_in) if lbm_in else d.low_bank_max
        except Exception:
            def_lbm = d.low_bank_max
        hosts_file = input(f"Hosts file path [{d.hosts_file}]: ").strip() or d.hosts_file
        use_super_for_read = _ask_bool("Prefer super-admin for read/list/show by default?", d.use_super_for_read)
        core.write_config(dcfg.path, user=user, password=pw, http=http, insecure=insecure,
                          pduid=def_pduid, low_bank_max=def_lbm, auto_bank=auto_bank,
                          hosts_file=os.path.expanduser(hosts_file), use_super_for_read=use_super_for_read)
        su_user = cur.get("superadmin","user", fallback="")
        su_pass = cur.get("superadmin","password", fallback="")
        resp = input("Configure super-admin now? [y/N]: ").strip().lower()
        if resp == "y":
            su_user_in = input(f"Super-admin user [{su_user}]: ") or su_user
            su_pass_in = getpass.getpass("Super-admin password (blank=keep existing): ") or su_pass
            core.write_super_to_config(dcfg.path, su_user_in, su_pass_in)
        print(f"Wrote config: {dcfg.path}")
        err.exit_with(err.ExitCode.OK)

    if not gargs.host:
        print("Error: --host is required for this action.")
        ex = text.examples_for(action)
        if ex:
            print("\nExamples:"); [print(f"  {e}") for e in ex]
        err.exit_with(err.ExitCode.USAGE)

    host_ip, _ = dcfg.resolve_host_label(gargs.host)
    pduid_lookup = dcfg.pduid_map().get(gargs.host) or dcfg.pduid_map().get(host_ip)
    pduid = gargs.pduid if gargs.pduid is not None else (pduid_lookup or d.pduid)
    base = f"{'http' if scheme_http else 'https'}://{host_ip}"
    client = core.PDUClient(base, insecure=insecure_flag, timeout=timeout, retries=retries, backoff=backoff, debug=gargs.debug)

    user, pw = dcfg.get_auth(gargs.user, gargs.password)
    su, sp = dcfg.get_super_auth(gargs.super_user, gargs.super_password)
    out_format = getattr(aargs, "format", None) or gargs.format

    def pick_read_auth(force_super: bool, force_no_super: bool) -> HTTPBasicAuth:
        if force_super and su and sp: return HTTPBasicAuth(su, sp)
        if force_no_super and user and pw: return HTTPBasicAuth(user, pw)
        if d.use_super_for_read and su and sp: return HTTPBasicAuth(su, sp)
        if user and pw: return HTTPBasicAuth(user, pw)
        return HTTPBasicAuth(user or "", pw or "")

    try:
        if action in ("show",):
            auth = pick_read_auth(force_super=getattr(aargs, "use_super", False),
                                  force_no_super=getattr(aargs, "no_super", False))
            if aargs.port or aargs.label:
                core.get_action(aargs.port, aargs.label, gargs.host, pduid, base, client, auth,
                                out_format=out_format, no_color=aargs.no_color, csv_path=getattr(aargs, "csv", None), csv_header=gargs.csv_header)
            else:
                core.list_action(gargs.host, pduid, base, client, auth, sort=aargs.sort, out_format=out_format, no_color=aargs.no_color,
                                 csv_path=getattr(aargs, "csv", None), csv_header=gargs.csv_header)
            err.exit_with(err.ExitCode.OK)

        if action in ("on","off"):
            if not user or not pw: print("Error: provide --user/--password or add [auth] to config."); err.exit_with(err.ExitCode.CONFIG)
            auth = HTTPBasicAuth(user, pw)
            act = core.PowerAction.ON if action=="on" else core.PowerAction.OFF
            ports = aargs.port or []
            if gargs.low_bank_max is not None:
                eff_lbm = gargs.low_bank_max
            elif d.auto_bank:
                eff_lbm = client.detect_low_bank_max(pduid, auth, d.low_bank_max)
            else:
                eff_lbm = d.low_bank_max
            label, rows, results = core.execute_on_off(act, ports, aargs.all, gargs.host, base, pduid, client, user, pw, auth, eff_lbm, sort=aargs.sort,
                                                       retry_once=getattr(aargs, "retry_ports_once", False), retry_count=(aargs.retry_ports or 0), retry_wait=getattr(aargs, "retry_wait", 0.0))
            date_str, time_str = core.now_date_time()
            payload = {"ok": all(r.get("ok") for r in results), "action": act.value, "date": date_str, "time": time_str,
                       "host": gargs.host, "pdu": label, "base": base, "ports": results,
                       "outlets": [{"n": n, "name": nm, "state": st, "lock": (True if lk else False if lk is not None else None)} for (n,nm,st,lk) in rows]}
            core._emit_by_format(out_format, f"PDU: {label}  ({base})", base, label, rows, act.value,
                                 getattr(aargs, "csv", None), gargs.csv_header, core.isatty_color(not aargs.no_color), payload)
            succ = sum(1 for r in results if r.get("ok")); fail = sum(1 for r in results if not r.get("ok"))
            if fail == 0: err.exit_with(err.ExitCode.OK)
            elif succ > 0: err.exit_with(err.ExitCode.PARTIAL, "partial: some outlets failed")
            else: err.exit_with(err.ExitCode.DEVICE, "failed: no outlets changed")

        if action in ("lock","unlock"):
            if not su or not sp:
                print("Error: super admin credentials missing. Add [superadmin] to config or pass --super-user/--super-password.")
                err.exit_with(err.ExitCode.AUTH)
            auth = HTTPBasicAuth(su, sp)
            label, rows, results = core.execute_lock_unlock(locked=(action=="lock"), ports=aargs.port or [], all_flag=aargs.all,
                                                            host=gargs.host, base=base, pduid=pduid, client=client, auth_basic=auth, sort=aargs.sort,
                                                            retry_once=getattr(aargs, "retry_ports_once", False), retry_count=(aargs.retry_ports or 0), retry_wait=getattr(aargs, "retry_wait", 0.0))
            date_str, time_str = core.now_date_time()
            actname = "lock" if action=="lock" else "unlock"
            payload = {"ok": all(r.get("ok") for r in results), "action": actname, "date": date_str, "time": time_str,
                       "host": gargs.host, "pdu": label, "base": base, "ports": results,
                       "outlets": [{"n": n, "name": nm, "state": st, "lock": (True if lk else False if lk is not None else None)} for (n,nm,st,lk) in rows]}
            core._emit_by_format(out_format, f"PDU: {label}  ({base})", base, label, rows, actname,
                                 getattr(aargs, "csv", None), gargs.csv_header, core.isatty_color(not aargs.no_color), payload)
            succ = sum(1 for r in results if r.get("ok")); fail = sum(1 for r in results if not r.get("ok"))
            if fail == 0: err.exit_with(err.ExitCode.OK)
            elif succ > 0: err.exit_with(err.ExitCode.PARTIAL, "partial: some locks failed")
            else: err.exit_with(err.ExitCode.DEVICE, "failed: no locks changed")

        if action in ("reboot","on_delay","off_delay","reboot_delay"):
            if not user or not pw: print("Error: provide --user/--password or add [auth] to config."); err.exit_with(err.ExitCode.CONFIG)
            auth = HTTPBasicAuth(user, pw)
            m = {
                "reboot": core.PowerAction.REBOOT,
                "on_delay": core.PowerAction.ON_DELAY,
                "off_delay": core.PowerAction.OFF_DELAY,
                "reboot_delay": core.PowerAction.REBOOT_DELAY,
            }
            if gargs.low_bank_max is not None:
                eff_lbm = gargs.low_bank_max
            elif d.auto_bank:
                eff_lbm = client.detect_low_bank_max(pduid, auth, d.low_bank_max)
            else:
                eff_lbm = d.low_bank_max
            label, rows, results = core.execute_on_off(m[action], [aargs.port], False, gargs.host, base, pduid, client, user, pw, auth, eff_lbm, sort="outlet",
                                                       retry_once=getattr(aargs, "retry_ports_once", False), retry_count=(aargs.retry_ports or 0), retry_wait=getattr(aargs, "retry_wait", 0.0))
            date_str, time_str = core.now_date_time()
            payload = {"ok": all(r.get("ok") for r in results), "action": m[action].value, "date": date_str, "time": time_str,
                       "host": gargs.host, "pdu": label, "base": base, "ports": results,
                       "outlets": [{"n": n, "name": nm, "state": st, "lock": (True if lk else False if lk is not None else None)} for (n,nm,st,lk) in rows]}
            core._emit_by_format(out_format, f"PDU: {label}  ({base})", base, label, rows, m[action].value,
                                 getattr(aargs, "csv", None), gargs.csv_header, core.isatty_color(not aargs.no_color), payload)
            if results and results[0].get("ok"): err.exit_with(err.ExitCode.OK)
            else: err.exit_with(err.ExitCode.DEVICE, "failed: outlet did not change")

        print("Unknown action."); err.exit_with(err.ExitCode.USAGE)
    except Exception as e:
        import traceback
        code = err.map_request_error(e)
        if getattr(gargs, "debug", False): traceback.print_exc()
        err.exit_with(code, f"error: {e}")

if __name__ == "__main__":
    main()
