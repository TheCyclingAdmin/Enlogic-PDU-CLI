#!/usr/bin/env python3
# file: enlogic_cli.py
from __future__ import annotations

import argparse
import configparser
import csv
import getpass
import json
import logging
import os
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Iterable, List, Optional, Tuple

import requests
from requests import Session
from requests.adapters import HTTPAdapter
from requests.auth import HTTPBasicAuth
from urllib3.exceptions import InsecureRequestWarning
from urllib3.util.retry import Retry

# Disable noisy TLS warnings (verification controlled by flags)
try:
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)  # type: ignore[attr-defined]
except Exception:
    pass

# ---------- Endpoints ----------
LOGIN = "/xhrlogin.jsp"
CTL_ENABLE = "/outlet_control_enable_set"
CTL_SET = "/xhroutpowstatset.jsp"
RF_PDU = "/redfish/v1/PowerEquipment/RackPDUs/{pduid}"
RF_GROUPS = "/redfish/v1/PowerEquipment/RackPDUs/{pduid}/OutletGroups"
RF_OUTLETS = "/redfish/v1/PowerEquipment/RackPDUs/{pduid}/Outlets"

DEFAULT_CFG = os.path.expanduser("~/.enlogic.ini")
DEFAULT_TIMEOUT = 10.0
DEFAULT_RETRIES = 3
DEFAULT_BACKOFF = 0.5
DEFAULT_PARALLEL = 6

CONFIG_HELP = f"""\
Config file (INI). Default path: {DEFAULT_CFG}

[auth]
user = <username>
password = <password>

[defaults]
# true -> use http://, false -> use https://
http = false
# true -> skip TLS verification, false -> verify TLS
insecure = false
# PDU ID fallback if host is not in [pduid]
pduid = 1
# First bank size for bitmask splitting (usually 24)
low_bank_max = 24
# Network tuning
timeout = 10.0
retries = 3
backoff = 0.5

[hosts]
# nick -> ip or hostname
example.rack = 10.0.0.10

[pduid]
# per-host PDU id override (nickname or IP)
example.rack = 2

Notes:
- Logging/CSV via CLI flags (--log-file, --csv, --csv-header).
- Use 'examples' to see common scenarios, and 'readme' to print the README.
- Globals first, then action. Example:
  enlogic_cli.py --user u --password p --insecure --host 10.0.0.1 list
"""

EXAMPLES_TEXT = r"""\
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
"""

README_TEXT = f"""\
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

{EXAMPLES_TEXT}

## Config
Run `enlogic_cli.py --config-help` to see the full annotated INI example.

## Exit Codes
- `0` success
- `1` usage/validation error
- `2` HTTP error
- `3` unexpected runtime error
"""

# ---------- Logging ----------
logger = logging.getLogger("enlogic")
logger.propagate = False

def setup_logger(log_path: Optional[str], debug: bool) -> None:
    logger.setLevel(logging.DEBUG if debug else logging.INFO)
    if not log_path:
        return
    os.makedirs(os.path.dirname(os.path.abspath(log_path)), exist_ok=True)
    fh = logging.FileHandler(log_path, mode="a", encoding="utf-8")
    fh.setLevel(logging.DEBUG if debug else logging.INFO)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    fh.setFormatter(fmt)
    if not any(isinstance(h, logging.FileHandler) and getattr(h, "baseFilename", None) == fh.baseFilename for h in logger.handlers):
        logger.addHandler(fh)

def log_cmdline() -> None:
    try:
        logger.info("cmd: %s", " ".join(sys.argv))
    except Exception:
        pass

# ---------- Actions ----------
class PowerAction(str, Enum):
    OFF = "off"
    ON = "on"
    OFF_DELAY = "off_delay"
    ON_DELAY = "on_delay"
    REBOOT = "reboot"
    REBOOT_DELAY = "reboot_delay"

POWSTAT: Dict[str, int] = {
    PowerAction.OFF: 0,
    PowerAction.ON: 1,
    PowerAction.OFF_DELAY: 2,
    PowerAction.ON_DELAY: 3,
    PowerAction.REBOOT: 4,
    PowerAction.REBOOT_DELAY: 5,
}

# ---------- Helpers ----------
def isatty_color(enabled_flag: bool) -> bool:
    return enabled_flag and sys.stdout.isatty()

def colorize(text: str, state: str, enable: bool) -> str:
    if not enable:
        return text
    palette = {"on": f"\033[1;32m{text}\033[0m", "off": f"\033[1;31m{text}\033[0m"}
    return palette.get(state, f"\033[2m{text}\033[0m")

def bitmask(port: int, low_max: int = 24) -> Tuple[int, int]:
    if port < 1:
        raise ValueError("Port numbers start at 1.")
    if port <= low_max:
        return (1 << (port - 1), 0)
    return (0, 1 << (port - low_max - 1))

def norm_state(raw: Any) -> Optional[str]:
    s = str(raw).strip().lower()
    m = {
        "on": "on", "off": "off", "1": "on", "0": "off",
        "enabled": "on", "disabled": "off", "poweringon": "on", "poweringoff": "off",
        "present": None, "absent": None, "ok": None, "warning": None, "critical": None,
    }
    return m.get(s)

def parse_outlet_number(obj: dict, uri_hint: Optional[str]) -> Optional[int]:
    for k in ("outlet", "Outlet", "OutletNumber", "Number", "Id", "MemberId"):
        v = obj.get(k)
        if isinstance(v, int):
            return v
        if isinstance(v, str) and v.isdigit():
            return int(v)
    for k in ("Name", "name", "Label", "OutletName", "Description"):
        v = obj.get(k)
        if isinstance(v, str):
            m = re.search(r"(\d+)", v)
            if m:
                return int(m.group(1))
    if uri_hint:
        m = re.search(r"(?:Outlets|OUTLET)[/ ]?(\d+)", uri_hint, flags=re.I)
        if m:
            return int(m.group(1))
    return None

def parse_outlet_name(obj: dict) -> str:
    for k in ("Label", "OutletName", "Name", "name", "Description"):
        v = obj.get(k)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return ""

def parse_outlet_state(obj: dict) -> Optional[str]:
    for k in ("PowerState", "OutletState", "OutletStatus", "State"):
        if k in obj:
            st = norm_state(obj[k])
            if st in {"on", "off"}:
                return st
    status = obj.get("Status")
    if isinstance(status, dict):
        st = norm_state(status.get("State"))
        if st in {"on", "off"}:
            return st
    return None

def now_date_time() -> Tuple[str, str]:
    dt = datetime.now()
    return dt.date().isoformat(), dt.time().isoformat(timespec="seconds")

# ---------- Config ----------
@dataclass
class Defaults:
    pduid: int = 1
    insecure: bool = False
    http: bool = False
    low_bank_max: int = 24
    timeout: float = DEFAULT_TIMEOUT
    retries: int = DEFAULT_RETRIES
    backoff: float = DEFAULT_BACKOFF

class AppConfig:
    def __init__(self, path: Optional[str]):
        self.cfg = configparser.ConfigParser()
        for candidate in [path, DEFAULT_CFG]:
            if candidate and os.path.exists(candidate):
                self.cfg.read(candidate)
                break
    def hosts_map(self) -> Dict[str, str]:
        return dict(self.cfg.items("hosts")) if self.cfg.has_section("hosts") else {}
    def pduid_map(self) -> Dict[str, int]:
        if not self.cfg.has_section("pduid"):
            return {}
        return {k: int(v) for k, v in self.cfg.items("pduid")}
    def defaults(self) -> Defaults:
        d = Defaults()
        if self.cfg.has_section("defaults"):
            d.pduid = self.cfg.getint("defaults", "pduid", fallback=d.pduid)
            d.insecure = self.cfg.getboolean("defaults", "insecure", fallback=d.insecure)
            d.http = self.cfg.getboolean("defaults", "http", fallback=d.http)
            d.low_bank_max = self.cfg.getint("defaults", "low_bank_max", fallback=d.low_bank_max)
            d.timeout = self.cfg.getfloat("defaults", "timeout", fallback=d.timeout)
            d.retries = self.cfg.getint("defaults", "retries", fallback=d.retries)
            d.backoff = self.cfg.getfloat("defaults", "backoff", fallback=d.backoff)
        return d
    def get_auth(self, user_arg: Optional[str], pw_arg: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
        user = user_arg or self.cfg.get("auth", "user", fallback=None)
        pw = pw_arg or self.cfg.get("auth", "password", fallback=None)
        return user, pw
    def resolve_host_label(self, host_arg: str) -> Tuple[str, Optional[str]]:
        hmap = self.hosts_map()
        return (hmap[host_arg], host_arg) if host_arg in hmap else (host_arg, None)

# ---------- CSV ----------
CSV_HEADER = ["index","date","time","host","pdu","outlet","name","state","action","ok"]

def _prog() -> str:
    return os.path.basename(sys.argv[0] or "enlogic_cli.py")

def _csv_target_for_append(path: str, expected_header: List[str], mode: str) -> Tuple[str, bool]:
    """
    Returns (target_path, write_header).
    - mode='never' : never write header.
    - mode='auto'  : write header on new files or when writing a redirected .new.csv.
    - mode='always': write header before rows (even when appending to matching header).
      Note: 'always' may duplicate header lines in existing files.
    Redirects to '<path>.new.csv' when the existing header mismatches expected_header.
    """
    def _new_name(base_path: str) -> str:
        base, ext = os.path.splitext(base_path)
        new_path = f"{base}.new{ext or '.csv'}"
        i = 2
        while os.path.exists(new_path):
            new_path = f"{base}.new{i}{ext or '.csv'}"
            i += 1
        return new_path

    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return path, (mode != "never")

    try:
        with open(path, "r", encoding="utf-8") as f:
            reader = csv.reader(f)
            existing = next(reader, [])
        if existing == expected_header:
            # Matching header in existing file.
            if mode == "always":
                return path, True
            return path, False
        # Mismatch -> redirect to new file.
        sys.stderr.write(f"(!) CSV header mismatch in {path}. Writing to a new file.\n")
        new_path = _new_name(path)
        return new_path, (mode != "never")
    except Exception:
        new_path = _new_name(path)
        return new_path, (mode != "never")

def _csv_write(path: str, rows: List[Dict[str, Any]], header_mode: str) -> None:
    try:
        target, write_header = _csv_target_for_append(path, CSV_HEADER, header_mode)
        os.makedirs(os.path.dirname(os.path.abspath(target)), exist_ok=True)
        with open(target, "a", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=CSV_HEADER)
            if write_header:
                w.writeheader()
            for r in rows:
                w.writerow({k: r.get(k, "") for k in CSV_HEADER})
        logger.info("csv: wrote %d rows -> %s", len(rows), target)
    except Exception as e:
        logger.error("csv: failed to write %s: %s", path, e)

def _csv_rows_from_table(base: str, pdu_label: str, rows: Iterable[Tuple[int,str,str]], action: str, result_by_port: Optional[Dict[int, Optional[bool]]] = None) -> List[Dict[str, Any]]:
    host_ip = base.split("://", 1)[1]
    date_str, time_str = now_date_time()
    out: List[Dict[str, Any]] = []
    for idx, (n, nm, st) in enumerate(rows, start=1):
        ok_val = None
        if result_by_port and n in result_by_port:
            v = result_by_port[n]
            ok_val = "true" if v else "false"
        out.append({"index": idx, "date": date_str, "time": time_str, "host": host_ip, "pdu": pdu_label,
                    "outlet": n, "name": nm, "state": st, "action": action, "ok": ok_val if ok_val is not None else ""})
    return out

def _csv_rows_from_batch(rows: Iterable[Tuple[str,int,str,str]], action: str) -> List[Dict[str, Any]]:
    date_str, time_str = now_date_time()
    out: List[Dict[str, Any]] = []
    for idx, (host, n, nm, st) in enumerate(rows, start=1):
        out.append({"index": idx, "date": date_str, "time": time_str, "host": host, "pdu": "", "outlet": n,
                    "name": nm, "state": st, "action": action, "ok": ""})
    return out

# ---------- HTTP/Redfish ----------
def _make_retry(retries: int, backoff: float) -> Retry:
    base_kwargs = dict(
        total=retries, connect=retries, read=retries,
        backoff_factor=backoff,
        status_forcelist=(502, 503, 504, 521, 522, 524),
        raise_on_status=False,
    )
    try:
        return Retry(allowed_methods=frozenset({"GET", "POST"}), **base_kwargs)  # urllib3 v2
    except TypeError:
        return Retry(method_whitelist=frozenset({"GET", "POST"}), **base_kwargs)  # urllib3 v1

class PDUClient:
    def __init__(self, base_url: str, insecure: bool, timeout: float, retries: int, backoff: float, debug: bool):
        self.base = base_url.rstrip("/")
        self.insecure = insecure
        self.timeout = timeout
        self.debug = debug
        self.session = self._build_session(retries, backoff)
    def _build_session(self, retries: int, backoff: float) -> Session:
        sess = requests.Session()
        retry = _make_retry(retries, backoff)
        adapter = HTTPAdapter(max_retries=retry, pool_maxsize=8)
        sess.mount("http://", adapter);  sess.mount("https://", adapter)
        return sess
    def _dbg(self, msg: str) -> None:
        if self.debug:
            sys.stderr.write(f"[debug] {msg}\n"); logger.debug(msg)
    def rf_get(self, path_or_abs: str, auth: Optional[HTTPBasicAuth]) -> dict:
        url = path_or_abs if path_or_abs.startswith(("http://","https://")) else f"{self.base}{path_or_abs}"
        self._dbg(f"GET {url}")
        r = self.session.get(url, auth=auth, verify=not self.insecure, timeout=self.timeout); r.raise_for_status()
        try:
            return r.json()
        except Exception as e:
            self._dbg(f"JSON decode failed for {url}: {e}; body[:200]={r.text[:200]!r}")
            raise
    def post_json(self, path_or_abs: str, payload: dict) -> requests.Response:
        url = path_or_abs if path_or_abs.startswith(("http://","https://")) else f"{self.base}{path_or_abs}"
        self._dbg(f"POST {url} payload={payload}")
        r = self.session.post(url, json=payload, verify=not self.insecure, timeout=self.timeout); r.raise_for_status()
        return r
    def login_cookie(self, user: str, password: str) -> int:
        data = self.post_json(LOGIN, {"username":user,"password":password,"cookie":0}).json()
        if "cookie" not in data: raise RuntimeError("Login failed: no cookie in response")
        return int(data["cookie"])
    def enable_control(self, cookie: int) -> None:
        self.post_json(CTL_ENABLE, {"cookie":cookie,"enable":1})
    def set_power(self, cookie: int, pduid: int, port: int, action: PowerAction, low_max: int) -> dict:
        o1,o2 = bitmask(port, low_max)
        payload = {"cookie":cookie,"outlet1":o1,"outlet2":o2,"pduid":pduid,"powstat":POWSTAT[action]}
        try:
            return self.post_json(CTL_SET, payload).json()
        except json.JSONDecodeError:
            return {"status":"OK"}
    def _collect_members(self, container: dict) -> List[Tuple[dict, Optional[str]]]:
        results: List[Tuple[dict, Optional[str]]] = []
        seq = container.get("Members") or container.get("Outlets") or []
        if isinstance(seq, list):
            for item in seq:
                if isinstance(item, dict) and ("@odata.id" in item or "href" in item):
                    uri = item.get("@odata.id") or item.get("href"); results.append(({"__link__":True}, uri))
                elif isinstance(item, dict):
                    results.append((item, None))
        return results
    def _parse_member_obj(self, obj: dict, uri_hint: Optional[str], status: Dict[int,str], names: Dict[int,str]) -> None:
        n = parse_outlet_number(obj, uri_hint)
        if not n:
            self._dbg(f"skip: no outlet number in obj keys={list(obj.keys())} uri_hint={uri_hint}")
            return
        nm = parse_outlet_name(obj); st = parse_outlet_state(obj)
        if nm: names[n] = nm
        if st in {"on","off"}: status[n] = st
        else: status.setdefault(n,"unknown")
    def fetch_maps(self, pduid: int, auth: HTTPBasicAuth) -> Tuple[Dict[int,str], Dict[int,str]]:
        status: Dict[int,str] = {}; names: Dict[int,str] = {}
        try:
            groups = self.rf_get(RF_GROUPS.format(pduid=pduid), auth)
            group_list = groups.get("groups") or groups.get("Members") or []
            flat: List[Tuple[dict, Optional[str]]] = []
            if isinstance(group_list, list):
                for g in group_list:
                    if isinstance(g, dict) and "Members" in g: flat.extend(self._collect_members(g))
                    elif isinstance(g, dict): flat.append((g, None))
            for obj, uri in flat:
                if obj.get("__link__"):
                    try: o = self.rf_get(uri, auth); self._parse_member_obj(o, uri, status, names)
                    except Exception as e: self._dbg(f"group member GET {uri} failed: {e}")
                else: self._parse_member_obj(obj, None, status, names)
        except Exception as e: self._dbg(f"groups fetch failed: {e}")
        if not status or len(status)<2:
            try:
                coll = self.rf_get(RF_OUTLETS.format(pduid=pduid)+"?$expand=.", auth)
                members = self._collect_members(coll)
                if not members:
                    coll = self.rf_get(RF_OUTLETS.format(pduid=pduid)+"?$expand=*", auth)
                    members = self._collect_members(coll)
                for obj, uri in members:
                    if obj.get("__link__"):
                        try: o = self.rf_get(uri, auth); self._parse_member_obj(o, uri, status, names)
                        except Exception as e: self._dbg(f"outlet GET {uri} failed: {e}")
                    else: self._parse_member_obj(obj, None, status, names)
            except Exception as e: self._dbg(f"outlets expanded fetch failed: {e}")
        if not status or len(status)<2:
            try:
                coll = self.rf_get(RF_OUTLETS.format(pduid=pduid), auth)
                members = self._collect_members(coll)
                for obj, uri in members:
                    if obj.get("__link__") and uri:
                        try: o = self.rf_get(uri, auth); self._parse_member_obj(o, uri, status, names)
                        except Exception as e: self._dbg(f"outlet GET {uri} failed: {e}")
                    elif isinstance(obj, dict): self._parse_member_obj(obj, None, status, names)
            except Exception as e: self._dbg(f"outlets collection fetch failed: {e}")
        if not status: status = {n:"unknown" for n in range(1,49)}
        return status, names
    def pdu_display(self, pduid: int, auth: HTTPBasicAuth, override: Optional[str]=None) -> str:
        if override: return override
        try:
            obj = self.rf_get(RF_PDU.format(pduid=pduid), auth)
            return obj.get("Name") or obj.get("Id") or self.base.split("://",1)[-1]
        except Exception as e:
            self._dbg(f"pdu_display failed: {e}");  return self.base.split("://",1)[-1]

# ---------- Output ----------
def print_table(title: str, rows: Iterable[Tuple[int,str,str]], use_color: bool) -> None:
    print(f"\n{title}\n")
    print("Outlet | Label / Name                 | State")
    print("-------+------------------------------+--------")
    for n, nm, st in rows:
        state_disp = colorize(st, st, use_color)
        print(f"{n:02d}     | {nm[:28]:<28} | {state_disp}")
    print()

def print_batch_table(title: str, rows: Iterable[Tuple[str,int,str,str]], use_color: bool) -> None:
    print(f"\n{title}\n")
    print("Host             | Outlet | Label / Name                 | State")
    print("-----------------+--------+------------------------------+--------")
    for host, n, nm, st in rows:
        state_disp = colorize(st, st, use_color)
        print(f"{host:<16} | {n:02d}    | {nm[:28]:<28} | {state_disp}")
    print()

def emit_json(data: dict) -> None:
    print(json.dumps(data, indent=2))

# ---------- Friendly argparse ----------
GLOBAL_FLAGS = {
    "-H","--host","-u","--user","-P","--password","-k","--insecure","--secure",
    "-x","--http","--https","-d","--pduid","--timeout","--retries","--backoff",
    "--parallel","--log-file","--config","--low-bank-max","--debug","--config-help",
}

def _examples_for(action: str) -> List[str]:
    prog = _prog()
    if action == "list":
        return [
            f"{prog} --user u --password p --insecure --host 10.0.0.10 list",
            f"{prog} --user u --password p --host 10.0.0.10 list --sort name",
        ]
    if action == "get":
        return [
            f"{prog} --user u --password p --host 10.0.0.10 get --port 8",
            f"{prog} --user u --password p --host 10.0.0.10 get --label PSU1",
        ]
    if action in ("on","off"):
        return [
            f"{prog} --user u --password p --host 10.0.0.10 {action} --port 3 5 7",
            f"{prog} --user u --password p --host 10.0.0.10 {action} --all",
        ]
    if action == "reboot":
        return [f"{prog} --user u --password p --host 10.0.0.10 reboot --port 8"]
    if action == "batch":
        return [
            f"{prog} --user u --password p --insecure batch on --hosts 10.0.0.10 10.0.0.11 --port 8",
            f"{prog} --user u --password p --insecure batch list --host-file hosts.txt --all --csv /tmp/pdu.csv",
        ]
    return [f"{prog} examples", f"{prog} readme"]

class FriendlyActionParser(argparse.ArgumentParser):
    def __init__(self, action: str, raw_argv: List[str]):
        super().__init__(add_help=False, allow_abbrev=False)
        self._action_name = action
        self._raw_argv = raw_argv

    def error(self, message: str) -> None:  # noqa: D401
        sys.stderr.write(f"\nError in '{self._action_name}': {message}\n")
        # Detect global flags placed after the action
        if any(tok in GLOBAL_FLAGS for tok in self._raw_argv):
            sys.stderr.write(
                "\nHint: Global flags must come *before* the action.\n"
                f"Format: {_prog()} [GLOBALS] {self._action_name} [ACTION FLAGS]\n"
                "Common globals: --host, --user, --password, --insecure, --http/--https, --secure\n"
            )
        # Show concise examples
        examples = _examples_for(self._action_name)
        if examples:
            sys.stderr.write("\nExamples:\n")
            for ex in examples:
                sys.stderr.write(f"  {ex}\n")
        # Show short help for this action
        sys.stderr.write("\nHelp for this action:\n")
        self.print_help()
        sys.exit(2)

# ---------- Business helpers ----------
def find_port(status: Dict[int,str], names: Dict[int,str], port: Optional[int], label: Optional[str]) -> Optional[int]:
    if port is not None:
        return port if port in status else None
    if label:
        lbl = label.lower()
        exact = [n for n, nm in names.items() if nm.lower()==lbl]
        if exact: return sorted(exact)[0]
        subs = [n for n, nm in names.items() if lbl in nm.lower()]
        if subs: return sorted(subs)[0]
    return None

def _maybe_warn_all_unknown(all_unknown: bool) -> None:
    if all_unknown and sys.stdout.isatty():
        sys.stderr.write("(!) No reliable Redfish outlet data parsed. Try --insecure/--http if needed, or --debug to inspect shapes.\n")

# ---------- Setup ----------
def write_config(path: str, user: str, password: str, http: bool, insecure: bool, pduid: Optional[int] = None, low_bank_max: Optional[int] = None) -> None:
    cfg = configparser.ConfigParser()
    if os.path.exists(path): cfg.read(path)
    if not cfg.has_section("auth"): cfg.add_section("auth")
    if not cfg.has_section("defaults"): cfg.add_section("defaults")
    cfg.set("auth","user", user); cfg.set("auth","password", password)
    cfg.set("defaults","http", "true" if http else "false")
    cfg.set("defaults","insecure", "true" if insecure else "false")
    if pduid is not None: cfg.set("defaults","pduid", str(pduid))
    if low_bank_max is not None: cfg.set("defaults","low_bank_max", str(low_bank_max))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f: cfg.write(f)
    try:
        if os.name == "posix": os.chmod(path, 0o600)
    except Exception:
        pass

def prompt_bool(prompt: str, default: Optional[bool]) -> bool:
    d = "Y/n" if default is True else "y/N" if default is False else "y/n"
    while True:
        ans = input(f"{prompt} [{d}]: ").strip().lower()
        if not ans and default is not None: return default
        if ans in ("y","yes"): return True
        if ans in ("n","no"): return False
        print("Please answer y or n.")

def run_setup(args) -> int:
    path = args.config or DEFAULT_CFG
    cur = configparser.ConfigParser()
    if os.path.exists(path): cur.read(path)
    cur_user = cur.get("auth","user", fallback=None)
    cur_pass = cur.get("auth","password", fallback=None)
    cur_http = cur.getboolean("defaults","http", fallback=False)
    cur_insec = cur.getboolean("defaults","insecure", fallback=False)
    user = args.user or cur_user or input(f"Username [{cur_user or ''}]: ") or (cur_user or "")
    if not args.password and not cur_pass: pw = getpass.getpass("Password: ")
    else: pw = args.password or cur_pass or ""
    if args.http is None and args.https is None: http = prompt_bool(f"Use HTTP (not HTTPS)? Current={cur_http}", cur_http)
    else: http = True if args.http else False if args.https else cur_http
    if args.insecure is None and args.secure is None: insecure = prompt_bool(f"Skip TLS verification? Current={cur_insec}", cur_insec)
    else: insecure = True if args.insecure else False if args.secure else cur_insec
    write_config(path, user=user, password=pw, http=http, insecure=insecure)
    print(f"Wrote config: {path}"); print(CONFIG_HELP); logger.info("setup: wrote config %s", path); return 0

# ---------- Shared fetchers ----------
@dataclass
class DefaultsBundle:
    pduid: int; insecure: bool; http: bool; low_bank_max: int; timeout: float; retries: int; backoff: float

def _build_client(base: str, g, defaults) -> PDUClient:
    return PDUClient(base_url=base,
                     insecure=(g.insecure if g.insecure is not None else defaults.insecure),
                     timeout=(g.timeout if g.timeout is not None else defaults.timeout),
                     retries=(g.retries if g.retries is not None else defaults.retries),
                     backoff=(g.backoff if g.backoff is not None else defaults.backoff),
                     debug=g.debug)

def fetch_table_for(g, cfg: AppConfig, user: str, pw: str, sort_order: str="outlet"):
    host_ip, nick = cfg.resolve_host_label(g.host)
    defaults = cfg.defaults()
    pduid_lookup = cfg.pduid_map().get(g.host) or cfg.pduid_map().get(host_ip)
    pduid = g.pduid if g.pduid is not None else (pduid_lookup or defaults.pduid)
    base = f"{'http' if (g.http if g.http is not None else defaults.http) else 'https'}://{host_ip}"
    client = _build_client(base, g, defaults)
    auth = HTTPBasicAuth(user, pw)
    label = client.pdu_display(pduid, auth, override=nick or host_ip)
    status, names = client.fetch_maps(pduid, auth)
    order = sorted(status) if sort_order=="outlet" else sorted(status, key=lambda n:(names.get(n,"").lower(), n))
    rows = [(n, names.get(n,""), status.get(n,"unknown")) for n in order]
    return base, label, pduid, client, auth, rows, status, names

# ---------- Single-host actions ----------
def run_hosts(cfg: AppConfig) -> int:
    hmap = cfg.hosts_map()
    if not hmap: print("No hosts configured in [hosts]."); return 0
    width = max(len(k) for k in hmap)
    for k,v in sorted(hmap.items()): print(f"{k.ljust(width)} -> {v}")
    return 0

def run_examples() -> int:
    print(EXAMPLES_TEXT); return 0

def run_readme() -> int:
    print(README_TEXT); return 0

def _json_row_from_table(rows: List[Tuple[int,str,str]], action: str) -> List[Dict[str, Any]]:
    date_str, time_str = now_date_time()
    out = []
    for idx, (n, nm, st) in enumerate(rows, start=1):
        out.append({"index": idx, "date": date_str, "time": time_str, "n": n, "name": nm, "state": st, "action": action})
    return out

def _print_examples_for(action: str) -> None:
    ex = _examples_for(action)
    if ex:
        print("\nExamples:")
        for e in ex:
            print(f"  {e}")

def run_list(args, g, cfg: AppConfig) -> int:
    user, pw = cfg.get_auth(g.user, g.password)
    if not user or not pw:
        if args.json: emit_json({"ok": False, "error": "missing_credentials"})
        else:
            print("Error: provide --user/--password or add [auth] to config.")
            _print_examples_for("list")
        return 1
    if not g.host:
        if args.json: emit_json({"ok": False, "error": "missing_host"})
        else:
            print("Error: --host is required.")
            _print_examples_for("list")
        return 1

    base, label, _, _, _, rows, status, names = fetch_table_for(g, cfg, user, pw, args.sort)

    if args.json:
        payload = {
            "ok": True, "pdu": label, "host": g.host, "base": base,
            "outlets": _json_row_from_table(rows, action="list"),
        }
        if args.port is not None:
            n = find_port(status, names, port=args.port, label=None)
            date_str, time_str = now_date_time()
            payload["selected"] = {
                "requested_port": args.port, "found": bool(n),
                "outlet": ({"index": 1, "date": date_str, "time": time_str, "n": n,
                            "name": names.get(n,""), "state": status.get(n,"unknown"), "action":"list"} if n else None),
            }
        emit_json(payload)
    else:
        print_table(f"PDU: {label}  ({base})", rows, isatty_color(not args.no_color))
        _maybe_warn_all_unknown(all(v=="unknown" for v in status.values()))
        if args.port is not None:
            n = find_port(status, names, port=args.port, label=None)
            print(f"Note: --port {args.port} was specified with 'list'. Matching outlet shown below:")
            if n:
                print_table("Selected outlet", [(n, names.get(n,""), status.get(n,"unknown"))], isatty_color(not args.no_color))
            else:
                print("No matching outlet number found.")

    if args.csv:
        csv_rows = _csv_rows_from_table(base, label, rows, action="list")
        _csv_write(args.csv, csv_rows, header_mode=args.csv_header)
    logger.info("list: host=%s rows=%d", g.host, len(rows))
    return 0

def run_get(args, g, cfg: AppConfig) -> int:
    user, pw = cfg.get_auth(g.user, g.password)
    if not user or not pw:
        if args.json: emit_json({"ok": False, "error": "missing_credentials"})
        else:
            print("Error: provide --user/--password or add [auth] to config.")
            _print_examples_for("get")
        return 1
    if not g.host:
        if args.json: emit_json({"ok": False, "error": "missing_host"})
        else:
            print("Error: --host is required.")
            _print_examples_for("get")
        return 1
    if (args.port is None) and (args.label is None):
        if args.json: emit_json({"ok": False, "error": "missing_selector", "message": "get requires --port or --label"})
        else:
            print("Error: get requires --port or --label.")
            _print_examples_for("get")
        return 1

    base, label_disp, _, _, _, rows, status, names = fetch_table_for(g, cfg, user, pw, "outlet")
    n = find_port(status, names, port=args.port, label=args.label)
    if not n:
        if args.json:
            known = [{"n": k, "name": v} for k,v in sorted(names.items())]
            emit_json({"ok": False, "error":"not_found","host":g.host,"selector":{"port":args.port,"label":args.label},"known":known})
        else:
            print("No matching outlet (by number or label).")
            print("\nKnown outlets (num : label):")
            for k in sorted(names): print(f"  {k:02d} : {names[k]}")
            _maybe_warn_all_unknown(all(v=="unknown" for v in status.values()))
            _print_examples_for("get")
        logger.info("get: host=%s selector=%s not_found", g.host, {"port":args.port,"label":args.label}); return 1

    if args.json:
        date_str, time_str = now_date_time()
        payload = {"ok": True, "pdu": label_disp, "host": g.host, "base": base,
                   "outlet": {"index": 1, "date": date_str, "time": time_str, "n": n,
                              "name": names.get(n,""), "state": status.get(n,"unknown"), "action":"get"}}
        emit_json(payload)
    else:
        print_table(f"PDU: {label_disp}  ({base})", [(n, names.get(n,""), status.get(n,"unknown"))], isatty_color(not args.no_color))
        _maybe_warn_all_unknown(all(v=="unknown" for v in status.values()))

    if args.csv:
        sel_rows = [(n, names.get(n,""), status.get(n,"unknown"))]
        csv_rows = _csv_rows_from_table(base, label_disp, sel_rows, action="get")
        _csv_write(args.csv, csv_rows, header_mode=args.csv_header)
    logger.info("get: host=%s port=%s ok", g.host, n); return 0

def _control_error(msg: str, as_json: bool, action_for_examples: Optional[str] = None) -> int:
    if as_json:
        emit_json({"ok": False, "error": msg})
    else:
        print(msg)
        if action_for_examples:
            _print_examples_for(action_for_examples)
    logger.error("control_error: %s", msg); return 1

def run_on_off(args, g, cfg: AppConfig, action: PowerAction) -> int:
    user, pw = cfg.get_auth(g.user, g.password)
    if not user or not pw:
        return _control_error("Error: provide --user/--password or add [auth] to config.", args.json, action.value)
    if not g.host:
        return _control_error("Error: --host is required.", args.json, action.value)

    host_ip, _ = cfg.resolve_host_label(g.host)
    defaults = cfg.defaults()
    pduid_lookup = cfg.pduid_map().get(g.host) or cfg.pduid_map().get(host_ip)
    pduid = g.pduid if g.pduid is not None else (pduid_lookup or defaults.pduid)
    low_max = g.low_bank_max if g.low_bank_max is not None else defaults.low_bank_max
    base = f"{'http' if (g.http if g.http is not None else defaults.http) else 'https'}://{host_ip}"
    client = _build_client(base, g, defaults)
    auth = HTTPBasicAuth(user, pw)

    if args.all:
        try:
            status, _ = client.fetch_maps(pduid, auth); ports_to_change = sorted(status.keys())
        except Exception as e:
            return _control_error(f"Error discovering ports for --all: {e}", args.json, action.value)
    else:
        ports_to_change = args.port or []

    try:
        cookie = client.login_cookie(user, pw); client.enable_control(cookie)
        results = []
        for p in ports_to_change:
            try: ok = bool(client.set_power(cookie, pduid, p, action, low_max)); results.append({"port":p,"ok":ok})
            except Exception as ex: results.append({"port":p,"ok":False,"error":str(ex)})

        label = client.pdu_display(pduid, auth, override=host_ip)
        status2, names2 = client.fetch_maps(pduid, auth)
        order = sorted(status2) if args.sort=="outlet" else sorted(status2, key=lambda n:(names2.get(n,"").lower(),n))
        table_rows = [(n, names2.get(n,""), status2.get(n,"unknown")) for n in order]

        if args.json:
            date_str, time_str = now_date_time()
            emit_json({
                "ok": True, "action": action.value, "date": date_str, "time": time_str,
                "host": g.host, "pdu": label, "base": base, "ports": results,
                "outlets": _json_row_from_table(table_rows, action=action.value),
            })
        else:
            ok_ports = [r["port"] for r in results if r.get("ok")]
            fail_ports = [r for r in results if not r.get("ok")]
            print(f"Action '{action.value}' applied. Success on ports: {ok_ports or 'none'}")
            if fail_ports:
                for r in fail_ports: print(f"  Port {r['port']}: ERROR {r.get('error','unknown')}")
            print_table(f"PDU: {label}  ({base})", table_rows, isatty_color(not args.no_color))
            if ok_ports:
                sel = [(p, names2.get(p,""), status2.get(p,"unknown")) for p in ok_ports if p in status2]
                if sel: print_table("Selected outlet(s)", sel, isatty_color(not args.no_color))
            _maybe_warn_all_unknown(all(v=="unknown" for v in status2.values()))

        if args.csv:
            result_by = {r["port"]: r.get("ok") for r in results}
            csv_rows = _csv_rows_from_table(base, label, table_rows, action=action.value, result_by_port=result_by)
            _csv_write(args.csv, csv_rows, header_mode=args.csv_header)

        logger.info("%s: host=%s changed=%d", action.value, g.host, sum(1 for r in results if r.get("ok"))); return 0

    except requests.HTTPError as e:
        if args.json: emit_json({"ok": False, "error": f"HTTP {e.response.status_code}", "body": e.response.text})
        else: print(f"HTTP {e.response.status_code}: {e.response.reason}\n{e.response.text[:800]}")
        logger.error("%s: HTTP %s", action.value, getattr(e.response, "status_code", "?")); return 2
    except Exception as e:
        if args.json: emit_json({"ok": False, "error": str(e)})
        else: print(f"Error: {e}")
        logger.error("%s: error %s", action.value, e); return 3

def run_single_port(args, g, cfg: AppConfig, action: PowerAction) -> int:
    user, pw = cfg.get_auth(g.user, g.password)
    if not user or not pw: return _control_error("Error: provide --user/--password or add [auth] to config.", args.json, action.value)
    if not g.host: return _control_error("Error: --host is required.", args.json, action.value)
    if args.port is None: return _control_error("Error: --port is required.", args.json, action.value)

    host_ip, _ = cfg.resolve_host_label(g.host)
    defaults = cfg.defaults()
    pduid_lookup = cfg.pduid_map().get(g.host) or cfg.pduid_map().get(host_ip)
    pduid = g.pduid if g.pduid is not None else (pduid_lookup or defaults.pduid)
    low_max = g.low_bank_max if g.low_bank_max is not None else defaults.low_bank_max
    base = f"{'http' if (g.http if g.http is not None else defaults.http) else 'https'}://{host_ip}"
    client = _build_client(base, g, defaults)
    auth = HTTPBasicAuth(user, pw)

    try:
        cookie = client.login_cookie(user, pw); client.enable_control(cookie)
        client.set_power(cookie, pduid, args.port, action, low_max)
        label = client.pdu_display(pduid, auth, override=host_ip)
        status2, names2 = client.fetch_maps(pduid, auth)
        table_rows = [(args.port, names2.get(args.port,""), status2.get(args.port,"unknown"))]

        if args.json:
            date_str, time_str = now_date_time()
            emit_json({"ok": True, "action": action.value, "date": date_str, "time": time_str,
                       "host": g.host, "pdu": label, "base": base,
                       "outlets": _json_row_from_table(table_rows, action=action.value)})
        else:
            print(f"Action '{action.value}' applied to port {args.port}.")
            print_table(f"PDU: {label}  ({base})", table_rows, isatty_color(not args.no_color))

        if args.csv:
            csv_rows = _csv_rows_from_table(base, label, table_rows, action=action.value, result_by_port={args.port: True})
            _csv_write(args.csv, csv_rows, header_mode=args.csv_header)

        logger.info("%s: host=%s port=%s ok", action.value, g.host, args.port); return 0

    except requests.HTTPError as e:
        if args.json: emit_json({"ok": False, "error": f"HTTP {e.response.status_code}", "body": e.response.text})
        else: print(f"HTTP {e.response.status_code}: {e.response.reason}\n{e.response.text[:800]}")
        logger.error("%s: HTTP %s", action.value, getattr(e.response, "status_code", "?")); return 2
    except Exception as e:
        if args.json: emit_json({"ok": False, "error": str(e)})
        else: print(f"Error: {e}")
        logger.error("%s: error %s", action.value, e); return 3

# ---------- Batch (parallel) ----------
def _load_hosts_from_file(path: str) -> List[str]:
    out: List[str] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"): continue
            out.append(s)
    return out

def _batch_worker(host: str, args, g, cfg: AppConfig) -> Tuple[str, List[Tuple[str,int,str,str]], Dict[str, Any]]:
    defaults = cfg.defaults()
    try:
        host_ip, _ = cfg.resolve_host_label(host)
        pduid_lookup = cfg.pduid_map().get(host) or cfg.pduid_map().get(host_ip)
        pduid = g.pduid if g.pduid is not None else (pduid_lookup or defaults.pduid)
        base = f"{'http' if (g.http if g.http is not None else defaults.http) else 'https'}://{host_ip}"
        client = _build_client(base, g, defaults)
        user, pw = cfg.get_auth(g.user, g.password)
        if not user or not pw: return host, [], {"ok": False, "error":"missing_credentials"}
        auth = HTTPBasicAuth(user, pw)
        status, names = client.fetch_maps(pduid, auth)
        rows: List[Tuple[str,int,str,str]] = []
        if args.batch_action in ("list","get"):
            if args.all: ports = sorted(status.keys())
            elif args.port: ports = sorted(set(args.port))
            else: return host, [], {"ok": False, "error":"missing --all or --port"}
            for p in ports: rows.append((host_ip, p, names.get(p,""), status.get(p,"unknown")))
            return host, rows, {"ok": True}
        if args.all: target_ports = sorted(status.keys())
        elif args.port: target_ports = sorted(set(args.port))
        else: return host, [], {"ok": False, "error":"missing --all or --port"}
        cookie = client.login_cookie(user, pw); client.enable_control(cookie)
        results = []; action = PowerAction(args.batch_action)
        for p in target_ports:
            try: ok = bool(client.set_power(cookie, pduid, p, action, defaults.low_bank_max)); results.append({"port":p,"ok":ok})
            except Exception as ex: results.append({"port":p,"ok":False,"error":str(ex)})
        status2, names2 = client.fetch_maps(pduid, auth)
        emit_ports = sorted(status2.keys()) if args.all else target_ports
        for p in emit_ports:
            nm = names2.get(p, names.get(p,"")); st = status2.get(p, status.get(p,"unknown"))
            rows.append((host_ip, p, nm, st))
        return host, rows, {"ok": True, "results": results}
    except Exception as e:
        return host, [], {"ok": False, "error": str(e)}

def run_batch(args, g, cfg: AppConfig) -> int:
    targets: List[str] = []
    if args.hosts: targets.extend(args.hosts)
    if args.host_file:
        try: targets.extend(_load_hosts_from_file(args.host_file))
        except Exception as e: return _control_error(f"Error reading --host-file: {e}", args.json, "batch")
    if not targets:
        return _control_error("Error: provide --hosts or --host-file.", args.json, "batch")

    rows_all: List[Tuple[str,int,str,str]] = []; host_meta: Dict[str, Any] = {}
    max_workers = g.parallel if g.parallel is not None else DEFAULT_PARALLEL
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        futmap = {ex.submit(_batch_worker, h, args, g, cfg): h for h in targets}
        for fut in as_completed(futmap):
            h = futmap[fut]
            try:
                host_key, rows, meta = fut.result()
                rows_all.extend(rows); host_meta[host_key] = meta
            except Exception as e:
                host_meta[h] = {"ok": False, "error": str(e)}
    rows_all.sort(key=lambda r:(r[0], r[1]))

    if args.json:
        date_str, time_str = now_date_time()
        payload_rows = []
        for idx, (h, n, nm, st) in enumerate(rows_all, start=1):
            payload_rows.append({"index": idx, "date": date_str, "time": time_str, "host": h,
                                 "outlet": n, "name": nm, "state": st, "action": args.batch_action})
        emit_json({"ok": True, "action": args.batch_action, "date": date_str, "time": time_str,
                   "rows": payload_rows, "hosts": host_meta})
    else:
        title = f"Batch {args.batch_action}"
        print_batch_table(title, rows_all, isatty_color(not args.no_color))
        failures = {h:r for h,r in host_meta.items() if not r.get("ok")}
        if failures:
            print("Failures:")
            for h,r in failures.items(): print(f"  {h}: {r.get('error','unknown')}")

    if args.csv:
        _csv_write(args.csv, _csv_rows_from_batch(rows_all, action=args.batch_action), header_mode=args.csv_header)

    logger.info("batch: action=%s hosts=%d rows=%d", args.batch_action, len(targets), len(rows_all)); return 0

# ---------- Parsers ----------
def build_global_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        add_help=True,
        allow_abbrev=False,
        description=(
            "Enlogic PDU CLI — globals first, then action.\n"
            "See 'examples' and 'readme' for guidance.\n"
            "Examples:\n"
            f"  {_prog()} --user u --password p --insecure --host 10.0.0.1 list\n"
            f"  {_prog()} --user u --password p --insecure --host 10.0.0.1 on --port 8\n"
            f"  {_prog()} --user u --password p --insecure batch on --hosts 10.0.0.1 10.0.0.2 --all\n"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )
    p.add_argument("-c","--config", help=f"Config file (default: {DEFAULT_CFG} if present)")
    p.add_argument("-H","--host", help="Nickname or IP (nickname resolved via [hosts])")
    p.add_argument("-u","--user", help="Username (defaults to [auth] user)")
    p.add_argument("-P","--password", help="Password (defaults to [auth] password)")
    p.add_argument("-k","--insecure", action="store_true", default=None, help="Skip TLS verification")
    p.add_argument("--secure", dest="secure", action="store_true", default=None, help="Verify TLS")
    p.add_argument("-x","--http", action="store_true", default=None, help="Use HTTP instead of HTTPS")
    p.add_argument("--https", dest="https", action="store_true", default=None, help="Use HTTPS")
    p.add_argument("-d","--pduid", type=int, help="PDU ID (override)")
    p.add_argument("--low-bank-max", type=int, help="Outlet1 bank size (default 24)")
    p.add_argument("--timeout", type=float, help=f"HTTP timeout seconds (default {DEFAULT_TIMEOUT})")
    p.add_argument("--retries", type=int, help=f"HTTP retries (default {DEFAULT_RETRIES})")
    p.add_argument("--backoff", type=float, help=f"HTTP backoff factor (default {DEFAULT_BACKOFF})")
    p.add_argument("--parallel", type=int, help=f"Batch parallelism (default {DEFAULT_PARALLEL})")
    p.add_argument("--log-file", help="Append logs to this file (includes the full command and results/errors)")
    p.add_argument("--debug", action="store_true", help="Print HTTP request/exception debug to stderr and log")
    p.add_argument("--config-help", action="store_true", help="Show config file help and exit")
    p.add_argument("--csv-header", choices=["never","auto","always"], default="auto",
                   help="CSV header policy: never write, auto-detect (default), or always write before rows")
    p.add_argument("action", nargs="?", choices=[
        "hosts", "setup", "examples", "readme", "list", "get",
        "on", "off", "reboot", "on_delay", "off_delay", "reboot_delay",
        "multi", "batch",
    ], help="Command to run (appears after globals)")
    return p

def build_action_parser(action: str, raw_argv: List[str]) -> argparse.ArgumentParser:
    ap = FriendlyActionParser(action, raw_argv=raw_argv)
    if action in ("hosts","setup","examples","readme"):
        pass
    elif action == "list":
        ap.add_argument("--sort", choices=["outlet","name"], default="outlet")
        ap.add_argument("--no-color", action="store_true")
        ap.add_argument("--port", type=int, help="If provided, also show the specific outlet row underneath")
        ap.add_argument("--json", action="store_true", help="Emit JSON instead of a human table")
        ap.add_argument("--csv", help="Append table rows to CSV at this path")
        ap.add_argument("--csv-header", choices=["never","auto","always"], default="auto")
    elif action == "get":
        ap.add_argument("--port", type=int)
        ap.add_argument("--label")
        ap.add_argument("--no-color", action="store_true")
        ap.add_argument("--json", action="store_true", help="Emit JSON instead of a human table")
        ap.add_argument("--csv", help="Append selected outlet row to CSV at this path")
        ap.add_argument("--csv-header", choices=["never","auto","always"], default="auto")
    elif action in ("on","off"):
        mx = ap.add_mutually_exclusive_group(required=True)
        mx.add_argument("--port", nargs="+", type=int, help="One or more outlet numbers")
        mx.add_argument("--all", action="store_true", help="Operate on ALL outlets")
        ap.add_argument("--sort", choices=["outlet","name"], default="outlet")
        ap.add_argument("--no-color", action="store_true")
        ap.add_argument("--json", action="store_true", help="Emit JSON instead of a human table")
        ap.add_argument("--csv", help="Append resulting table rows to CSV at this path")
        ap.add_argument("--csv-header", choices=["never","auto","always"], default="auto")
    elif action in ("reboot","on_delay","off_delay","reboot_delay"):
        ap.add_argument("--port", type=int, required=True)
        ap.add_argument("--no-color", action="store_true")
        ap.add_argument("--json", action="store_true", help="Emit JSON instead of a human table")
        ap.add_argument("--csv", help="Append selected outlet row to CSV at this path")
        ap.add_argument("--csv-header", choices=["never","auto","always"], default="auto")
    elif action == "multi":
        ap.add_argument("multi_action", choices=[a.value for a in PowerAction], help="Action to apply")
        ap.add_argument("-p","--port", nargs="+", type=int, required=True)
        ap.add_argument("--sort", choices=["outlet","name"], default="outlet")
        ap.add_argument("--no-color", action="store_true")
        ap.add_argument("--json", action="store_true", help="Emit JSON instead of a human table")
        ap.add_argument("--csv", help="Append resulting table rows to CSV at this path")
        ap.add_argument("--csv-header", choices=["never","auto","always"], default="auto")
    elif action == "batch":
        ap.add_argument("batch_action", choices=["on","off","reboot","on_delay","off_delay","reboot_delay","list","get"], help="Action to apply to each host")
        ap.add_argument("--hosts", nargs="+", help="Space-separated host/IP list")
        ap.add_argument("--host-file", dest="host_file", help="File with one host/IP per line")
        bx = ap.add_mutually_exclusive_group(required=True)
        bx.add_argument("--port", nargs="+", type=int, help="Specific outlet number(s) on each host")
        bx.add_argument("--all", action="store_true", help="Operate on ALL ports on each host")
        ap.add_argument("--sort", choices=["outlet","name"], default="outlet")
        ap.add_argument("--no-color", action="store_true")
        ap.add_argument("--json", action="store_true", help="Emit JSON instead of a human table")
        ap.add_argument("--csv", help="Append aggregated rows to CSV at this path")
        ap.add_argument("--csv-header", choices=["never","auto","always"], default="auto")
    return ap

# ---------- Globals & Main ----------
@dataclass
class Globals:
    config: Optional[str]; host: Optional[str]; user: Optional[str]; password: Optional[str]
    insecure: Optional[bool]; secure: Optional[bool]; http: Optional[bool]; https: Optional[bool]
    pduid: Optional[int]; low_bank_max: Optional[int]; timeout: Optional[float]; retries: Optional[int]
    backoff: Optional[float]; parallel: Optional[int]; log_file: Optional[str]; debug: bool
    csv_header: str

def combine_tls_flags(insecure: Optional[bool], secure: Optional[bool]) -> Optional[bool]:
    if insecure is True: return True
    if secure is True: return False
    return None

def combine_scheme_flags(http: Optional[bool], https: Optional[bool]) -> Optional[bool]:
    if http is True: return True
    if https is True: return False
    return None

def main() -> None:
    gparser = build_global_parser()
    gargs, rest = gparser.parse_known_args()
    setup_logger(getattr(gargs, "log_file", None), getattr(gargs, "debug", False))
    log_cmdline()

    if gargs.config_help: print(CONFIG_HELP); sys.exit(0)
    if not gargs.action: gparser.print_help(); sys.exit(0)

    aparser = build_action_parser(gargs.action, raw_argv=rest)
    aargs = aparser.parse_args(rest)

    if gargs.action == "examples": sys.exit(run_examples())
    if gargs.action == "readme": sys.exit(run_readme())

    g = Globals(config=gargs.config, host=gargs.host, user=gargs.user, password=gargs.password,
                insecure=combine_tls_flags(gargs.insecure, gargs.secure), secure=gargs.secure,
                http=combine_scheme_flags(gargs.http, gargs.https), https=gargs.https,
                pduid=gargs.pduid, low_bank_max=gargs.low_bank_max, timeout=gargs.timeout,
                retries=gargs.retries, backoff=gargs.backoff, parallel=gargs.parallel,
                log_file=gargs.log_file, debug=gargs.debug, csv_header=getattr(gargs, "csv_header", "auto"))

    cfg = AppConfig(g.config)

    # Prompt password when user present but password missing
    if gargs.action not in {"hosts","setup"}:
        u, p = cfg.get_auth(g.user, g.password)
        if u and not p:
            try:
                p = getpass.getpass("Password: "); g.user, g.password = u, p
            except Exception: pass

    try:
        # Wire action handlers
        if gargs.action == "hosts": rc = run_hosts(cfg)
        elif gargs.action == "setup": rc = run_setup(gargs)
        elif gargs.action == "list":
            # inject global csv header policy into action args for writers
            setattr(aargs, "csv_header", g.csv_header)
            rc = run_list(aargs, g, cfg)
        elif gargs.action == "get":
            setattr(aargs, "csv_header", g.csv_header)
            rc = run_get(aargs, g, cfg)
        elif gargs.action == "on":
            setattr(aargs, "csv_header", g.csv_header)
            rc = run_on_off(aargs, g, cfg, PowerAction.ON)
        elif gargs.action == "off":
            setattr(aargs, "csv_header", g.csv_header)
            rc = run_on_off(aargs, g, cfg, PowerAction.OFF)
        elif gargs.action == "reboot":
            setattr(aargs, "csv_header", g.csv_header)
            rc = run_single_port(aargs, g, cfg, PowerAction.REBOOT)
        elif gargs.action == "on_delay":
            setattr(aargs, "csv_header", g.csv_header)
            rc = run_single_port(aargs, g, cfg, PowerAction.ON_DELAY)
        elif gargs.action == "off_delay":
            setattr(aargs, "csv_header", g.csv_header)
            rc = run_single_port(aargs, g, cfg, PowerAction.OFF_DELAY)
        elif gargs.action == "reboot_delay":
            setattr(aargs, "csv_header", g.csv_header)
            rc = run_single_port(aargs, g, cfg, PowerAction.REBOOT_DELAY)
        elif gargs.action == "multi":
            print("Tip: 'multi' is superseded by 'on/off --port .../--all' and 'batch'."); rc = 1
        elif gargs.action == "batch":
            setattr(aargs, "csv_header", g.csv_header)
            rc = run_batch(aargs, g, cfg)
        else:
            gparser.error("Unknown action"); return
        sys.exit(rc)
    except requests.HTTPError as e:
        if hasattr(aargs, "json") and aargs.json: emit_json({"ok": False, "error": f"HTTP {e.response.status_code}", "body": e.response.text})
        else:
            print(f"\nHTTP {e.response.status_code}: {e.response.reason}\n")
            print(e.response.text[:800])
            _print_examples_for(gargs.action)
        logger.exception("HTTP error"); sys.exit(2)
    except Exception as e:
        if hasattr(aargs, "json") and aargs.json: emit_json({"ok": False, "error": str(e)})
        else:
            print(f"Error: {e}")
            _print_examples_for(gargs.action)
        logger.exception("fatal error"); sys.exit(3)

if __name__ == "__main__":
    main()
