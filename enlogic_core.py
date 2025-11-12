# =========================================
# file: enlogic_core.py
# =========================================
"""
Core logic: HTTP/Redfish client, config, parsing, actions, and output helpers.
Compatible with Python 3.9+ (RHEL 8/9, Ubuntu 22.04/24.04).
"""

from __future__ import annotations

import configparser
import csv
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

# Constants
LOGIN = "/xhrlogin.jsp"
CTL_ENABLE = "/outlet_control_enable_set"
CTL_SET = "/xhroutpowstatset.jsp"
RF_PDU = "/redfish/v1/PowerEquipment/RackPDUs/{pduid}"
RF_GROUPS = "/redfish/v1/PowerEquipment/RackPDUs/{pduid}/OutletGroups"
RF_OUTLETS = "/redfish/v1/PowerEquipment/RackPDUs/{pduid}/Outlets"
RF_OUTLET_ITEM = "/redfish/v1/PowerEquipment/RackPDUs/{pduid}/Outlets/OUTLET{n}"

DEFAULT_CFG = os.path.expanduser("~/.enlogic.ini")
DEFAULT_TIMEOUT = 10.0
DEFAULT_RETRIES = 3
DEFAULT_BACKOFF = 0.5
DEFAULT_PARALLEL = 6

CSV_HEADER = ["index","date","time","host","pdu","outlet","name","state","action","ok"]

# Logging
logger = logging.getLogger("enlogic_cli")
if not logger.handlers:
    _handler = logging.StreamHandler(sys.stderr)
    _handler.setLevel(logging.INFO)
    _handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(_handler)
logger.setLevel(logging.DEBUG)

# TLS warnings (controlled by flags)
try:
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)  # type: ignore[attr-defined]
except Exception:
    pass

# -------- Utilities --------
def now_date_time() -> Tuple[str, str]:
    dt = datetime.now()
    return dt.date().isoformat(), dt.time().isoformat(timespec="seconds")

def norm_state(value: Any) -> Optional[str]:
    if isinstance(value, bool): return "on" if value else "off"
    if isinstance(value, (int, float)): return "on" if value else "off"
    if isinstance(value, str):
        s = value.strip().lower()
        m = {"on":"on","off":"off","open":"off","close":"on","closed":"on","opened":"off","1":"on","0":"off"}
        return m.get(s)
    return None

def parse_outlet_number(obj: dict, uri_hint: Optional[str]) -> Optional[int]:
    for k in ("outlet","Outlet","OutletNumber","Number","Id","MemberId"):
        v = obj.get(k) 
        if isinstance(v, int): return v
        if isinstance(v, str) and v.isdigit(): return int(v)
    for k in ("Name","name","Label","OutletName","Description"):
        v = obj.get(k)
        if isinstance(v, str):
            m = re.search(r"(\d+)", v) 
            if m: 
                try: return int(m.group(1))
                except Exception: pass
    if uri_hint and isinstance(uri_hint, str):
        m = re.search(r"OUTLET(\d+)", uri_hint)
        if m:
            try: return int(m.group(1))
            except Exception: pass
    return None

def parse_outlet_name(obj: dict) -> str:
    for k in ("Label","OutletName","Name","name","Description"):
        v = obj.get(k)
        if isinstance(v, str) and v.strip(): return v.strip()
    return ""

def parse_outlet_state(obj: dict) -> Optional[str]:
    for k in ("PowerState","OutletState","OutletStatus","State"):
        if k in obj:
            st = norm_state(obj[k]) 
            if st in {"on","off"}: return st
    status = obj.get("Status")
    if isinstance(status, dict):
        st = norm_state(status.get("State"))
        if st in {"on","off"}: return st
    return None

def parse_outlet_locked(obj: dict) -> Optional[bool]:
    v = obj.get("PowerControlLocked")
    if isinstance(v, bool): return v
    status = obj.get("Status")
    if isinstance(status, dict) and isinstance(status.get("Locked"), bool):
        return status.get("Locked")
    return None

def bitmask(port: int, low_bank_max: int) -> Tuple[int, int]:
    if port <= 0: return 0,0
    if port <= low_bank_max: return (1 << (port-1)), 0
    return 0, (1 << (port - low_bank_max - 1))

# -------- Config --------
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
        self.path = path or DEFAULT_CFG
        self.cfg = configparser.ConfigParser()
        if os.path.exists(self.path):
            self.cfg.read(self.path)

    def hosts_map(self) -> Dict[str, str]:
        return dict(self.cfg.items("hosts")) if self.cfg.has_section("hosts") else {}

    def pduid_map(self) -> Dict[str, int]:
        if not self.cfg.has_section("pduid"):
            return {}
        return {k: int(v) for k, v in self.cfg.items("pduid")}

    def defaults(self) -> Defaults:
        d = Defaults()
        if self.cfg.has_section("defaults"):
            d.pduid = self.cfg.getint("defaults","pduid", fallback=d.pduid)
            d.insecure = self.cfg.getboolean("defaults","insecure", fallback=d.insecure)
            d.http = self.cfg.getboolean("defaults","http", fallback=d.http)
            d.low_bank_max = self.cfg.getint("defaults","low_bank_max", fallback=d.low_bank_max)
            d.timeout = self.cfg.getfloat("defaults","timeout", fallback=d.timeout)
            d.retries = self.cfg.getint("defaults","retries", fallback=d.retries)
            d.backoff = self.cfg.getfloat("defaults","backoff", fallback=d.backoff)
        return d

    def get_auth(self, user_arg: Optional[str], pw_arg: Optional[str]) -> Tuple[Optional[str], Optional[str]]:
        user = user_arg or self.cfg.get("auth", "user", fallback=None)
        pw = pw_arg or self.cfg.get("auth", "password", fallback=None)
        return user, pw

    def get_super_auth(self, user_arg: Optional[str] = None, pw_arg: Optional[str] = None) -> Tuple[Optional[str], Optional[str]]:
        user = user_arg or self.cfg.get("superadmin", "user", fallback=None)
        pw = pw_arg or self.cfg.get("superadmin", "password", fallback=None)
        return user, pw

    def resolve_host_label(self, host_arg: str) -> Tuple[str, Optional[str]]:
        hmap = self.hosts_map()
        return (hmap[host_arg], host_arg) if host_arg in hmap else (host_arg, None)

# -------- HTTP Client --------
def _make_retry(retries: int, backoff: float) -> Retry:
    base_kwargs = dict(
        total=retries, connect=retries, read=retries,
        backoff_factor=backoff, status_forcelist=(502,503,504,521,522,524),
        raise_on_status=False,
    )
    try:
        return Retry(allowed_methods=frozenset({"GET","POST"}), **base_kwargs)  # urllib3 v2
    except TypeError:
        return Retry(method_whitelist=frozenset({"GET","POST"}), **base_kwargs)  # urllib3 v1

class PDUClient:
    def __init__(self, base_url: str, insecure: bool, timeout: float, retries: int, backoff: float, debug: bool):
        self.base = base_url.rstrip("/")
        self.insecure = insecure
        self.timeout = timeout
        self.debug = debug
        self.session = self._build_session(retries, backoff)

    def _dbg(self, msg: str) -> None:
        if self.debug:
            sys.stderr.write(f"[debug] {msg}\n")
            logger.debug(msg)

    def _build_session(self, retries: int, backoff: float) -> Session:
        sess = requests.Session()
        retry = _make_retry(retries, backoff)
        adapter = HTTPAdapter(max_retries=retry, pool_maxsize=8)
        sess.mount("http://", adapter)
        sess.mount("https://", adapter)
        return sess

    def rf_get(self, path_or_abs: str, auth: Optional[HTTPBasicAuth]) -> dict:
        url = path_or_abs if path_or_abs.startswith(("http://","https://")) else f"{self.base}{path_or_abs}"
        self._dbg(f"GET {url}")
        r = self.session.get(url, auth=auth, verify=not self.insecure, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def rf_post(self, path_or_abs: str, auth: Optional[HTTPBasicAuth], payload: dict) -> requests.Response:
        url = path_or_abs if path_or_abs.startswith(("http://","https://")) else f"{self.base}{path_or_abs}"
        self._dbg(f"POST {url} payload={payload}")
        r = self.session.post(url, json=payload, auth=auth, verify=not self.insecure, timeout=self.timeout)
        r.raise_for_status()
        return r

    def post_json(self, path_or_abs: str, payload: dict) -> requests.Response:
        url = path_or_abs if path_or_abs.startswith(("http://","https://")) else f"{self.base}{path_or_abs}"
        self._dbg(f"POST {url} payload={payload}")
        r = self.session.post(url, json=payload, verify=not self.insecure, timeout=self.timeout)
        r.raise_for_status()
        return r

    def login_cookie(self, user: str, password: str) -> int:
        data = self.post_json(LOGIN, {"username":user,"password":password,"cookie":0}).json()
        if "cookie" not in data: raise RuntimeError("Login failed: no cookie in response")
        return int(data["cookie"])

    def enable_control(self, cookie: int) -> None:
        self.post_json(CTL_ENABLE, {"cookie":cookie,"enable":1})

    def set_power(self, cookie: int, pduid: int, port: int, action: "PowerAction", low_max: int) -> dict:
        o1,o2 = bitmask(port, low_max)
        payload = {"cookie":cookie,"outlet1":o1,"outlet2":o2,"pduid":pduid,"powstat":POWSTAT[action]}
        try:
            return self.post_json(CTL_SET, payload).json()
        except json.JSONDecodeError:
            return {"status":"OK"}

    def set_lock(self, pduid: int, port: int, locked: bool, auth: HTTPBasicAuth) -> bool:
        uri = RF_OUTLET_ITEM.format(pduid=pduid, n=port)
        try:
            self.rf_post(uri, auth, {"PowerControlLocked": bool(locked)})
            return True
        except Exception as e:
            self._dbg(f"lock POST failed for outlet {port}: {e}")
            return False

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

    def fetch_locks_map(self, pduid: int, auth: HTTPBasicAuth) -> Dict[int, Optional[bool]]:
        locks: Dict[int, Optional[bool]] = {}
        try:
            coll = self.rf_get(RF_OUTLETS.format(pduid=pduid), auth)
            members = self._collect_members(coll)
            for obj, uri in members:
                cur = obj
                if isinstance(obj, dict) and obj.get("__link__") and uri:
                    cur = self.rf_get(uri, auth)
                n = parse_outlet_number(cur, uri)
                if n:
                    lk = parse_outlet_locked(cur)
                    locks[n] = lk if lk is not None else locks.get(n, None)
        except Exception as e:
            self._dbg(f"locks map fetch failed: {e}")
        return locks

    def fetch_maps(self, pduid: int, auth: HTTPBasicAuth) -> Tuple[Dict[int,str], Dict[int,str]]:
        status: Dict[int,str] = {}; names: Dict[int,str] = {}
        try:
            groups = self.rf_get(RF_GROUPS.format(pduid=pduid), auth)
            group_list = groups.get("groups") or groups.get("Members") or []
            if isinstance(group_list, list):
                for item in group_list:
                    try:
                        uri = item.get("@odata.id") if isinstance(item, dict) else None
                        if uri:
                            grp = self.rf_get(uri, auth)
                            members = grp.get("Members") or grp.get("Outlets") or []
                            if isinstance(members, list):
                                for mem in members:
                                    if isinstance(mem, dict):
                                        self._parse_member_obj(mem, None, status, names)
                    except Exception as e:
                        self._dbg(f"group member parse fail: {e}")
        except Exception as e:
            self._dbg(f"groups fetch failed: {e}")
        if not status or len(status) < 2:
            try:
                coll = self.rf_get(RF_OUTLETS.format(pduid=pduid), auth)
                members = self._collect_members(coll)
                for obj, uri in members:
                    if obj.get("__link__") and uri:
                        try:
                            o = self.rf_get(uri, auth); self._parse_member_obj(o, uri, status, names)
                        except Exception as e:
                            self._dbg(f"outlet GET {uri} failed: {e}")
                    elif isinstance(obj, dict):
                        self._parse_member_obj(obj, None, status, names)
            except Exception as e:
                self._dbg(f"outlets collection fetch failed: {e}")
        if not status:
            status = {n:"unknown" for n in range(1,49)}
        return status, names

    def pdu_display(self, pduid: int, auth: HTTPBasicAuth, override: Optional[str]=None) -> str:
        if override: return override
        try:
            obj = self.rf_get(RF_PDU.format(pduid=pduid), auth)
            return obj.get("Name") or obj.get("Id") or self.base.split("://",1)[-1]
        except Exception as e:
            self._dbg(f"pdu_display failed: {e}")
            return self.base.split("://",1)[-1]

# -------- Output --------
def isatty_color(enabled_flag: bool) -> bool:
    return enabled_flag and sys.stdout.isatty()

def colorize(text: str, state: str, enable: bool) -> str:
    if not enable: return text
    palette = {"on":"\033[32m","off":"\033[31m","unknown":"\033[90m"}
    reset = "\033[0m"
    color = palette.get(state, "")
    return f"{color}{text}{reset}" if color else text

def print_table(title: str, rows: Iterable[Tuple[int,str,str,Optional[bool]]], use_color: bool) -> None:
    print(f"\n{title}\n")
    print("Outlet | Label / Name                 | State   | Lock")
    print("-------+------------------------------+---------+------")
    for n, nm, st, lk in rows:
        state_disp = colorize(st, st, use_color)
        lk_disp = "locked" if lk else ("unlocked" if lk is not None else "-")
        print(f"{n:02d}     | {nm[:28]:<28} | {state_disp:<7} | {lk_disp}")
    print()

def print_batch_table(title: str, rows: Iterable[Tuple[str,int,str,str,Optional[bool]]], use_color: bool) -> None:
    print(f"\n{title}\n")
    print("Host             | Outlet | Label / Name                 | State   | Lock")
    print("-----------------+--------+------------------------------+---------+------")
    for host, n, nm, st, lk in rows:
        state_disp = colorize(st, st, use_color)
        lk_disp = "locked" if lk else ("unlocked" if lk is not None else "-")
        print(f"{host:<16} | {n:02d}    | {nm[:28]:<28} | {state_disp:<7} | {lk_disp}")
    print()

def emit_json(data: dict) -> None:
    print(json.dumps(data, indent=2))

# -------- CSV --------
def _csv_target_for_append(path: str, header: List[str], mode: str) -> Tuple[str, bool]:
    def _new_name(p: str) -> str:
        base, ext = os.path.splitext(p)
        i = 1
        while True:
            cand = f"{base}-{i}{ext}"
            if not os.path.exists(cand): return cand
            i += 1
    try:
        if not os.path.exists(path):
            return path, True
        with open(path, "r") as f:
            first = f.readline().strip()
        if first == ",".join(header):
            if mode == "always": return path, True
            return path, False
        sys.stderr.write(f"(!) CSV header mismatch in {path}. Writing to a new file.\n")
        new_path = _new_name(path)
        return new_path, (mode != "never")
    except Exception:
        new_path = _new_name(path)
        return new_path, (mode != "never")

def _csv_write(path: str, rows: List[Dict[str, Any]], header_mode: str) -> None:
    target, write_header = _csv_target_for_append(path, CSV_HEADER, header_mode)
    with open(target, "a", newline="") as f:
        w = csv.DictWriter(f, fieldnames=CSV_HEADER)
        if write_header: w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in CSV_HEADER})
    logger.info("csv: wrote %d rows -> %s", len(rows), target)

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

def _csv_print_stdout(rows: List[Dict[str, Any]]) -> None:
    w = csv.DictWriter(sys.stdout, fieldnames=CSV_HEADER)
    w.writeheader()
    for r in rows:
        w.writerow({k: r.get(k, "") for k in CSV_HEADER})

# -------- Actions --------
class PowerAction(str, Enum):
    OFF = "off"
    ON = "on"
    OFF_DELAY = "off_delay"
    ON_DELAY = "on_delay"
    REBOOT = "reboot"
    REBOOT_DELAY = "reboot_delay"

POWSTAT: Dict["PowerAction", int] = {
    PowerAction.OFF: 0,
    PowerAction.ON: 1,
    PowerAction.OFF_DELAY: 2,
    PowerAction.ON_DELAY: 3,
    PowerAction.REBOOT: 4,
    PowerAction.REBOOT_DELAY: 5,
}

def _build_client(base: str, insecure: bool, timeout: float, retries: int, backoff: float, debug: bool) -> PDUClient:
    return PDUClient(base, insecure, timeout, retries, backoff, debug)

def parse_sort_key(sort: str, status: Dict[int,str], names: Dict[int,str]) -> List[int]:
    if sort == "outlet": return sorted(status)
    return sorted(status, key=lambda n: (names.get(n,"").lower(), n))

def fetch_table_for(host: str, pduid: int, base: str, client: PDUClient, auth: HTTPBasicAuth, sort: str):
    status, names = client.fetch_maps(pduid, auth)
    label = client.pdu_display(pduid, auth, override=base.split("://",1)[-1])
    order = parse_sort_key(sort, status, names)
    locks = client.fetch_locks_map(pduid, auth)
    rows = [(n, names.get(n,""), status.get(n,"unknown"), locks.get(n)) for n in order]
    return label, rows, status, names, locks

def _emit_by_format(format_: str, title: str, base: str, label: str,
                    rows: List[Tuple[int,str,str,Optional[bool]]],
                    action_name: str,
                    csv_path: Optional[str], csv_header: str,
                    use_color: bool, as_json_payload: Optional[dict] = None) -> None:
    if format_ == "json":
        emit_json(as_json_payload if as_json_payload is not None else {"ok": True, "action": action_name})
    elif format_ == "csv":
        csv_rows = _csv_rows_from_table(base, label, [(n,nm,st) for (n,nm,st,_) in rows], action=action_name)
        _csv_print_stdout(csv_rows)
        if csv_path:
            _csv_write(csv_path, csv_rows, header_mode=csv_header)
    else:
        print_table(title, rows, use_color)
        if csv_path:
            _csv_write(csv_path, _csv_rows_from_table(base, label, [(n,nm,st) for (n,nm,st,_) in rows], action=action_name), header_mode=csv_header)

def list_action(host: str, pduid: int, base: str, client: PDUClient, auth: HTTPBasicAuth, sort: str,
                out_format: str, no_color: bool, csv_path: Optional[str], csv_header: str) -> None:
    label, rows, status, names, _locks = fetch_table_for(host, pduid, base, client, auth, sort)
    date_str, time_str = now_date_time()
    payload = {
        "ok": True, "action": "list", "date": date_str, "time": time_str,
        "host": host, "pdu": label, "base": base,
        "outlets": [{"n": n, "name": nm, "state": st, "lock": (True if lk else False if lk is not None else None)}
                    for (n, nm, st, lk) in rows],
    }
    _emit_by_format(out_format, f"PDU: {label}  ({base})", base, label, rows, "list", csv_path, csv_header,
                    isatty_color(not no_color), payload)

def get_action(port: Optional[int], label_query: Optional[str], host: str, pduid: int, base: str, client: PDUClient,
               auth: HTTPBasicAuth, out_format: str, no_color: bool, csv_path: Optional[str], csv_header: str) -> None:
    _, rows, status, names, locks = fetch_table_for(host, pduid, base, client, auth, "outlet")
    target: Optional[int] = None
    if port is not None:
        target = port
    elif label_query:
        for n, nm in names.items():
            if nm == label_query:
                target = n; break
    if target is None:
        print("Not found. Use --port or --label to identify an outlet.")
        return
    row = (target, names.get(target,""), status.get(target,"unknown"), locks.get(target))
    date_str, time_str = now_date_time()
    payload = {"ok": True, "action": "get", "date": date_str, "time": time_str,
               "host": host, "base": base,
               "outlet": {"n": row[0], "name": row[1], "state": row[2], "lock": (True if row[3] else False if row[3] is not None else None)}}
    _emit_by_format(out_format, f"PDU: {host}  ({base})", base, host, [row], "get", csv_path, csv_header,
                    isatty_color(not no_color), payload)

class PowerAction(str, Enum):
    OFF = "off"
    ON = "on"
    OFF_DELAY = "off_delay"
    ON_DELAY = "on_delay"
    REBOOT = "reboot"
    REBOOT_DELAY = "reboot_delay"

POWSTAT: Dict["PowerAction", int] = {
    PowerAction.OFF: 0,
    PowerAction.ON: 1,
    PowerAction.OFF_DELAY: 2,
    PowerAction.ON_DELAY: 3,
    PowerAction.REBOOT: 4,
    PowerAction.REBOOT_DELAY: 5,
}

def on_off_action(action: PowerAction, ports: List[int], all_flag: bool, host: str, base: str, pduid: int, client: PDUClient,
                  auth_user: str, auth_pw: str, auth_basic: HTTPBasicAuth, low_bank_max: int,
                  sort: str, out_format: str, no_color: bool, csv_path: Optional[str], csv_header: str) -> None:
    if all_flag:
        status, _ = client.fetch_maps(pduid, auth_basic); ports_to_change = sorted(status.keys())
    else:
        ports_to_change = ports
    cookie = client.login_cookie(auth_user, auth_pw); client.enable_control(cookie)
    results = []
    for p in ports_to_change:
        try:
            client.set_power(cookie, pduid, p, action, low_bank_max)
            results.append({"port":p, "ok": True})
        except Exception as ex:
            results.append({"port":p, "ok": False, "error": str(ex)})
    label, rows, _, _, _ = fetch_table_for(host, pduid, base, client, auth_basic, sort)
    date_str, time_str = now_date_time()
    payload = {"ok": True, "action": action.value, "date": date_str, "time": time_str,
               "host": host, "pdu": label, "base": base, "ports": results,
               "outlets": [{"n": n, "name": nm, "state": st, "lock": (True if lk else False if lk is not None else None)}
                           for (n,nm,st,lk) in rows]}
    _emit_by_format(out_format, f"PDU: {label}  ({base})", base, label, rows, action.value, csv_path, csv_header,
                    isatty_color(not no_color), payload)

def lock_unlock_action(locked: bool, ports: List[int], all_flag: bool, host: str, base: str, pduid: int,
                       client: PDUClient, auth_basic: HTTPBasicAuth,
                       sort: str, out_format: str, no_color: bool, csv_path: Optional[str], csv_header: str) -> None:
    if all_flag:
        status, _ = client.fetch_maps(pduid, auth_basic); ports_to_change = sorted(status.keys())
    else:
        ports_to_change = ports
    results = [{"port": p, "ok": client.set_lock(pduid, p, locked, auth_basic)} for p in ports_to_change]
    label, rows, _, _, _ = fetch_table_for(host, pduid, base, client, auth_basic, sort)
    date_str, time_str = now_date_time()
    payload = {"ok": True, "action": ("lock" if locked else "unlock"),
               "date": date_str, "time": time_str,
               "host": host, "pdu": label, "base": base, "ports": results,
               "outlets": [{"n": n, "name": nm, "state": st, "lock": (True if lk else False if lk is not None else None)}
                           for (n,nm,st,lk) in rows]}
    _emit_by_format(out_format, f"PDU: {label}  ({base})", base, label, rows,
                    "lock" if locked else "unlock", csv_path, csv_header,
                    isatty_color(not no_color), payload)

# Batch (read-only demo)
def _batch_worker(host: str, base: str, pduid: int, client: PDUClient, auth_basic: HTTPBasicAuth) -> Tuple[str, List[Tuple[str,int,str,str,Optional[bool]]]]:
    status, names = client.fetch_maps(pduid, auth_basic)
    locks = client.fetch_locks_map(pduid, auth_basic)
    rows = [(base.split("://",1)[-1], n, names.get(n,""), status.get(n,"unknown"), locks.get(n)) for n in sorted(status)]
    return host, rows

def batch_list(hosts: List[str], build_client_params: dict, cfg: AppConfig, out_format: str, json_out: bool, no_color: bool) -> None:
    # out_format respected; json_out kept for backward compat (alias of --format json)
    rows_all: List[Tuple[str,int,str,str,Optional[bool]]] = []
    with ThreadPoolExecutor(max_workers=build_client_params.get("parallel", DEFAULT_PARALLEL)) as ex:
        futs = {}
        for h in hosts:
            host_ip, _ = cfg.resolve_host_label(h)
            d = cfg.defaults()
            pduid_lookup = cfg.pduid_map().get(h) or cfg.pduid_map().get(host_ip)
            pduid = build_client_params.get("pduid") or pduid_lookup or d.pduid
            base = f"{'http' if (build_client_params.get('http', d.http)) else 'https'}://{host_ip}"
            client = _build_client(base, build_client_params.get("insecure", d.insecure), build_client_params.get("timeout", d.timeout),
                                   build_client_params.get("retries", d.retries), build_client_params.get("backoff", d.backoff),
                                   build_client_params.get("debug", False))
            user, pw = cfg.get_auth(build_client_params.get("user"), build_client_params.get("password"))
            auth_basic = HTTPBasicAuth(user or "", pw or "")
            futs[ex.submit(_batch_worker, h, base, pduid, client, auth_basic)] = h
        for fut in as_completed(futs):
            _host, rows = fut.result()
            rows_all.extend(rows)
    if out_format == "json" or json_out:
        date_str, time_str = now_date_time()
        emit_json({"ok": True, "action": "batch_list", "date": date_str, "time": time_str,
                   "rows": [{"host": h, "n": n, "name": nm, "state": st, "lock": (True if lk else False if lk is not None else None)}
                            for (h,n,nm,st,lk) in rows_all]})
    elif out_format == "csv":
        # project batch rows into CSV rows (host,n,name,state)
        from io import StringIO
        # reuse table CSV with host column in 'host'; pdu left blank
        csv_rows = _csv_rows_from_batch([(h,n,nm,st) for (h,n,nm,st,_lk) in rows_all], action="batch_list")
        _csv_print_stdout(csv_rows)
    else:
        print_batch_table("Batch results", rows_all, isatty_color(not no_color))

# -------- Setup helpers --------
def write_config(path: str, user: str, password: str, http: bool, insecure: bool,
                 pduid: Optional[int] = None, low_bank_max: Optional[int] = None) -> None:
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

def write_super_to_config(path: str, user: str, password: str) -> None:
    cfg = configparser.ConfigParser()
    if os.path.exists(path): cfg.read(path)
    if not cfg.has_section("superadmin"): cfg.add_section("superadmin")
    cfg.set("superadmin","user", user); cfg.set("superadmin","password", password)
    with open(path, "w") as f: cfg.write(f)
    try:
        if os.name == "posix": os.chmod(path, 0o600)
    except Exception:
        pass
