#!/usr/bin/env python3
# file: pdu_web.py
from __future__ import annotations

import os
import re
import json
import html
import logging
from dataclasses import dataclass
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

from flask import Flask, request, render_template_string, jsonify
import requests
from requests import Session
from requests.adapters import HTTPAdapter
from requests.auth import HTTPBasicAuth
from urllib3.util.retry import Retry

# ---------------------- TLS noise off (self-signed is common) ----------------------
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

# ---------------------- Endpoints ----------------------
LOGIN = "/xhrlogin.jsp"
CTL_ENABLE = "/outlet_control_enable_set"
CTL_SET = "/xhroutpowstatset.jsp"
RF_PDU = "/redfish/v1/PowerEquipment/RackPDUs/{pduid}"
RF_GROUPS = "/redfish/v1/PowerEquipment/RackPDUs/{pduid}/OutletGroups"
RF_OUTLETS = "/redfish/v1/PowerEquipment/RackPDUs/{pduid}/Outlets"

POWSTAT = {"off":0,"on":1,"off_delay":2,"on_delay":3,"reboot":4,"reboot_delay":5}

DEFAULT_CFG = os.path.expanduser("~/.enlogic.ini")
APP_PORT = int(os.environ.get("FLASK_PORT", "8000"))

# ---------------------- Minimal client ----------------------
def _make_retry(retries: int, backoff: float) -> Retry:
    base = dict(total=retries, connect=retries, read=retries, backoff_factor=backoff,
                status_forcelist=(502,503,504,521,522,524), raise_on_status=False)
    try:
        return Retry(allowed_methods=frozenset({"GET","POST"}), **base)  # urllib3 v2
    except TypeError:
        return Retry(method_whitelist=frozenset({"GET","POST"}), **base)  # urllib3 v1

def _parse_outlet_number(obj: dict, uri_hint: Optional[str]) -> Optional[int]:
    for k in ("outlet","Outlet","OutletNumber","Number","Id","MemberId"):
        v = obj.get(k)
        if isinstance(v,int): return v
        if isinstance(v,str) and v.isdigit(): return int(v)
    for k in ("Name","name","Label","OutletName","Description"):
        v = obj.get(k)
        if isinstance(v,str):
            m = re.search(r"(\d+)", v)
            if m: return int(m.group(1))
    if uri_hint:
        m = re.search(r"(?:Outlets|OUTLET)[/ ]?(\d+)", uri_hint, flags=re.I)
        if m: return int(m.group(1))
    return None

def _parse_outlet_name(obj: dict) -> str:
    for k in ("Label","OutletName","Name","name","Description"):
        v = obj.get(k)
        if isinstance(v,str) and v.strip(): return v.strip()
    return ""

def _norm_state(raw: Any) -> Optional[str]:
    s = str(raw).strip().lower()
    m = {"on":"on","off":"off","1":"on","0":"off","enabled":"on","disabled":"off","poweringon":"on","poweringoff":"off"}
    return m.get(s)

def _parse_outlet_state(obj: dict) -> Optional[str]:
    for k in ("PowerState","OutletState","OutletStatus","State"):
        if k in obj:
            st = _norm_state(obj[k])
            if st in {"on","off"}: return st
    status = obj.get("Status")
    if isinstance(status, dict):
        st = _norm_state(status.get("State"))
        if st in {"on","off"}: return st
    return None

def _bitmask(port: int, low_max: int = 24) -> Tuple[int,int]:
    if port < 1: raise ValueError("Port numbers start at 1.")
    return ((1 << (port-1), 0) if port <= low_max else (0, 1 << (port - low_max - 1)))

@dataclass
class ClientOpts:
    base: str
    insecure: bool
    timeout: float
    retries: int
    backoff: float
    debug: bool = False

class EnlogicClient:
    def __init__(self, opts: ClientOpts):
        self.base = opts.base.rstrip("/")
        self.insecure = opts.insecure
        self.timeout = opts.timeout
        self.debug = opts.debug
        self.sess = self._build_session(opts.retries, opts.backoff)

    def _build_session(self, retries: int, backoff: float) -> Session:
        sess = requests.Session()
        retry = _make_retry(retries, backoff)
        adapter = HTTPAdapter(max_retries=retry, pool_maxsize=16)
        sess.mount("http://", adapter); sess.mount("https://", adapter)
        return sess

    def _get(self, path_or_url: str, auth: Optional[HTTPBasicAuth]) -> dict:
        url = path_or_url if path_or_url.startswith(("http://","https://")) else f"{self.base}{path_or_url}"
        if self.debug: print(f"[debug] GET {url}")
        r = self.sess.get(url, auth=auth, verify=not self.insecure, timeout=self.timeout); r.raise_for_status()
        return r.json()

    def _post_json(self, path_or_url: str, payload: dict) -> requests.Response:
        url = path_or_url if path_or_url.startswith(("http://","https://")) else f"{self.base}{path_or_url}"
        if self.debug: print(f"[debug] POST {url} payload={payload}")
        r = self.sess.post(url, json=payload, verify=not self.insecure, timeout=self.timeout); r.raise_for_status()
        return r

    def login_cookie(self, user: str, password: str) -> int:
        data = self._post_json(LOGIN, {"username":user,"password":password,"cookie":0}).json()
        if "cookie" not in data: raise RuntimeError("Login failed: no cookie in response")
        return int(data["cookie"])

    def enable_control(self, cookie: int) -> None:
        self._post_json(CTL_ENABLE, {"cookie":cookie,"enable":1})

    def set_power(self, cookie: int, pduid: int, port: int, action: str, low_max: int) -> dict:
        o1, o2 = _bitmask(port, low_max)
        payload = {"cookie":cookie,"outlet1":o1,"outlet2":o2,"pduid":pduid,"powstat":POWSTAT[action]}
        try:
            return self._post_json(CTL_SET, payload).json()
        except json.JSONDecodeError:
            return {"status":"OK"}

    def fetch_maps(self, pduid: int, auth: HTTPBasicAuth) -> Tuple[Dict[int,str], Dict[int,str]]:
        status: Dict[int,str] = {}; names: Dict[int,str] = {}
        # Groups
        try:
            groups = self._get(RF_GROUPS.format(pduid=pduid), auth)
            glist = groups.get("groups") or groups.get("Members") or []
            flat: List[Tuple[dict, Optional[str]]] = []
            if isinstance(glist, list):
                for g in glist:
                    if isinstance(g, dict) and "Members" in g:
                        for m in g["Members"]:
                            if isinstance(m, dict) and ("@odata.id" in m or "href" in m):
                                flat.append(({"__link__":True}, m.get("@odata.id") or m.get("href")))
                            elif isinstance(m, dict):
                                flat.append((m, None))
            for obj, uri in flat:
                if obj.get("__link__"):
                    try: o = self._get(uri, auth); self._eat_member(o, uri, status, names)
                    except Exception: pass
                else:
                    self._eat_member(obj, None, status, names)
        except Exception:
            pass
        # Outlets (expanded then members)
        if not status or len(status) < 2:
            for expand in (".$expand=.", ".$expand=*", ""):
                try:
                    path = RF_OUTLETS.format(pduid=pduid) + (("?"+expand[2:]) if expand else "")
                    coll = self._get(path, auth)
                    members = []
                    seq = coll.get("Members") or coll.get("Outlets") or []
                    if isinstance(seq, list):
                        for it in seq:
                            if isinstance(it, dict) and ("@odata.id" in it or "href" in it):
                                members.append(({"__link__":True}, it.get("@odata.id") or it.get("href")))
                            elif isinstance(it, dict):
                                members.append((it, None))
                    for obj, uri in members:
                        if obj.get("__link__"):
                            try: o = self._get(uri, auth); self._eat_member(o, uri, status, names)
                            except Exception: pass
                        else:
                            self._eat_member(obj, None, status, names)
                    if status: break
                except Exception:
                    pass
        if not status: status = {n:"unknown" for n in range(1,49)}
        return status, names

    def _eat_member(self, obj: dict, uri: Optional[str], status: Dict[int,str], names: Dict[int,str]) -> None:
        n = _parse_outlet_number(obj, uri)
        if not n: return
        nm = _parse_outlet_name(obj); st = _parse_outlet_state(obj)
        if nm: names[n] = nm
        if st in {"on","off"}: status[n] = st
        else: status.setdefault(n, "unknown")

    def pdu_label(self, pduid: int, auth: HTTPBasicAuth) -> str:
        try:
            obj = self._get(RF_PDU.format(pduid=pduid), auth)
            return obj.get("Name") or obj.get("Id") or self.base.split("://",1)[-1]
        except Exception:
            return self.base.split("://",1)[-1]

# ---------------------- Config helpers ----------------------
def _load_cfg(path: Optional[str]):
    import configparser
    cfg = configparser.ConfigParser()
    for candidate in [path, os.environ.get("PDU_CONFIG"), DEFAULT_CFG]:
        if candidate and os.path.exists(candidate):
            cfg.read(candidate)
            return cfg, candidate
    return cfg, path or os.environ.get("PDU_CONFIG") or DEFAULT_CFG

def _cfg_bool(cfg, sec: str, opt: str, fallback: bool) -> bool:
    try:
        return cfg.getboolean(sec, opt, fallback=fallback)
    except Exception:
        return fallback

def _cfg_int(cfg, sec: str, opt: str, fallback: int) -> int:
    try:
        return cfg.getint(sec, opt, fallback=fallback)
    except Exception:
        return fallback

def _cfg_float(cfg, sec: str, opt: str, fallback: float) -> float:
    try:
        return cfg.getfloat(sec, opt, fallback=fallback)
    except Exception:
        return fallback

def _hosts_map(cfg) -> Dict[str,str]:
    return dict(cfg.items("hosts")) if cfg.has_section("hosts") else {}

def _pduid_map(cfg) -> Dict[str,int]:
    if cfg.has_section("pduid"):
        try:
            return {k:int(v) for k,v in cfg.items("pduid")}
        except Exception:
            pass
    return {}

def _resolve_host(token: str, cfg) -> Tuple[str, Optional[str]]:
    hmap = _hosts_map(cfg)
    return (hmap[token], token) if token in hmap else (token, None)

def _pduid_for(host_token: str, resolved_ip: str, cfg, fallback: int) -> int:
    pmap = _pduid_map(cfg)
    if host_token in pmap: return pmap[host_token]
    if resolved_ip in pmap: return pmap[resolved_ip]
    return fallback

# ---------------------- Flask app ----------------------
app = Flask(__name__)
logging.getLogger("werkzeug").setLevel(logging.WARNING)

INDEX_HTML = """<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>Enlogic PDU Web</title>
  <style>
    body{font-family:system-ui,Arial,sans-serif;margin:20px;line-height:1.4;}
    fieldset{border:1px solid #ccc;padding:12px;margin-bottom:16px;}
    legend{font-weight:700;}
    input[type=text],input[type=password],input[type=number]{padding:6px;width:260px;}
    textarea{width:520px;height:90px;padding:6px;}
    label{margin-right:8px;}
    table{border-collapse:collapse;margin:10px 0;min-width:600px;}
    th,td{border:1px solid #ddd;padding:6px 8px;text-align:left;}
    th{background:#f6f6f6;}
    .state-on{color:#0a0;font-weight:700}
    .state-off{color:#a00;font-weight:700}
    .host-card{border:1px solid #ddd;padding:10px;margin:12px 0;border-radius:6px;}
    .btn{padding:5px 9px;margin:2px;border:1px solid #888;border-radius:4px;background:#eee;cursor:pointer}
    .btn:hover{background:#e2e2e2}
    .row-actions .btn{font-size:12px;padding:3px 6px}
    .small{font-size:12px;color:#555}
    .muted{color:#777}
    .pill{display:inline-block;border:1px solid #bbb;border-radius:999px;padding:2px 8px;margin:2px;cursor:pointer;}
    .pill:hover{background:#f3f3f3}
    .flex{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
  </style>
</head>
<body>
  <h2>Enlogic PDU Web</h2>
  <form method="post" action="{{ url_for('scan') }}">
    <fieldset>
      <legend>Config</legend>
      <div class="flex">
        <label>Config path:</label>
        <input name="config_path" value="{{ preset.config_path|e }}" style="width:360px"/>
        <span class="muted">Used to load [auth], [defaults], [hosts], [pduid].</span>
      </div>
    </fieldset>

    <fieldset>
      <legend>Targets</legend>
      <div>
        <label>IP(s) or nicknames (one per line or comma-separated):</label><br/>
        <textarea name="hosts" placeholder="10.0.0.10, lab.pdu1">{{ preset.hosts }}</textarea>
      </div>
      {% if config_hosts %}
        <div class="small muted">Configured [hosts]: click to insert</div>
        <div>
          {% for nick, ip in config_hosts %}
            <span class="pill" onclick="addHost('{{ nick }}')">{{ nick }}</span>
            <span class="pill" onclick="addHost('{{ ip }}')">{{ ip }}</span>
          {% endfor %}
          {% if config_hosts|length > 0 %}
            <span class="pill" onclick="insertAll()">Insert all</span>
          {% endif %}
        </div>
      {% endif %}
    </fieldset>

    <fieldset>
      <legend>Auth & Network</legend>
      <div><label>User:</label><input name="user" value="{{ preset.user }}"/>
           <label>Password:</label><input type="password" name="password" value="{{ preset.password }}"/></div>
      <div><label><input type="checkbox" name="http" {% if preset.http %}checked{% endif %}/> Use HTTP (not HTTPS)</label>
           <label><input type="checkbox" name="insecure" {% if preset.insecure %}checked{% endif %}/> Skip TLS verification</label></div>
      <div class="small">Self-signed certs → enable “Skip TLS verification”.</div>
    </fieldset>

    <fieldset>
      <legend>Advanced</legend>
      <label>PDU ID</label> <input type="number" name="pduid" value="{{ preset.pduid or 1 }}" min="1" style="width:80px"/>
      <label>Low bank max</label> <input type="number" name="low_bank_max" value="{{ preset.low_bank_max or 24 }}" min="1" style="width:100px"/>
      <label>Timeout</label> <input type="number" step="0.1" name="timeout" value="{{ preset.timeout or 10.0 }}" style="width:90px"/>
      <label>Retries</label> <input type="number" name="retries" value="{{ preset.retries or 3 }}" style="width:80px"/>
      <label>Backoff</label> <input type="number" step="0.1" name="backoff" value="{{ preset.backoff or 0.5 }}" style="width:90px"/>
      <label>Parallel</label> <input type="number" name="parallel" value="{{ preset.parallel or 6 }}" style="width:90px"/>
      <div class="small muted">Per-host PDU ID overrides from [pduid] are applied automatically.</div>
    </fieldset>

    <button class="btn" type="submit">Scan PDUs</button>
  </form>

  {% if results %}
    <hr/>
    <h3>Results</h3>
    {% for res in results %}
      <div class="host-card" id="host-{{ res.host_id }}">
        <div>
          <b>Host:</b> {{ res.host }}{% if res.nick %} <span class="muted">(nick: {{ res.nick }})</span>{% endif %} &nbsp;|&nbsp; <b>PDU:</b> {{ res.label }}
          <div style="float:right;margin-top:-2px;">
            <button class="btn" onclick="actAll('{{ res.host }}','on')">All On</button>
            <button class="btn" onclick="actAll('{{ res.host }}','off')">All Off</button>
            <button class="btn" onclick="actAll('{{ res.host }}','reboot')">Reboot All</button>
          </div>
        </div>
        <div class="small">Base: {{ res.base }} &nbsp;|&nbsp; PDU ID used: {{ res.pduid }}</div>
        <table id="tbl-{{ res.host_id }}">
          <thead><tr><th>Outlet</th><th>Label / Name</th><th>State</th><th>Actions</th></tr></thead>
          <tbody>
            {% for row in res.rows %}
              <tr data-port="{{ row.n }}">
                <td>{{ "%02d"|format(row.n) }}</td>
                <td>{{ row.name|e }}</td>
                <td class="state {{ 'state-on' if row.state=='on' else ('state-off' if row.state=='off' else '') }}">{{ row.state }}</td>
                <td class="row-actions">
                  <button class="btn" onclick="actOne('{{ res.host }}', {{ row.n }}, 'on')">On</button>
                  <button class="btn" onclick="actOne('{{ res.host }}', {{ row.n }}, 'off')">Off</button>
                  <button class="btn" onclick="actOne('{{ res.host }}', {{ row.n }}, 'reboot')">Reboot</button>
                </td>
              </tr>
            {% endfor %}
          </tbody>
        </table>
      </div>
    {% endfor %}
  {% endif %}

<script>
const cfg = {{ js_cfg|tojson }};
const configHosts = {{ config_hosts|tojson }};

function addHost(token){
  const ta = document.querySelector('textarea[name="hosts"]');
  if(!ta) return;
  let v = ta.value.trim();
  if(v && !v.endsWith("\\n")) v += "\\n";
  ta.value = v + token;
}
function insertAll(){
  const ta = document.querySelector('textarea[name="hosts"]');
  if(!ta) return;
  const toks = [];
  for(const [nick, ip] of configHosts){
    toks.push(nick);
  }
  ta.value = toks.join("\\n");
}

function stateClass(s){ return s === 'on' ? 'state-on' : (s === 'off' ? 'state-off' : ''); }

async function actOne(host, port, action){
  const payload = {host, port, action, ...cfg};
  const r = await fetch('{{ url_for("api_action") }}', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload)});
  const data = await r.json();
  if(!data.ok){ alert('Error: ' + (data.error || 'unknown')); return; }
  const hostId = 'host-' + host.replaceAll('.', '-');
  const table = document.querySelector('#' + hostId + ' table tbody');
  if(!table) return;
  for(const row of data.rows){
    if(row.outlet === port){
      const tr = table.querySelector('tr[data-port="'+port+'"]');
      if(tr){
        const td = tr.querySelector('td.state');
        td.textContent = row.state;
        td.className = 'state ' + stateClass(row.state);
      }
    }
  }
}

async function actAll(host, action){
  if(!confirm(action.toUpperCase() + " ALL outlets on " + host + " ?")) return;
  const payload = {host, action, all:true, ...cfg};
  const r = await fetch('{{ url_for("api_action") }}', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify(payload)});
  const data = await r.json();
  if(!data.ok){ alert('Error: ' + (data.error || 'unknown')); return; }
  const hostId = 'host-' + host.replaceAll('.', '-');
  const table = document.querySelector('#' + hostId + ' table tbody');
  if(!table) return;
  for(const row of data.rows){
    const tr = table.querySelector('tr[data-port="'+row.outlet+'"]');
    if(tr){
      const td = tr.querySelector('td.state');
      td.textContent = row.state;
      td.className = 'state ' + stateClass(row.state);
    }
  }
}
</script>
</body></html>
"""

# ---------------------- Utilities ----------------------
def _host_tokens(raw: str) -> List[str]:
    if not raw: return []
    toks = [t.strip() for t in raw.replace(",", "\n").splitlines()]
    return [t for t in toks if t]

def _host_id(host: str) -> str:
    return host.replace(".", "-").replace(":", "-")

def _build_base(host: str, http: bool) -> str:
    return f"{'http' if http else 'https'}://{host}"

def _rows_from_status(status: Dict[int,str], names: Dict[int,str]) -> List[Dict[str, Any]]:
    return [{"n": n, "name": names.get(n,""), "state": status.get(n,"unknown")} for n in sorted(status)]

# ---------------------- Scan / Action ----------------------
def _scan_one(resolved_host: str, nick: Optional[str], user: str, password: str, http: bool, insecure: bool,
              pduid: int, low_bank_max: int, timeout: float, retries: int, backoff: float) -> Dict[str, Any]:
    base = _build_base(resolved_host, http)
    opts = ClientOpts(base=base, insecure=insecure, timeout=timeout, retries=retries, backoff=backoff)
    client = EnlogicClient(opts)
    auth = HTTPBasicAuth(user, password)
    label = client.pdu_label(pduid, auth)
    status, names = client.fetch_maps(pduid, auth)
    return {
        "ok": True,
        "host": resolved_host,
        "nick": nick,
        "host_id": _host_id(resolved_host),
        "base": base,
        "label": label,
        "pduid": pduid,
        "rows": _rows_from_status(status, names),
    }

def _action_one(resolved_host: str, user: str, password: str, http: bool, insecure: bool,
                pduid: int, low_bank_max: int, timeout: float, retries: int, backoff: float,
                action: str, ports: Optional[List[int]], all_ports: bool) -> Dict[str, Any]:
    base = _build_base(resolved_host, http)
    opts = ClientOpts(base=base, insecure=insecure, timeout=timeout, retries=retries, backoff=backoff)
    client = EnlogicClient(opts)
    auth = HTTPBasicAuth(user, password)
    if all_ports:
        status, _ = client.fetch_maps(pduid, auth)
        ports = sorted(status.keys())
    ports = ports or []
    cookie = client.login_cookie(user, password)
    client.enable_control(cookie)
    # why: continue best-effort even if one fails
    for p in ports:
        try:
            client.set_power(cookie, pduid, p, action, low_bank_max)
        except Exception:
            pass
    status2, names2 = client.fetch_maps(pduid, auth)
    rows = [{"outlet": n, "name": names2.get(n,""), "state": status2.get(n,"unknown")} for n in sorted(status2)]
    return {"ok": True, "rows": rows}

# ---------------------- Routes ----------------------
@app.route("/", methods=["GET"])
def index():
    cfg, cfg_path = _load_cfg(None)
    # fallbacks pulled from INI
    preset = {
        "config_path": cfg_path or DEFAULT_CFG,
        "hosts": os.environ.get("PDU_HOSTS", ""),
        "user": cfg.get("auth","user", fallback=os.environ.get("PDU_USER","")),
        "password": cfg.get("auth","password", fallback=os.environ.get("PDU_PASSWORD","")),
        "http": _cfg_bool(cfg, "defaults", "http", os.environ.get("PDU_HTTP","").lower() in ("1","true","yes")),
        "insecure": _cfg_bool(cfg, "defaults", "insecure", os.environ.get("PDU_INSECURE","").lower() in ("1","true","yes")),
        "pduid": _cfg_int(cfg, "defaults", "pduid", int(os.environ.get("PDU_ID","1"))),
        "low_bank_max": _cfg_int(cfg, "defaults", "low_bank_max", int(os.environ.get("PDU_LOW_MAX","24"))),
        "timeout": _cfg_float(cfg, "defaults", "timeout", float(os.environ.get("PDU_TIMEOUT","10"))),
        "retries": _cfg_int(cfg, "defaults", "retries", int(os.environ.get("PDU_RETRIES","3"))),
        "backoff": _cfg_float(cfg, "defaults", "backoff", float(os.environ.get("PDU_BACKOFF","0.5"))),
        "parallel": _cfg_int(cfg, "defaults", "parallel", int(os.environ.get("PDU_PARALLEL","6"))),
    }
    config_hosts = sorted(_hosts_map(cfg).items())
    return render_template_string(INDEX_HTML, preset=preset, results=None, js_cfg={}, config_hosts=config_hosts)

@app.route("/scan", methods=["POST"])
def scan():
    # reload cfg each time so edits are picked up
    cfg_path = request.form.get("config_path") or os.environ.get("PDU_CONFIG") or DEFAULT_CFG
    cfg, cfg_path = _load_cfg(cfg_path)
    hosts_raw = request.form.get("hosts","")
    tokens = _host_tokens(hosts_raw)
    user = request.form.get("user","") or cfg.get("auth","user", fallback="")
    password = request.form.get("password","") or cfg.get("auth","password", fallback="")
    http = (request.form.get("http") == "on") if "http" in request.form else _cfg_bool(cfg, "defaults", "http", False)
    insecure = (request.form.get("insecure") == "on") if "insecure" in request.form else _cfg_bool(cfg, "defaults", "insecure", False)
    pduid_fallback = int(request.form.get("pduid","") or _cfg_int(cfg, "defaults", "pduid", 1))
    low_bank_max = int(request.form.get("low_bank_max","") or _cfg_int(cfg, "defaults", "low_bank_max", 24))
    timeout = float(request.form.get("timeout","") or _cfg_float(cfg, "defaults", "timeout", 10.0))
    retries = int(request.form.get("retries","") or _cfg_int(cfg, "defaults", "retries", 3))
    backoff = float(request.form.get("backoff","") or _cfg_float(cfg, "defaults", "backoff", 0.5))
    parallel = max(1, int(request.form.get("parallel","") or _cfg_int(cfg, "defaults", "parallel", 6)))

    config_hosts = sorted(_hosts_map(cfg).items())
    if not tokens or not user or not password:
        preset = {
            "config_path": cfg_path, "hosts":"\n".join(tokens), "user":user, "password":password,
            "http":http, "insecure":insecure, "pduid":pduid_fallback, "low_bank_max":low_bank_max,
            "timeout":timeout, "retries":retries, "backoff":backoff, "parallel":parallel
        }
        return render_template_string(INDEX_HTML, preset=preset, results=[], js_cfg={}, config_hosts=config_hosts)

    jobs: List[Tuple[str, Optional[str], int]] = []
    for tok in tokens:
        ip, nick = _resolve_host(tok, cfg)
        pduid = _pduid_for(tok, ip, cfg, pduid_fallback)
        jobs.append((ip, nick, pduid))

    results: List[Dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=parallel) as ex:
        futs = {ex.submit(_scan_one, ip, nick, user, password, http, insecure, pduid, low_bank_max, timeout, retries, backoff): (ip, nick, pduid) for (ip, nick, pduid) in jobs}
        for f in as_completed(futs):
            ip, nick, pduid = futs[f]
            try:
                res = f.result()
            except Exception as e:
                res = {"ok": False, "host": ip, "nick": nick, "host_id": _host_id(ip), "base": _build_base(ip, http),
                       "label": "(error)", "pduid": pduid, "rows": [], "error": str(e)}
            results.append(res)
    results.sort(key=lambda r: (r.get("host",""), r.get("nick") or ""))

    js_cfg = {
        "config_path": cfg_path,  # not used server-side; kept for reference
        "user": user, "password": password, "http": http, "insecure": insecure,
        "low_bank_max": low_bank_max, "timeout": timeout, "retries": retries, "backoff": backoff
    }
    preset = {
        "config_path": cfg_path, "hosts":"\n".join(tokens), "user":user, "password":password,
        "http":http, "insecure":insecure, "pduid":pduid_fallback, "low_bank_max":low_bank_max,
        "timeout":timeout, "retries":retries, "backoff":backoff, "parallel":parallel
    }
    return render_template_string(INDEX_HTML, preset=preset, results=results, js_cfg=js_cfg, config_hosts=config_hosts)

@app.route("/api/action", methods=["POST"])
def api_action():
    data = request.get_json(force=True, silent=True) or {}
    try:
        cfg, _ = _load_cfg(data.get("config_path"))
        host = data["host"]
        action = data["action"]
        if action not in ("on","off","reboot"): return jsonify({"ok": False, "error": "invalid_action"})
        user = data.get("user") or cfg.get("auth","user", fallback="")
        password = data.get("password") or cfg.get("auth","password", fallback="")
        http = bool(data.get("http", _cfg_bool(cfg, "defaults", "http", False)))
        insecure = bool(data.get("insecure", _cfg_bool(cfg, "defaults", "insecure", False)))
        # Per-host PDU ID override from [pduid] if present
        pduid_fallback = _cfg_int(cfg, "defaults", "pduid", 1)
        pduid = _pduid_for(host, host, cfg, pduid_fallback)
        low_bank_max = int(data.get("low_bank_max", _cfg_int(cfg, "defaults", "low_bank_max", 24)))
        timeout = float(data.get("timeout", _cfg_float(cfg, "defaults", "timeout", 10.0)))
        retries = int(data.get("retries", _cfg_int(cfg, "defaults", "retries", 3)))
        backoff = float(data.get("backoff", _cfg_float(cfg, "defaults", "backoff", 0.5)))
        all_ports = bool(data.get("all", False))
        ports = None
        if not all_ports:
            if "port" not in data: return jsonify({"ok": False, "error": "missing_port"})
            ports = [int(data["port"])]
        res = _action_one(host, user, password, http, insecure, pduid, low_bank_max, timeout, retries, backoff, action, ports, all_ports)
        return jsonify({"ok": True, "rows": res["rows"]})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 200

# ---------------------- Entrypoint ----------------------
if __name__ == "__main__":
    host = os.environ.get("FLASK_HOST", "0.0.0.0")
    port = int(os.environ.get("FLASK_PORT", str(APP_PORT)))
    app.run(host=host, port=port, debug=False)
