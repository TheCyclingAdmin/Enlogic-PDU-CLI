#!/usr/bin/env python3
import os, csv, io, configparser, re
from typing import Dict
from fastapi import FastAPI, Request, UploadFile, File, Form
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import requests
from requests.auth import HTTPBasicAuth

APP_ROOT=os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR=os.path.join(APP_ROOT,"templates"); STATIC_DIR=os.path.join(APP_ROOT,"static")

app=FastAPI(title="Enlogic Suite", version="2.0.3")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
templates=Jinja2Templates(directory=TEMPLATES_DIR)

DEFAULT_HOSTS=os.path.expanduser("~/.enlogic-hosts.ini")

LOGIN="/xhrlogin.jsp"
CTL_ENABLE="/outlet_control_enable_set"
CTL_SET="/xhroutpowstatset.jsp"
LOCK_SET1="/xhroutletlockset.jsp"
LOCK_SET2="/outlet_lock_set"
RF_BASE="/redfish/v1"
RF_OUTLETS=RF_BASE + "/PowerEquipment/RackPDUs/{pduid}/Outlets"

state={"user":"","password":"","admin_user":"","admin_password":""}

def load_hosts(path: str|None):
    p=os.path.expanduser(path) if path else DEFAULT_HOSTS
    hosts={}
    hc=configparser.ConfigParser()
    if os.path.exists(p):
        hc.read(p)
        if hc.has_section("hosts"): hosts=dict(hc.items("hosts"))
    return hosts

def resolve_host(hnick:str, hosts:Dict[str,str])->str:
    return hosts.get(hnick, hnick)

def rf(session, base, path, auth, insecure, timeout:int=10):
    r=session.get(base+path, auth=auth, verify=not insecure, timeout=timeout); r.raise_for_status(); return r.json()

def post(session, url, payload, insecure, timeout:int=10):
    r=session.post(url, json=payload, verify=not insecure, timeout=timeout); r.raise_for_status(); return r

def fetch_outlets(sess, base, pduid, auth, insecure):
    res={}
    try:
        coll=rf(sess, base, RF_OUTLETS.format(pduid=pduid), auth, insecure)
        for m in coll.get("Members") or []:
            uri=m.get("@odata.id") or m.get("href")
            if not uri: continue
            try: o=rf(sess, base, uri, auth, insecure)
            except Exception: continue
            name=(o.get("Name") or o.get("name") or "").strip()
            st=(o.get("PowerState") or (o.get("Status") or {}).get("State") or "").strip().lower()
            if st not in ("on","off"): st="unknown"
            n=None
            for k in ("Id","Name","name"):
                v=o.get(k)
                if isinstance(v,str):
                    mm=re.search(r'(\d+)', v)
                    if mm: n=int(mm.group(1)); break
            if not n and isinstance(uri,str):
                mm=re.search(r'OUTLET(\d+)', uri, re.I)
                if mm: n=int(mm.group(1))
            if n: res[n]={"name":name,"state":st}
    except Exception:
        pass
    return res

def login_cookie(sess, base, user, pw, insecure)->int:
    data=post(sess, base+LOGIN, {"username":user,"password":pw,"cookie":0}, insecure).json()
    if "cookie" not in data: raise RuntimeError("login failed")
    return int(data["cookie"])

def enable_control(sess, base, cookie, insecure): post(sess, base+CTL_ENABLE, {"cookie":cookie,"enable":1}, insecure)

def bitmask(n:int, split:int=24)->tuple[int,int]:
    if n<1: raise ValueError("Outlet numbers start at 1")
    return ((1<<(n-1),0) if n<=split else (0,1<<(n-1-split)))

def set_power(sess, base, cookie, pduid, n, action, insecure, split=24):
    POWSTAT={"off":0,"on":1,"off_delay":2,"on_delay":3,"reboot":4,"reboot_delay":5}
    o1,o2=bitmask(n, split)
    payload={"cookie":cookie,"outlet1":o1,"outlet2":o2,"pduid":pduid,"powstat":POWSTAT[action]}
    try: post(sess, base+CTL_SET, payload, insecure).json()
    except Exception: pass

def set_lock(sess, base, cookie, pduid, n, locked:bool, insecure, split=24):
    o1,o2=bitmask(n, split)
    payload={"cookie":cookie,"outlet1":o1,"outlet2":o2,"pduid":pduid,"lock": 1 if locked else 0}
    for ep in (LOCK_SET1, LOCK_SET2):
        try:
            post(sess, base+ep, payload, insecure).json()
            return True
        except Exception:
            continue
    return False

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("home.html", {"request": request})

@app.get("/hosts", response_class=HTMLResponse)
async def hosts_page(request: Request):
    hosts=load_hosts(None)
    return templates.TemplateResponse("hosts.html", {"request": request, "hosts": hosts})

@app.get("/pdu", response_class=HTMLResponse)
async def pdu_page(request: Request, host: str, pduid: int = 1, insecure: int = 1, http: int = 0):
    hosts=load_hosts(None)
    ip=resolve_host(host, hosts)
    base=f"{'http' if http else 'https'}://{ip}"
    auth=HTTPBasicAuth(state["user"], state["password"]) if (state["user"] and state["password"]) else None
    sess=requests.Session()
    outlets=fetch_outlets(sess, base, pduid, auth, bool(insecure))
    is_admin = bool(state["admin_user"] and state["admin_password"])
    return templates.TemplateResponse("pdu.html", {"request": request, "host": host, "ip": ip, "pduid": pduid, "rows": sorted(outlets.items()), "is_admin": is_admin})

@app.post("/action", response_class=RedirectResponse)
async def action(request: Request, host: str = Form(...), pduid: int = Form(1), verb: str = Form(...), ports: str = Form(""), insecure: int = Form(1), http: int = Form(0)):
    hosts=load_hosts(None)
    ip=resolve_host(host, hosts)
    base=f"{'http' if http else 'https'}://{ip}"
    sess=requests.Session()
    user=state["user"]; pw=state["password"]
    if not (user and pw):
        return RedirectResponse(f"/pdu?host={host}&pduid={pduid}", status_code=302)
    cookie=login_cookie(sess, base, user, pw, bool(insecure))
    enable_control(sess, base, cookie, bool(insecure))
    ports_list=[]
    for t in ports.split(","):
        t=t.strip()
        if not t: continue
        try: ports_list.append(int(t))
        except: continue
    if verb in ("on","off","reboot"):
        for n in ports_list: set_power(sess, base, cookie, pduid, n, verb, bool(insecure))
    elif verb in ("all-on","all-off"):
        auth=HTTPBasicAuth(user, pw)
        outlets=fetch_outlets(sess, base, pduid, auth, bool(insecure))
        targets=sorted(outlets) if outlets else list(range(1,49))
        for n in targets: set_power(sess, base, cookie, pduid, n, "on" if verb=="all-on" else "off", bool(insecure))
    elif verb in ("lock","unlock","lock-all","unlock-all"):
        admin_user=state["admin_user"]; admin_pw=state["admin_password"]
        if not (admin_user and admin_pw):
            return RedirectResponse(f"/pdu?host={host}&pduid={pduid}", status_code=302)
        auth=HTTPBasicAuth(user, pw)
        outlets=fetch_outlets(sess, base, pduid, auth, bool(insecure))
        targets=sorted(outlets) if "all" in verb else ports_list
        for n in targets:
            set_lock(sess, base, cookie, pduid, n, True if "lock" in verb and "unlock" not in verb else False, bool(insecure))
    return RedirectResponse(f"/pdu?host={host}&pduid={pduid}", status_code=302)

@app.get("/admin/creds", response_class=HTMLResponse)
async def creds_page(request: Request):
    return templates.TemplateResponse("creds.html", {"request": request, "state": state})

@app.post("/admin/creds", response_class=RedirectResponse)
async def creds_save(request: Request,
                     user: str = Form(""),
                     password: str = Form(""),
                     admin_user: str = Form(""),
                     admin_password: str = Form("")):
    state["user"]=user.strip()
    state["password"]=password.strip()
    state["admin_user"]=admin_user.strip()
    state["admin_password"]=admin_password.strip()
    return RedirectResponse("/admin/creds", status_code=302)

_metrics_cache={"rows":[]}

@app.get("/metrics", response_class=HTMLResponse)
async def metrics_page(request: Request):
    return templates.TemplateResponse("metrics.html", {"request": request, "rows": _metrics_cache["rows"]})

@app.post("/metrics/refresh", response_class=RedirectResponse)
async def metrics_refresh(request: Request, insecure: int = Form(1), http: int = Form(0)):
    hosts=load_hosts(None)
    rows=[]
    sess=requests.Session()
    auth=HTTPBasicAuth(state["user"], state["password"]) if (state["user"] and state["password"]) else None
    for nick, ip in hosts.items():
        base=f"{'http' if http else 'https'}://{ip}"
        try:
            coll=rf(sess, base, RF_OUTLETS.format(pduid=1), auth, bool(insecure))
            count=len(coll.get("Members") or [])
        except Exception:
            count=0
        rows.append({"nick":nick,"ip":ip,"outlets":count})
    _metrics_cache["rows"]=rows
    return RedirectResponse("/metrics", status_code=302)
