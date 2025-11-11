#!/usr/bin/env python3
import argparse, configparser, csv, json, os, re, sys, time
from typing import Dict, List, Any, Optional
import concurrent.futures as cf
import requests
from requests.auth import HTTPBasicAuth
try:
    from requests.packages.urllib3.exceptions import InsecureRequestWarning  # type: ignore
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except Exception:
    pass

LOGIN="/xhrlogin.jsp"
CTL_ENABLE="/outlet_control_enable_set"
CTL_SET="/xhroutpowstatset.jsp"
LOCK_SET1="/xhroutletlockset.jsp"
LOCK_SET2="/outlet_lock_set"

RF_BASE="/redfish/v1"
RF_PDU=RF_BASE + "/PowerEquipment/RackPDUs/{pduid}"
RF_OUTLETS=RF_BASE + "/PowerEquipment/RackPDUs/{pduid}/Outlets"
RF_MANAGERS=RF_BASE + "/Managers"

POWSTAT={"off":0,"on":1,"off_delay":2,"on_delay":3,"reboot":4,"reboot_delay":5}
DEFAULT_CFG=os.path.expanduser("~/.enlogic.ini")
DEFAULT_HOSTS=os.path.expanduser("~/.enlogic-hosts.ini")

def load_cfg(path:str):
    cfg=configparser.ConfigParser()
    if path and os.path.exists(path): cfg.read(path)
    elif os.path.exists(DEFAULT_CFG): cfg.read(DEFAULT_CFG)
    return cfg

def load_hosts(path:str|None):
    p=os.path.expanduser(path) if path else DEFAULT_HOSTS
    hosts={}; groups={}
    hc=configparser.ConfigParser()
    if os.path.exists(p):
        hc.read(p)
        if hc.has_section("hosts"): hosts=dict(hc.items("hosts"))
        if hc.has_section("groups"):
            for g,line in hc.items("groups"):
                lst=[t.strip() for t in re.split(r'[,\s]+', line) if t.strip()]
                if lst: groups[g]=lst
    return hosts, groups

def resolve_host(hnick:str, hosts:Dict[str,str])->str:
    return hosts.get(hnick, hnick)

def rf(session, base, path, auth, insecure, timeout:int=10):
    r=session.get(base+path, auth=auth, verify=not insecure, timeout=timeout); r.raise_for_status(); return r.json()

def post(session, url, payload, insecure, timeout:int=10):
    r=session.post(url, json=payload, verify=not insecure, timeout=timeout); r.raise_for_status(); return r

def fetch_outlets(sess, base, pduid, auth, insecure)->Dict[int, Dict[str,str]]:
    res={}
    try:
        coll=rf(sess, base, RF_OUTLETS.format(pduid=pduid), auth, insecure)
        for m in coll.get("Members") or []:
            uri=m.get("@odata.id") or m.get("href")
            if not uri: continue
            try:
                o=rf(sess, base, uri, auth, insecure)
            except Exception:
                continue
            name=(o.get("Name") or o.get("name") or "").strip()
            state=(o.get("PowerState") or (o.get("Status") or {}).get("State") or "").strip().lower()
            if state not in ("on","off"): state="unknown"
            n=None
            for key in ("Id","Name","name"):
                v=o.get(key)
                if isinstance(v,str):
                    mm=re.search(r'(\d+)', v)
                    if mm: n=int(mm.group(1)); break
            if not n and isinstance(uri,str):
                mm=re.search(r'OUTLET(\d+)', uri, re.I)
                if mm: n=int(mm.group(1))
            if n: res[n]={"name":name,"state":state}
    except Exception:
        pass
    return res

def _first(*vals):
    for v in vals:
        if isinstance(v,str) and v.strip(): return v.strip()
        if v not in (None, "", [], {}): return v
    return None

def _flatten_oem(oem: Any, limit:int=2) -> Dict[str,str]:
    out={}
    def walk(prefix, obj, depth):
        if depth>limit: return
        if isinstance(obj, dict):
            for k,v in obj.items():
                key=(prefix+"_"+k) if prefix else k
                if isinstance(v,(str,int,float)) and (str(v).strip()!=""):
                    out[key]=str(v).strip()
                elif isinstance(v, dict):
                    walk(key, v, depth+1)
    if isinstance(oem, dict): walk("", oem, 0)
    return out

def _dig_numbers(obj, keys:List[str]) -> Optional[str]:
    from collections import deque
    if not isinstance(obj, dict): return None
    dq=deque([("", obj)])
    while dq:
        _, cur = dq.popleft()
        for k,v in cur.items():
            kl=k.lower()
            if any(kl==t or kl.endswith(t) or t in kl for t in keys):
                if isinstance(v,(int,float)): return str(v)
                if isinstance(v,str) and v.strip(): return v.strip()
            if isinstance(v, dict):
                dq.append((kl, v))
    return None

def fetch_inventory(sess, base, pduid, auth, insecure)->Dict[str,Any]:
    inv={"name":None,"manufacturer":None,"model":None,"serial":None,"part_number":None,"sku":None,"firmware":None,"asset_tag":None,"hardware_revision":None,
         "rated_current_amps":None,"nominal_voltage":None,"line_frequency_hz":None,"rated_power_watts":None}
    try:
        mgr_root=rf(sess, base, RF_MANAGERS, auth, insecure)
        members=mgr_root.get("Members") or []
        if members:
            href=members[0].get("@odata.id") or members[0].get("href")
            if href:
                mgr=rf(sess, base, href, auth, insecure)
                inv["firmware"]=_first(mgr.get("FirmwareVersion"), mgr.get("Version"))
                inv["manufacturer"]=_first(mgr.get("Manufacturer"))
                inv["model"]=_first(mgr.get("Model"))
                inv["serial"]=_first(mgr.get("SerialNumber"))
                inv["part_number"]=_first(mgr.get("PartNumber"), mgr.get("SparePartNumber"))
                inv["sku"]=_first(mgr.get("SKU"))
                inv["name"]= _first(mgr.get("Name"))
                inv["asset_tag"]=_first(mgr.get("AssetTag"))
                inv["hardware_revision"]=_first(mgr.get("HardwareVersion"), mgr.get("HardwareRevision"))
                oem=_flatten_oem(mgr.get("Oem", {}))
                if oem: inv["oem"]=oem
    except Exception:
        pass
    try:
        pdu=rf(sess, base, RF_PDU.format(pduid=pduid), auth, insecure)
        inv["name"]= _first(inv["name"], pdu.get("Name"), pdu.get("Id"))
        inv["manufacturer"]= _first(inv["manufacturer"], pdu.get("Manufacturer"))
        inv["model"]= _first(inv["model"], pdu.get("Model"))
        inv["serial"]= _first(inv["serial"], pdu.get("SerialNumber"))
        inv["part_number"]= _first(inv["part_number"], pdu.get("PartNumber"), pdu.get("SparePartNumber"))
        inv["sku"]= _first(inv["sku"], pdu.get("SKU"))
        inv["firmware"]= _first(inv["firmware"], pdu.get("FirmwareVersion"))
        inv["asset_tag"]= _first(inv["asset_tag"], pdu.get("AssetTag"))
        inv["hardware_revision"]= _first(inv["hardware_revision"], pdu.get("HardwareVersion"), pdu.get("HardwareRevision"))
        inv["rated_current_amps"] = _first(_dig_numbers(pdu, ["ratedcurrentamps","ratedcapacityamps","ratedcurrent","maxcurrent","rated_amps"]))
        inv["nominal_voltage"]    = _first(_dig_numbers(pdu, ["nominalvoltage","voltage","ratedvoltage"]))
        inv["line_frequency_hz"]  = _first(_dig_numbers(pdu, ["linefrequencyhz","frequencyhz","frequency"]))
        inv["rated_power_watts"]  = _first(_dig_numbers(pdu, ["ratedpowerwatts","capacitywatts","powercapacity"]))
        oem=_flatten_oem(pdu.get("Oem", {}))
        if oem: inv.setdefault("oem",{}).update(oem)
    except Exception:
        pass
    outlets=fetch_outlets(sess, base, pduid, auth, insecure)
    inv["outlet_count"]= max(outlets) if outlets else 0
    for k,v in list(inv.items()):
        if v in (None,""): inv[k]="unknown"
    return inv

def login_cookie(sess, base, user, pw, insecure)->int:
    data=post(sess, base+LOGIN, {"username":user,"password":pw,"cookie":0}, insecure).json()
    if "cookie" not in data: raise RuntimeError("login failed")
    return int(data["cookie"])

def enable_control(sess, base, cookie, insecure): post(sess, base+CTL_ENABLE, {"cookie":cookie,"enable":1}, insecure)

def bitmask(n:int, split:int=24)->tuple[int,int]:
    if n<1: raise ValueError("Outlet numbers start at 1")
    return ((1<<(n-1),0) if n<=split else (0,1<<(n-1-split)))

def set_power(sess, base, cookie, pduid, n, action, insecure, split=24):
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

def _append_csv(path:str, row:Dict[str,Any], header:List[str]):
    p=os.path.expanduser(path)
    exists=os.path.exists(p)
    if exists:
        with open(p,"r",encoding="utf-8") as f:
            first=f.readline().strip()
        if first and first.replace("\ufeff","") != ",".join(header):
            base,ext=os.path.splitext(p); p=f"{base}.{int(time.time())}{ext}"; exists=False
    with open(p, "a", encoding="utf-8", newline="") as f:
        w=csv.DictWriter(f, fieldnames=header)
        if not exists: w.writeheader()
        w.writerow({k:row.get(k,"") for k in header})
    return p

def parse_csv_hosts(file_path:str)->List[str]:
    rows=[]; p=os.path.expanduser(file_path)
    with open(p,"r",encoding="utf-8") as f:
        r=csv.DictReader(f)
        for row in r:
            h=row.get("host") or row.get("ip") or row.get("nickname")
            if h: rows.append(h.strip())
    return rows

def inventory_one(host: str, user: Optional[str], pw: Optional[str], pduid: int, http: bool, insecure: bool, timeout:int)->Dict[str,Any]:
    base=f"{'http' if http else 'https'}://{host}"; sess=requests.Session()
    auth=HTTPBasicAuth(user or "", pw or "") if (user and pw) else None
    try:
        inv=fetch_inventory(sess, base, pduid, auth, insecure)
        return {"ok":True, "host":host, **inv}
    except requests.HTTPError as e:
        return {"ok":False, "host":host, "error": f"HTTP {e.response.status_code}"}
    except requests.Timeout:
        return {"ok":False, "host":host, "error":"timeout"}
    except Exception as e:
        return {"ok":False, "host":host, "error": str(e)}

def main():
    actions=[
        "list","get","getlist",
        "on","off","reboot","multi","all-on","all-off",
        "lock","unlock","lock-all","unlock-all",
        "inventory","inventory-scan"
    ]
    ap=argparse.ArgumentParser(description="Enlogic PDU CLI (v2.0.3)")
    ap.add_argument("--config","-c"); ap.add_argument("--hosts-file")
    ap.add_argument("--host","-H"); ap.add_argument("--user","-u"); ap.add_argument("--password","-P")
    ap.add_argument("--pduid","-d", type=int, default=1); ap.add_argument("--http", action="store_true")
    ap.add_argument("--insecure","-k", action="store_true"); ap.add_argument("--port","-p", nargs="+", type=int)
    ap.add_argument("--json", action="store_true"); ap.add_argument("--csv", help="Inventory CSV append path")
    ap.add_argument("--timeout", type=int, default=10)
    ap.add_argument("--parallel", type=int, default=8)
    ap.add_argument("--csv-hosts", help="CSV with 'host' or 'nickname' for inventory-scan")
    ap.add_argument("--yes", action="store_true", help="Assume Yes for confirmations")
    ap.add_argument("--action","-a"); ap.add_argument("maybe_action", nargs="?")
    args=ap.parse_args()

    cfg=load_cfg(args.config or DEFAULT_CFG); hosts_map,_=load_hosts(args.hosts_file)
    action=(args.action or args.maybe_action or "").lower()
    if not action or action not in actions: ap.print_help(); sys.exit(0)

    user=args.user or cfg.get("auth","user", fallback=None)
    pw=args.password or cfg.get("auth","password", fallback=None)
    http=args.http or cfg.getboolean("defaults","http", fallback=False)
    insecure=args.insecure or cfg.getboolean("defaults","insecure", fallback=False)

    def base_for(host_in:str)->str:
        ip=resolve_host(host_in, hosts_map); return f"{'http' if http else 'https'}://{ip}", ip

    if action in ("list","get","getlist","inventory"):
        if not args.host: print("Error: --host/-H required"); sys.exit(1)
        base, ip = base_for(args.host)
        sess=requests.Session()
        auth=HTTPBasicAuth(user or "", pw or "") if (user and pw) else None
        if action=="inventory":
            inv=fetch_inventory(sess, base, args.pduid, auth, insecure)
            out={"ok":True,"host":args.host,"ip":ip,"pduid":args.pduid, **inv}
            if args.csv:
                ts=time.localtime(); date=f"{ts.tm_year:04d}-{ts.tm_mon:02d}-{ts.tm_mday:02d}"; t=f"{ts.tm_hour:02d}:{ts.tm_min:02d}:{ts.tm_sec:02d}"
                header=["index","date","time","host","ip","pduid","name","manufacturer","model","serial","part_number","sku","firmware","hardware_revision","asset_tag","rated_current_amps","nominal_voltage","line_frequency_hz","rated_power_watts","outlet_count"]
                p=os.path.expanduser(args.csv); idx=1
                if os.path.exists(p):
                    try:
                        with open(p,"r",encoding="utf-8") as f: idx=sum(1 for _ in f)
                        idx=max(1, idx)
                    except Exception: idx=1
                row={k:out.get(k,"") for k in header if k not in ("index","date","time")}
                row={"index":idx,"date":date,"time":t, **row}
                _append_csv(args.csv, row, header)
                print(json.dumps({"ok":True,"csv":os.path.expanduser(args.csv),"row":row}, indent=2) if args.json else f"Appended inventory to {os.path.expanduser(args.csv)}")
            else:
                if args.json: print(json.dumps(out, indent=2))
                else:
                    print("\nInventory")
                    for k in ["host","ip","pduid","name","manufacturer","model","serial","part_number","sku","firmware","hardware_revision","asset_tag","rated_current_amps","nominal_voltage","line_frequency_hz","rated_power_watts","outlet_count"]:
                        print(f"{k:24} : {out.get(k,'')}")
            sys.exit(0)
        outlets=fetch_outlets(sess, base, args.pduid, auth, insecure)
        def print_table(ip, outlets):
            print(f"\nPDU: {ip}\n"); print("Outlet | Label / Name                 | State"); print("-------+------------------------------+--------")
            for n,d in sorted(outlets.items()): print(f"{n:02d}     | {d['name'][:28]:<28} | {d['state']}")
            print()
        if action=="list":
            if args.json: print(json.dumps({"ok":True,"host":args.host,"ip":ip,"rows":[{"outlet":n,**d} for n,d in sorted(outlets.items())]}, indent=2))
            else: print_table(ip, outlets)
            sys.exit(0)
        if action in ("get","getlist"):
            if args.port:
                n=args.port[0]; d=outlets.get(n, {"name":"","state":"unknown"})
                if args.json: print(json.dumps({"ok":True,"host":args.host,"ip":ip,"rows":[{"outlet":n,**d}]}, indent=2))
                else:
                    if action=="getlist": print_table(ip, outlets)
                    print(f"\nRequested outlet\n\nOutlet | Label / Name                 | State\n-------+------------------------------+--------")
                    print(f"{n:02d}     | {d['name'][:28]:<28} | {d['state']}"); print()
            else:
                if args.json: print(json.dumps({"ok":True,"host":args.host,"ip":ip,"rows":[{"outlet":n,**d} for n,d in sorted(outlets.items())]}, indent=2))
                else: print_table(ip, outlets)
            sys.exit(0)

    if action=="inventory-scan":
        if args.csv_hosts:
            hosts = parse_csv_hosts(args.csv_hosts)
        else:
            hm,_ = load_hosts(args.hosts_file); hosts = sorted(set(list(hm.values()) + list(hm.keys())))
        resolved=[]; hm,_=load_hosts(args.hosts_file)
        for h in hosts:
            ip=resolve_host(h, hm)
            if ip not in resolved: resolved.append(ip)
        if not resolved:
            print("No hosts to scan. Provide --csv-hosts or --hosts-file with [hosts] section."); sys.exit(1)
        def job(h: str):
            return inventory_one(h, user, pw, args.pduid, http, insecure, args.timeout)
        results=[]
        with cf.ThreadPoolExecutor(max_workers=max(1,args.parallel)) as ex:
            for res in ex.map(job, resolved):
                results.append(res)
        ok=[r for r in results if r.get("ok")]
        fail=[r for r in results if not r.get("ok")]
        if args.csv:
            header=["index","date","time","host","name","manufacturer","model","serial","part_number","sku","firmware","hardware_revision","asset_tag","rated_current_amps","nominal_voltage","line_frequency_hz","rated_power_watts","outlet_count"]
            ts=time.localtime(); date=f"{ts.tm_year:04d}-{ts.tm_mon:02d}-{ts.tm_mday:02d}"; t=f"{ts.tm_hour:02d}:{ts.tm_min:02d}:{ts.tm_sec:02d}"
            p=os.path.expanduser(args.csv); idx_start=1
            if os.path.exists(p):
                try:
                    with open(p,"r",encoding="utf-8") as f: idx_start=sum(1 for _ in f)
                    idx_start=max(1, idx_start)
                except Exception: idx_start=1
            idx=idx_start
            for r in ok:
                row={"index":idx,"date":date,"time":t,"host":r.get("host","")}
                for k in header:
                    if k in ("index","date","time","host"): continue
                    row[k]=r.get(k,"")
                _append_csv(args.csv, row, header); idx+=1
        if args.json:
            print(json.dumps({"ok":True,"scanned":len(results),"success":len(ok),"failed":len(fail),"results":results}, indent=2))
        else:
            print(f"\nInventory scan complete: {len(results)} hosts; {len(ok)} ok; {len(fail)} failed.")
            if fail:
                print("Failures:")
                for r in fail: print(f"  - {r.get('host')}: {r.get('error')}")
        sys.exit(0)

    if not args.host: print("Error: --host/-H required"); sys.exit(1)
    base, ip = base_for(args.host)
    if not (user and pw): print("Error: auth required for control/lock actions"); sys.exit(1)
    sess=requests.Session()
    cookie=login_cookie(sess, base, user, pw, insecure)
    enable_control(sess, base, cookie, insecure); split=24

    def confirm(prompt:str)->bool:
        if args.yes: return True
        try:
            ans=input(f"{prompt} [y/N]: ").strip().lower()
        except EOFError:
            return False
        return ans in ("y","yes")

    if action in ("all-on","all-off","lock-all","unlock-all"):
        outlets=fetch_outlets(sess, base, args.pduid, HTTPBasicAuth(user,pw), insecure)
        targets=sorted(outlets) if outlets else list(range(1,49))
        verb = {"all-on":"on","all-off":"off","lock-all":"lock","unlock-all":"unlock"}[action]
        if not confirm(f"Apply '{verb}' to {len(targets)} outlets on {ip}?"): sys.exit(1)
        for n in targets:
            if verb in ("on","off"): set_power(sess, base, cookie, args.pduid, n, verb, insecure, split)
            else: set_lock(sess, base, cookie, args.pduid, n, True if verb=="lock" else False, insecure, split)
        outlets=fetch_outlets(sess, base, args.pduid, HTTPBasicAuth(user,pw), insecure)
        if args.json:
            print(json.dumps({"ok":True,"host":args.host,"ip":ip,"action":action,"ports":targets,
                              "rows":[{"outlet":n,**outlets.get(n,{"name":"","state":"unknown"})} for n in sorted(outlets)]}, indent=2))
        else:
            print(f"\nApplied '{verb}' to {len(targets)} outlets on {ip}.")
            print(f"\nPDU: {ip}\n"); print("Outlet | Label / Name                 | State"); print("-------+------------------------------+--------")
            for n,d in sorted(outlets.items()): print(f"{n:02d}     | {d['name'][:28]:<28} | {d['state']}")
            print()
        sys.exit(0)

    if action in ("on","off","reboot","lock","unlock","multi"):
        if not args.port: print("Error: --port required"); sys.exit(1)
        targets=args.port if action=="multi" else [args.port[0]]
        verb = None if action=="multi" else action
        if verb in ("lock","unlock") and not confirm(f"{verb.capitalize()} {len(targets)} outlet(s) on {ip}?"):
            sys.exit(1)
        if action=="multi" and not confirm(f"Apply to {len(targets)} outlets on {ip}?"):
            sys.exit(1)
        for n in targets:
            if verb in ("on","off","reboot"): set_power(sess, base, cookie, args.pduid, n, verb, insecure, split)
            elif verb in ("lock","unlock"): set_lock(sess, base, cookie, args.pduid, n, True if verb=="lock" else False, insecure, split)
        outlets=fetch_outlets(sess, base, args.pduid, HTTPBasicAuth(user,pw), insecure)
        if args.json:
            print(json.dumps({"ok":True,"host":args.host,"ip":ip,"action":action,"ports":targets,
                              "rows":[{"outlet":n,**outlets.get(n,{"name":"","state":"unknown"})} for n in sorted(outlets)]}, indent=2))
        else:
            print("\nAffected outlets\n\nOutlet | Label / Name                 | State\n-------+------------------------------+--------")
            for n in targets:
                d=outlets.get(n,{"name":"","state":"unknown"}); print(f"{n:02d}     | {d['name'][:28]:<28} | {d['state']}")
            print(f"\nPDU: {ip}\n"); print("Outlet | Label / Name                 | State"); print("-------+------------------------------+--------")
            for n,d in sorted(outlets.items()): print(f"{n:02d}     | {d['name'][:28]:<28} | {d['state']}")
            print()

if __name__=="__main__":
    main()
