#!/usr/bin/env python3
"""
NetMap Server
Usage: python server.py [devices.xml]

API:
  GET  /api/devices              all devices from XML
  GET  /api/status               current status store {mac: status}
  POST /api/ping                 body: {macs:[...]}  — ping those IPs, grouped by VLAN, 15s pause between groups
                                 returns {mac: "online"|"offline"|"no_info", ...}
  GET  /api/history              {mac: {status, last_seen, last_changed}} for switches only
  GET  /api/layout               saved map layout JSON
  POST /api/layout               save map layout JSON
  GET  /api/alerts               saved alert rules [{id,mac,name,condition,notified}]
  POST /api/alerts               save alert rules
  GET  /api/search?q=...         search by ip or name (max 20)
"""

import sys, os, re, json, time, threading, subprocess, platform, hashlib, secrets, socket, base64
import xml.etree.ElementTree as ET
import http.server, socketserver, urllib.parse
from pathlib import Path
from collections import defaultdict

# Paramiko is optional — only needed for AP restart (VLAN 1010)
try:
    import paramiko
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False

# ── HTTPS self-signed certificate ──────────────────────────────────────
def ensure_https_cert():
    """Generate netmap.crt + netmap.key next to server.py if missing.
    Self-signed, valid 10 years, CN=localhost. Browser will show 'Not secure'
    warning on first visit — click 'Advanced → Proceed' once per browser.
    Traffic IS encrypted; the warning is only about identity verification,
    which is meaningless on localhost."""
    cert_dir = Path(__file__).resolve().parent
    crt = cert_dir / "netmap.crt"
    key = cert_dir / "netmap.key"
    if crt.exists() and key.exists():
        return str(crt), str(key)
    print("🔐  No HTTPS cert found — generating self-signed cert for localhost...")
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from datetime import datetime, timedelta
        import ipaddress

        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subj = issuer = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NetMap"),
        ])
        cert = (x509.CertificateBuilder()
            .subject_name(subj).issuer_name(issuer)
            .public_key(priv.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.utcnow())
            .not_valid_after(datetime.utcnow() + timedelta(days=3650))
            .add_extension(x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            ]), critical=False)
            .sign(priv, hashes.SHA256()))
        crt.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key.write_bytes(priv.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))
        print(f"   wrote {crt.name} and {key.name}")
    except ImportError:
        print("❌  cryptography library missing — install with: pip install cryptography")
        raise
    return str(crt), str(key)

# ── Config ───────────────────────────────────────────────────────────────────────────────
PORT         = 8000
VLAN_PAUSE   = 15
LAYOUT_FILE  = None
HISTORY_FILE = None
ALERTS_FILE  = None
KNOWN_FILE   = None
AUTH_FILE    = None
ACTIONS_FILE = None
FILTER_HIST_FILE = None    # group-wide filter history shared across users
TOOLBAR_PREFS_FILE = None  # per-host toolbar customization, keyed by hostname
LIVE_STATUS_FILE = None    # shared status file — any user's ping benefits everyone
STATUS_FRESHNESS_MAX = 15 * 60  # seconds; older statuses render as "no info"
XML_HISTORY_FILE = None    # rolling snapshots of parsed XML (cap 30)
XML_HISTORY_MAX  = 30      # keep at most N snapshots
PHOTOS_DIR = None          # folder next to XML holding uploaded photos
PHOTO_MAX_BYTES = 5 * 1024 * 1024   # 5 MB per photo
PHOTO_ALLOWED_EXT = {".jpg", ".jpeg", ".png", ".webp", ".gif"}
TEMPLATES_FILE = None      # command templates (SSH + Windows), private + public
SITE_CONFIG_FILE = None    # plant-specific settings (VLANs, IPs, mappings)
SITE_CONFIG_CACHE = None   # in-memory cached copy — reloaded on POST

DHCP_VLANS   = {"1010", "1088", "1048"}

# ── Stores ───────────────────────────────────────────────────────────────────────────────
devices_by_mac: dict[str, dict] = {}
status_store:   dict[str, str]  = {}
history_store:  dict[str, dict] = {}
known_macs:     set             = set()
active_tokens:  set             = set()
xml_path_store = [None]   # mutable list avoids Python scoping issues
store_lock = threading.Lock()
ping_lock  = threading.Lock()
ping_cancel_flag = threading.Event()   # set by /api/ping/cancel to abort current cycle

# ── Device type ─────────────────────────────────────────────────────────────────
def guess_type(name: str) -> str:
    n = (name or "").lower()
    if any(x in n for x in ["sw","switch"]):        return "switch"
    if any(x in n for x in ["rt","router","gw"]):   return "router"
    if any(x in n for x in ["ap","wifi","wlan"]):   return "access_point"
    if any(x in n for x in ["srv","server","nas"]): return "server"
    if any(x in n for x in ["cam","camera","nvr"]): return "camera"
    if any(x in n for x in ["prn","print"]):        return "printer"
    if any(x in n for x in ["pc","desktop","laptop","ws"]): return "pc"
    return "unknown"

# ── XML parser ──────────────────────────────────────────────────────────────────
def load_xml(path: str) -> dict[str, dict]:
    tree = ET.parse(path)
    root = tree.getroot()
    # Core fields we always handle explicitly
    CORE = {"mac","ip","name","switch","port","switch-port","vlan"}
    out = {}
    for dev in root.findall("device"):
        g  = lambda t: (dev.findtext(t) or "").strip()
        # treat literal "None" from XML the same as empty
        gn = lambda t: "" if g(t).lower() in ("none","null","-") else g(t)
        mac = gn("mac")
        if not mac: continue
        name = gn("name")
        record = {
            "mac":    mac,
            "ip":     gn("ip"),
            "name":   name,
            "switch": gn("switch"),
            # accept either <port> or <switch-port> in XML
            "port":   gn("port") or gn("switch-port"),
            "vlan":   gn("vlan"),
            "type":   normalize_type(gn("type")) or guess_type(name),
        }
        # Capture ALL extra fields from XML automatically
        for child in dev:
            if child.tag not in CORE and child.tag != "type" and child.text:
                val = child.text.strip()
                if val.lower() not in ("none","null","-"):
                    record[child.tag] = val
        out[mac] = record
    return out

def normalize_type(t: str) -> str:
    """Map XML <type> spelling variants onto the canonical type keys the
    frontend ICONS map understands. Case-insensitive."""
    if not t:
        return ""
    key = t.strip().lower()
    aliases = {
        # ap / iap / router all use the router type + icon
        "ap": "router", "iap": "router", "router": "router",
        # standalone access-point spellings keep their own type
        "access_point": "access_point", "accesspoint": "access_point",
        "access-point": "access_point",
        # Lantronix controllers — accept common misspellings
        "controller": "controller", "controler": "controller",
        "contoller": "controller", "lantronix": "controller",
        # Helmholz remote gateways
        "helmholz": "helmholz", "helmoltz": "helmholz",
        # Kaba terminals
        "timereg": "timereg", "time-reg": "timereg", "timeregistration": "timereg",
        "accesscontrol": "accesscontrol", "access-control": "accesscontrol",
        "kaba": "accesscontrol",
    }
    return aliases.get(key, key)

def make_demo() -> dict[str, dict]:
    rows = [
        ("00:1A:2B:3C:4D:01","192.168.1.2","PC-Alice","192.168.8.11","1","10"),
        ("00:1A:2B:3C:4D:02","192.168.1.3","PC-Bob","192.168.8.11","2","10"),
        ("00:1A:2B:3C:4D:03","192.168.1.4","PC-Carol","192.168.8.11","3","20"),
        ("00:1A:2B:3C:4D:04","192.168.1.5","AP-H1-01","192.168.8.11","24","99"),
        ("00:1A:2B:3C:4D:10","192.168.1.10","SW-H1-A-1","192.168.8.11","48","1"),
        ("00:1A:2B:3C:4D:11","192.168.1.11","SW-H1-A-2","192.168.8.11","47","1"),
        ("00:1A:2B:3C:4D:12","192.168.1.12","SW-H1-A-3","192.168.8.11","46","1"),
        ("00:2B:3C:4D:5E:01","192.168.2.2","PC-Dave","192.168.8.21","1","10"),
        ("00:2B:3C:4D:5E:02","192.168.2.3","CAM-H2-01","192.168.8.21","10","30"),
        ("00:2B:3C:4D:5E:10","192.168.2.10","SW-H2-A-1","192.168.8.21","48","1"),
        ("00:2B:3C:4D:5E:11","192.168.2.11","SW-H2-A-2","192.168.8.21","47","1"),
        ("00:3C:4D:5E:6F:01","192.168.3.2","Printer-WH","192.168.8.31","5","20"),
        ("00:3C:4D:5E:6F:02","192.168.3.3","CAM-WH-01","192.168.8.31","6","30"),
        ("00:3C:4D:5E:6F:10","192.168.3.10","SW-WH-A-1","192.168.8.31","48","1"),
        ("00:3C:4D:5E:6F:11","192.168.3.11","SW-WH-A-2","192.168.8.31","47","1"),
        ("00:3C:4D:5E:6F:20","192.168.3.20","SW-WH-B-1","192.168.8.32","48","1"),
        ("00:4D:5E:6F:70:01","192.168.4.2","SRV-AD-01","192.168.8.41","1","5"),
        ("00:4D:5E:6F:70:02","192.168.4.3","SRV-AD-02","192.168.8.41","2","5"),
        ("00:4D:5E:6F:70:03","192.168.4.4","PC-Admin","192.168.8.41","3","10"),
        ("00:4D:5E:6F:70:10","192.168.4.10","SW-AD-A-1","192.168.8.41","48","1"),
        ("00:4D:5E:6F:70:11","192.168.4.11","SW-AD-A-2","192.168.8.41","47","1"),
        ("00:4D:5E:6F:70:12","192.168.4.12","AP-AD-01","192.168.8.41","20","99"),
    ]
    out = {}
    for mac,ip,name,sw,port,vlan in rows:
        out[mac] = {"mac":mac,"ip":ip,"name":name,"switch":sw,
                    "port":port,"vlan":vlan,"type":guess_type(name)}
    return out

# ── Ping ────────────────────────────────────────────────────────────────────────
def ping_once(ip: str) -> bool:
    """Single ICMP ping. Works on Windows and Linux/macOS."""
    system = platform.system().lower()
    try:
        if system == "windows":
            cmd = ["ping", "-n", "1", "-w", "2000", ip]
        else:
            cmd = ["ping", "-c", "1", "-W", "2", ip]

        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5
        )
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        return False
    except FileNotFoundError:
        print("[ping] ERROR: 'ping' command not found")
        return False
    except Exception as e:
        print(f"[ping] {ip} → exception: {e}")
        return False

# Cap: keep history for at most this many devices total. Old/never-seen ones get pruned.
HISTORY_MAX_DEVICES = 5000
# Cap per-device transition log so timeline doesn't grow unbounded.
# At ~one transition per day, this is ~270 days of history per device.
HISTORY_MAX_TRANSITIONS = 300

def update_history(mac: str, new_status: str):
    """Update history for ALL devices. Thread-safe (called inside store_lock).
    Capped via HISTORY_MAX_DEVICES (oldest last_seen pruned first).
    Each device entry also keeps a `transitions` list with status-change events
    for the timeline view."""
    dev = devices_by_mac.get(mac)
    if not dev:
        return
    now = time.time()
    prev = history_store.get(mac, {})
    prev_status = prev.get("status", "no_info")
    transitions = prev.get("transitions", [])

    # Log a transition when status actually changes
    if prev_status != new_status:
        transitions.append({"ts": int(now), "status": new_status})
        # Cap: drop oldest transitions
        if len(transitions) > HISTORY_MAX_TRANSITIONS:
            transitions = transitions[-HISTORY_MAX_TRANSITIONS:]

    entry = {
        "status":       new_status,
        "last_changed": prev.get("last_changed", now) if prev_status == new_status else now,
        "last_seen":    now if new_status == "online" else prev.get("last_seen", None),
        "prev_status":  prev_status,
        "transitions":  transitions,
    }
    history_store[mac] = entry

    # Cap: if too many entries, drop ones with the oldest last_seen
    if len(history_store) > HISTORY_MAX_DEVICES:
        sorted_macs = sorted(history_store.items(),
                            key=lambda kv: kv[1].get("last_seen") or 0,
                            reverse=True)
        history_store.clear()
        for m, e in sorted_macs[:HISTORY_MAX_DEVICES]:
            history_store[m] = e

def do_ping(macs: list[str], partial_cb=None) -> dict[str, str]:
    """
    Ping a list of MACs. Groups by VLAN, pauses VLAN_PAUSE seconds between groups.
    Updates status_store and history_store. Returns {mac: status}.
    Honors ping_cancel_flag — if set during a cycle, returns partial results immediately.

    If partial_cb is supplied, it's called after each VLAN group completes with
    the batch of results from that VLAN. Used to stream results to the shared
    live_status.json file so other users see them without waiting for the full
    scan to complete.
    """
    if not ping_lock.acquire(blocking=False):
        # another ping is in progress — return current store snapshot
        with store_lock:
            return {m: status_store.get(m, "no_info") for m in macs}
    try:
        # Reset cancel flag at the start of a fresh run
        ping_cancel_flag.clear()
        devs = [devices_by_mac[m] for m in macs if m in devices_by_mac]
        by_vlan = defaultdict(list)
        for d in devs:
            by_vlan[d.get("vlan", "0")].append(d)

        results = {}
        for i, (vlan, group) in enumerate(sorted(by_vlan.items())):
            # Check cancel BEFORE starting this VLAN group
            if ping_cancel_flag.is_set():
                print(f"[ping] cancelled by user — stopping after VLAN groups processed so far")
                break

            batch = {}
            # Read DHCP VLAN list from site config (with fallback to hardcoded default).
            # This lets other plants configure their DHCP VLANs without code changes.
            try:
                _cfg = get_site_config()
                _dhcp_set = set(str(v) for v in _cfg.get("netmap", {}).get("dhcp_vlans", []))
                if not _dhcp_set:
                    _dhcp_set = DHCP_VLANS
            except Exception:
                _dhcp_set = DHCP_VLANS
            is_dhcp = vlan in _dhcp_set

            def probe(d, res=batch, dhcp=is_dhcp):
                mac  = d["mac"]
                ip   = d.get("ip", "")
                name = d.get("name", "")

                if dhcp:
                    target = name if name else ip
                    if not target:
                        res[mac] = "no_info"; return
                    ok = ping_once(target)
                    print(f"[ping] DHCP VLAN {vlan}  {name} ({ip}) → {'online' if ok else 'offline'}")
                    res[mac] = "online" if ok else "offline"
                else:
                    if not ip:
                        res[mac] = "no_info"; return
                    res[mac] = "online" if ping_once(ip) else "offline"

            threads = []
            for d in group:
                t = threading.Thread(target=probe, args=(d,), daemon=True)
                threads.append(t); t.start()
            for t in threads:
                t.join(timeout=6)
            for d in group:
                if d["mac"] not in batch:
                    batch[d["mac"]] = "no_info"
            results.update(batch)
            online = sum(1 for s in batch.values() if s == "online")
            mode   = "hostname" if is_dhcp else "ip"
            print(f"[ping] VLAN {vlan:>6} ({mode:>8})  {len(group):>3} devs  online={online}")
            # Stream this batch to the shared file so users watching /api/live-status
            # see updates within their 6-second poll instead of waiting for all VLANs.
            # Also update the in-memory status_store and history so other API endpoints
            # (dashboard, sidebar) see fresh data mid-scan.
            if partial_cb:
                try: partial_cb(batch)
                except Exception as _e: print(f"[ping] partial_cb failed: {_e}")
            with store_lock:
                status_store.update(batch)
                for mac, st in batch.items():
                    update_history(mac, st)
            # VLAN pause — but break early if cancelled during pause
            if i < len(by_vlan) - 1:
                # Sleep in 0.5s chunks so we can check cancel often
                slept = 0
                pause_s = _cfg_runtime("vlan_pause", VLAN_PAUSE)
                while slept < pause_s:
                    if ping_cancel_flag.is_set():
                        break
                    time.sleep(0.5)
                    slept += 0.5

        with store_lock:
            status_store.update(results)
            for mac, st in results.items():
                update_history(mac, st)
        save_history()
        return results
    finally:
        ping_lock.release()

# ── Persistence ─────────────────────────────────────────────────────────────────
# ── Atomic file writes (prevents corruption from concurrent processes) ──────
def atomic_write(path: Path, content: str):
    """Write to a temp file in same dir, then atomic rename to target.
    Eliminates the risk of half-written files when multiple users save at once.
    On Windows os.replace() is atomic — if write fails partway, target is untouched."""
    if path is None:
        return
    try:
        tmp = path.with_suffix(path.suffix + f".tmp.{os.getpid()}.{int(time.time()*1000)}")
        tmp.write_text(content, encoding='utf-8')
        os.replace(str(tmp), str(path))   # atomic on Windows + Unix
    except Exception as e:
        print(f"[atomic_write] {path.name}: {e}")
        try:
            if tmp.exists(): tmp.unlink()
        except: pass

def load_layout() -> dict:
    if LAYOUT_FILE.exists():
        try: return json.loads(LAYOUT_FILE.read_text(encoding='utf-8'))
        except: pass
    return {"rooms":[], "devices":{}, "racks":[], "annotations":[], "drawings":[]}

def save_layout(data: dict):
    atomic_write(LAYOUT_FILE, json.dumps(data, indent=2))

def load_history() -> dict:
    if HISTORY_FILE.exists():
        try: return json.loads(HISTORY_FILE.read_text(encoding='utf-8'))
        except: pass
    return {}

def save_history():
    atomic_write(HISTORY_FILE, json.dumps(history_store, indent=2))

# ── Shared live status ─────────────────────────────────────────────────
# One user's ping benefits everyone. Any client's ping cycle writes results here;
# every client polls this file to see the latest known status of each MAC.
# File shape: { "MAC": {"status":"online|offline", "ts": epoch, "by":"hostname"}, ... }
_live_status_lock = threading.Lock()

def load_live_status() -> dict:
    if not LIVE_STATUS_FILE or not LIVE_STATUS_FILE.exists():
        return {}
    try: return json.loads(LIVE_STATUS_FILE.read_text(encoding='utf-8'))
    except: return {}

def save_live_status(data: dict):
    if not LIVE_STATUS_FILE: return
    atomic_write(LIVE_STATUS_FILE, json.dumps(data))

def update_live_status(mac_results: dict, by_user: str = ""):
    """Merge new results into the shared status file.
    mac_results: {mac: 'online'|'offline'}"""
    if not LIVE_STATUS_FILE:
        print(f"[live-status] SKIP — LIVE_STATUS_FILE not set")
        return
    if not mac_results:
        print(f"[live-status] SKIP — empty results dict")
        return
    now = int(time.time())
    with _live_status_lock:
        cur = load_live_status()
        for mac, st in mac_results.items():
            cur[mac] = {"status": st, "ts": now, "by": by_user or _my_user_label}
        # cap size — drop entries older than the configured freshness cutoff
        # This must be >= the client-side status_freshness_max, otherwise entries
        # get evicted server-side before the client renders them.
        eviction_cutoff = max(30*60, _cfg_runtime("status_freshness_max", 900))
        cutoff = now - eviction_cutoff
        before = len(cur)
        cur = {m: v for m, v in cur.items() if v.get("ts", 0) >= cutoff}
        after = len(cur)
        save_live_status(cur)
        print(f"[live-status] wrote {len(mac_results)} results by={by_user or '?'}, "
              f"total entries={after} (evicted {before-after}), "
              f"path={LIVE_STATUS_FILE}")

# ── XML history snapshots ──────────────────────────────────────────────
# Rolling capped list of parsed XML snapshots — used by:
#  • "what changed today" — diff current vs yesterday
#  • historical playback — recreate device set as of any snapshot time
# File shape: [ {ts, count, devs: {mac: {ip,name,vlan,type,switch,port}}}, ...newest first ]
# Only stores CORE fields per device to bound file size.
_xml_hist_lock = threading.Lock()

def load_xml_history() -> list:
    if not XML_HISTORY_FILE or not XML_HISTORY_FILE.exists():
        return []
    try:
        d = json.loads(XML_HISTORY_FILE.read_text(encoding='utf-8'))
        return d if isinstance(d, list) else []
    except: return []

def save_xml_history(data: list):
    if not XML_HISTORY_FILE: return
    atomic_write(XML_HISTORY_FILE, json.dumps(data))

def _slim_devs(devs: dict) -> dict:
    """Extract just the fields we care about, to keep snapshots small."""
    slim = {}
    for mac, d in devs.items():
        slim[mac] = {
            "ip":     d.get("ip",""),
            "name":   d.get("name",""),
            "vlan":   d.get("vlan",""),
            "type":   d.get("type",""),
            "switch": d.get("switch",""),
            "port":   d.get("port",""),
        }
    return slim

def _snapshot_fingerprint(devs: dict) -> str:
    """Stable hash of the slim device set — used to skip snapshots for no-change reloads."""
    slim = _slim_devs(devs)
    canon = json.dumps(slim, sort_keys=True, separators=(',',':'))
    return hashlib.sha256(canon.encode('utf-8')).hexdigest()[:16]

def snapshot_xml_if_changed(devs: dict) -> bool:
    """Add a new snapshot to xml_history.json if content differs from the newest one.
    Caps history at XML_HISTORY_MAX. Returns True if a snapshot was added."""
    if not XML_HISTORY_FILE: return False
    try:
        with _xml_hist_lock:
            hist = load_xml_history()
            fp = _snapshot_fingerprint(devs)
            if hist and hist[0].get("fp") == fp:
                return False   # no change
            entry = {
                "ts":    int(time.time()),
                "fp":    fp,
                "count": len(devs),
                "devs":  _slim_devs(devs),
            }
            hist.insert(0, entry)
            hist = hist[:XML_HISTORY_MAX]
            save_xml_history(hist)
            return True
    except Exception as e:
        print(f"[xml-history] {e}")
        return False

# ── COMMAND TEMPLATES ─────────────────────────────────────────────
# templates.json shape:
#  { "public":  [{id, name, type, commands:[...], description, created_by, created_at, updated_by, updated_at}],
#    "private": { "HOST-A": [ {id, name, type, commands, ...}, ... ], "HOST-B": [...] } }
_templates_lock = threading.Lock()

def load_templates() -> dict:
    if not TEMPLATES_FILE or not TEMPLATES_FILE.exists():
        return {"public": [], "private": {}}
    try:
        d = json.loads(TEMPLATES_FILE.read_text(encoding='utf-8'))
        if not isinstance(d, dict): d = {}
        d.setdefault("public", [])
        d.setdefault("private", {})
        return d
    except: return {"public": [], "private": {}}

def save_templates(data: dict):
    if not TEMPLATES_FILE: return
    atomic_write(TEMPLATES_FILE, json.dumps(data, indent=2))

# ── SITE CONFIG ───────────────────────────────────────────────────
# Plant-specific settings loaded from site_config.json alongside the XML.
# Read on startup; refreshed whenever the client saves via /api/site-config.
# Never contains credentials — those are prompted per-scan and used in memory.
_site_cfg_lock = threading.Lock()

def load_site_config() -> dict:
    """Load site_config.json, merged with defaults from inventory module."""
    try:
        # Delegate to inventory module — it owns the schema + defaults
        from inventory import load_config
        return load_config(SITE_CONFIG_FILE) if SITE_CONFIG_FILE else load_config()
    except Exception as e:
        print(f"[site-config] load failed: {e}")
        return {}

def save_site_config(data: dict):
    if not SITE_CONFIG_FILE: return
    atomic_write(SITE_CONFIG_FILE, json.dumps(data, indent=2))
    global SITE_CONFIG_CACHE
    SITE_CONFIG_CACHE = None   # invalidate cache

def get_site_config() -> dict:
    """Cached accessor — used everywhere the server needs plant-specific settings."""
    global SITE_CONFIG_CACHE
    if SITE_CONFIG_CACHE is None:
        SITE_CONFIG_CACHE = load_site_config()
    return SITE_CONFIG_CACHE

def _strip_deep(obj, key_to_remove):
    """Recursively remove a key from a nested dict/list. Used to sanitize
    site config uploads so no credential-like key can sneak in."""
    if isinstance(obj, dict):
        obj.pop(key_to_remove, None)
        for v in obj.values(): _strip_deep(v, key_to_remove)
    elif isinstance(obj, list):
        for v in obj: _strip_deep(v, key_to_remove)

def _cfg_runtime(key: str, default):
    """Read a NetMap runtime setting from site config with fallback.
    Never raises — bad config falls back to the default."""
    try:
        nm = get_site_config().get("netmap", {})
        val = nm.get(key, default)
        # coerce to same type as default
        if isinstance(default, int) and not isinstance(val, bool):
            return int(val)
        if isinstance(default, float):
            return float(val)
        return val
    except Exception:
        return default

def apply_runtime_config():
    """Rebind global runtime constants from site_config.json.
    Called on startup and after every /api/site-config POST."""
    global VLAN_PAUSE, PRESENCE_TTL, STATUS_FRESHNESS_MAX, XML_HISTORY_MAX
    global PHOTO_MAX_BYTES
    try:
        nm = get_site_config().get("netmap", {})
        if isinstance(nm.get("vlan_pause"),           int): VLAN_PAUSE           = nm["vlan_pause"]
        if isinstance(nm.get("presence_ttl"),         int): PRESENCE_TTL         = nm["presence_ttl"]
        if isinstance(nm.get("status_freshness_max"), int): STATUS_FRESHNESS_MAX = nm["status_freshness_max"]
        if isinstance(nm.get("xml_history_max"),      int): XML_HISTORY_MAX      = nm["xml_history_max"]
        if isinstance(nm.get("photo_max_mb"),         int): PHOTO_MAX_BYTES      = nm["photo_max_mb"] * 1024 * 1024
    except Exception as e:
        print(f"[cfg] apply_runtime_config: {e}")



def load_alerts() -> list:
    if ALERTS_FILE.exists():
        try: return json.loads(ALERTS_FILE.read_text(encoding='utf-8'))
        except: pass
    return []

def save_alerts(data: list):
    atomic_write(ALERTS_FILE, json.dumps(data, indent=2))

# ── Action log (per-device admin action history) ────────────────────────────
actions_lock = threading.Lock()

def load_actions() -> dict:
    """Returns {mac: [{ts, action, user, result, detail}, ...]}"""
    if ACTIONS_FILE and ACTIONS_FILE.exists():
        try: return json.loads(ACTIONS_FILE.read_text(encoding='utf-8'))
        except: pass
    return {}

def save_actions(data: dict):
    atomic_write(ACTIONS_FILE, json.dumps(data, indent=2))

def log_action(mac: str, action: str, user: str, result: str, detail: str = ""):
    """Append a single entry to the action log for one device.
    Keeps max 100 entries per device (oldest dropped)."""
    if not mac or not ACTIONS_FILE: return
    with actions_lock:
        store = load_actions()
        entry = {
            "ts": time.strftime("%Y-%m-%d %H:%M:%S"),
            "action": action,
            "user": user or "",
            "result": result,    # "ok" / "fail"
            "detail": (detail or "")[:300],
        }
        if mac not in store: store[mac] = []
        store[mac].insert(0, entry)
        store[mac] = store[mac][:100]
        save_actions(store)

# ── Presence (who else is using the same XML right now) ────────────────────
PRESENCE_FILE = None         # set in main alongside the rest
PRESENCE_TTL  = 60           # entries older than this are considered offline (seconds)
HEARTBEAT_INT = 25           # how often we update our entry (seconds)
presence_lock = threading.Lock()

# Stable per-instance ID (different across users even on same PC if 2 instances open)
_my_user_id = f"{platform.node()}-{os.getpid()}"
_my_user_label = platform.node() or "user"

def load_presence() -> dict:
    if PRESENCE_FILE and PRESENCE_FILE.exists():
        try: return json.loads(PRESENCE_FILE.read_text(encoding='utf-8'))
        except: pass
    return {}

def save_presence(data: dict):
    atomic_write(PRESENCE_FILE, json.dumps(data, indent=2))

def heartbeat_tick(ping_active: bool = None, ping_filter: str = None, ping_wait_min: int = None):
    """Write our entry to presence.json and reap stale entries.
    Optional ping-state fields let clients advertise their ping status so other
    users can see who is actively pinging and avoid double-pinging."""
    if not PRESENCE_FILE: return
    try:
        with presence_lock:
            store = load_presence()
            now = int(time.time())
            entry = store.get(_my_user_id) or {}
            entry.update({"name": _my_user_label, "ts": now})
            # Only overwrite ping fields if explicitly given (heartbeat_loop
            # calls with no args and MUST preserve whatever the client set last)
            if ping_active is not None:
                entry["ping_active"] = bool(ping_active)
                entry["ping_updated"] = now
            if ping_filter is not None:
                entry["ping_filter"] = str(ping_filter)[:200]
            if ping_wait_min is not None:
                entry["ping_wait_min"] = int(ping_wait_min) if ping_wait_min else 0
            # Auto-clear a stale ping flag — if the client's ping_updated ts is
            # older than 90s (missed 3 heartbeats worth), consider ping inactive.
            if entry.get("ping_active") and now - entry.get("ping_updated", 0) > 90:
                entry["ping_active"] = False
            store[_my_user_id] = entry
            # reap stale users entirely
            stale = [k for k,v in store.items() if now - v.get("ts",0) > PRESENCE_TTL]
            for k in stale: del store[k]
            save_presence(store)
    except Exception as e:
        print(f"[presence] {e}")

def heartbeat_loop():
    """Background thread — beats every HEARTBEAT_INT seconds."""
    while True:
        heartbeat_tick()
        time.sleep(HEARTBEAT_INT)

def remove_my_presence():
    """Best-effort cleanup on exit."""
    if not PRESENCE_FILE: return
    try:
        with presence_lock:
            store = load_presence()
            if _my_user_id in store:
                del store[_my_user_id]
                save_presence(store)
    except: pass

# ── Auth ─────────────────────────────────────────────────────────────────────
def hash_pw(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def load_auth() -> dict:
    """Returns {hash: str} or {} if no password set yet."""
    if AUTH_FILE.exists():
        try: return json.loads(AUTH_FILE.read_text(encoding='utf-8'))
        except: pass
    return {}

def save_auth(pw_hash: str):
    atomic_write(AUTH_FILE, json.dumps({"hash": pw_hash}))

def auth_status() -> str:
    """'none' if no password set, 'set' if password exists."""
    return "set" if load_auth().get("hash") else "none"

def verify_token(headers) -> bool:
    token = headers.get("X-Auth-Token","")
    return token in active_tokens


    if KNOWN_FILE.exists():
        try: return set(json.loads(KNOWN_FILE.read_text()))
        except: pass
    return set()

def load_known_macs() -> set:
    if KNOWN_FILE.exists():
        try: return set(json.loads(KNOWN_FILE.read_text(encoding='utf-8')))
        except: pass
    return set()

def save_known_macs():
    atomic_write(KNOWN_FILE, json.dumps(list(known_macs)))

def merge_devices(new_devs: dict):
    """
    Merge newly parsed XML devices into devices_by_mac.
    - New MAC → add it
    - Existing MAC with changed fields → update ALL changed fields
    - MAC in known_macs but not in new_devs → keep in devices_by_mac, set removed=True
    - MAC in new_devs that was removed → clear removed flag
    """
    global known_macs
    changed = []

    # Every field that load_xml might surface (CORE + Extras like serial,
    # designation, model, rack, etc.) — merge ALL of them, not just the
    # original 6. Otherwise edits to "extra" fields write to XML but never
    # propagate to the runtime store.
    SKIP_FIELDS = {"first-seen", "history", "xml_change_status", "previous-mac"}

    for mac, dev in new_devs.items():
        if mac in devices_by_mac:
            existing = devices_by_mac[mac]
            updates = {}
            for f, v in dev.items():
                if f in SKIP_FIELDS: continue
                if v != existing.get(f):
                    updates[f] = v
            if updates:
                existing.update(updates)
                existing.pop("removed", None)
                changed.append(f"updated {existing.get('name',mac)}: {list(updates.keys())}")
            elif existing.get("removed"):
                existing.pop("removed", None)
                changed.append(f"restored {existing.get('name',mac)}")
        else:
            devices_by_mac[mac] = {**dev, "removed": False}
            status_store[mac] = "no_info"
            changed.append(f"new device {dev.get('name',mac)} ({dev.get('ip','')})")

    # mark anything previously known but absent from new XML
    for mac in known_macs:
        if mac not in new_devs and mac in devices_by_mac:
            if not devices_by_mac[mac].get("removed"):
                devices_by_mac[mac]["removed"] = True
                changed.append(f"removed from XML: {devices_by_mac[mac].get('name',mac)}")

    known_macs.update(new_devs.keys())
    save_known_macs()

    if changed:
        print(f"[xml] {len(changed)} change(s):")
        for c in changed: print(f"      • {c}")
    else:
        print("[xml] no changes detected")

    # Inherit layout positions from previous-mac (device replacements)
    inherit_positions_from_previous_mac()

    return changed

def inherit_positions_from_previous_mac():
    """For any device that has a <previous-mac> field in its XML record,
    if the new MAC has no saved position but the previous MAC does, copy
    the position over. This handles network card swaps automatically."""
    if not LAYOUT_FILE: return
    try:
        layout = load_layout()
        devs = layout.get("devices", {}) or {}
        racks = layout.get("racks", []) or []
        notes = layout.get("notes", {}) or {}
        changed = False
        inherits = []

        for new_mac, dev in devices_by_mac.items():
            prev_mac = (dev.get("previous-mac") or dev.get("previous_mac") or "").strip()
            if not prev_mac: continue
            prev_mac = prev_mac.upper()

            # Inherit free-placed position
            if new_mac not in devs and prev_mac in devs:
                devs[new_mac] = devs.pop(prev_mac)
                inherits.append(f"position {prev_mac} → {new_mac} ({dev.get('name','?')})")
                changed = True

            # Inherit rack membership (replace old MAC with new in any rack)
            for rack in racks:
                sw = rack.get("switches", [])
                if prev_mac in sw and new_mac not in sw:
                    rack["switches"] = [new_mac if m == prev_mac else m for m in sw]
                    inherits.append(f"rack slot {prev_mac} → {new_mac}")
                    changed = True

            # Inherit notes
            if new_mac not in notes and prev_mac in notes:
                notes[new_mac] = notes.pop(prev_mac)
                inherits.append(f"note {prev_mac} → {new_mac}")
                changed = True

        if changed:
            layout["devices"] = devs
            layout["racks"] = racks
            layout["notes"] = notes
            save_layout(layout)
            print(f"[layout] {len(inherits)} inheritance(s) applied:")
            for x in inherits: print(f"      • {x}")
    except Exception as e:
        print(f"[layout] inherit error: {e}")

# ── HTTP ─────────────────────────────────────────────────────────────────────────
# ── Admin tool helpers ──────────────────────────────────────────────────────────
def admin_check_online(ip: str, timeout: float = 1.5) -> bool:
    """Quick check if a Windows PC is reachable on SMB port 445."""
    try:
        s = socket.create_connection((ip, 445), timeout=timeout)
        s.close()
        return True
    except:
        # try ICMP ping as fallback
        try:
            cmd = ["ping","-n","1","-w","1500",ip] if platform.system()=="Windows" \
                else ["ping","-c","1","-W","2",ip]
            r = subprocess.run(cmd, capture_output=True, timeout=3)
            return r.returncode == 0
        except:
            return False

def admin_run_local(cmd_list, timeout=30):
    """Run a local subprocess and capture output."""
    try:
        r = subprocess.run(cmd_list, capture_output=True, text=True,
                          timeout=timeout, encoding='utf-8', errors='replace')
        return {"ok": r.returncode == 0, "output": (r.stdout or "") + (r.stderr or ""),
                "code": r.returncode}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "Command timed out", "output": ""}
    except Exception as e:
        return {"ok": False, "error": str(e), "output": ""}

def _build_iface_command(port: str) -> str:
    """Build 'interface gigabitethernet X/Y' from a port string.
    Accepts '1/32' (already complete) or just '32' (prepends 1/)."""
    p = (port or "").strip()
    if "/" not in p:
        p = f"1/{p}"
    return f"interface gigabitethernet {p}"

def _build_multi_iface_command(ports: list) -> str:
    """Build 'interface gigabitethernet 1/1,1/22,1/23' for Extreme switches.
    Lets us run one shutdown/no-shutdown command across many ports at once.
    Normalizes each port to 'X/Y' format and dedupes."""
    norm = []
    seen = set()
    for p in ports:
        s = (str(p) or "").strip()
        if not s: continue
        if "/" not in s:
            s = f"1/{s}"
        if s not in seen:
            seen.add(s); norm.append(s)
    return f"interface gigabitethernet {','.join(norm)}"

def admin_ap_restart(switch_ip: str, port: str, user: str, pwd: str):
    """Single-port version of bulk_ap_restart. Used by per-device admin panel."""
    return bulk_ap_restart(switch_ip, [port], user, pwd)

def run_switch_commands(switch_ip: str, commands: list, user: str, pwd: str) -> dict:
    """Run a list of arbitrary commands on one Extreme switch via paramiko.
    Used by the "Run custom commands" admin tool — user can paste a multi-line
    script and see output from each. Sequential, with a sensible delay between commands.
    Returns {ok, output, error?}."""
    if not HAS_PARAMIKO:
        return {"ok": False, "error": "Paramiko not installed on server"}
    if not commands:
        return {"ok": False, "error": "No commands given"}
    client = None
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(switch_ip, username=user, password=pwd, timeout=12,
                      look_for_keys=False, allow_agent=False)
        chan = client.invoke_shell()
        time.sleep(1)
        if chan.recv_ready(): chan.recv(65535)

        out = f"=== {switch_ip} ===\n"
        # Drain any banner/prompts before sending user commands.
        # NO auto-prepend — runs exactly what the user typed, nothing more.
        if chan.recv_ready(): chan.recv(65535)

        for cmd in commands:
            cmd = cmd.strip()
            if not cmd:
                continue
            out += f"\n> {cmd}\n"
            chan.send(cmd + "\n")
            time.sleep(1.0)
            # Read until idle (extends a bit on each data burst)
            buf = b""
            deadline = time.time() + 10
            while time.time() < deadline:
                if chan.recv_ready():
                    buf += chan.recv(65535)
                    deadline = time.time() + 0.6
                else:
                    time.sleep(0.15)
                    if not chan.recv_ready(): break
            out += buf.decode("utf-8", errors="replace")

        # Done - just close the session
        chan.close()
        client.close()
        return {"ok": True, "output": out}
    except paramiko.AuthenticationException:
        return {"ok": False, "error": "Authentication failed"}
    except socket.timeout:
        return {"ok": False, "error": f"Connection timeout to {switch_ip}"}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}
    finally:
        if client:
            try: client.close()
            except: pass

def bulk_ap_restart(switch_ip: str, ports: list, user: str, pwd: str):
    """SSH once and PoE-cycle multiple ports on the same switch in a single
    interface command, e.g. 'interface gigabit ethernet 1/1,1/22,1/23'.
    Returns {ok, ports, output}."""
    if not HAS_PARAMIKO:
        return {"ok": False, "error": "Paramiko not installed on server"}
    if not ports:
        return {"ok": True, "ports": [], "output": "no ports given"}
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(switch_ip, username=user, password=pwd, timeout=10,
                      look_for_keys=False, allow_agent=False)
        chan = client.invoke_shell()
        time.sleep(1)
        chan.recv(65535)

        def send(cmd, wait=1.0):
            chan.send(cmd + "\n")
            time.sleep(wait)
            return chan.recv(65535).decode("utf-8", errors="replace") if chan.recv_ready() else ""

        log = ""
        log += send("enable")
        log += send("configure terminal")
        # ONE interface command for all ports
        log += send(_build_multi_iface_command(ports))
        log += send("poe poe-shutdown")
        # Wait for PoE to drop on all ports
        time.sleep(5)
        log += send("no poe-shutdown")
        chan.close()
        client.close()
        return {"ok": True, "ports": ports, "output": log[-3000:]}
    except paramiko.AuthenticationException:
        return {"ok": False, "error": "Authentication failed — check username/password"}
    except paramiko.SSHException as e:
        return {"ok": False, "error": f"SSH error: {e}"}
    except socket.timeout:
        return {"ok": False, "error": f"Connection to {switch_ip} timed out"}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}

def bulk_port_shutdown(switch_ip: str, ports: list, user: str, pwd: str):
    """SSH once and shut/no-shut multiple ports on the same switch in one
    interface command. Used for both VLAN-1088 port-shutdowns and the
    'common action' when mixed device types are selected."""
    if not HAS_PARAMIKO:
        return {"ok": False, "error": "Paramiko not installed on server"}
    if not ports:
        return {"ok": True, "ports": [], "output": "no ports given"}
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(switch_ip, username=user, password=pwd, timeout=10,
                      look_for_keys=False, allow_agent=False)
        chan = client.invoke_shell()
        time.sleep(1)
        chan.recv(65535)

        def send(cmd, wait=1.0):
            chan.send(cmd + "\n")
            time.sleep(wait)
            return chan.recv(65535).decode("utf-8", errors="replace") if chan.recv_ready() else ""

        log = ""
        log += send("enable")
        log += send("configure terminal")
        log += send(_build_multi_iface_command(ports))
        log += send("shutdown")
        time.sleep(3)
        log += send("no shutdown")
        chan.close()
        client.close()
        return {"ok": True, "ports": ports, "output": log[-3000:]}
    except paramiko.AuthenticationException:
        return {"ok": False, "error": "Authentication failed — check username/password"}
    except paramiko.SSHException as e:
        return {"ok": False, "error": f"SSH error: {e}"}
    except socket.timeout:
        return {"ok": False, "error": f"Connection to {switch_ip} timed out"}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}

def admin_port_shutdown(switch_ip: str, port: str, user: str, pwd: str):
    """SSH to switch and shutdown/no-shutdown the given port.
    Used for VLANs 1088, 1021-1024, 1028."""
    if not HAS_PARAMIKO:
        return {"ok": False, "error": "Paramiko not installed on server"}
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(switch_ip, username=user, password=pwd, timeout=10,
                      look_for_keys=False, allow_agent=False)
        chan = client.invoke_shell()
        time.sleep(1)
        chan.recv(65535)

        def send(cmd, wait=1.0):
            chan.send(cmd + "\n")
            time.sleep(wait)
            return chan.recv(65535).decode("utf-8", errors="replace") if chan.recv_ready() else ""

        log = ""
        log += send("enable")
        log += send("configure terminal")
        log += send(_build_iface_command(port))
        log += send("shutdown")
        time.sleep(5)
        log += send("no shutdown")
        # Close cleanly without 'end' — just close the session
        chan.close()
        client.close()
        return {"ok": True, "output": log[-2000:]}
    except paramiko.AuthenticationException:
        return {"ok": False, "error": "Authentication failed — check username/password"}
    except paramiko.SSHException as e:
        return {"ok": False, "error": f"SSH error: {e}"}
    except socket.timeout:
        return {"ok": False, "error": f"Connection to {switch_ip} timed out"}
    except Exception as e:
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}

def admin_remote_power(ip: str, action: str, user: str, pwd: str):
    """Restart or shutdown a remote Windows PC.
    Fire-and-forget: returns immediately after sending the command, since the
    target PC kills the SMB session as it shuts down (server would hang otherwise)."""
    flag = "/r" if action == "restart" else "/s"
    target = f"\\\\{ip}"
    try:
        # Step 1: clean up any stale connection (ignore errors)
        subprocess.run(["net", "use", f"\\\\{ip}\\IPC$", "/delete", "/y"],
                      capture_output=True, timeout=5)

        # Step 2: authenticate with given credentials
        if user and pwd:
            net_cmd = ["net", "use", f"\\\\{ip}\\IPC$", pwd, f"/user:{user}"]
            net_r = subprocess.run(net_cmd, capture_output=True, text=True, timeout=10,
                                  encoding='utf-8', errors='replace')
            if net_r.returncode != 0:
                err = (net_r.stderr or net_r.stdout or "").strip()
                return {"ok": False, "error": f"Authentication failed: {err[:300]}"}

        # Step 3: fire shutdown command with short timeout
        # Use 5s timeout — the PC will lose its SMB connection mid-response,
        # which throws TimeoutExpired even though the command was accepted.
        cmd = ["shutdown", flag, "/m", target, "/t", "0", "/f"]
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=5,
                              encoding='utf-8', errors='replace')
            # Cleanup if it returned (rare — usually times out)
            subprocess.run(["net","use",f"\\\\{ip}\\IPC$","/delete","/y"],
                          capture_output=True, timeout=5)
            if r.returncode == 0:
                return {"ok": True, "output": f"{action.capitalize()} command accepted by {ip}"}
            out = (r.stdout or "") + (r.stderr or "")
            return {"ok": False, "error": f"Command failed (code {r.returncode})",
                    "output": out[-500:]}
        except subprocess.TimeoutExpired:
            # This is the EXPECTED outcome — the PC restarted before responding.
            # The command was already accepted; consider it a success.
            return {"ok": True,
                    "output": f"{action.capitalize()} command sent to {ip} — PC is going down now."}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def admin_open_explorer(ip: str, user: str = "", pwd: str = ""):
    r"""Open \\IP\c$ in Windows Explorer using provided credentials.
    Uses 'net use' to establish an authenticated connection, then opens Explorer."""
    try:
        path = f"\\\\{ip}\\c$"
        if platform.system() != "Windows":
            subprocess.Popen(["xdg-open", path])
            return {"ok": True}

        # Step 1: clean up any existing connection to this host (ignore errors)
        subprocess.run(["net", "use", path, "/delete", "/y"],
                      capture_output=True, timeout=5)

        # Step 2: authenticate with provided credentials
        if user and pwd:
            net_cmd = ["net", "use", path, pwd, f"/user:{user}"]
            r = subprocess.run(net_cmd, capture_output=True, text=True,
                              timeout=15, encoding='utf-8', errors='replace')
            if r.returncode != 0:
                err = (r.stderr or r.stdout or "").strip()
                return {"ok": False,
                        "error": f"Authentication failed: {err[:300]}"}

        # Step 3: open Explorer at the now-authenticated path
        try:
            os.startfile(path)
        except Exception:
            subprocess.Popen(f'explorer.exe "{path}"', shell=True)

        return {"ok": True,
                "note": f"Connected to {path} as {user or '(your Windows user)'}"}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def admin_open_ssh(ip: str, user: str):
    """Open an interactive SSH session in a new console window.
    Uses Windows built-in OpenSSH client (ssh.exe) — no install required.
    The user types their password directly in the cmd window that opens."""
    try:
        if platform.system() == "Windows":
            ssh_args = (
                f'ssh -o StrictHostKeyChecking=no '
                f'-o UserKnownHostsFile=NUL '
                f'-o ConnectTimeout=10 '
                f'{user}@{ip}'
            )
            # /k keeps the cmd window open after ssh exits
            cmd = f'start "SSH {user}@{ip}" cmd /k "{ssh_args}"'
            subprocess.Popen(cmd, shell=True)
            return {"ok": True,
                    "note": "If 'ssh' is not recognized, install OpenSSH Client from Windows Optional Features."}
        else:
            subprocess.Popen(["xterm", "-e", f"ssh {user}@{ip}"])
            return {"ok": True}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def admin_run_remote_cmd(pc_name: str, cmd: str, user: str, pwd: str):
    """Run a PowerShell command on a remote Windows PC using Invoke-Command.
    Format: Invoke-Command -ComputerName "pcname" -ScriptBlock {command}
    """
    try:
        # Escape single quotes in password for PS string
        pwd_esc = pwd.replace("'", "''")
        # Build the PowerShell expression
        ps_script = (
            f"$pwd = ConvertTo-SecureString '{pwd_esc}' -AsPlainText -Force; "
            f"$cred = New-Object System.Management.Automation.PSCredential('{user}', $pwd); "
            f"Invoke-Command -ComputerName \"{pc_name}\" -Credential $cred "
            f"-ScriptBlock {{ {cmd} }} -ErrorAction Stop"
        )
        ps_cmd = ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_script]
        r = subprocess.run(ps_cmd, capture_output=True, text=True, timeout=60,
                          encoding='utf-8', errors='replace')
        out = (r.stdout or "") + (r.stderr or "")
        return {"ok": r.returncode == 0, "output": out[-3000:] if out else "(no output)"}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "Command timed out (60s)"}
    except Exception as e:
        return {"ok": False, "error": str(e)}

# ══════════════════════════════════════════════════════════════════════════
# MANUAL ADD: append a new <device> to the XML file
# ══════════════════════════════════════════════════════════════════════════
def _diff_layouts(old: dict, new: dict) -> list:
    """Compare two layout dicts and return a list of admin-log events.
    Each event: {event, target, detail}"""
    events = []
    old_devs = (old or {}).get("devices", {}) or {}
    new_devs = (new or {}).get("devices", {}) or {}

    # Devices added/removed
    for mac in set(new_devs) - set(old_devs):
        events.append({"event":"placed", "target":mac,
                       "detail":f"x={new_devs[mac].get('x','?')} y={new_devs[mac].get('y','?')}"})
    for mac in set(old_devs) - set(new_devs):
        events.append({"event":"unplaced", "target":mac, "detail":""})

    # Devices moved or display name changed
    for mac in set(old_devs) & set(new_devs):
        o, n = old_devs[mac], new_devs[mac]
        if o.get('x') != n.get('x') or o.get('y') != n.get('y'):
            events.append({"event":"moved","target":mac,
                "detail":f"({o.get('x','?')},{o.get('y','?')}) -> ({n.get('x','?')},{n.get('y','?')})"})
        if o.get('displayName') != n.get('displayName'):
            events.append({"event":"display-name", "target":mac,
                "detail":f"'{o.get('displayName','')}' -> '{n.get('displayName','')}'"})
        if o.get('size') != n.get('size'):
            events.append({"event":"resized","target":mac,
                "detail":f"size {o.get('size','normal')} -> {n.get('size','normal')}"})

    # Notes
    old_notes = (old or {}).get("notes", {}) or {}
    new_notes = (new or {}).get("notes", {}) or {}
    for mac in set(new_notes):
        if new_notes[mac] != old_notes.get(mac):
            events.append({"event":"note", "target":mac,
                "detail":f"'{(new_notes[mac] or '')[:200]}'"})
    for mac in set(old_notes) - set(new_notes):
        events.append({"event":"note-deleted", "target":mac, "detail":""})

    # Rooms
    old_rooms = {r["id"]: r for r in (old or {}).get("rooms",[]) if r.get("id")}
    new_rooms = {r["id"]: r for r in (new or {}).get("rooms",[]) if r.get("id")}
    for rid in set(new_rooms) - set(old_rooms):
        events.append({"event":"room-added","target":rid,
            "detail":f"label='{new_rooms[rid].get('label','')}'"})
    for rid in set(old_rooms) - set(new_rooms):
        events.append({"event":"room-deleted","target":rid,
            "detail":f"label='{old_rooms[rid].get('label','')}'"})

    # Racks
    old_racks = {r["id"]: r for r in (old or {}).get("racks",[]) if r.get("id")}
    new_racks = {r["id"]: r for r in (new or {}).get("racks",[]) if r.get("id")}
    for rid in set(new_racks) - set(old_racks):
        events.append({"event":"rack-added","target":rid,
            "detail":f"label='{new_racks[rid].get('label','')}' switches={len(new_racks[rid].get('switches',[]))}"})
    for rid in set(old_racks) - set(new_racks):
        events.append({"event":"rack-deleted","target":rid,
            "detail":f"label='{old_racks[rid].get('label','')}'"})

    return events

# ══════════════════════════════════════════════════════════════════════════
# MANUAL ADD: append a new <device> to the XML file
# ══════════════════════════════════════════════════════════════════════════
def _append_device_to_xml(xml_file: str, dev: dict, mac: str) -> bool:
    """Append a new <device> element to the existing XML file.
    Field set & order matches inventory.py builder exactly so the next
    inventory scan can update fields naturally without conflicts.

    User-fillable fields (manual or via cross-reference):
      name, ip, mac, vlan, switch, port, type, serial

    Builder will fill the rest on next scan: rack, designation, model,
    second-ip, etc. — the empty tags are written so structure matches."""
    try:
        from xml.etree import ElementTree as ET
        tree = ET.parse(xml_file)
        root = tree.getroot()

        dev_id = secrets.token_hex(4)
        new_el = ET.SubElement(root, 'device')
        new_el.set('id', dev_id)

        ts = time.strftime("%Y-%m-%dT%H:%M:%S") + "Z"

        # Resolve type: user input > VLAN map > name prefix > empty
        type_value = (
            (dev.get('type','') or '').strip()
            or _type_from_vlan(dev.get('vlan','') or '')
            or _guess_type_from_name(dev.get('name','') or '')
        )

        # EXACT field order from inventory.py _build()
        # Empty fields get empty tags so XML structure stays consistent.
        fields = [
            ('ip',                (dev.get('ip','') or '').strip()),
            ('mac',               mac),
            ('vlan',              str(dev.get('vlan','') or '').strip()),
            ('last-vlan',         ''),
            ('switch',            (dev.get('switch','') or '').strip()),
            ('port',              (dev.get('port','') or '').strip()),
            ('name',              (dev.get('name','') or '').strip()),
            ('rack',              ''),                 # builder fills via RACK_MAPPING
            ('type',              type_value),
            ('serial',            (dev.get('serial','') or '').strip()),
            ('second-ip',         ''),                 # builder discovers
            ('last-ip',           ''),
            ('designation',       ''),                 # builder discovers
            ('model',             ''),                 # builder discovers
            ('previous-mac',      ''),
            ('first-seen',        ts),                 # ALWAYS server-set
            ('history',           ''),
            ('xml_change_status', f"manual-add:{ts}"),
        ]
        for tag, val in fields:
            sub = ET.SubElement(new_el, tag)
            sub.text = val if val else ''

        # Pretty-print (Python 3.9+)
        try: ET.indent(tree, space='  ', level=0)
        except: pass

        tree.write(xml_file, encoding='utf-8', xml_declaration=True)
        return True
    except Exception as e:
        print(f"[manual-add] {e}")
        return False

def _update_device_in_xml(xml_file: str, mac: str, updates: dict) -> tuple[bool, str]:
    """Find <device> with matching <mac> and update specified fields.
    Returns (ok, error_message)."""
    try:
        from xml.etree import ElementTree as ET
        tree = ET.parse(xml_file)
        root = tree.getroot()

        target = None
        for dev in root.findall('device'):
            m = dev.find('mac')
            if m is not None and (m.text or '').strip().upper() == mac.upper():
                target = dev; break
        if target is None:
            return False, f"Device with MAC {mac} not found in XML"

        ts = time.strftime("%Y-%m-%dT%H:%M:%S") + "Z"
        changed = []
        for tag, val in updates.items():
            # Don't allow editing of mac, first-seen, history fields
            if tag in ('mac', 'first-seen', 'last-seen', 'last_seen',
                       'last-update', 'last_update',
                       'history', 'xml_change_status', 'previous-mac', 'removed'):
                continue
            new_val = str(val if val is not None else '').strip()
            sub = target.find(tag)
            if sub is None:
                sub = ET.SubElement(target, tag)
            old_val = (sub.text or '').strip()
            if old_val != new_val:
                sub.text = new_val if new_val else ''
                changed.append(f"{tag}: '{old_val}'→'{new_val}'")

        # Note the change in xml_change_status
        if changed:
            xcs = target.find('xml_change_status')
            if xcs is None:
                xcs = ET.SubElement(target, 'xml_change_status')
            xcs.text = f"manual-edit:{ts}"

        try: ET.indent(tree, space='  ', level=0)
        except: pass
        tree.write(xml_file, encoding='utf-8', xml_declaration=True)
        return True, ('; '.join(changed) if changed else 'no changes')
    except Exception as e:
        return False, str(e)

def _delete_device_from_xml(xml_file: str, mac: str) -> tuple[bool, str]:
    """Remove the <device> element with matching <mac> from XML.
    Returns (ok, error_message_or_summary)."""
    try:
        from xml.etree import ElementTree as ET
        tree = ET.parse(xml_file)
        root = tree.getroot()

        target = None
        for dev in root.findall('device'):
            m = dev.find('mac')
            if m is not None and (m.text or '').strip().upper() == mac.upper():
                target = dev; break
        if target is None:
            return False, f"Device with MAC {mac} not found in XML"

        # Capture identity for log
        name = (target.findtext('name') or '').strip()
        ip   = (target.findtext('ip')   or '').strip()
        root.remove(target)

        try: ET.indent(tree, space='  ', level=0)
        except: pass
        tree.write(xml_file, encoding='utf-8', xml_declaration=True)
        return True, f"name={name} ip={ip}"
    except Exception as e:
        return False, str(e)

def _guess_type_from_name(name: str) -> str:
    """Guess device type from name prefix as a fallback only.
    inventory.py uses VLAN_TYPE_MAP to determine type — this is just a hint."""
    n = (name or '').upper()
    if n.startswith(('C','W')):  return 'pc'
    if n.startswith('SW'):       return 'switch'
    if n.startswith('AP'):       return 'ap'
    if n.startswith('PR'):       return 'printer'
    return ''

# Mirror VLAN_TYPE_MAP from inventory.py so manual-add picks the same type
# the builder would assign. If user enters a type, it overrides this.
INVENTORY_VLAN_TYPE_MAP = {
    "pc":      ["22", "23"],
    "switch":  ["8",  "9"],
    "printer": ["30", "31"],
    "plc":     ["40", "41"],
    "hmi":     ["42", "43"],
    "camera":  ["50"],
    "server":  ["10", "11"],
}
def _type_from_vlan(vlan: str) -> str:
    v = (vlan or '').strip()
    for t, vlans in INVENTORY_VLAN_TYPE_MAP.items():
        if v in vlans: return t
    return ''

# ══════════════════════════════════════════════════════════════════════════
# XML BUILDER RUNNER
# Runs xmlbuilder.py (next to server.py or .exe) in a new CMD window.
# User enters SSH credentials interactively in the CMD window.
# User picks scan mode and enters SSH credentials interactively.
# ══════════════════════════════════════════════════════════════════════════

def _normalize_mac(s: str) -> str:
    """Normalize MAC to AA:BB:CC:DD:EE:FF format."""
    import re as _re
    raw = _re.sub(r'[^0-9a-fA-F]', '', s or '')
    if len(raw) != 12: return (s or '').upper()
    return ':'.join(raw[i:i+2].upper() for i in range(0, 12, 2))

def find_builder_path() -> str | None:
    """Find xmlbuilder.py next to server.py or next to the .exe."""
    candidates = []
    try:
        candidates.append(Path(__file__).resolve().parent / "xmlbuilder.py")
    except: pass
    try:
        import sys as _sys
        if getattr(_sys, 'frozen', False):
            candidates.append(Path(_sys.executable).parent / "xmlbuilder.py")
    except: pass
    if xml_path_store[0]:
        candidates.append(Path(xml_path_store[0]).parent / "xmlbuilder.py")
    for p in candidates:
        if p and p.exists():
            return str(p)
    return None

def run_builder_in_cmd(xml_path: str) -> dict:
    """Open a new CMD window (elevated to admin) running xmlbuilder.py.
    User picks scan mode and enters SSH credentials interactively.

    Approach: write a small .bat file to TEMP, launch it elevated via PowerShell.
    This is more reliable than trying to escape & and " through PowerShell ArgumentList.
    Returns {ok, note/error}."""
    builder = find_builder_path()
    if not builder:
        return {"ok": False, "error":
            "xmlbuilder.py not found. Place it next to server.py or NetMap.exe."}
    if not xml_path:
        return {"ok": False, "error":
            "No XML file loaded. Restart the server with the XML path: python server.py \"C:\\path\\to\\file.xml\""}

    # Check that python.exe is on PATH
    try:
        res = subprocess.run(["where", "python"], capture_output=True, text=True,
                            timeout=5, shell=True)
        if res.returncode != 0 or not res.stdout.strip():
            return {"ok": False, "error":
                "Python is not installed or not in PATH. The XML builder needs Python to run.\n"
                "Install Python from https://python.org and make sure 'Add to PATH' is checked during install."}
    except Exception:
        pass

    # Write a .bat file so cmd has a real script to run
    # (More reliable than trying to escape long command lines through PowerShell)
    try:
        import tempfile
        bat_dir = Path(tempfile.gettempdir()) / "netmap"
        bat_dir.mkdir(exist_ok=True)
        bat_file = bat_dir / "run_xml_builder.bat"
        bat_content = (
            f'@echo off\r\n'
            f'title NetMap XML Builder\r\n'
            f'echo ============================================\r\n'
            f'echo  NetMap XML Builder\r\n'
            f'echo  Running with administrator privileges\r\n'
            f'echo ============================================\r\n'
            f'echo.\r\n'
            f'cd /d "{Path(builder).parent}"\r\n'
            f'python "{builder}" --xml "{xml_path}"\r\n'
            f'echo.\r\n'
            f'echo ============================================\r\n'
            f'echo  Builder finished. Press any key to close.\r\n'
            f'echo ============================================\r\n'
            f'pause\r\n'
        )
        bat_file.write_text(bat_content, encoding='utf-8')
    except Exception as e:
        return {"ok": False, "error": f"Failed to write launcher .bat: {e}"}

    # Launch the .bat elevated. Use cmd /k so the window stays open even if the bat returns early.
    ps_cmd = f"Start-Process cmd.exe -Verb RunAs -ArgumentList '/k','\"{bat_file}\"'"
    try:
        subprocess.Popen(
            ["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", ps_cmd],
            shell=False
        )
        return {"ok": True,
                "note": "Builder window opening — accept the UAC prompt, then choose scan mode and enter SSH credentials."}
    except Exception as e:
        return {"ok": False, "error": f"Failed to launch elevated CMD: {e}"}

# ══════════════════════════════════════════════════════════════════════════
# ADMIN LOG (encrypted, supervisor-only)
# ══════════════════════════════════════════════════════════════════════════
ADMIN_LOG_FILE = None  # set in main
# Audit password - obfuscated with XOR. The plaintext is given to you separately.
# This is obfuscation, not real cryptography — anyone reading server.py can extract it.
_AUDIT_OBFUSCATED = "exIyf1QGIEdPGgcCFC5BdlN1Kj9JGTEy"
_AUDIT_XOR_KEY = "NetMapAuditKey2026"
def _audit_password() -> str:
    raw = base64.b64decode(_AUDIT_OBFUSCATED)
    return ''.join(chr(b ^ ord(_AUDIT_XOR_KEY[i % len(_AUDIT_XOR_KEY)])) for i,b in enumerate(raw))

def _audit_key() -> bytes:
    """Derive a 32-byte AES key from the audit password using SHA-256."""
    return hashlib.sha256(_audit_password().encode('utf-8')).digest()

def _encrypt_blob(plaintext: str) -> str:
    """Encrypt with AES-256-CBC and return base64. Each call uses fresh random IV."""
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        key = _audit_key()
        iv  = secrets.token_bytes(16)
        # PKCS7 padding
        data = plaintext.encode('utf-8')
        pad  = 16 - (len(data) % 16)
        data = data + bytes([pad]*pad)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        ct = cipher.encryptor().update(data) + cipher.encryptor().finalize()
        return base64.b64encode(iv + ct).decode('ascii')
    except Exception as e:
        print(f"[audit] encrypt failed: {e}")
        return ""

def _decrypt_blob(blob: str) -> str:
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        raw = base64.b64decode(blob)
        iv, ct = raw[:16], raw[16:]
        cipher = Cipher(algorithms.AES(_audit_key()), modes.CBC(iv), backend=default_backend())
        pt = cipher.decryptor().update(ct) + cipher.decryptor().finalize()
        pad = pt[-1]
        return pt[:-pad].decode('utf-8')
    except Exception as e:
        print(f"[audit] decrypt failed: {e}")
        return ""

admin_log_lock = threading.Lock()

# ── SITE-SETTINGS PASSWORD ─────────────────────────────────────────
# Opening the ⚙ gear (Site Settings) requires this password.
# Same obfuscation approach as audit — real protection is the OS filesystem
# permissions on server.py, not the XOR key here.
_SETTINGS_OBFUSCATED = "A1xQPzBHNSkXWScMRhgdFSEAE0hvJlMV"
_SETTINGS_XOR_KEY = "NetMapSettingsKey2026"
def _settings_password() -> str:
    raw = base64.b64decode(_SETTINGS_OBFUSCATED)
    return ''.join(chr(b ^ ord(_SETTINGS_XOR_KEY[i % len(_SETTINGS_XOR_KEY)])) for i,b in enumerate(raw))

settings_tokens = set()
def verify_settings_token(headers) -> bool:
    return headers.get("X-Settings-Token","") in settings_tokens

def log_admin(event: str, user: str = "", target: str = "", detail: str = ""):
    """Append an entry to the encrypted admin log."""
    if not ADMIN_LOG_FILE: return
    with admin_log_lock:
        existing = load_admin_log()
        entry = {
            "ts":     time.strftime("%Y-%m-%d %H:%M:%S"),
            "host":   platform.node(),
            "user":   user or "",
            "event":  event,
            "target": target or "",
            "detail": (detail or "")[:500],
        }
        existing.insert(0, entry)
        existing = existing[:10000]   # cap at 10000 entries (was 2000; more room for template/photo/box audit)
        save_admin_log(existing)

def load_admin_log() -> list:
    if not ADMIN_LOG_FILE or not ADMIN_LOG_FILE.exists(): return []
    try:
        blob = ADMIN_LOG_FILE.read_text(encoding='utf-8').strip()
        if not blob: return []
        plain = _decrypt_blob(blob)
        return json.loads(plain) if plain else []
    except Exception as e:
        print(f"[audit] load failed: {e}")
        return []

def save_admin_log(entries: list):
    if not ADMIN_LOG_FILE: return
    try:
        blob = _encrypt_blob(json.dumps(entries))
        atomic_write(ADMIN_LOG_FILE, blob)
    except Exception as e: print(f"[audit] save failed: {e}")

# Audit-mode session tokens (separate from regular auth)
audit_tokens = set()

def verify_audit_token(headers) -> bool:
    return headers.get("X-Audit-Token","") in audit_tokens


class Handler(http.server.SimpleHTTPRequestHandler):
    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Auth-Token, X-Audit-Token, X-User-Host")

    def _json(self, data):
        body = json.dumps(data).encode('utf-8')
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._cors()
        self.end_headers()
        self.wfile.write(body)

    def _error(self, msg, status=500):
        body = json.dumps({"ok": False, "error": str(msg)}).encode('utf-8')
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._cors()
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def log_message(self, format, *args):
        pass   # suppress default request logging

    def do_GET(self):
        p = urllib.parse.urlparse(self.path)
        path, qs = p.path, urllib.parse.parse_qs(p.query)

        # Serve the HTML at root (embedded by .exe launcher, or from www/ on disk)
        if path == "/" or path == "/index.html":
            try:
                import builtins
                html = getattr(builtins, '__NETMAP_HTML__', None)
                if html is None:
                    html_file = Path(__file__).parent / 'www' / 'index.html'
                    if html_file.exists():
                        html = html_file.read_text(encoding='utf-8')
                if html:
                    body = html.encode('utf-8')
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    # Force browsers to always fetch fresh — prevents stale UI bugs
                    self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
                    self.send_header("Pragma", "no-cache")
                    self.send_header("Expires", "0")
                    self._cors()
                    self.end_headers()
                    self.wfile.write(body)
                    return
                self.send_error(404, "index.html not available")
                return
            except Exception as e:
                self.send_error(500, f"Failed to serve HTML: {e}")
                return

        if path == "/api/devices":
            # include removed flag so frontend can distinguish
            self._json(list(devices_by_mac.values()))

        elif path == "/api/xml-history":
            # Returns metadata for all XML history snapshots (no device data — keeps small)
            try:
                hist = load_xml_history()
                meta = [{"ts": h.get("ts"), "count": h.get("count"), "fp": h.get("fp")}
                        for h in hist]
                self._json({"ok": True, "snapshots": meta})
            except Exception as e:
                self._json({"ok": False, "error": str(e)})

        elif path == "/api/xml-history/snapshot":
            # ?ts=<epoch>  — returns the full snapshot at that timestamp (device data)
            try:
                ts = int(qs.get("ts",["0"])[0] or 0)
                hist = load_xml_history()
                match = next((h for h in hist if h.get("ts") == ts), None)
                if not match:
                    self._json({"ok": False, "error":"snapshot not found"})
                    return
                self._json({"ok": True, "snapshot": match})
            except Exception as e:
                self._json({"ok": False, "error": str(e)})

        elif path == "/api/xml-history/diff":
            # ?since=<epoch>  — diff against snapshot closest to that time.
            # Returns {added:[mac...], removed:[mac...], changed:[{mac,fields:[...]}]}
            try:
                since = int(qs.get("since",["0"])[0] or 0)
                hist = load_xml_history()
                if not hist:
                    self._json({"ok": True, "added":[], "removed":[], "changed":[],
                                "base_ts": None, "current_ts": None})
                    return
                # Find the OLDEST snapshot whose ts >= since (the one closest AFTER 'since');
                # if none exists, use the newest snapshot older than 'since' as baseline.
                older = [h for h in hist if h.get("ts",0) <= since]
                base = older[0] if older else hist[-1]   # newest of the old, or oldest overall
                current = hist[0]                         # newest snapshot overall
                if base is current:
                    self._json({"ok": True, "added":[], "removed":[], "changed":[],
                                "base_ts": base.get("ts"), "current_ts": current.get("ts")})
                    return
                base_devs    = base.get("devs", {})
                current_devs = current.get("devs", {})
                added   = [m for m in current_devs if m not in base_devs]
                removed = [m for m in base_devs   if m not in current_devs]
                changed = []
                for mac in current_devs:
                    if mac not in base_devs: continue
                    diffs = []
                    for f in ("ip","name","vlan","type","switch","port"):
                        if current_devs[mac].get(f) != base_devs[mac].get(f):
                            diffs.append({"field": f,
                                          "from": base_devs[mac].get(f,""),
                                          "to":   current_devs[mac].get(f,"")})
                    if diffs:
                        changed.append({"mac": mac, "diffs": diffs,
                                        "name": current_devs[mac].get("name",""),
                                        "ip": current_devs[mac].get("ip","")})
                # enrich added/removed with names/ips
                added_out = [{"mac": m, "name": current_devs[m].get("name",""),
                              "ip": current_devs[m].get("ip",""),
                              "vlan": current_devs[m].get("vlan","")}
                             for m in added]
                removed_out = [{"mac": m, "name": base_devs[m].get("name",""),
                                "ip": base_devs[m].get("ip",""),
                                "vlan": base_devs[m].get("vlan","")}
                               for m in removed]
                self._json({"ok": True,
                            "added": added_out, "removed": removed_out, "changed": changed,
                            "base_ts": base.get("ts"), "current_ts": current.get("ts")})
            except Exception as e:
                self._json({"ok": False, "error": str(e)})

        elif path == "/api/reload":
            # re-parse XML on demand and return diff summary
            if xml_path:
                try:
                    new_devs = load_xml(xml_path)
                    changes  = merge_devices(new_devs)
                    # Snapshot into rolling XML history if content actually changed
                    snapshot_xml_if_changed(new_devs)
                    self._json({"ok": True, "changes": changes,
                                "total": len(devices_by_mac)})
                except Exception as e:
                    self._error(str(e))
            else:
                self._json({"ok": False, "changes": [], "msg": "No XML file loaded"})

        elif path == "/api/ping-test":
            # Quick single-IP test: /api/ping-test?ip=192.168.1.1
            ip = qs.get("ip",[""])[0].strip()
            if not ip:
                self._json({"error": "provide ?ip=..."})
                return
            import time as _t
            t0=_t.time()
            ok=ping_once(ip)
            ms=round((_t.time()-t0)*1000)
            self._json({"ip":ip,"reachable":ok,"ms":ms,
                        "platform":platform.system()})

        elif path == "/api/debug":
            with store_lock:
                sample_devs  = list(devices_by_mac.items())[:15]
                sample_status = list(status_store.items())[:15]
            self._json({
                "total_devices":     len(devices_by_mac),
                "total_status_keys": len(status_store),
                "sample_device_macs":  [m for m,_ in sample_devs],
                "sample_device_ips":   {m:d.get("ip","?") for m,d in sample_devs},
                "sample_status":       {m:s for m,s in sample_status},
                "platform": platform.system(),
            })

        elif path == "/api/auth/status":
            # Returns whether a password has been set
            self._json({"status": auth_status()})

        elif path == "/api/status":
            with store_lock:
                self._json(dict(status_store))

        elif path == "/api/env":
            # Runtime environment info — admin privilege, OS, python version.
            # Used by the Run Scan modal to warn if WinRM features may fail.
            try:
                is_admin = False
                if os.name == "nt":
                    try:
                        import ctypes
                        is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
                    except Exception:
                        is_admin = False
                else:
                    try:
                        is_admin = os.geteuid() == 0
                    except Exception:
                        is_admin = False
                self._json({
                    "ok": True,
                    "os": os.name,
                    "platform": platform.system(),
                    "is_admin": is_admin,
                    "hostname": platform.node(),
                })
            except Exception as e:
                self._json({"ok": False, "error": str(e)})

        elif path == "/api/live-status":
            # Shared status file — any user's ping updates land here.
            # Returns {mac: {status, ts, by, age_sec}} for every fresh entry.
            # Entries older than STATUS_FRESHNESS_MAX are omitted (treated as no-info).
            try:
                cur = load_live_status()
                now = int(time.time())
                fresh = {}
                for mac, entry in cur.items():
                    ts  = entry.get("ts", 0)
                    age = now - ts
                    if age <= STATUS_FRESHNESS_MAX:
                        fresh[mac] = {
                            "status": entry.get("status", "no_info"),
                            "ts":     ts,
                            "by":     entry.get("by", ""),
                            "age":    age
                        }
                self._json({"statuses": fresh, "now": now,
                            "freshness_max": STATUS_FRESHNESS_MAX})
            except Exception as e:
                self._json({"statuses":{}, "now": int(time.time()),
                            "freshness_max": STATUS_FRESHNESS_MAX})

        elif path.startswith("/photos/"):
            # Serve an uploaded photo. Path traversal is blocked by rejecting
            # any filename that resolves outside PHOTOS_DIR.
            try:
                fname = path[len("/photos/"):]
                if not fname or "/" in fname or "\\" in fname or ".." in fname:
                    self.send_error(404); return
                fp = (PHOTOS_DIR / fname).resolve()
                if not fp.exists() or not str(fp).startswith(str(PHOTOS_DIR.resolve())):
                    self.send_error(404); return
                ext = fp.suffix.lower()
                mime = {".jpg":"image/jpeg", ".jpeg":"image/jpeg", ".png":"image/png",
                        ".webp":"image/webp", ".gif":"image/gif"}.get(ext, "application/octet-stream")
                data = fp.read_bytes()
                self.send_response(200)
                self.send_header("Content-Type", mime)
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "public, max-age=86400")
                self._cors()
                self.end_headers()
                self.wfile.write(data)
            except Exception as e:
                self.send_error(500, str(e))

        elif path == "/api/photos/list":
            # List uploaded photos with size + mtime — used by device photos modal / gallery.
            try:
                if not PHOTOS_DIR or not PHOTOS_DIR.exists():
                    self._json({"ok": True, "photos": []}); return
                entries = []
                for fp in PHOTOS_DIR.iterdir():
                    if fp.is_file() and fp.suffix.lower() in PHOTO_ALLOWED_EXT:
                        try:
                            st = fp.stat()
                            entries.append({"name": fp.name, "size": st.st_size,
                                            "mtime": int(st.st_mtime),
                                            "url": f"/photos/{fp.name}"})
                        except: pass
                entries.sort(key=lambda x: -x["mtime"])
                self._json({"ok": True, "photos": entries, "count": len(entries)})
            except Exception as e:
                self._json({"ok": False, "error": str(e)})

        elif path == "/api/storage/stats":
            # Report size of all data files + photos folder.
            # Client shows this in Settings → Advanced.
            try:
                info = {}
                files = {
                    "layout.json":         LAYOUT_FILE,
                    "history.json":        HISTORY_FILE,
                    "alerts.json":         ALERTS_FILE,
                    "known_macs.json":     KNOWN_FILE,
                    "actions.json":        ACTIONS_FILE,
                    "presence.json":       PRESENCE_FILE,
                    "admin.json":          ADMIN_LOG_FILE,
                    "filter_history.json": FILTER_HIST_FILE,
                    "toolbar_prefs.json":  TOOLBAR_PREFS_FILE,
                    "live_status.json":    LIVE_STATUS_FILE,
                    "xml_history.json":    XML_HISTORY_FILE,
                    "templates.json":      TEMPLATES_FILE,
                    "site_config.json":    SITE_CONFIG_FILE,
                }
                total = 0
                for name, fp in files.items():
                    if fp and fp.exists():
                        try: sz = fp.stat().st_size
                        except: sz = 0
                    else: sz = 0
                    info[name] = sz
                    total += sz
                photos_total = 0; photos_count = 0
                if PHOTOS_DIR and PHOTOS_DIR.exists():
                    for fp in PHOTOS_DIR.iterdir():
                        if fp.is_file():
                            try: photos_total += fp.stat().st_size; photos_count += 1
                            except: pass
                info["photos/ (folder)"] = photos_total
                total += photos_total
                self._json({"ok": True, "files": info, "total": total,
                            "photos_count": photos_count})
            except Exception as e:
                self._json({"ok": False, "error": str(e)})

        elif path == "/api/photos/size":
            # Report total size of photos/ folder + a warning threshold.
            # Client shows a banner when total > threshold.
            try:
                total = 0
                count = 0
                if PHOTOS_DIR and PHOTOS_DIR.exists():
                    for fp in PHOTOS_DIR.iterdir():
                        if fp.is_file():
                            try: total += fp.stat().st_size; count += 1
                            except: pass
                # Read cap from config; fall back to 10 GB
                cap_gb = _cfg_runtime("photos_folder_gb", 10)
                warn_bytes = cap_gb * 1024 * 1024 * 1024
                self._json({"ok": True,
                            "bytes": total, "count": count,
                            "warn_bytes": warn_bytes,
                            "warn_reached": total > warn_bytes})
            except Exception as e:
                self._json({"ok": False, "error": str(e)})

        elif path == "/api/site-config":
            # Returns the effective site config (defaults merged with user values).
            try:
                self._json({"ok": True, "config": get_site_config()})
            except Exception as e:
                self._json({"ok": False, "error": str(e)})

        elif path == "/api/templates":
            # Return this host's private templates + ALL public templates.
            # ?host= override for testing; normally hostname is auto-detected.
            try:
                host = (self.headers.get("X-User-Host") or "").strip() \
                       or (qs.get("host",[""])[0].strip()) \
                       or platform.node()
                with _templates_lock:
                    data = load_templates()
                mine = data.get("private", {}).get(host, [])
                pub  = data.get("public", [])
                self._json({"ok": True, "host": host, "private": mine, "public": pub})
            except Exception as e:
                self._json({"ok": False, "error": str(e)})

        elif path == "/api/history":
            # return history enriched with device name/ip for switches
            out = {}
            with store_lock:
                for mac, h in history_store.items():
                    d = devices_by_mac.get(mac, {})
                    out[mac] = {**h, "name": d.get("name",""), "ip": d.get("ip","")}
            self._json(out)

        elif path == "/api/timeline":
            # /api/timeline?mac=AA:BB:CC:DD:EE:FF&days=30
            # Returns the device's status transitions for the last N days.
            mac  = (qs.get("mac",[""])[0] or "").strip()
            try: days = max(1, min(365, int(qs.get("days",["30"])[0])))
            except: days = 30
            if not mac:
                self._json({"ok": False, "error":"missing mac"}); return
            with store_lock:
                h = history_store.get(mac)
                d = devices_by_mac.get(mac, {})
            if not h:
                self._json({"ok": True, "mac": mac, "transitions":[],
                            "name": d.get("name",""), "ip": d.get("ip","")})
                return
            cutoff = int(time.time()) - days*86400
            trans = [t for t in (h.get("transitions") or []) if t.get("ts",0) >= cutoff]
            # Fallback for devices that have history.json data but no transitions array yet
            if not trans:
                last_changed = h.get("last_changed")
                current      = h.get("status", "no_info")
                if last_changed and last_changed >= cutoff and current in ("online","offline"):
                    trans = [{"ts": int(last_changed), "status": current, "_synthesized": True}]
            self._json({
                "ok": True,
                "mac": mac,
                "name": d.get("name",""),
                "ip":   d.get("ip",""),
                "current_status": h.get("status","no_info"),
                "transitions": trans,
                "days": days,
                "now": int(time.time())
            })

        elif path == "/api/timeline/bulk":
            # /api/timeline/bulk?macs=AA:BB:CC,DD:EE:FF&days=30
            # Returns timeline data for many devices at once — used by bulk export.
            macs_raw = (qs.get("macs",[""])[0] or "").strip()
            try: days = max(1, min(365, int(qs.get("days",["30"])[0])))
            except: days = 30
            if not macs_raw:
                self._json({"ok": False, "error":"missing macs"}); return
            mac_list = [m.strip().upper() for m in macs_raw.split(",") if m.strip()]
            cutoff = int(time.time()) - days*86400
            now = int(time.time())
            results = []
            with store_lock:
                for mac in mac_list:
                    h = history_store.get(mac, {})
                    d = devices_by_mac.get(mac, {})
                    trans = [t for t in (h.get("transitions") or []) if t.get("ts",0) >= cutoff]
                    if not trans:
                        last_changed = h.get("last_changed")
                        current      = h.get("status", "no_info")
                        if last_changed and last_changed >= cutoff and current in ("online","offline"):
                            trans = [{"ts": int(last_changed), "status": current, "_synthesized": True}]
                    results.append({
                        "mac": mac,
                        "name": d.get("name",""),
                        "ip":   d.get("ip",""),
                        "vlan": d.get("vlan",""),
                        "current_status": h.get("status","no_info"),
                        "transitions": trans
                    })
            self._json({
                "ok": True,
                "days": days,
                "now": now,
                "devices": results
            })

        elif path == "/api/alerts":
            self._json(load_alerts())

        elif path == "/api/actions":
            # /api/actions?mac=AA:BB:CC:DD:EE:FF returns log for one device
            mac = (qs.get("mac",[""])[0] or "").strip()
            store = load_actions()
            if mac:
                self._json(store.get(mac, []))
            else:
                self._json(store)

        elif path == "/api/filter-history":
            # Returns group-wide filter history (last 30 entries used by any user).
            # File layout: [{query, user, ts}, ...] newest first.
            try:
                if not FILTER_HIST_FILE or not FILTER_HIST_FILE.exists():
                    self._json([])
                else:
                    data = json.loads(FILTER_HIST_FILE.read_text(encoding='utf-8'))
                    self._json(data[:30])
            except Exception as e: self._error(str(e))

        elif path == "/api/toolbar-prefs":
            # Returns the calling host's saved toolbar customization.
            # File layout: { "HOSTNAME": {"hidden": ["t-rack","t-ann",...]}, ... }
            try:
                host = (self.headers.get("X-User-Host") or "").strip() or platform.node()
                if not TOOLBAR_PREFS_FILE or not TOOLBAR_PREFS_FILE.exists():
                    self._json({"ok": True, "hidden": []})
                else:
                    allprefs = json.loads(TOOLBAR_PREFS_FILE.read_text(encoding='utf-8'))
                    mine = allprefs.get(host) or {}
                    self._json({"ok": True, "hidden": mine.get("hidden", [])})
            except Exception as e:
                self._json({"ok": True, "hidden": []})  # never block UI on prefs error

        elif path == "/api/presence":
            # Refresh our own heartbeat on every poll, then return who else is online
            heartbeat_tick()
            store = load_presence()
            now = int(time.time())
            users = []
            for uid, info in store.items():
                ts = info.get("ts", 0)
                if now - ts > PRESENCE_TTL: continue
                users.append({
                    "id":   uid,
                    "name": info.get("name", "?"),
                    "self": uid == _my_user_id,
                    "age":  now - ts,
                    "ping_active":   bool(info.get("ping_active")),
                    "ping_filter":   info.get("ping_filter", ""),
                    "ping_wait_min": int(info.get("ping_wait_min") or 0),
                })
            users.sort(key=lambda u: (not u["self"], u["name"]))
            self._json({"count": len(users), "users": users, "me": _my_user_id})

        elif path == "/api/audit/log":
            # Returns admin log entries — only if X-Audit-Token header is valid
            if not verify_audit_token(self.headers):
                self.send_response(403); self._cors(); self.end_headers(); return
            entries = load_admin_log()
            limit = int(qs.get("limit",["500"])[0] or 500)
            self._json(entries[:limit])

        elif path == "/api/audit/status":
            # Frontend asks: is my X-Audit-Token still valid?
            self._json({"audit": verify_audit_token(self.headers)})

        elif path == "/api/layout":
            self._json(load_layout())

        elif path == "/api/search":
            q = qs.get("q",[""])[0].lower().strip()
            res = [d for d in devices_by_mac.values()
                   if q in d.get("ip","").lower() or q in d.get("name","").lower()] if q else []
            self._json(res[:20])

        else:
            super().do_GET()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body   = self.rfile.read(length)

        if self.path == "/api/ping":
            try:
                data  = json.loads(body)
                macs  = data.get("macs", [])
                by_user = (data.get("user_label") or "").strip() \
                          or (self.headers.get("X-User-Host") or "").strip() \
                          or _my_user_label
                if not macs:
                    self._json({})
                    return
                # Publish each VLAN batch to live_status.json as it completes
                # so the frontend + other users see updates immediately, not only
                # after the entire multi-VLAN scan (with 15s pauses) finishes.
                def _stream(batch):
                    try: update_live_status(batch, by_user)
                    except Exception as _e: print(f"[live-status] stream failed: {_e}")
                result = do_ping(macs, partial_cb=_stream)
                # Final consolidated write covers any race — cheap safety net
                try: update_live_status(result, by_user)
                except Exception as _e: print(f"[live-status] final failed: {_e}")
                self._json(result)
            except Exception as e:
                self._error(str(e))

        elif self.path == "/api/ping/state":
            # POST {active:bool, filter:str, wait_min:int, user_label?}
            # Client publishes its ping-session state so others can see who is pinging.
            try:
                data = json.loads(body)
                active  = bool(data.get("active"))
                filt    = str(data.get("filter") or "")[:200]
                wait_m  = int(data.get("wait_min") or 0)
                heartbeat_tick(ping_active=active, ping_filter=filt, ping_wait_min=wait_m)
                self._json({"ok": True})
            except Exception as e: self._error(str(e))

        elif self.path == "/api/ping/cancel":
            # Signal the current ping cycle to abort immediately.
            # Useful when the user toggles ping OFF — server stops processing VLAN groups.
            try:
                ping_cancel_flag.set()
                self._json({"ok": True})
            except Exception as e:
                self._error(str(e))

        elif self.path == "/api/ping/mark":
            # POST {event: "paused" | "resumed"}
            # Logs a marker in every device's history so the timeline knows
            # when ping was off (= no data is the truth, NOT continued last status).
            try:
                data = json.loads(body)
                event = (data.get("event") or "").strip()
                if event not in ("paused", "resumed"):
                    self._json({"ok": False, "error":"event must be paused or resumed"}); return
                now = int(time.time())
                with store_lock:
                    for mac, h in history_store.items():
                        trans = h.get("transitions") or []
                        # Avoid duplicate consecutive markers
                        if trans and trans[-1].get("status") == f"ping_{event}":
                            continue
                        trans.append({"ts": now, "status": f"ping_{event}"})
                        if len(trans) > HISTORY_MAX_TRANSITIONS:
                            trans = trans[-HISTORY_MAX_TRANSITIONS:]
                        h["transitions"] = trans
                    save_history()
                self._json({"ok": True, "event": event, "marked": len(history_store)})
            except Exception as e: self._error(str(e))

        elif self.path == "/api/layout":
            try:
                # Enforce configurable layout.json size cap (default 50 MB)
                cap_mb = _cfg_runtime("layout_max_mb", 50)
                if cap_mb > 0 and len(body) > cap_mb * 1024 * 1024:
                    self._json({"ok": False,
                                "error": f"Layout size {len(body)//1024//1024} MB exceeds cap of {cap_mb} MB. "
                                         f"Consider deleting old drawings/boxes/annotations."})
                    return
                new_layout = json.loads(body)
                # Diff vs previous layout for admin-log purposes
                try:
                    prev = load_layout()
                    diffs = _diff_layouts(prev, new_layout)
                    user_label = self.headers.get("X-User-Host","") or platform.node()
                    for d in diffs:
                        log_admin(d["event"], user_label, d.get("target",""), d.get("detail",""))
                except Exception as e:
                    print(f"[admin] diff failed: {e}")
                save_layout(new_layout)
                self._json({"ok": True})
            except Exception as e:
                self._error(str(e))

        elif self.path == "/api/alerts":
            try:
                save_alerts(json.loads(body))
                self._json({"ok": True})
            except Exception as e:
                self._error(str(e))

        elif self.path == "/api/run-builder":
            # Opens a new CMD window running xmlbuilder.py interactively.
            # User picks scan mode and enters SSH credentials in that window.
            try:
                user_label = (json.loads(body).get("user_label") or "").strip() or platform.node()
                result = run_builder_in_cmd(xml_path_store[0] or "")
                if result.get("ok"):
                    log_admin("run-builder", user_label, "", "XML builder launched")
                self._json(result)
            except Exception as e: self._error(str(e))

        elif self.path == "/api/bulk-ping":
            # Ping a list of targets (IPs, ranges, or hostnames). Generates
            # firewall ARP traffic so the FortiGate learns the MACs.
            # POST {targets: "10.93.1.5, 10.93.2.10-30, hostname1, hostname2"}
            try:
                data = json.loads(body)
                raw = (data.get("targets") or "").strip()
                if not raw:
                    self._json({"ok": False, "error": "No targets given"}); return

                # Parse: comma/newline separated; each entry is an IP, range, or name
                targets = []
                for chunk in re.split(r'[,;\n]+', raw):
                    t = chunk.strip()
                    if not t: continue
                    # IP range like 10.93.1.10-30
                    m = re.match(r'^(\d+\.\d+\.\d+\.)(\d+)-(\d+)$', t)
                    if m:
                        prefix, lo, hi = m.group(1), int(m.group(2)), int(m.group(3))
                        if hi >= lo and hi - lo <= 254:
                            for i in range(lo, hi + 1):
                                targets.append(prefix + str(i))
                        continue
                    targets.append(t)

                if not targets:
                    self._json({"ok": False, "error": "No valid targets parsed"}); return
                if len(targets) > 1024:
                    self._json({"ok": False,
                        "error": f"Too many targets ({len(targets)}). Limit: 1024."}); return

                # Ping all in parallel
                from concurrent.futures import ThreadPoolExecutor
                results = []
                def _ping_one(target):
                    is_online = admin_check_online(target, timeout=1.5)
                    return {"target": target, "online": is_online}
                with ThreadPoolExecutor(max_workers=50) as exe:
                    for r in exe.map(_ping_one, targets):
                        results.append(r)

                online_count = sum(1 for r in results if r["online"])
                self._json({
                    "ok": True,
                    "count": len(results),
                    "online_count": online_count,
                    "offline_count": len(results) - online_count,
                    "results": results
                })
            except Exception as e: self._error(str(e))

        elif self.path == "/api/admin/check":
            try:
                data = json.loads(body)
                ip   = (data.get("ip") or "").strip()
                if not ip: self._json({"online": False, "error":"no IP"}); return
                self._json({"online": admin_check_online(ip)})
            except Exception as e: self._error(str(e))

        elif self.path == "/api/actions/log":
            try:
                data = json.loads(body)
                mac    = (data.get("mac") or "").strip()
                action = (data.get("action") or "").strip()
                user   = (data.get("user") or "").strip()
                result = (data.get("result") or "ok").strip()
                detail = data.get("detail") or ""
                if not mac or not action:
                    self._json({"ok": False, "error":"missing mac or action"}); return
                log_action(mac, action, user, result, detail)
                self._json({"ok": True})
            except Exception as e: self._error(str(e))

        elif self.path == "/api/filter-history":
            # POST {query, user} — append to group-wide filter history
            try:
                data = json.loads(body)
                query = (data.get("query") or "").strip()
                user  = (data.get("user") or "").strip() or platform.node()
                if not query:
                    self._json({"ok": False, "error":"empty query"}); return
                if len(query) > 500:
                    self._json({"ok": False, "error":"query too long"}); return
                # Load existing
                hist = []
                if FILTER_HIST_FILE and FILTER_HIST_FILE.exists():
                    try: hist = json.loads(FILTER_HIST_FILE.read_text(encoding='utf-8'))
                    except: hist = []
                # Remove any prior entries with the same query (case-insensitive) so newer wins
                hist = [h for h in hist if (h.get("query") or "").lower() != query.lower()]
                # Insert at front
                hist.insert(0, {
                    "query": query,
                    "user":  user,
                    "ts":    int(time.time())
                })
                # Cap at 200 entries total to keep file tiny
                hist = hist[:200]
                atomic_write(FILTER_HIST_FILE, json.dumps(hist, indent=2))
                self._json({"ok": True})
            except Exception as e: self._error(str(e))

        elif self.path == "/api/toolbar-prefs":
            # POST {hidden:[...button ids...], user_label?}
            # Saves this host's toolbar customization. Keyed by hostname so each
            # user on the shared XML keeps their own toolbar layout.
            try:
                data = json.loads(body)
                host = (data.get("user_label") or "").strip() \
                       or (self.headers.get("X-User-Host") or "").strip() \
                       or platform.node()
                hidden = data.get("hidden") or []
                if not isinstance(hidden, list):
                    self._json({"ok": False, "error":"hidden must be a list"}); return
                # sanitize — only allow simple id strings
                hidden = [str(x)[:64] for x in hidden if isinstance(x, str)][:100]

                allprefs = {}
                if TOOLBAR_PREFS_FILE and TOOLBAR_PREFS_FILE.exists():
                    try: allprefs = json.loads(TOOLBAR_PREFS_FILE.read_text(encoding='utf-8'))
                    except: allprefs = {}
                if not isinstance(allprefs, dict): allprefs = {}
                allprefs[host] = {"hidden": hidden, "ts": int(time.time())}
                atomic_write(TOOLBAR_PREFS_FILE, json.dumps(allprefs, indent=2))
                self._json({"ok": True, "host": host, "hidden": hidden})
            except Exception as e: self._error(str(e))

        elif self.path == "/api/photos/upload":
            # POST body: {name: "original.jpg", data: "<base64>"}  →  saves file
            # Returns { ok, filename: "abc123.jpg", url: "/photos/abc123.jpg" }
            try:
                data = json.loads(body)
                orig_name = (data.get("name") or "photo").strip()
                b64 = data.get("data") or ""
                if not b64:
                    self._json({"ok": False, "error": "no data"}); return

                # Extract extension safely
                ext = ""
                if "." in orig_name:
                    ext = "." + orig_name.rsplit(".", 1)[-1].lower()
                if ext not in PHOTO_ALLOWED_EXT:
                    self._json({"ok": False,
                                "error": f"Extension {ext} not allowed. Use JPG/PNG/WEBP/GIF"})
                    return

                # Decode base64
                import base64, uuid
                # Strip data-URL prefix if present
                if b64.startswith("data:"):
                    b64 = b64.split(",", 1)[-1]
                try:
                    raw = base64.b64decode(b64, validate=False)
                except Exception:
                    self._json({"ok": False, "error": "bad base64"}); return
                if len(raw) > PHOTO_MAX_BYTES:
                    mb = round(PHOTO_MAX_BYTES/1024/1024, 1)
                    self._json({"ok": False,
                                "error": f"Photo too big — max {mb} MB"})
                    return
                # Enforce total folder cap — 10 GB across all photos
                try:
                    total = 0
                    if PHOTOS_DIR.exists():
                        for f in PHOTOS_DIR.iterdir():
                            if f.is_file():
                                try: total += f.stat().st_size
                                except: pass
                    cap_gb = _cfg_runtime("photos_folder_gb", 10)
                    cap_bytes = cap_gb * 1024 * 1024 * 1024
                    if total + len(raw) > cap_bytes:
                        gb = round((total + len(raw)) / 1024**3, 2)
                        self._json({"ok": False,
                                    "error": f"Photos folder would exceed {cap_gb} GB ({gb} GB after this upload). "
                                             f"Delete old photos first."})
                        return
                except Exception as _e:
                    pass  # size check is advisory — don't block on stat errors
                # Ensure dir exists (in case someone deleted it)
                if not PHOTOS_DIR.exists(): PHOTOS_DIR.mkdir(exist_ok=True)
                # Generate unique filename to avoid collisions
                fname = uuid.uuid4().hex[:12] + ext
                fp = PHOTOS_DIR / fname
                fp.write_bytes(raw)
                # Audit log — photo uploads use shared disk space, worth tracking
                who = (self.headers.get("X-User-Host") or "").strip() or platform.node()
                log_admin("photo-upload", who, fname,
                          f"orig={orig_name[:60]} size={len(raw)}")
                self._json({"ok": True, "filename": fname,
                            "url": f"/photos/{fname}", "bytes": len(raw)})
            except Exception as e: self._error(str(e))

        elif self.path == "/api/photos/delete":
            # POST body: {filename: "abc123.jpg"}  →  removes the file if it exists
            try:
                data = json.loads(body)
                fname = (data.get("filename") or "").strip()
                if not fname or "/" in fname or "\\" in fname or ".." in fname:
                    self._json({"ok": False, "error": "invalid filename"}); return
                fp = (PHOTOS_DIR / fname).resolve()
                if not str(fp).startswith(str(PHOTOS_DIR.resolve())):
                    self._json({"ok": False, "error": "path check failed"}); return
                if fp.exists():
                    fp.unlink()
                    who = (self.headers.get("X-User-Host") or "").strip() or platform.node()
                    log_admin("photo-delete", who, fname, "")
                    self._json({"ok": True, "deleted": fname})
                else:
                    self._json({"ok": True, "deleted": None, "note": "file not found"})
            except Exception as e: self._error(str(e))

        elif self.path == "/api/site-config":
            # POST body: full site config JSON.
            # Requires a valid settings token (obtained via /api/settings/login).
            if not verify_settings_token(self.headers):
                self.send_response(403); self._cors(); self.end_headers()
                return
            try:
                data = json.loads(body)
                if not isinstance(data, dict):
                    self._json({"ok": False, "error": "config must be an object"}); return
                # Strip any credential-looking fields as a safety net
                for danger_key in ("username", "password", "credentials", "creds", "auth"):
                    _strip_deep(data, danger_key)
                with _site_cfg_lock:
                    save_site_config(data)
                # Rebind global runtime constants so changes take effect
                # immediately without a server restart.
                apply_runtime_config()
                # Audit-log the config change (no field values — just that it happened)
                who = (self.headers.get("X-User-Host") or "").strip() or platform.node()
                log_admin("site-config-update", who, "", f"keys={list(data.keys())[:20]}")
                self._json({"ok": True})
            except Exception as e: self._error(str(e))

        elif self.path == "/api/scan/warmup":
            # POST body: {user, pass} — credentials for one-shot firewall ARP dump.
            # Never persisted. Just returns the current device list from firewall.
            try:
                data = json.loads(body)
                user = data.get("user") or ""
                pw   = data.get("pass") or ""
                if not user or not pw:
                    self._json({"ok": False, "error": "credentials required"}); return
                try:
                    from inventory import firewall_warmup
                except ImportError as e:
                    self._json({"ok": False, "error": f"inventory module missing: {e}"}); return
                cfg = get_site_config()
                if not cfg.get("firewall", {}).get("host"):
                    self._json({"ok": False, "error": "no firewall configured — set one in Settings"}); return
                result = firewall_warmup(cfg, user, pw)
                # Clear locals before returning — Python GC will handle
                user = pw = None
                who = (self.headers.get("X-User-Host") or "").strip() or platform.node()
                log_admin("scan-warmup", who, "", f"devices={result.get('count',0)}")
                self._json({"ok": True, **result})
            except Exception as e: self._error(str(e))

        elif self.path == "/api/scan/run":
            # POST body: {user, pass, mode: "full"|"new"|"fields"}
            # Runs the full scan pipeline. Long-running (blocking response until done).
            # Credentials never persist beyond this handler.
            try:
                data = json.loads(body)
                user = data.get("user") or ""
                pw   = data.get("pass") or ""
                mode = data.get("mode") or "full"
                if not user or not pw:
                    self._json({"ok": False, "error": "credentials required"}); return
                if mode not in ("full", "new", "fields"):
                    self._json({"ok": False, "error": "invalid mode"}); return
                try:
                    from inventory import run_full_scan
                except ImportError as e:
                    self._json({"ok": False, "error": f"inventory module missing: {e}"}); return
                cfg = get_site_config()
                if not cfg.get("firewall", {}).get("host"):
                    self._json({"ok": False, "error": "no firewall configured — set one in Settings"}); return
                # Use current XML path as scan output
                xml_target = xml_path_store[0] or cfg.get("output", {}).get("xml_file")
                stats = run_full_scan(cfg, user, pw, mode=mode, xml_path=xml_target)
                user = pw = None
                # Reload XML into runtime store so map updates immediately
                if xml_path_store[0]:
                    try:
                        new_devs = load_xml(xml_path_store[0])
                        merge_devices(new_devs)
                        snapshot_xml_if_changed(new_devs)
                    except Exception as _e:
                        print(f"[scan] post-scan reload failed: {_e}")
                who = (self.headers.get("X-User-Host") or "").strip() or platform.node()
                log_admin("scan-run", who, "", f"mode={mode} stats={stats}")
                self._json({"ok": True, "stats": stats, "mode": mode})
            except Exception as e: self._error(str(e))

        elif self.path == "/api/scan/manual-add":
            # POST body: {mac, ip?, name?, vlan?, switch?, port?, extras?}
            # Adds one device to the XML directly. No credentials needed.
            try:
                data = json.loads(body)
                mac = (data.get("mac") or "").strip()
                if not mac:
                    self._json({"ok": False, "error": "MAC required"}); return
                try:
                    from inventory import manual_add_device
                except ImportError as e:
                    self._json({"ok": False, "error": f"inventory module missing: {e}"}); return
                cfg = get_site_config()
                xml_target = xml_path_store[0] or cfg.get("output", {}).get("xml_file")
                result = manual_add_device(
                    cfg, xml_target, mac,
                    ip=data.get("ip",""), name=data.get("name",""),
                    vlan=data.get("vlan",""), switch=data.get("switch",""),
                    port=data.get("port",""),
                    **(data.get("extras") or {})
                )
                if result.get("ok") and xml_path_store[0]:
                    try:
                        new_devs = load_xml(xml_path_store[0])
                        merge_devices(new_devs)
                        snapshot_xml_if_changed(new_devs)
                    except Exception as _e:
                        print(f"[scan] post-add reload failed: {_e}")
                who = (self.headers.get("X-User-Host") or "").strip() or platform.node()
                log_admin("scan-manual-add", who, mac, "")
                self._json(result)
            except Exception as e: self._error(str(e))

        elif self.path == "/api/templates/save":
            # Body: {id?, name, type: "ssh"|"windows", commands:[...], description?, scope:"private"|"public"}
            # Creates or updates a template. Private ones are keyed by hostname.
            try:
                data = json.loads(body)
                host = (self.headers.get("X-User-Host") or "").strip() \
                       or (data.get("user_label") or "").strip() \
                       or platform.node()
                scope = data.get("scope") or "private"
                name  = (data.get("name") or "").strip()
                ttype = (data.get("type") or "").strip().lower()
                cmds  = data.get("commands") or []
                desc  = (data.get("description") or "").strip()[:400]
                tid   = data.get("id") or ("tmpl_" + str(int(time.time()*1000)))

                if not name:      self._json({"ok": False, "error":"name required"}); return
                if ttype not in ("ssh","windows"):
                    self._json({"ok": False, "error":"type must be ssh or windows"}); return
                if not isinstance(cmds, list) or not cmds:
                    self._json({"ok": False, "error":"at least one command required"}); return
                # sanitize commands to strings, cap length
                cmds = [str(c)[:2000] for c in cmds if isinstance(c, (str, int, float))][:200]
                if not cmds:
                    self._json({"ok": False, "error":"no valid commands"}); return

                now = int(time.time())
                is_new = True
                with _templates_lock:
                    d = load_templates()
                    if scope == "public":
                        lst = d.setdefault("public", [])
                    else:
                        lst = d.setdefault("private", {}).setdefault(host, [])
                    # Find existing by id
                    existing = next((t for t in lst if t.get("id") == tid), None)
                    if existing:
                        is_new = False
                        existing.update({
                            "name": name, "type": ttype, "commands": cmds,
                            "description": desc,
                            "updated_by": host, "updated_at": now,
                        })
                    else:
                        lst.append({
                            "id": tid, "name": name, "type": ttype,
                            "commands": cmds, "description": desc,
                            "created_by": host, "created_at": now,
                            "updated_by": host, "updated_at": now,
                        })
                    save_templates(d)
                # Audit log
                log_admin("template-" + ("update" if not is_new else "create"),
                          host, name,
                          f"scope={scope} type={ttype} commands={len(cmds)}")
                self._json({"ok": True, "id": tid})
            except Exception as e: self._error(str(e))

        elif self.path == "/api/templates/delete":
            # Body: {id, scope:"private"|"public"}
            try:
                data = json.loads(body)
                tid = data.get("id") or ""
                scope = data.get("scope") or "private"
                host = (self.headers.get("X-User-Host") or "").strip() or platform.node()
                if not tid:
                    self._json({"ok": False, "error":"id required"}); return
                deleted_name = ""
                with _templates_lock:
                    d = load_templates()
                    if scope == "public":
                        for t in d.get("public",[]):
                            if t.get("id") == tid: deleted_name = t.get("name",""); break
                        d["public"] = [t for t in d.get("public",[]) if t.get("id") != tid]
                    else:
                        priv = d.setdefault("private", {})
                        for t in priv.get(host, []):
                            if t.get("id") == tid: deleted_name = t.get("name",""); break
                        priv[host] = [t for t in priv.get(host, []) if t.get("id") != tid]
                    save_templates(d)
                log_admin("template-delete", host, deleted_name or tid, f"scope={scope}")
                self._json({"ok": True, "deleted": tid})
            except Exception as e: self._error(str(e))

        elif self.path == "/api/templates/publish":
            # Body: {id}
            # Makes a private template public (one-way — no un-publish).
            # Public copy is a copy; original private stays.
            try:
                data = json.loads(body)
                tid = data.get("id") or ""
                host = (self.headers.get("X-User-Host") or "").strip() or platform.node()
                if not tid:
                    self._json({"ok": False, "error":"id required"}); return
                with _templates_lock:
                    d = load_templates()
                    mine = d.get("private", {}).get(host, [])
                    src = next((t for t in mine if t.get("id") == tid), None)
                    if not src:
                        self._json({"ok": False, "error":"template not found in your private list"}); return
                    now = int(time.time())
                    new_id = "tmpl_" + str(int(time.time()*1000))
                    d.setdefault("public", []).append({
                        "id": new_id,
                        "name": src.get("name",""),
                        "type": src.get("type","ssh"),
                        "commands": list(src.get("commands", [])),
                        "description": src.get("description",""),
                        "created_by": host, "created_at": now,
                        "updated_by": host, "updated_at": now,
                    })
                    save_templates(d)
                log_admin("template-publish", host, src.get("name",""),
                          f"type={src.get('type')} commands={len(src.get('commands',[]))}")
                self._json({"ok": True, "public_id": new_id})
            except Exception as e: self._error(str(e))

        elif self.path == "/api/admin/ap-restart":
            try:
                data = json.loads(body)
                sw   = (data.get("switch_ip") or "").strip()
                port = str(data.get("port") or "").strip()
                u    = data.get("user") or ""
                p    = data.get("pass") or ""
                if not (sw and port and u and p):
                    self._json({"ok": False, "error": "Missing switch IP, port, user or password"}); return
                self._json(admin_ap_restart(sw, port, u, p))
            except Exception as e: self._error(str(e))

        elif self.path == "/api/admin/port-shutdown":
            try:
                data = json.loads(body)
                sw   = (data.get("switch_ip") or "").strip()
                port = str(data.get("port") or "").strip()
                u    = data.get("user") or ""
                p    = data.get("pass") or ""
                if not (sw and port and u and p):
                    self._json({"ok": False, "error": "Missing switch IP, port, user or password"}); return
                self._json(admin_port_shutdown(sw, port, u, p))
            except Exception as e: self._error(str(e))

        elif self.path == "/api/admin/bulk-ap-restart":
            # POST {switch_ip, ports:[...], user, pass}
            # PoE-cycles multiple ports on the same switch in ONE SSH session.
            try:
                data = json.loads(body)
                sw   = (data.get("switch_ip") or "").strip()
                ports = data.get("ports") or []
                u    = data.get("user") or ""
                p    = data.get("pass") or ""
                if not (sw and u and p):
                    self._json({"ok": False, "error": "Missing switch IP, user, or password"}); return
                if not ports:
                    self._json({"ok": False, "error": "Missing ports list"}); return
                self._json(bulk_ap_restart(sw, [str(x) for x in ports], u, p))
            except Exception as e: self._error(str(e))

        elif self.path == "/api/admin/bulk-port-shutdown":
            # POST {switch_ip, ports:[...], user, pass}
            # Shut/no-shut multiple ports on the same switch in ONE SSH session.
            try:
                data = json.loads(body)
                sw   = (data.get("switch_ip") or "").strip()
                ports = data.get("ports") or []
                u    = data.get("user") or ""
                p    = data.get("pass") or ""
                if not (sw and u and p):
                    self._json({"ok": False, "error": "Missing switch IP, user, or password"}); return
                if not ports:
                    self._json({"ok": False, "error": "Missing ports list"}); return
                self._json(bulk_port_shutdown(sw, [str(x) for x in ports], u, p))
            except Exception as e: self._error(str(e))

        elif self.path == "/api/admin/run-switch-cmd":
            # POST {switch_ips:[...], commands: "line1\nline2", user, pass}
            # Runs the same commands on each switch sequentially.
            # Returns per-switch output.
            try:
                data = json.loads(body)
                switches = data.get("switch_ips") or []
                raw_cmds = (data.get("commands") or "").strip()
                u    = data.get("user") or ""
                p    = data.get("pass") or ""
                if not switches:
                    self._json({"ok": False, "error":"No switches selected"}); return
                if not raw_cmds:
                    self._json({"ok": False, "error":"No commands given"}); return
                if not (u and p):
                    self._json({"ok": False, "error":"Missing user/password"}); return
                # Cap to prevent runaway scripts
                cmds = [c for c in raw_cmds.split("\n") if c.strip()]
                if len(cmds) > 50:
                    self._json({"ok": False, "error":f"Too many commands ({len(cmds)}). Limit: 50."}); return
                if len(switches) > 100:
                    self._json({"ok": False, "error":f"Too many switches ({len(switches)}). Limit: 100."}); return
                # Run sequentially per switch (Extreme dislikes parallel sessions)
                results = []
                for sw in switches:
                    r = run_switch_commands(sw, cmds, u, p)
                    results.append({
                        "switch_ip": sw,
                        "ok": bool(r.get("ok")),
                        "output": r.get("output") or "",
                        "error": r.get("error") or ""
                    })
                ok_count = sum(1 for r in results if r["ok"])
                # Audit log — one line summarising the whole run.
                # Includes template name if invoked via a template, else "adhoc".
                tmpl = (data.get("template_name") or "").strip()
                detail = (f"template={tmpl}" if tmpl else "adhoc") + \
                         f" · switches={len(switches)} cmds={len(cmds)} " + \
                         f"ok={ok_count} fail={len(results)-ok_count}"
                log_admin("ssh-bulk-run", u, ",".join(switches[:5]) + ("…" if len(switches)>5 else ""), detail)
                self._json({
                    "ok": True,
                    "ok_count": ok_count,
                    "fail_count": len(results)-ok_count,
                    "results": results
                })
            except Exception as e: self._error(str(e))

        elif self.path == "/api/admin/bulk-precheck":
            # POST {targets:[{mac, ip, name}, ...]} → ping each in parallel, return online/offline split.
            # Used before bulk PC operations so we don't waste time on offline PCs.
            try:
                data = json.loads(body)
                targets = data.get("targets") or []
                if not targets:
                    self._json({"ok": False, "error": "No targets"}); return
                from concurrent.futures import ThreadPoolExecutor
                def _check(t):
                    ip = (t.get("ip") or "").strip()
                    ok = admin_check_online(ip, timeout=1.5) if ip else False
                    return {"mac": t.get("mac",""), "ip": ip, "name": t.get("name",""),
                            "online": ok}
                results = []
                with ThreadPoolExecutor(max_workers=min(50, len(targets))) as exe:
                    for r in exe.map(_check, targets):
                        results.append(r)
                online = [r for r in results if r["online"]]
                offline = [r for r in results if not r["online"]]
                self._json({"ok": True,
                            "online": online,
                            "offline": offline,
                            "online_count": len(online),
                            "offline_count": len(offline)})
            except Exception as e: self._error(str(e))

        elif self.path == "/api/admin/bulk-power":
            # POST {targets:[{mac, ip, name}, ...], action: restart|shutdown, user, pass}
            # Runs shutdown.exe in parallel against each target PC.
            # Caller should run /api/admin/bulk-precheck FIRST to filter out offline PCs.
            try:
                data = json.loads(body)
                targets = data.get("targets") or []
                action  = (data.get("action") or "").strip()
                u       = data.get("user") or ""
                p       = data.get("pass") or ""
                if action not in ("restart", "shutdown"):
                    self._json({"ok": False, "error": "action must be restart or shutdown"}); return
                if not (u and p):
                    self._json({"ok": False, "error": "Missing user/password"}); return
                if not targets:
                    self._json({"ok": False, "error": "No targets"}); return
                from concurrent.futures import ThreadPoolExecutor
                def _run(t):
                    ip = (t.get("ip") or "").strip()
                    if not ip:
                        return {"mac": t.get("mac",""), "ip": "", "name": t.get("name",""),
                                "ok": False, "error": "no IP"}
                    r = admin_remote_power(ip, action, u, p)
                    return {"mac": t.get("mac",""), "ip": ip, "name": t.get("name",""),
                            "ok": bool(r.get("ok")),
                            "error": r.get("error") or "",
                            "output": (r.get("output") or "")[-300:]}
                results = []
                with ThreadPoolExecutor(max_workers=min(20, len(targets))) as exe:
                    for r in exe.map(_run, targets):
                        results.append(r)
                ok_count = sum(1 for r in results if r["ok"])
                self._json({"ok": True,
                            "action": action,
                            "results": results,
                            "ok_count": ok_count,
                            "fail_count": len(results) - ok_count})
            except Exception as e: self._error(str(e))

        elif self.path == "/api/admin/bulk-cmd":
            # POST {targets:[{mac, ip, name}, ...], cmd, user, pass}
            # Runs the same PowerShell command via Invoke-Command against each target PC.
            # Returns per-PC result.
            try:
                data = json.loads(body)
                targets = data.get("targets") or []
                cmd     = (data.get("cmd") or "").strip()
                u       = data.get("user") or ""
                p       = data.get("pass") or ""
                if not cmd:
                    self._json({"ok": False, "error": "Missing command"}); return
                if not (u and p):
                    self._json({"ok": False, "error": "Missing user/password"}); return
                if not targets:
                    self._json({"ok": False, "error": "No targets"}); return
                from concurrent.futures import ThreadPoolExecutor
                def _run(t):
                    # Invoke-Command uses HOSTNAME (admin_run_remote_cmd convention),
                    # so prefer the device name; fall back to IP.
                    host = (t.get("name") or t.get("ip") or "").strip()
                    if not host:
                        return {"mac": t.get("mac",""), "ip": t.get("ip",""), "name": "",
                                "ok": False, "error": "no host/IP"}
                    r = admin_run_remote_cmd(host, cmd, u, p)
                    return {"mac": t.get("mac",""), "ip": t.get("ip",""), "name": host,
                            "ok": bool(r.get("ok")),
                            "error": r.get("error") or "",
                            "output": (r.get("output") or "")[-500:]}
                results = []
                with ThreadPoolExecutor(max_workers=min(15, len(targets))) as exe:
                    for r in exe.map(_run, targets):
                        results.append(r)
                ok_count = sum(1 for r in results if r["ok"])
                # Audit log — one summary line per bulk-cmd invocation
                tmpl = (data.get("template_name") or "").strip()
                sample = ",".join((t.get("name") or t.get("ip") or "") for t in targets[:5])
                detail = (f"template={tmpl}" if tmpl else "adhoc") + \
                         f" · pcs={len(targets)} ok={ok_count} fail={len(results)-ok_count} " + \
                         f"· cmd={(cmd[:120])}"
                log_admin("windows-bulk-cmd", u,
                          sample + ("…" if len(targets)>5 else ""), detail)
                self._json({"ok": True,
                            "results": results,
                            "ok_count": ok_count,
                            "fail_count": len(results) - ok_count})
            except Exception as e: self._error(str(e))

        elif self.path == "/api/admin/power":
            try:
                data   = json.loads(body)
                ip     = (data.get("ip") or "").strip()
                action = (data.get("action") or "").strip()
                u      = data.get("user") or ""
                p      = data.get("pass") or ""
                if action not in ("restart","shutdown"):
                    self._json({"ok": False, "error":"action must be restart or shutdown"}); return
                if not ip:
                    self._json({"ok": False, "error":"missing IP"}); return
                self._json(admin_remote_power(ip, action, u, p))
            except Exception as e: self._error(str(e))

        elif self.path == "/api/admin/explorer":
            try:
                data = json.loads(body)
                ip   = (data.get("ip") or "").strip()
                u    = data.get("user") or ""
                p    = data.get("pass") or ""
                if not ip: self._json({"ok": False, "error":"missing IP"}); return
                self._json(admin_open_explorer(ip, u, p))
            except Exception as e: self._error(str(e))

        elif self.path == "/api/admin/cmd":
            try:
                data    = json.loads(body)
                pc_name = (data.get("pc_name") or data.get("ip") or "").strip()
                cmd     = (data.get("cmd") or "").strip()
                u       = data.get("user") or ""
                p       = data.get("pass") or ""
                if not (pc_name and cmd and u and p):
                    self._json({"ok": False, "error":"Missing PC name, command, user or password"}); return
                self._json(admin_run_remote_cmd(pc_name, cmd, u, p))
            except Exception as e: self._error(str(e))

        elif self.path == "/api/admin/ssh-open":
            try:
                data = json.loads(body)
                ip   = (data.get("ip") or "").strip()
                u    = (data.get("user") or "").strip()
                if not (ip and u):
                    self._json({"ok": False, "error":"Missing IP or user"}); return
                self._json(admin_open_ssh(ip, u))
            except Exception as e: self._error(str(e))

        elif self.path == "/api/manual-add":
            # POST {device:{...fields...}}
            # Adds a new <device> to the XML. Strict duplicate check by MAC, IP, name.
            try:
                data = json.loads(body)
                dev  = data.get("device") or {}
                user_label = (data.get("user_label") or "").strip() or platform.node()

                ip   = (dev.get("ip") or "").strip()
                mac  = _normalize_mac(dev.get("mac") or "")
                name = (dev.get("name") or "").strip()
                dhcp = bool(dev.get("dhcp"))

                # Validation
                if not mac:
                    self._json({"ok": False, "error":"MAC is required"}); return
                if dhcp:
                    # DHCP devices: NO IP allowed, name required
                    if not name:
                        self._json({"ok": False, "error":"Name is required for DHCP devices"}); return
                    if ip:
                        self._json({"ok": False, "error":"DHCP devices cannot have a static IP — clear the IP field"}); return
                else:
                    # Static devices: IP required
                    if not ip:
                        self._json({"ok": False, "error":"IP is required (or check DHCP)"}); return

                # Duplicate check: ANY match (MAC, IP, or name) blocks the add
                for existing_mac, existing_dev in devices_by_mac.items():
                    if existing_mac.upper() == mac.upper():
                        self._json({"ok": False, "error":f"MAC {mac} already exists in XML as '{existing_dev.get('name','?')}' ({existing_dev.get('ip','?')})"}); return
                    if ip and existing_dev.get("ip","").strip() == ip:
                        self._json({"ok": False, "error":f"IP {ip} already exists in XML as '{existing_dev.get('name','?')}' (MAC {existing_mac})"}); return
                    if name and existing_dev.get("name","").strip().lower() == name.lower():
                        self._json({"ok": False, "error":f"Name '{name}' already exists in XML (MAC {existing_mac})"}); return

                if not xml_path_store[0]:
                    self._json({"ok": False, "error":"No XML file loaded"}); return

                ok = _append_device_to_xml(xml_path_store[0], dev, mac)
                if not ok:
                    self._json({"ok": False, "error":"Failed to write XML"}); return

                # Reload XML so the new device appears
                new_devs = load_xml(xml_path_store[0])
                merge_devices(new_devs)

                log_admin("manual-add", user_label, mac,
                         f"name={name} ip={ip} vlan={dev.get('vlan','')}")
                self._json({"ok": True, "mac": mac})
            except Exception as e: self._error(str(e))

        elif self.path == "/api/device/update":
            # POST {mac, updates:{field:value,...}, user_label?}
            # Edits XML fields on an existing device.
            try:
                data = json.loads(body)
                mac = _normalize_mac(data.get("mac") or "")
                updates = data.get("updates") or {}
                user_label = (data.get("user_label") or "").strip() or platform.node()

                if not mac:
                    self._json({"ok": False, "error":"MAC required"}); return
                if not isinstance(updates, dict) or not updates:
                    self._json({"ok": False, "error":"No fields to update"}); return
                if not xml_path_store[0]:
                    self._json({"ok": False, "error":"No XML file loaded"}); return

                # Duplicate-check for IP/name if those are being changed
                new_ip   = (updates.get('ip')   or '').strip()
                new_name = (updates.get('name') or '').strip()
                for existing_mac, existing_dev in devices_by_mac.items():
                    if existing_mac.upper() == mac.upper(): continue
                    if new_ip and existing_dev.get("ip","").strip() == new_ip:
                        self._json({"ok": False, "error":f"IP {new_ip} already used by '{existing_dev.get('name','?')}' (MAC {existing_mac})"}); return
                    if new_name and existing_dev.get("name","").strip().lower() == new_name.lower():
                        self._json({"ok": False, "error":f"Name '{new_name}' already used (MAC {existing_mac})"}); return

                ok, msg = _update_device_in_xml(xml_path_store[0], mac, updates)
                if not ok:
                    self._json({"ok": False, "error": msg}); return

                # Reload XML so the changes propagate
                new_devs = load_xml(xml_path_store[0])
                merge_devices(new_devs)

                log_admin("device-update", user_label, mac, msg)
                self._json({"ok": True, "mac": mac, "summary": msg})
            except Exception as e: self._error(str(e))

        elif self.path == "/api/device/delete":
            # POST {mac, user_label?}
            # Removes the device entirely from XML.
            try:
                data = json.loads(body)
                mac = _normalize_mac(data.get("mac") or "")
                user_label = (data.get("user_label") or "").strip() or platform.node()

                if not mac:
                    self._json({"ok": False, "error":"MAC required"}); return
                if not xml_path_store[0]:
                    self._json({"ok": False, "error":"No XML file loaded"}); return

                ok, msg = _delete_device_from_xml(xml_path_store[0], mac)
                if not ok:
                    self._json({"ok": False, "error": msg}); return

                # Reload XML so the deletion propagates
                new_devs = load_xml(xml_path_store[0])
                # Forcibly drop the deleted MAC from devices_by_mac
                with store_lock:
                    devices_by_mac.pop(mac, None)
                    devices_by_mac.pop(mac.upper(), None)
                    devices_by_mac.pop(mac.lower(), None)
                merge_devices(new_devs)
                # Also drop history for the removed device
                with store_lock:
                    history_store.pop(mac, None)
                    save_history()

                log_admin("device-delete", user_label, mac, msg)
                self._json({"ok": True, "mac": mac, "summary": msg})
            except Exception as e: self._error(str(e))

        elif self.path == "/api/audit/login":
            # POST {password} -> {token} on success, 403 on fail
            try:
                data = json.loads(body)
                pw   = data.get("password","")
                if pw == _audit_password():
                    token = secrets.token_hex(32)
                    audit_tokens.add(token)
                    log_admin("audit-login", platform.node(), "", "audit mode entered")
                    self._json({"ok": True, "token": token})
                else:
                    log_admin("audit-login-failed", platform.node(), "", "wrong password")
                    self.send_response(403); self._cors(); self.end_headers()
            except Exception as e: self._error(str(e))

        elif self.path == "/api/settings/login":
            # POST {password} → {token}. Same pattern as audit-login.
            # Token unlocks the ⚙ Settings modal on the client.
            try:
                data = json.loads(body)
                pw   = data.get("password","")
                if pw == _settings_password():
                    token = secrets.token_hex(32)
                    settings_tokens.add(token)
                    log_admin("settings-login", platform.node(), "", "settings unlocked")
                    self._json({"ok": True, "token": token})
                else:
                    log_admin("settings-login-failed", platform.node(), "", "wrong password")
                    self.send_response(403); self._cors(); self.end_headers()
            except Exception as e: self._error(str(e))

        elif self.path == "/api/settings/logout":
            try:
                tok = self.headers.get("X-Settings-Token","")
                settings_tokens.discard(tok)
                self._json({"ok": True})
            except Exception as e: self._error(str(e))

        elif self.path == "/api/audit/logout":
            try:
                tok = self.headers.get("X-Audit-Token","")
                audit_tokens.discard(tok)
                self._json({"ok": True})
            except Exception as e: self._error(str(e))

        elif self.path == "/api/auth/login":
            # POST {password} → returns {token} or 401
            try:
                data = json.loads(body)
                pw   = data.get("password","")
                auth = load_auth()
                if not auth.get("hash"):
                    # No password set yet — first login sets the password
                    save_auth(hash_pw(pw))
                    token = secrets.token_hex(32)
                    active_tokens.add(token)
                    self._json({"ok": True, "token": token, "first_setup": True})
                elif auth["hash"] == hash_pw(pw):
                    token = secrets.token_hex(32)
                    active_tokens.add(token)
                    self._json({"ok": True, "token": token})
                else:
                    self.send_response(401)
                    self._cors(); self.end_headers()
                    self.wfile.write(json.dumps({"ok": False, "error": "Wrong password"}).encode())
            except Exception as e:
                self._error(str(e))

        elif self.path == "/api/auth/logout":
            try:
                data  = json.loads(body)
                token = data.get("token","")
                active_tokens.discard(token)
                self._json({"ok": True})
            except Exception as e:
                self._error(str(e))

        elif self.path == "/api/auth/change-password":
            # POST {token, old_password, new_password}
            try:
                data   = json.loads(body)
                token  = data.get("token","")
                old_pw = data.get("old_password","")
                new_pw = data.get("new_password","")
                auth   = load_auth()
                if token not in active_tokens:
                    self.send_response(401); self._cors(); self.end_headers()
                    self.wfile.write(json.dumps({"ok":False,"error":"Not authenticated"}).encode())
                    return
                if auth.get("hash") and auth["hash"] != hash_pw(old_pw):
                    self.send_response(401); self._cors(); self.end_headers()
                    self.wfile.write(json.dumps({"ok":False,"error":"Wrong current password"}).encode())
                    return
                save_auth(hash_pw(new_pw))
                self._json({"ok": True})
            except Exception as e:
                self._error(str(e))

        else:
            self.send_response(404); self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200); self._cors(); self.end_headers()

    def _json(self, obj):
        data = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",len(data))
        self._cors(); self.end_headers(); self.wfile.write(data)

    def _error(self, msg):
        data = json.dumps({"error":msg}).encode()
        self.send_response(400)
        self.send_header("Content-Type","application/json")
        self._cors(); self.end_headers(); self.wfile.write(data)

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin","*")
        self.send_header("Access-Control-Allow-Methods","GET,POST,OPTIONS")
        self.send_header("Access-Control-Allow-Headers","Content-Type")

    def log_message(self, fmt, *a):
        msg = fmt % a
        if "/api/status" not in msg and "/api/history" not in msg:
            print(f"  {msg}")

# ── Main ────────────────────────────────────────────────────────────────────────
def main():
    """Server startup. Called from launcher.py or via __main__ below."""
    global PORT
    global LAYOUT_FILE, HISTORY_FILE, ALERTS_FILE, KNOWN_FILE, AUTH_FILE
    global ACTIONS_FILE, PRESENCE_FILE, ADMIN_LOG_FILE, FILTER_HIST_FILE
    global TOOLBAR_PREFS_FILE, LIVE_STATUS_FILE, XML_HISTORY_FILE
    global PHOTOS_DIR, TEMPLATES_FILE, SITE_CONFIG_FILE
    xml_path = sys.argv[1] if len(sys.argv) > 1 else None

    # Store globally so other functions (run_builder_in_cmd, manual-add) can find it
    if xml_path:
        xml_path_store[0] = str(Path(xml_path).resolve())

    # All data files saved alongside the XML file
    if xml_path:
        xml_abs = Path(xml_path).resolve()
        data_dir = xml_abs.parent
        print(f"📂  XML file:        {xml_abs}")
    else:
        data_dir = Path(__file__).resolve().parent
        print(f"⚠️   No XML provided — data files will go next to server.py")

    LAYOUT_FILE  = data_dir / "layout.json"
    HISTORY_FILE = data_dir / "history.json"
    ALERTS_FILE  = data_dir / "alerts.json"
    KNOWN_FILE   = data_dir / "known_macs.json"
    AUTH_FILE    = data_dir / "auth.json"
    ACTIONS_FILE = data_dir / "actions.json"
    PRESENCE_FILE = data_dir / "presence.json"
    ADMIN_LOG_FILE = data_dir / "admin.json"
    FILTER_HIST_FILE = data_dir / "filter_history.json"
    TOOLBAR_PREFS_FILE = data_dir / "toolbar_prefs.json"
    LIVE_STATUS_FILE = data_dir / "live_status.json"
    XML_HISTORY_FILE = data_dir / "xml_history.json"
    PHOTOS_DIR = data_dir / "photos"
    try: PHOTOS_DIR.mkdir(exist_ok=True)
    except Exception as e: print(f"[photos] could not create dir: {e}")
    TEMPLATES_FILE = data_dir / "templates.json"
    SITE_CONFIG_FILE = data_dir / "site_config.json"
    print(f"📁  Data directory:  {data_dir}")
    print(f"   auth.json     -> {AUTH_FILE}")
    print(f"   layout.json   -> {LAYOUT_FILE}")
    print(f"   presence.json -> {PRESENCE_FILE}")
    print(f"   admin.json    -> {ADMIN_LOG_FILE} (encrypted)")
    print(f"   live_status.json -> {LIVE_STATUS_FILE}")
    print(f"   xml_history.json -> {XML_HISTORY_FILE}")
    print(f"   photos/          -> {PHOTOS_DIR}")

    # Start presence heartbeat (announces this user to others on the same share)
    heartbeat_tick()
    threading.Thread(target=heartbeat_loop, daemon=True).start()
    import atexit
    atexit.register(remove_my_presence)

    # load previously known MACs first so merge can detect removals
    known_macs.update(load_known_macs())

    if xml_path:
        print(f"📂  Loading {xml_path} …")
        new_devs = load_xml(xml_path)
        merge_devices(new_devs)
        snapshot_xml_if_changed(new_devs)
    else:
        print("⚠️   No XML file — using demo data")
        print("    Usage: python server.py devices.xml")
        demo = make_demo()
        merge_devices(demo)

    with store_lock:
        for mac in devices_by_mac:
            if mac not in status_store:
                status_store[mac] = "no_info"

    history_store.update(load_history())
    print(f"✅  {len(devices_by_mac)} devices ({sum(1 for d in devices_by_mac.values() if d.get('removed'))} removed)")

    www = Path(__file__).parent / "www"
    www.mkdir(exist_ok=True)
    os.chdir(www)

    print(f"\n  ┌──────────────────────────────────┐")
    print(f"  │  NetMap  →  http://localhost:{PORT}  │")
    print(f"  └──────────────────────────────────┘\n")

    socketserver.TCPServer.allow_reuse_address = True
    # ThreadingTCPServer handles each request in its own thread, so a long-running
    # ping doesn't block the UI from fetching action history, presence, etc.
    class ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
        daemon_threads = True
        allow_reuse_address = True

    # Apply per-plant runtime settings (VLAN pause, timeouts, caps, etc.)
    # so they take effect BEFORE any request is served.
    apply_runtime_config()

    # Config can override the listen port
    try:
        cfg_port = int(get_site_config().get("netmap", {}).get("port", PORT))
        if cfg_port > 0 and cfg_port != PORT:
            PORT = cfg_port
            print(f"[cfg] Using port {PORT} from site config")
    except Exception:
        pass

    # HTTPS: generate a self-signed cert on first run, then wrap the server
    # socket. Localhost-only, so identity verification (the browser warning)
    # is cosmetic — encryption still works fully.
    import ssl
    crt_path, key_path = ensure_https_cert()
    ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ssl_ctx.load_cert_chain(certfile=crt_path, keyfile=key_path)

    with ThreadedServer(("", PORT), Handler) as srv:
        srv.socket = ssl_ctx.wrap_socket(srv.socket, server_side=True)
        print(f"🔒  HTTPS enabled — open https://localhost:{PORT}")
        srv.serve_forever()


if __name__ == "__main__":
    main()