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

import sys, os, re, json, time, threading, subprocess, platform, hashlib, secrets, socket, base64, shutil
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
FILTER_MINE_FILE = None    # each PC's own filter history {pc_name: [...]}
TOOLBAR_PREFS_FILE = None  # per-host toolbar customization, keyed by hostname
LIVE_STATUS_FILE = None    # shared status file — any user's ping benefits everyone
STATUS_FRESHNESS_MAX = 15 * 60  # seconds; older statuses render as "no info"
XML_HISTORY_FILE = None    # rolling snapshots of parsed XML (cap 30)
XML_HISTORY_MAX  = 30      # keep at most N snapshots
TEMPLATES_FILE = None      # command templates (SSH + Windows), private + public
STALE_FILE = None          # stale.json — per-device notice / renew timestamps
ARCHIVE_XML = None         # old_data.xml — devices moved out for inactivity
SITE_CONFIG_FILE = None    # plant-specific settings (VLANs, IPs, mappings)
SITE_CONFIG_CACHE = None   # in-memory cached copy — reloaded on POST


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
# Live progress of the ping cycle this server is running right now. Read by
# GET /api/ping/progress so the ping badge can show "47/120 · ~28s left".
ping_progress: dict = {"active": False}
# Live log of the inventory scan this server is running (GET /api/scan/progress).
# lines = step messages; counter = the "done/total" of the step in progress.
scan_state: dict = {"active": False, "lines": [], "counter": None}
scan_run_lock = threading.Lock()         # one scan at a time per server

def _scan_progress_cb(msg, done=None, total=None):
    if done is None:
        scan_state["lines"].append(str(msg))
        del scan_state["lines"][:-200]   # keep the tail only
        scan_state["counter"] = None
    else:
        scan_state["counter"] = {"label": str(msg), "done": int(done), "total": int(total or 0)}

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
    try: vlan_types, switch_ips = _type_rules()
    except Exception: vlan_types, switch_ips = {}, set()
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
            # type: what the XML says → the VLAN type map in Settings → the
            # name as a last guess. An IP listed under Settings → Switches is
            # always a switch (racks and port lookups depend on it).
            "type":   (normalize_type(gn("type")) if normalize_type(gn("type")) != "unknown" else "")
                      or normalize_type(vlan_types.get(gn("vlan"), ""))
                      or guess_type(name),
        }
        if gn("ip") in switch_ips and record["type"] not in ("switch", "router"):
            record["type"] = "switch"
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

# ── Ping ────────────────────────────────────────────────────────────────────────
def icmp_reply_ok(returncode: int, stdout: bytes) -> bool:
    """True only for a real echo reply from the target.

    Windows ping exits 0 whenever ANY reply packet arrives — including
    "Destination host unreachable" sent by a gateway or by this PC itself.
    That made dead addresses look online. A genuine echo reply always carries
    "TTL=" on its line (in every Windows display language); the unreachable
    message never does. Linux/macOS exit codes are already reliable."""
    if returncode != 0:
        return False
    if platform.system().lower() == "windows":
        return b"TTL=" in (stdout or b"").upper()
    return True

def ping_once(ip: str, wait_ms: int = 2000) -> bool:
    """Single ICMP ping. Works on Windows and Linux/macOS."""
    system = platform.system().lower()
    try:
        if system == "windows":
            cmd = ["ping", "-n", "1", "-w", str(int(wait_ms)), ip]
        else:
            cmd = ["ping", "-c", "1", "-W", str(max(1, round(wait_ms / 1000))), ip]

        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=wait_ms / 1000 + 3
        )
        return icmp_reply_ok(result.returncode, result.stdout)
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
        vlan_order = sorted(by_vlan.items())
        prog = {
            "active": True, "started": time.time(), "total": len(devs),
            "done_before": 0, "batch": {}, "vlans_total": len(vlan_order),
            "vlan_index": 0, "vlan": "", "vlan_size": 0, "next_vlan": "",
            "phase": "pinging", "phase_started": time.time(),
            "pause_until": 0, "pause_s": 0,
            "probe_secs": 0.0, "groups_done": 0,
        }
        ping_progress.clear(); ping_progress.update(prog)
        for i, (vlan, group) in enumerate(vlan_order):
            # Check cancel BEFORE starting this VLAN group
            if ping_cancel_flag.is_set():
                print(f"[ping] cancelled by user — stopping after VLAN groups processed so far")
                break

            batch = {}
            _grp_t0 = time.time()
            ping_progress.update({
                "phase": "pinging", "phase_started": _grp_t0, "batch": batch,
                "vlan": str(vlan), "vlan_index": i + 1, "vlan_size": len(group),
                "next_vlan": str(vlan_order[i + 1][0]) if i + 1 < len(vlan_order) else "",
            })
            # Read DHCP VLAN list from site config (with fallback to hardcoded default).
            # This lets other plants configure their DHCP VLANs without code changes.
            try:
                _cfg = get_site_config()
                _dhcp_set = set(str(v) for v in _cfg.get("netmap", {}).get("dhcp_vlans", []))
            except Exception:
                _dhcp_set = set()
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
            ping_progress.update({
                "done_before": len(results), "batch": {},
                "probe_secs": ping_progress.get("probe_secs", 0.0) + (time.time() - _grp_t0),
                "groups_done": i + 1,
            })
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
                ping_progress.update({
                    "phase": "pause", "phase_started": time.time(),
                    "pause_s": pause_s, "pause_until": time.time() + pause_s,
                })
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
        _st = ping_progress.get("started") or time.time()
        ping_progress.update({
            "active": False, "batch": {}, "finished": time.time(),
            "last_duration": round(time.time() - _st, 1),
            "cancelled": ping_cancel_flag.is_set(),
        })
        ping_lock.release()


def ping_progress_snapshot() -> dict:
    """JSON-safe view of the running ping cycle, with a remaining-time estimate.

    Devices in one VLAN group are probed in parallel, so the estimate works per
    group: average seconds a finished group took, plus the configured pause that
    sits before every group still to come."""
    p = dict(ping_progress)
    now = time.time()
    if not p.get("active"):
        return {"active": False,
                "last_duration": p.get("last_duration"),
                "finished": int(p["finished"]) if p.get("finished") else None,
                "total": p.get("total", 0),
                "cancelled": bool(p.get("cancelled"))}
    total = int(p.get("total", 0))
    done = min(total, int(p.get("done_before", 0)) + len(p.get("batch") or {}))
    groups_done = int(p.get("groups_done", 0))
    vlans_total = int(p.get("vlans_total", 0))
    vlan_index = int(p.get("vlan_index", 0))
    pause_s = float(p.get("pause_s") or _cfg_runtime("vlan_pause", VLAN_PAUSE) or 0)
    # Until one group has finished there is nothing to average — 3 s is what a
    # group with a few unreachable hosts typically takes (2 s ping timeout).
    avg_group = (p.get("probe_secs", 0.0) / groups_done) if groups_done else 3.0
    groups_left = max(0, vlans_total - vlan_index)   # groups after the current one
    if p.get("phase") == "pause":
        pause_left = max(0.0, float(p.get("pause_until", now)) - now)
        eta = pause_left + groups_left * avg_group + max(0, groups_left - 1) * pause_s
    else:
        in_group = now - float(p.get("phase_started", now))
        pause_left = 0.0
        eta = max(0.0, avg_group - in_group) + groups_left * (avg_group + pause_s)
    return {
        "active": True,
        "phase": p.get("phase", "pinging"),
        "total": total, "done": done,
        "vlan": p.get("vlan", ""), "vlan_index": vlan_index,
        "vlans_total": vlans_total, "vlan_size": int(p.get("vlan_size", 0)),
        "next_vlan": p.get("next_vlan", ""),
        "pause_left": round(pause_left, 1), "pause_s": pause_s,
        "elapsed": round(now - float(p.get("started", now)), 1),
        "eta": round(eta, 1),
    }

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

# ── LAYOUT SNAPSHOTS ─────────────────────────────────────────────────
# Snapshots are full copies of layout.json stored in a rotating folder
# alongside the XML. Users can restore any snapshot from ⚙ Settings or
# via a toolbar button (📸 above the session timer).
SNAPSHOTS_DIR = None    # set at startup, sibling of layout.json

def _snapshot_path(name: str):
    """Absolute path for a snapshot filename (no directory traversal)."""
    if not SNAPSHOTS_DIR: return None
    safe = re.sub(r'[^0-9A-Za-z._-]', '_', name)
    return SNAPSHOTS_DIR / safe

def create_layout_snapshot(reason: str = "manual", by_user: str = "") -> dict:
    """Save current layout.json as a timestamped snapshot.
    Returns {ok, filename, size, count} or {ok:False, error}."""
    if not SNAPSHOTS_DIR:
        return {"ok": False, "error": "Snapshots folder not initialized"}
    try:
        SNAPSHOTS_DIR.mkdir(exist_ok=True)
        if not LAYOUT_FILE.exists():
            return {"ok": False, "error": "No layout.json to snapshot"}
        raw = LAYOUT_FILE.read_bytes()
        ts = time.strftime("%Y%m%d-%H%M%S")
        # Filename encodes: timestamp, reason (auto/manual), user
        safe_user = re.sub(r'[^A-Za-z0-9_-]', '_', by_user or "unknown")[:30]
        safe_reason = re.sub(r'[^a-z]', '', reason.lower())[:10] or "manual"
        filename = f"layout_{ts}_{safe_reason}_{safe_user}.json"
        fpath = SNAPSHOTS_DIR / filename
        fpath.write_bytes(raw)
        # Rotate: keep only N newest snapshots
        cap = _cfg_runtime("snapshot_max", 30)
        rotate_snapshots(cap)
        return {"ok": True, "filename": filename, "size": len(raw),
                "count": _count_snapshots()}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def list_layout_snapshots() -> list:
    """Return a sorted list of snapshot metadata, newest first."""
    if not SNAPSHOTS_DIR or not SNAPSHOTS_DIR.exists(): return []
    entries = []
    for fp in SNAPSHOTS_DIR.iterdir():
        if not fp.is_file() or not fp.name.endswith('.json'): continue
        try:
            stat = fp.stat()
            # Parse filename: layout_YYYYMMDD-HHMMSS_reason_user.json
            m = re.match(r'layout_(\d{8}-\d{6})_(\w+?)_(.+)\.json$', fp.name)
            ts_str, reason, user = "", "?", "?"
            if m:
                ts_str, reason, user = m.group(1), m.group(2), m.group(3)
            entries.append({
                "filename": fp.name,
                "size": stat.st_size,
                "mtime": int(stat.st_mtime),
                "ts_str": ts_str,
                "reason": reason,
                "by": user,
            })
        except Exception:
            continue
    entries.sort(key=lambda e: e["mtime"], reverse=True)
    return entries

def _count_snapshots() -> int:
    return len(list_layout_snapshots())

def rotate_snapshots(cap: int):
    """Delete oldest snapshots beyond cap."""
    if cap <= 0: return
    entries = list_layout_snapshots()
    for e in entries[cap:]:
        try: (SNAPSHOTS_DIR / e["filename"]).unlink()
        except Exception: pass

def restore_layout_snapshot(filename: str, by_user: str = "") -> dict:
    """Restore a snapshot as the current layout. The current layout is
    first saved as a pre-restore snapshot so the operation is reversible."""
    fp = _snapshot_path(filename)
    if not fp or not fp.exists():
        return {"ok": False, "error": "Snapshot not found"}
    try:
        # Save the current layout as a safety snapshot before restore
        create_layout_snapshot(reason="prerestore", by_user=by_user)
        # Copy snapshot content into layout.json
        raw = fp.read_bytes()
        LAYOUT_FILE.write_bytes(raw)
        log_admin("layout-restore", by_user or platform.node(), filename,
                  f"restored layout from snapshot {filename}")
        return {"ok": True, "restored": filename}
    except Exception as e:
        return {"ok": False, "error": str(e)}

# Auto-snapshot scheduler — runs in a background thread
_snapshot_last_auto_date = None   # date string when we last auto-snapped
def _snapshot_scheduler_loop():
    """Every 60 seconds, check whether we've crossed the configured snapshot time
    for today and take an auto-snapshot if so."""
    global _snapshot_last_auto_date
    while True:
        try:
            time.sleep(60)
            if not _cfg_runtime("snapshot_enabled", True): continue
            hhmm = _cfg_runtime("snapshot_time", "03:00")
            try:
                target_h, target_m = [int(x) for x in str(hhmm).split(":")]
            except Exception:
                target_h, target_m = 3, 0
            now = time.localtime()
            today_str = time.strftime("%Y-%m-%d", now)
            # Trigger if past target time AND we haven't snapped today yet
            if _snapshot_last_auto_date == today_str: continue
            if (now.tm_hour, now.tm_min) < (target_h, target_m): continue
            result = create_layout_snapshot(reason="auto", by_user="scheduler")
            _snapshot_last_auto_date = today_str
            if result.get("ok"):
                print(f"[snapshot] auto-snapshot {result['filename']} "
                      f"({result['count']} total)")
            else:
                print(f"[snapshot] auto failed: {result.get('error')}")
        except Exception as e:
            print(f"[snapshot] scheduler error: {e}")

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

# ── PER-DEVICE CHANGE HISTORY ─────────────────────────────────────
# Assembles one timeline for a device out of data NetMap already keeps — no
# new storage:
#   • xml_history.json   dated field changes between consecutive XML snapshots
#   • the XML itself     previous values the scanner recorded (<history>,
#                        <last-ip>, <last-vlan>, <previous-mac>) — undated
#   • admin.json         who placed / moved / renamed it on the map
#   • actions.json       admin actions run against it (PoE cycle, templates…)
_HIST_FIELDS = ("name", "ip", "vlan", "type", "switch", "port")
# Audit events whose detail text is safe to show to everyone. Command events
# keep their detail behind the audit password; these only describe map edits.
_HIST_OPEN_DETAIL = {"placed", "moved", "unplaced", "display-name", "resized"}
_REPLACED_RX = re.compile(
    r"^replaced:((?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}):(.*):([^:]*):(\d{4}-\d\d-\d\dT.*)$")

def _epoch_from_any(ts_val) -> int:
    """Epoch seconds from an int, 'YYYY-MM-DD HH:MM:SS' (local) or ISO-8601 'Z' (UTC)."""
    if isinstance(ts_val, (int, float)):
        return int(ts_val)
    txt = str(ts_val or "").strip()
    if not txt:
        return 0
    try:
        return int(time.mktime(time.strptime(txt, "%Y-%m-%d %H:%M:%S")))
    except Exception:
        pass
    try:
        import calendar
        core = txt.rstrip("Z").split(".")[0]
        return int(calendar.timegm(time.strptime(core, "%Y-%m-%dT%H:%M:%S")))
    except Exception:
        return 0

def device_change_history(mac: str) -> dict:
    mac_u = (mac or "").strip().upper()
    dev = None
    for k, v in devices_by_mac.items():
        if k.upper() == mac_u:
            dev = v; break

    # 1. Dated field changes — walk snapshots oldest → newest
    changes = []
    hist = load_xml_history()            # newest first
    snaps = list(reversed(hist))
    prev = None                          # this device's fields in the previous snapshot
    seen_before = False
    for idx, snap in enumerate(snaps):
        devs = snap.get("devs", {}) or {}
        cur = None
        for k, v in devs.items():
            if k.upper() == mac_u:
                cur = v; break
        ts = int(snap.get("ts", 0))
        if cur is not None and prev is None:
            # idx 0 is simply the oldest snapshot we kept, not a real "first seen"
            if idx > 0:
                changes.append({"ts": ts, "kind": "returned" if seen_before else "appeared"})
        elif cur is None and prev is not None:
            changes.append({"ts": ts, "kind": "disappeared"})
        elif cur is not None and prev is not None:
            for f in _HIST_FIELDS:
                if (cur.get(f) or "") != (prev.get(f) or ""):
                    changes.append({"ts": ts, "kind": "field", "field": f,
                                    "from": prev.get(f) or "", "to": cur.get(f) or ""})
        if cur is not None:
            seen_before = True
        prev = cur
    changes.reverse()                    # newest first

    # 2. What the scanner wrote into the XML entry itself
    recorded = {"previous_ips": [], "previous_vlans": [], "previous_values": [],
                "replaced": [], "previous_mac": "", "first_seen": "",
                "last_scanned": "", "last_online": "", "change_status": ""}
    if dev:
        split = lambda v: [x.strip() for x in str(v or "").split(",") if x.strip()]
        recorded["previous_ips"]   = split(dev.get("last-ip"))
        recorded["previous_vlans"] = split(dev.get("last-vlan"))
        recorded["previous_mac"]   = dev.get("previous-mac", "") or ""
        recorded["first_seen"]     = dev.get("first-seen", "") or ""
        recorded["last_scanned"]   = dev.get("last-scanned", "") or ""
        recorded["last_online"]    = dev.get("last-online", "") or ""
        recorded["change_status"]  = dev.get("xml_change_status", "") or ""
        for item in split(dev.get("history")):
            m = _REPLACED_RX.match(item)
            if m:
                recorded["replaced"].append({
                    "old_mac": m.group(1), "old_name": m.group(2),
                    "old_type": m.group(3), "ts": _epoch_from_any(m.group(4))})
            elif ":" in item:
                field, _, value = item.partition(":")
                recorded["previous_values"].append({"field": field, "value": value})

    # 3. Map edits from the audit log (who + when; detail only for map edits)
    events = []
    try:
        for e in load_admin_log():
            if str(e.get("target", "")).upper() != mac_u:
                continue
            ev = e.get("event", "")
            row = {"ts": _epoch_from_any(e.get("ts")), "event": ev,
                   "by": e.get("user", "") or e.get("host", "")}
            if ev in _HIST_OPEN_DETAIL and e.get("detail"):
                row["detail"] = e.get("detail")
            events.append(row)
            if len(events) >= 100:
                break
    except Exception as _e:
        print(f"[device-history] audit read failed: {_e}")

    # 4. Admin actions run against this device
    actions = []
    try:
        store = load_actions()
        for k, rows in store.items():
            if k.upper() != mac_u:
                continue
            for a in rows[:50]:
                actions.append({"ts": _epoch_from_any(a.get("ts")),
                                "action": a.get("action", ""), "by": a.get("user", ""),
                                "result": a.get("result", "")})
    except Exception as _e:
        print(f"[device-history] actions read failed: {_e}")

    return {
        "ok": True, "mac": mac_u, "in_xml": bool(dev) and not (dev or {}).get("removed"),
        "name": (dev or {}).get("name", ""), "ip": (dev or {}).get("ip", ""),
        "changes": changes, "recorded": recorded,
        "events": events, "actions": actions,
        "snapshots": {"count": len(hist),
                      "oldest_ts": int(hist[-1].get("ts", 0)) if hist else None,
                      "newest_ts": int(hist[0].get("ts", 0)) if hist else None},
    }

# ── INACTIVE DEVICES → old_data.xml ───────────────────────────────
# A device that has not been online for `stale_days` (Settings, default 50)
# is moved out of the inventory XML into old_data.xml. Nothing is moved
# without warning: a device is first listed for `stale_warn_days` (default 7)
# and only moved once that notice period has also passed.
#
# "Last online" is the newest of:
#   • <last-online> in the XML      (a scan pinged it)
#   • last_seen in history.json     (NetMap's live ping saw it)
#   • <restored-at> in the XML      (it was brought back from the archive)
#   • "renewed" in stale.json       (a user reset its counter)
#   • <first-seen> in the XML       (it cannot be idle longer than it exists)
# A device with none of these starts counting from the first time NetMap
# checks it. Spares kept in a storage box are never listed — being offline
# is their normal state.
stale_lock = threading.Lock()
_ARCHIVE_TAGS = ("archived-at", "archived-by", "archived-reason")

def _iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

def load_stale() -> dict:
    if STALE_FILE and STALE_FILE.exists():
        try:
            d = json.loads(STALE_FILE.read_text(encoding='utf-8'))
            return d if isinstance(d, dict) else {}
        except Exception:
            pass
    return {}

def save_stale(data: dict):
    if STALE_FILE:
        atomic_write(STALE_FILE, json.dumps(data, indent=1))

def _stale_settings() -> dict:
    days = max(0, _cfg_runtime("stale_days", 50))
    warn = max(0, _cfg_runtime("stale_warn_days", 7))
    try: auto = bool(get_site_config().get("netmap", {}).get("stale_auto_archive", True))
    except Exception: auto = True
    return {"days": days, "warn": warn, "auto": auto, "enabled": days > 0}

def _storage_box_macs() -> set:
    try:
        return {str(d.get("mac", "")).upper()
                for box in (load_layout().get("storage_boxes") or [])
                for d in (box.get("devices") or []) if d.get("mac")}
    except Exception:
        return set()

def _write_xml_atomic(tree, path):
    """Write to a temp file beside the target, then swap — a crash or a
    dropped share mid-write leaves the original file intact."""
    path = Path(path)
    try: ET.indent(tree, space="  ", level=0)
    except Exception: pass
    tmp = path.with_name(path.name + ".tmp")
    tree.write(str(tmp), encoding="utf-8", xml_declaration=True)
    os.replace(str(tmp), str(path))

def _load_archive_tree():
    if ARCHIVE_XML and ARCHIVE_XML.exists():
        try:
            return ET.parse(str(ARCHIVE_XML))
        except Exception as e:
            # Never overwrite an archive we could not read
            raise RuntimeError(f"old_data.xml exists but cannot be read ({e}) — fix or rename it first")
    return ET.ElementTree(ET.Element("archive"))

def archived_macs() -> set:
    try:
        if not ARCHIVE_XML or not ARCHIVE_XML.exists(): return set()
        return {(el.findtext("mac") or "").strip().upper()
                for el in ET.parse(str(ARCHIVE_XML)).getroot().findall("device")}
    except Exception:
        return set()

def list_archived() -> list:
    if not ARCHIVE_XML or not ARCHIVE_XML.exists(): return []
    out = []
    for el in ET.parse(str(ARCHIVE_XML)).getroot().findall("device"):
        g = lambda t: (el.findtext(t) or "").strip()
        out.append({"mac": g("mac").upper(), "name": g("name"), "ip": g("ip"),
                    "vlan": g("vlan"), "type": g("type"),
                    "archived_at": _epoch_from_any(g("archived-at")),
                    "archived_by": g("archived-by"), "reason": g("archived-reason"),
                    "last_online": _epoch_from_any(g("last-online"))})
    out.sort(key=lambda d: d["archived_at"], reverse=True)
    return out

def _forget_devices(macs):
    """Drop devices from the runtime store so the map does not show them as
    'removed from XML' ghosts, and from layout.json so they are not placed."""
    macs = {m.upper() for m in macs}
    with store_lock:
        for m in list(devices_by_mac.keys()):
            if m.upper() in macs:
                devices_by_mac.pop(m, None)
                status_store.pop(m, None)
        for m in list(known_macs):
            if m.upper() in macs:
                known_macs.discard(m)
    save_known_macs()
    try:
        lay = load_layout()
        changed = False
        devs = lay.get("devices") or {}
        for m in list(devs.keys()):
            if m.upper() in macs:
                devs.pop(m); changed = True
        for rack in (lay.get("racks") or []):
            sw = rack.get("switches") or []
            kept = [m for m in sw if m.upper() not in macs]
            if len(kept) != len(sw):
                rack["switches"] = kept; changed = True
        for room in (lay.get("serverRooms") or []):
            for rack in (room.get("racks") or []):
                items = rack.get("items") or []
                kept = [it for it in items if not (it.get("mac") and str(it["mac"]).upper() in macs)]
                if len(kept) != len(items):
                    rack["items"] = kept; changed = True
        links = lay.get("hostLinks") or {}
        for host in list(links.keys()):
            if host.upper() in macs:
                links.pop(host); changed = True; continue
            kids = links[host] or []
            kept = [k for k in kids if not (k.get("mac") and str(k["mac"]).upper() in macs)]
            if len(kept) != len(kids):
                links[host] = kept; changed = True
        if changed:
            save_layout(lay)
    except Exception as e:
        print(f"[stale] layout cleanup skipped: {e}")

def _take_devices_from_xml(macs):
    """Parse the inventory XML and find the matching <device> elements.
    Returns (tree, root, elements); the caller removes them and writes."""
    xp = xml_path_store[0]
    if not xp or not Path(xp).exists():
        raise RuntimeError("No XML file loaded")
    macs = {m.upper() for m in macs}
    tree = ET.parse(xp)
    root = tree.getroot()
    taken = [el for el in root.findall("device")
             if (el.findtext("mac") or "").strip().upper() in macs]
    return tree, root, taken

def archive_devices(macs, reason: str, by: str) -> list:
    """Move devices from the inventory XML into old_data.xml.
    The archive is written first: if anything fails in between, a device can
    end up in both files but never in neither."""
    with stale_lock:
        tree, root, taken = _take_devices_from_xml(macs)
        if not taken:
            return []
        arch_tree = _load_archive_tree()
        arch_root = arch_tree.getroot()
        existing = {(el.findtext("mac") or "").strip().upper(): el
                    for el in arch_root.findall("device")}
        now_iso = _iso_now()
        moved = []
        for el in taken:
            mac = (el.findtext("mac") or "").strip().upper()
            if mac in existing:                     # keep one copy per MAC
                arch_root.remove(existing[mac])
            for tag in _ARCHIVE_TAGS + ("restored-at",):
                for old in el.findall(tag): el.remove(old)
            ET.SubElement(el, "archived-at").text = now_iso
            ET.SubElement(el, "archived-by").text = by
            ET.SubElement(el, "archived-reason").text = reason
            arch_root.append(el)
            moved.append({"mac": mac, "name": (el.findtext("name") or "").strip()})
        _write_xml_atomic(arch_tree, ARCHIVE_XML)
        for el in taken:
            root.remove(el)
        _write_xml_atomic(tree, xml_path_store[0])
        _forget_devices([m["mac"] for m in moved])
        try: snapshot_xml_if_changed(load_xml(xml_path_store[0]))
        except Exception as _e: print(f"[stale] snapshot skipped: {_e}")
        st = load_stale()
        for m in moved: st.pop(m["mac"], None)
        save_stale(st)
    names = ", ".join(m["name"] or m["mac"] for m in moved[:8]) + ("…" if len(moved) > 8 else "")
    log_admin("stale-archive", by, "", f"{len(moved)} device(s) → old_data.xml ({reason}): {names}")
    return moved

def delete_devices(macs, by: str) -> list:
    """Permanently remove devices from the inventory XML (bulk)."""
    with stale_lock:
        tree, root, taken = _take_devices_from_xml(macs)
        if not taken:
            return []
        gone = [{"mac": (el.findtext("mac") or "").strip().upper(),
                 "name": (el.findtext("name") or "").strip()} for el in taken]
        for el in taken:
            root.remove(el)
        _write_xml_atomic(tree, xml_path_store[0])
        _forget_devices([g["mac"] for g in gone])
        try: snapshot_xml_if_changed(load_xml(xml_path_store[0]))
        except Exception as _e: print(f"[stale] snapshot skipped: {_e}")
        with store_lock:
            for g in gone: history_store.pop(g["mac"], None)
            save_history()
        st = load_stale()
        for g in gone: st.pop(g["mac"], None)
        save_stale(st)
    names = ", ".join(g["name"] or g["mac"] for g in gone[:8]) + ("…" if len(gone) > 8 else "")
    log_admin("stale-delete", by, "", f"{len(gone)} inactive device(s) deleted from XML: {names}")
    return gone

def restore_devices(macs, by: str) -> list:
    """Bring devices back from old_data.xml into the inventory XML. They get
    a <restored-at> stamp, which restarts their inactivity counter."""
    with stale_lock:
        xp = xml_path_store[0]
        if not xp or not Path(xp).exists():
            raise RuntimeError("No XML file loaded")
        macs = {m.upper() for m in macs}
        arch_tree = _load_archive_tree()
        arch_root = arch_tree.getroot()
        tree = ET.parse(xp); root = tree.getroot()
        present = {(el.findtext("mac") or "").strip().upper() for el in root.findall("device")}
        now_iso = _iso_now()
        back = []
        for el in list(arch_root.findall("device")):
            mac = (el.findtext("mac") or "").strip().upper()
            if mac not in macs: continue
            arch_root.remove(el)
            if mac in present:                      # already back (e.g. re-added by a scan)
                continue
            for tag in _ARCHIVE_TAGS + ("restored-at",):
                for old in el.findall(tag): el.remove(old)
            ET.SubElement(el, "restored-at").text = now_iso
            root.append(el)
            back.append({"mac": mac, "name": (el.findtext("name") or "").strip()})
        _write_xml_atomic(tree, xp)                 # inventory first, then shrink the archive
        _write_xml_atomic(arch_tree, ARCHIVE_XML)
    try:
        merge_devices(load_xml(xp))
    except Exception as e:
        print(f"[stale] reload after restore failed: {e}")
    if back:
        log_admin("stale-restore", by, "", f"{len(back)} device(s) restored from old_data.xml")
    return back

def renew_devices(macs, by: str) -> int:
    """Restart the inactivity counter for these devices from now."""
    now = int(time.time())
    with stale_lock:
        st = load_stale()
        for m in macs:
            e = st.setdefault(m.upper(), {})
            e["renewed"] = now
            e.pop("notified", None)
        save_stale(st)
    log_admin("stale-renew", by, "", f"inactivity counter renewed for {len(macs)} device(s)")
    return len(macs)

def stale_report() -> dict:
    """Work out which devices are inside the warning window or overdue, and
    record when each one was first listed (that starts its notice period)."""
    cfg = _stale_settings()
    out = {"enabled": cfg["enabled"], "stale_days": cfg["days"], "warn_days": cfg["warn"],
           "auto": cfg["auto"], "flagged": []}
    if not cfg["enabled"]:
        return out
    now = int(time.time())
    day = 86400
    boxed = _storage_box_macs()
    with stale_lock:
        st = load_stale()
        dirty = False
        with store_lock:
            devs = [(m, dict(d)) for m, d in devices_by_mac.items() if not d.get("removed")]
            hist = {m: (h.get("last_seen") or 0) for m, h in history_store.items()}
        live = set()
        for mac, d in devs:
            mu = mac.upper()
            live.add(mu)
            e = st.get(mu, {})
            if mu in boxed:
                if e.pop("notified", None) is not None: dirty = True
                continue
            cands = [
                (_epoch_from_any(d.get("last-online")), "scan"),
                (int(hist.get(mac) or 0),               "live ping"),
                (_epoch_from_any(d.get("restored-at")), "restored"),
                (int(e.get("renewed") or 0),            "renewed"),
                (_epoch_from_any(d.get("first-seen")),  "first seen"),
            ]
            last, basis = max(cands, key=lambda c: c[0])
            if last <= 0:
                if not e.get("first_checked"):
                    e["first_checked"] = now; st[mu] = e; dirty = True
                last, basis = int(e["first_checked"]), "tracking started"
            idle = (now - last) / day
            if idle < cfg["days"] - cfg["warn"]:
                if e.pop("notified", None) is not None:
                    st[mu] = e; dirty = True
                continue
            if not e.get("notified"):
                e["notified"] = now; st[mu] = e; dirty = True
            move_at = max(last + cfg["days"] * day, int(e["notified"]) + cfg["warn"] * day)
            out["flagged"].append({
                "mac": mac, "name": d.get("name", ""), "ip": d.get("ip", ""),
                "vlan": d.get("vlan", ""), "type": d.get("type", ""),
                "last": last, "basis": basis, "idle_days": int(idle),
                "overdue": idle >= cfg["days"],
                "move_at": move_at, "due": now >= move_at,
            })
        # forget bookkeeping for devices that no longer exist
        for mu in [k for k in st if k not in live]:
            st.pop(mu); dirty = True
        if dirty:
            save_stale(st)
    out["flagged"].sort(key=lambda f: f["move_at"])
    return out

def stale_check(by: str) -> dict:
    """Report + (when enabled) move every device whose notice period is over."""
    rep = stale_report()
    rep["auto_archived"] = []
    if rep["enabled"] and rep["auto"]:
        due = [f["mac"] for f in rep["flagged"] if f["due"]]
        if due:
            try:
                rep["auto_archived"] = archive_devices(
                    due, f"not online for {rep['stale_days']}+ days", "auto")
                gone = {m["mac"] for m in rep["auto_archived"]}
                rep["flagged"] = [f for f in rep["flagged"] if f["mac"].upper() not in gone]
            except Exception as e:
                rep["auto_error"] = str(e)
                print(f"[stale] auto-archive failed: {e}")
    rep["archived_macs"] = sorted(archived_macs())
    return rep

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

# Up to this version the admin-tool VLANs were fixed in the page code. A
# site_config.json saved before the setting existed has no "admin_tools"
# section; for those plants the old fixed values are carried over so their
# admin tools keep working, and they show up in Settings where they can be
# edited. A new plant (no config file yet) starts with everything empty.
_LEGACY_ADMIN_TOOLS = {
    "web_vlans":        ["1151", "1028"],
    "pc_vlans":         ["1021", "1022", "1023", "1024", "1048"],
    "pc_name_prefixes": ["C", "W"],
    "port_vlans":       ["1088", "1021", "1022", "1023", "1024", "1028"],
}

# PoE and DHCP VLANs used to fall back to these when the setting was empty.
# Now empty means "none". Configs saved before that change get the old values
# copied in once (visible + editable in Settings); every save marks the file.
_LEGACY_POE_VLANS  = ["1010", "1162", "1159"]
_LEGACY_DHCP_VLANS = ["1010", "1088", "1048"]

def _carry_over_legacy_admin_tools(cfg: dict):
    try:
        if not SITE_CONFIG_FILE or not SITE_CONFIG_FILE.exists():
            return
        raw = json.loads(SITE_CONFIG_FILE.read_text(encoding='utf-8'))
        if not isinstance(raw, dict):
            return
        raw_nm = raw.get("netmap") or {}
        nm = cfg.setdefault("netmap", {})
        if "admin_tools" not in raw_nm:
            nm["admin_tools"] = {k: list(v) for k, v in _LEGACY_ADMIN_TOOLS.items()}
            nm["admin_tools"].setdefault("vnc_vlans", [])
        if not raw_nm.get("vlan_defaults_v2"):
            if not nm.get("poe_vlans"):  nm["poe_vlans"]  = list(_LEGACY_POE_VLANS)
            if not nm.get("dhcp_vlans"): nm["dhcp_vlans"] = list(_LEGACY_DHCP_VLANS)
    except Exception as e:
        print(f"[site-config] legacy admin-tools carry-over skipped: {e}")

def load_site_config() -> dict:
    """Load site_config.json, merged with defaults from inventory module."""
    try:
        # Delegate to inventory module — it owns the schema + defaults
        from inventory import load_config
        cfg = load_config(SITE_CONFIG_FILE) if SITE_CONFIG_FILE else load_config()
        _carry_over_legacy_admin_tools(cfg)
        return cfg
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
    try:
        nm = get_site_config().get("netmap", {})
        if isinstance(nm.get("vlan_pause"),           int): VLAN_PAUSE           = nm["vlan_pause"]
        if isinstance(nm.get("presence_ttl"),         int): PRESENCE_TTL         = nm["presence_ttl"]
        if isinstance(nm.get("status_freshness_max"), int): STATUS_FRESHNESS_MAX = nm["status_freshness_max"]
        if isinstance(nm.get("xml_history_max"),      int): XML_HISTORY_MAX      = nm["xml_history_max"]
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

EDIT_NOTICE_TTL = 30 * 60    # an "I'm editing" announcement lapses after this many seconds

def _is_editing(info: dict, now: int) -> bool:
    since = info.get("editing_since") or 0
    return bool(since) and now - since <= EDIT_NOTICE_TTL

def current_editors(exclude_self: bool = True) -> list:
    """Connected users who announced they are editing the map."""
    now = int(time.time())
    out = []
    for uid, info in load_presence().items():
        if now - info.get("ts", 0) > PRESENCE_TTL: continue
        if exclude_self and uid == _my_user_id: continue
        if _is_editing(info, now):
            out.append({"id": uid, "name": info.get("name", "?"),
                        "since": info.get("editing_since")})
    return out

# ── Live cursors ─────────────────────────────────────────────────────────
# Every open NetMap page sends where its mouse is on the map (world
# coordinates) about once a second; each is one small file in cursors/ beside
# the XML, so every NetMap on the shared drive can read the others.
CURSOR_DIR = None
CURSOR_FRESH = 20          # seconds — older cursors are not shown
_cursor_last_write = {}
_cursor_last_reap = [0]

def _cursor_file(tab: str):
    safe = re.sub(r"[^A-Za-z0-9_-]", "", f"{_my_user_id}-{tab}")[:80]
    return CURSOR_DIR / f"{safe}.json"

def cursor_put(tab: str, data: dict):
    if not CURSOR_DIR or not tab: return
    now = time.time()
    if now - _cursor_last_write.get(tab, 0) < 0.4:
        return                                    # at most ~2 writes / s per page
    _cursor_last_write[tab] = now
    try:
        CURSOR_DIR.mkdir(parents=True, exist_ok=True)
        rec = {"tab": str(tab)[:40], "uid": _my_user_id, "name": _my_user_label, "t": now}
        for k in ("x", "y"):
            v = data.get(k)
            rec[k] = float(v) if isinstance(v, (int, float)) else None
        for k, lim in (("sel", 40), ("sel_label", 80), ("where", 80)):
            v = data.get(k)
            rec[k] = str(v)[:lim] if v else ""
        rec["on_map"] = bool(data.get("on_map"))
        _cursor_file(tab).write_text(json.dumps(rec), encoding="utf-8")
    except Exception as e:
        print(f"[cursor] write failed: {e}")

def cursor_drop(tab: str):
    try:
        f = _cursor_file(tab)
        if f.exists(): f.unlink()
    except Exception: pass

def cursor_list(my_tab: str):
    out = []
    if not CURSOR_DIR or not CURSOR_DIR.exists(): return out
    now = time.time()
    reap = now - _cursor_last_reap[0] > 300
    if reap: _cursor_last_reap[0] = now
    for f in CURSOR_DIR.glob("*.json"):
        try:
            age = now - f.stat().st_mtime
            if age > 3600 and reap:
                try: f.unlink()
                except Exception: pass
                continue
            if age > CURSOR_FRESH: continue
            rec = json.loads(f.read_text(encoding="utf-8"))
            if rec.get("uid") == _my_user_id and rec.get("tab") == my_tab: continue
            rec["age"] = round(now - float(rec.get("t") or now), 1)
            rec["self_pc"] = rec.get("uid") == _my_user_id
            out.append(rec)
        except Exception:
            continue
    return out

def heartbeat_tick(ping_active: bool = None, ping_filter: str = None, ping_wait_min: float = None,
                   editing: bool = None):
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
                # Decimal minutes are allowed (0.5 = 30 seconds)
                entry["ping_wait_min"] = round(float(ping_wait_min), 2) if ping_wait_min else 0
            # Auto-clear a stale ping flag — if the client's ping_updated ts is
            # older than 90s (missed 3 heartbeats worth), consider ping inactive.
            if entry.get("ping_active") and now - entry.get("ping_updated", 0) > 90:
                entry["ping_active"] = False
            # "I'm editing the map" announcement — set/cleared explicitly, and
            # dropped on its own once it is older than EDIT_NOTICE_TTL.
            if editing is not None:
                if editing: entry["editing_since"] = now
                else:       entry.pop("editing_since", None)
            elif entry.get("editing_since") and not _is_editing(entry, now):
                entry.pop("editing_since", None)
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
                changed.append(f"changed in XML: {existing.get('name',mac)} — {', '.join(updates.keys())}")
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

    # This only reports what differs between the XML file and the copy this
    # NetMap holds in memory (after a scan, an edit, or a change made by another
    # NetMap on the same file). Nothing is written to the XML here.
    if changed:
        print(f"[xml] file re-read — {len(changed)} difference(s) picked up from the XML:")
        for c in changed[:15]: print(f"      • {c}")
        if len(changed) > 15:
            print(f"      … and {len(changed) - 15} more")
    else:
        print("[xml] file re-read — nothing changed")

    # A replaced device (new MAC with <previous-mac>) is NOT moved onto the old
    # device's map position here: the page asks the user to approve each
    # replacement first, and until then the old device stays where it is.
    return changed

# ── HTTP ─────────────────────────────────────────────────────────────────────────
# ── Admin tool helpers ──────────────────────────────────────────────────────────
def admin_check_online(ip: str, timeout: float = 1.5) -> bool:
    """Quick check if a Windows PC is reachable on SMB port 445."""
    try:
        s = socket.create_connection((ip, 445), timeout=timeout)
        s.close()
        return True
    except:
        # try ICMP ping as fallback (ping_once ignores "host unreachable" replies)
        return ping_once(ip, wait_ms=1500)

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

# ══════════════════════════════════════════════════════════════════════════
# LIVE SSH — interactive shells on several switches at once
# ══════════════════════════════════════════════════════════════════════════
# One session = the switches one user has open in the Live SSH window. Each
# switch has its own paramiko shell and a reader thread that keeps its output.
# The page long-polls for new output and sends keystrokes / lines to the
# switches it picks. Credentials are used to connect and then dropped; a
# session nobody polls for LIVE_SSH_IDLE seconds is closed.
LIVE_SSH_MAX_SWITCHES = 25
LIVE_SSH_BUF = 400_000            # characters of output kept per switch
LIVE_SSH_IDLE = 90                # seconds without a poll → disconnect
live_ssh_sessions: dict = {}
live_ssh_lock = threading.Lock()

class _LivePane:
    def __init__(self, ip, cond):
        self.ip = ip; self.cond = cond
        self.status = "connecting"; self.error = ""
        self.text = ""; self.start = 0          # absolute offset of text[0]
        self.client = None; self.chan = None

    def add(self, data: str):
        with self.cond:
            self.text += data
            if len(self.text) > LIVE_SSH_BUF:
                cut = len(self.text) - LIVE_SSH_BUF
                self.text = self.text[cut:]; self.start += cut
            self.cond.notify_all()

    def set_status(self, st, err=""):
        with self.cond:
            self.status = st; self.error = err
            self.cond.notify_all()

    def close(self):
        for o in (self.chan, self.client):
            try:
                if o: o.close()
            except Exception: pass
        if self.status in ("open", "connecting"):
            self.set_status("closed")

def _live_connect(pane: _LivePane, user: str, pwd: str):
    if not HAS_PARAMIKO:
        pane.set_status("error", "Paramiko not installed on server"); return
    try:
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        c.connect(pane.ip, username=user, password=pwd, timeout=12,
                  look_for_keys=False, allow_agent=False)
        ch = c.invoke_shell(term="vt100", width=200, height=50)
        ch.settimeout(1.0)
        pane.client, pane.chan = c, ch
        pane.set_status("open")
    except paramiko.AuthenticationException:
        pane.set_status("error", "Authentication failed"); return
    except Exception as e:
        pane.set_status("error", f"{type(e).__name__}: {e}"); return
    while True:
        try:
            data = ch.recv(65535)
            if not data:
                break
            pane.add(data.decode("utf-8", errors="replace"))
        except socket.timeout:
            if ch.closed or ch.exit_status_ready():
                break
        except Exception:
            break
    try: c.close()
    except Exception: pass
    if pane.status == "open":
        pane.set_status("closed", "connection closed by the switch")

def live_ssh_open(sid, ips, user, pwd):
    with live_ssh_lock:
        if sid and sid in live_ssh_sessions:
            sess = live_ssh_sessions[sid]
        else:
            sid = secrets.token_hex(8)
            sess = {"cond": threading.Condition(), "panes": {}, "last_poll": time.time()}
            live_ssh_sessions[sid] = sess
        started = []
        for ip in ips:
            old = sess["panes"].get(ip)
            if old and old.status in ("open", "connecting"):
                continue                      # already connected
            if old: old.close()
            if len([p for p in sess["panes"].values()
                    if p.status in ("open", "connecting")]) >= LIVE_SSH_MAX_SWITCHES:
                break
            pane = _LivePane(ip, sess["cond"])
            if old:                            # keep what was on screen
                pane.text, pane.start = old.text, old.start
                pane.add(f"\r\n--- reconnecting {ip} ---\r\n")
            sess["panes"][ip] = pane
            threading.Thread(target=_live_connect, args=(pane, user, pwd), daemon=True).start()
            started.append(ip)
        sess["last_poll"] = time.time()
    return sid, started

def live_ssh_poll(sid, offsets: dict, wait: float):
    sess = live_ssh_sessions.get(sid)
    if not sess:
        return None
    sess["last_poll"] = time.time()
    cond = sess["cond"]
    def _changed():
        for ip, p in sess["panes"].items():
            o = offsets.get(ip)
            if o is None or o.get("off", -1) < p.start + len(p.text) or o.get("st") != p.status:
                return True
        return False
    with cond:
        if not _changed():
            cond.wait(timeout=max(0.0, min(wait, 2.0)))
        out = {}
        for ip, p in sess["panes"].items():
            o = offsets.get(ip) or {}
            off = int(o.get("off", 0) or 0)
            end = p.start + len(p.text)
            rel = max(0, off - p.start)
            out[ip] = {"status": p.status, "error": p.error, "off": end,
                       "data": p.text[rel:] if off < end else "",
                       "lost": off < p.start}
    sess["last_poll"] = time.time()
    return out

def live_ssh_send(sid, ips, data: str):
    sess = live_ssh_sessions.get(sid)
    if not sess:
        return {}
    res = {}
    for ip in ips:
        p = sess["panes"].get(ip)
        if not p or p.status != "open" or not p.chan:
            res[ip] = False; continue
        try:
            p.chan.send(data); res[ip] = True
        except Exception as e:
            p.set_status("error", f"send failed: {e}"); res[ip] = False
    return res

def live_ssh_close(sid, ips=None):
    with live_ssh_lock:
        sess = live_ssh_sessions.get(sid)
        if not sess: return
        targets = list(sess["panes"].keys()) if ips is None else ips
        for ip in targets:
            p = sess["panes"].get(ip)
            if p: p.close()
            if ips is not None:
                sess["panes"].pop(ip, None)
        if ips is None:
            live_ssh_sessions.pop(sid, None)
        with sess["cond"]: sess["cond"].notify_all()

def _live_ssh_reaper():
    while True:
        time.sleep(10)
        try:
            now = time.time()
            for sid, sess in list(live_ssh_sessions.items()):
                if now - sess.get("last_poll", now) > LIVE_SSH_IDLE:
                    print(f"[live-ssh] session idle for {LIVE_SSH_IDLE}s — disconnecting")
                    live_ssh_close(sid)
        except Exception as e:
            print(f"[live-ssh] reaper: {e}")
threading.Thread(target=_live_ssh_reaper, daemon=True).start()

def _bring_to_front(pid: int, hint: str = "", seconds: float = 20.0):
    """Raise every visible top-level window of process `pid` (or whose title
    contains `hint`) to the foreground, as each one appears. Windows only."""
    if os.name != "nt": return
    try:
        import ctypes
        from ctypes import wintypes
        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32
        EnumProc = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
        # 64-bit safe handle types
        user32.GetForegroundWindow.restype = wintypes.HWND
        user32.SetWindowPos.argtypes = [wintypes.HWND, wintypes.HWND, ctypes.c_int, ctypes.c_int,
                                        ctypes.c_int, ctypes.c_int, wintypes.UINT]
        user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.c_void_p]
        user32.GetWindowThreadProcessId.restype = wintypes.DWORD
        HWND_TOPMOST, HWND_NOTOPMOST = -1, -2
        SWP_NOMOVE, SWP_NOSIZE, SWP_SHOWWINDOW = 0x2, 0x1, 0x40
        VK_MENU, KEYUP = 0x12, 0x2
        hint_l = (hint or "").lower()
        done = set()

        def windows():
            found = []
            def cb(hwnd, _):
                if not user32.IsWindowVisible(hwnd): return True
                wpid = wintypes.DWORD()
                user32.GetWindowThreadProcessId(hwnd, ctypes.byref(wpid))
                n = user32.GetWindowTextLengthW(hwnd)
                buf = ctypes.create_unicode_buffer(n + 1)
                user32.GetWindowTextW(hwnd, buf, n + 1)
                title = buf.value or ""
                if wpid.value == pid or (hint_l and hint_l in title.lower()):
                    found.append(hwnd)
                return True
            user32.EnumWindows(EnumProc(cb), 0)
            return found

        def raise_(hwnd):
            if user32.IsIconic(hwnd): user32.ShowWindow(hwnd, 9)      # SW_RESTORE
            else: user32.ShowWindow(hwnd, 5)                          # SW_SHOW
            # topmost on / off puts it above the browser without pinning it there
            user32.SetWindowPos(hwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW)
            user32.SetWindowPos(hwnd, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_SHOWWINDOW)
            # a short Alt tap lets this process hand over keyboard focus
            user32.keybd_event(VK_MENU, 0, 0, 0)
            user32.keybd_event(VK_MENU, 0, KEYUP, 0)
            fg = user32.GetForegroundWindow()
            cur_t = kernel32.GetCurrentThreadId()
            fg_t = user32.GetWindowThreadProcessId(fg, None)
            attached = bool(fg_t and fg_t != cur_t and user32.AttachThreadInput(cur_t, fg_t, True))
            try:
                user32.BringWindowToTop(hwnd)
                user32.SetForegroundWindow(hwnd)
                user32.SetFocus(hwnd)
            finally:
                if attached: user32.AttachThreadInput(cur_t, fg_t, False)

        t0 = time.time()
        while time.time() - t0 < seconds:
            for hwnd in windows():
                if hwnd not in done:
                    done.add(hwnd)
                    time.sleep(0.15)          # let the window finish drawing
                    try: raise_(hwnd)
                    except Exception as e: print(f"[vnc] raise failed: {e}")
            time.sleep(0.3)
    except Exception as e:
        print(f"[vnc] bring-to-front skipped: {e}")

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

    # Server rooms — where each device sits ("Room › Rack U12")
    def _sr_places(lay):
        out = {}
        for room in ((lay or {}).get("serverRooms") or []):
            for rack in (room.get("racks") or []):
                for it in (rack.get("items") or []):
                    if it.get("mac"):
                        out[it["mac"]] = f"{room.get('label','')} › {rack.get('label','')} U{it.get('u','?')}" \
                                         + (f"-{int(it.get('u',0))+int(it.get('h',1))-1}" if int(it.get('h',1) or 1) > 1 else "")
        return out
    old_sr, new_sr = _sr_places(old), _sr_places(new)
    for mac in set(new_sr) - set(old_sr):
        events.append({"event":"sroom-in", "target":mac, "detail":new_sr[mac]})
    for mac in set(old_sr) - set(new_sr):
        events.append({"event":"sroom-out", "target":mac, "detail":old_sr[mac]})
    for mac in set(old_sr) & set(new_sr):
        if old_sr[mac] != new_sr[mac]:
            events.append({"event":"sroom-moved", "target":mac, "detail":f"{old_sr[mac]} -> {new_sr[mac]}"})

    # Hosts — extra NICs / VMs attached to a physical device
    def _links(lay):
        out = {}
        for host, kids in (((lay or {}).get("hostLinks") or {}).items()):
            for k in (kids or []):
                if k.get("mac"): out[k["mac"]] = (host, k.get("kind", "vm"))
        return out
    old_l, new_l = _links(old), _links(new)
    for mac in set(new_l) - set(old_l):
        events.append({"event":"host-attached", "target":mac, "detail":f"{new_l[mac][1].upper()} of {new_l[mac][0]}"})
    for mac in set(old_l) - set(new_l):
        events.append({"event":"host-detached", "target":mac, "detail":f"was {old_l[mac][1].upper()} of {old_l[mac][0]}"})

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

def _type_rules():
    """Settings → Mapping → "VLAN type map" as {vlan: type}, plus the switch IPs
    from Settings → Switches. Nothing is hardcoded: every plant sets its own."""
    cfg = get_site_config() or {}
    by_vlan = {}
    for t, vlans in (cfg.get("vlan_type_map") or {}).items():
        if isinstance(vlans, str): vlans = vlans.split(",")
        for v in vlans or []:
            v = str(v).strip()
            if v: by_vlan[v] = str(t).strip().lower()
    sw_ips = {str(x).strip() for x in ((cfg.get("switches") or {}).get("ips") or []) if str(x).strip()}
    return by_vlan, sw_ips

def _type_from_vlan(vlan: str) -> str:
    """Same VLAN → type rule the scanner uses (Settings → Mapping)."""
    return _type_rules()[0].get((vlan or '').strip(), '')

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
            xp = xml_path_store[0]
            if xp:
                try:
                    new_devs = load_xml(xp)
                    changes  = merge_devices(new_devs)
                    # Snapshot into rolling XML history if content actually changed
                    snapshot_xml_if_changed(new_devs)
                    self._json({"ok": True, "changes": changes,
                                "total": len(devices_by_mac)})
                except Exception as e:
                    self._error(str(e))
            else:
                self._json({"ok": False, "changes": [], "msg": "No XML file loaded"})

        elif path == "/api/device/history":
            # ?mac=AA:BB:..  — merged change timeline for one device.
            try:
                self._json(device_change_history(qs.get("mac", [""])[0]))
            except Exception as e:
                self._json({"ok": False, "error": str(e)})

        elif path == "/api/stale/archive":
            # Devices currently in old_data.xml
            try:
                self._json({"ok": True, "devices": list_archived()})
            except Exception as e:
                self._json({"ok": False, "error": str(e)})

        elif path == "/api/scan/progress":
            # Live step log of the running inventory scan (polled by the scan window).
            try:
                st = scan_state
                self._json({
                    "active": bool(st.get("active")),
                    "mode": st.get("mode", ""),
                    "elapsed": round(time.time() - st["started"], 1) if st.get("active") and st.get("started") else None,
                    "lines": list(st.get("lines", [])),
                    "counter": st.get("counter"),
                })
            except Exception as e:
                self._json({"active": False, "lines": [], "error": str(e)})

        elif path == "/api/ping/progress":
            # Live progress of the ping cycle this server is running (badge tooltip).
            try:
                self._json(ping_progress_snapshot())
            except Exception as e:
                self._json({"active": False, "error": str(e)})

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
            # Runtime environment info — admin privilege, OS, python version, username.
            # Used by the Run Scan modal to warn if WinRM features may fail,
            # and by the toolbar identity indicator.
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
                # Username — whoever launched NetMap.exe
                username = ""
                try:
                    username = os.getlogin()
                except Exception:
                    username = os.environ.get("USERNAME") or os.environ.get("USER") or ""
                self._json({
                    "ok": True,
                    "os": os.name,
                    "platform": platform.system(),
                    "is_admin": is_admin,
                    "hostname": platform.node(),
                    "username": username,
                })
            except Exception as e:
                self._json({"ok": False, "error": str(e)})

        elif path == "/api/scan/default-script":
            # The built-in WinRM scan script (Settings → "Load default")
            try:
                from inventory import DEFAULT_PS_SCRIPT
                self._json({"ok": True, "script": DEFAULT_PS_SCRIPT})
            except Exception as e: self._error(str(e))

        elif path == "/api/cursors":
            # Other people's cursors (fresh ones), excluding this page's own
            try:
                tab = (qs.get("tab") or [""])[0]
                self._json({"ok": True, "cursors": cursor_list(tab)})
            except Exception as e: self._error(str(e))

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
                # Editing announcements ride along on this 6-second poll so
                # other users see them quickly (the presence poll is 30 s).
                try: editors = current_editors()
                except Exception: editors = []
                self._json({"statuses": fresh, "now": now,
                            "freshness_max": STATUS_FRESHNESS_MAX,
                            "editors": editors})
            except Exception as e:
                self._json({"statuses":{}, "now": int(time.time()),
                            "freshness_max": STATUS_FRESHNESS_MAX})

        elif path == "/api/snapshots":
            # List all layout snapshots, newest first.
            try:
                entries = list_layout_snapshots()
                self._json({"ok": True, "snapshots": entries, "count": len(entries)})
            except Exception as e:
                self._json({"ok": False, "error": str(e)})

        elif path == "/api/snapshot/get":
            # Return a snapshot's contents for preview. ?filename=layout_XXXX.json
            try:
                name = qs.get("filename",[""])[0]
                fp = _snapshot_path(name)
                if not fp or not fp.exists():
                    self._json({"ok": False, "error": "Not found"}); return
                self._json({"ok": True, "content": json.loads(fp.read_text(encoding='utf-8'))})
            except Exception as e:
                self._json({"ok": False, "error": str(e)})

        elif path == "/api/storage/stats":
            # Report size of all data files + photos folder.
            # Client shows this in Settings → Advanced.
            try:
                info = {}
                # Single-file data files next to the XML
                files = {
                    "layout.json":         LAYOUT_FILE,
                    "history.json":        HISTORY_FILE,
                    "alerts.json":         ALERTS_FILE,
                    "known_macs.json":     KNOWN_FILE,
                    "auth.json":           AUTH_FILE,
                    "actions.json":        ACTIONS_FILE,
                    "presence.json":       PRESENCE_FILE,
                    "admin.json":          ADMIN_LOG_FILE,
                    "filter_history.json": FILTER_HIST_FILE,
                    "filter_history_mine.json": FILTER_MINE_FILE,
                    "toolbar_prefs.json":  TOOLBAR_PREFS_FILE,
                    "live_status.json":    LIVE_STATUS_FILE,
                    "xml_history.json":    XML_HISTORY_FILE,
                    "templates.json":      TEMPLATES_FILE,
                    "site_config.json":    SITE_CONFIG_FILE,
                    "stale.json":          STALE_FILE,
                    "old_data.xml (archive)": ARCHIVE_XML,
                }
                # Also report the XML file itself (main inventory)
                try:
                    xp = xml_path_store[0]
                    if xp and Path(xp).exists():
                        files[Path(xp).name + " (XML)"] = Path(xp)
                except Exception: pass
                total = 0
                for name, fp in files.items():
                    if fp and fp.exists():
                        try: sz = fp.stat().st_size
                        except: sz = 0
                    else: sz = 0
                    info[name] = sz
                    total += sz
                # Snapshots folder: sum + count
                snap_total = 0; snap_count = 0
                if SNAPSHOTS_DIR and SNAPSHOTS_DIR.exists():
                    for fp in SNAPSHOTS_DIR.iterdir():
                        if fp.is_file():
                            try: snap_total += fp.stat().st_size; snap_count += 1
                            except: pass
                info["layout_snapshots/ (folder, " + str(snap_count) + " files)"] = snap_total
                total += snap_total
                # HTTPS cert files (next to server.py, not in data dir but relevant)
                try:
                    crt_path, key_path = ensure_https_cert()
                    for label, fp in [("netmap.crt", Path(crt_path)),
                                      ("netmap.key", Path(key_path))]:
                        if fp.exists():
                            try:
                                sz = fp.stat().st_size
                                info[label] = sz
                                total += sz
                            except Exception: pass
                except Exception: pass
                self._json({"ok": True, "files": info, "total": total,
                            "snapshots_count": snap_count})
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

        elif path == "/api/filter-history" and (qs.get("mine") or [""])[0]:
            # This PC's own filter history (kept per PC name, beside the XML)
            try:
                user = ((qs.get("user") or [""])[0]).strip() or platform.node()
                mine = []
                if FILTER_MINE_FILE and FILTER_MINE_FILE.exists():
                    try: mine = (json.loads(FILTER_MINE_FILE.read_text(encoding='utf-8')) or {}).get(user) or []
                    except Exception: mine = []
                self._json(mine[:50])
            except Exception as e: self._error(str(e))

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
                    self._json({"ok": True, "hidden": [], "saved": False})
                else:
                    allprefs = json.loads(TOOLBAR_PREFS_FILE.read_text(encoding='utf-8'))
                    mine = allprefs.get(host)
                    # saved = this PC has stored a toolbar before (even "show all")
                    self._json({"ok": True, "hidden": (mine or {}).get("hidden", []),
                                "saved": isinstance(mine, dict)})
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
                    "ping_wait_min": round(float(info.get("ping_wait_min") or 0), 2),
                    "editing":       _is_editing(info, now),
                    "editing_since": info.get("editing_since") if _is_editing(info, now) else None,
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

        elif path == "/api/audit/last-touched":
            # Returns a map of {target-id: {by, ts, event}} for the most recent
            # position/edit action per target. Used by hover tooltips to show
            # "Position last changed by X · Ndays ago". Available to all users
            # (only usernames + timestamps, not command details).
            try:
                entries = load_admin_log()
                keep_events = {
                    "placed", "moved", "unplaced", "display-name", "resized", "note",
                    "room-added", "room-deleted",
                    "rack-added", "rack-deleted",
                    "manual-add",
                    "scan-run", "scan-manual-add",
                }
                def _to_epoch(ts_val):
                    # log_admin() stores ts as "YYYY-MM-DD HH:MM:SS" (local time).
                    # Convert to epoch seconds for the client's age math.
                    if isinstance(ts_val, (int, float)):
                        return int(ts_val)
                    try:
                        return int(time.mktime(time.strptime(str(ts_val), "%Y-%m-%d %H:%M:%S")))
                    except Exception:
                        return 0
                latest = {}
                for e in entries:   # newest first from load_admin_log
                    ev = e.get("event","")
                    tgt = e.get("target","")
                    if not tgt or ev not in keep_events: continue
                    if tgt in latest: continue
                    latest[tgt] = {
                        "by": e.get("user",""),
                        "ts": _to_epoch(e.get("ts")),
                        "event": ev,
                    }
                self._json({"ok": True, "touched": latest, "count": len(latest)})
            except Exception as e:
                self._json({"ok": False, "error": str(e)})

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
            # POST {active:bool, filter:str, wait_min:float (decimal minutes), user_label?}
            # Client publishes its ping-session state so others can see who is pinging.
            try:
                data = json.loads(body)
                active  = bool(data.get("active"))
                filt    = str(data.get("filter") or "")[:200]
                try: wait_m = max(0.0, min(1440.0, float(data.get("wait_min") or 0)))
                except (TypeError, ValueError): wait_m = 0.0
                heartbeat_tick(ping_active=active, ping_filter=filt, ping_wait_min=wait_m)
                self._json({"ok": True})
            except Exception as e: self._error(str(e))

        elif self.path == "/api/stale/check":
            # POST {} — inactive-device report; also moves devices whose notice
            # period is over into old_data.xml when auto-archive is on.
            try:
                who = (self.headers.get("X-User-Host") or "").strip() or platform.node()
                rep = stale_check(who)
                rep["ok"] = True
                self._json(rep)
            except Exception as e: self._json({"ok": False, "error": str(e)})

        elif self.path == "/api/stale/action":
            # POST {action: "renew"|"archive"|"delete"|"restore", macs: [...]}
            try:
                data = json.loads(body)
                action = data.get("action")
                macs = [_normalize_mac(m) for m in (data.get("macs") or []) if m]
                who = (self.headers.get("X-User-Host") or "").strip() or platform.node()
                if not macs:
                    self._json({"ok": False, "error": "no devices selected"}); return
                if action == "renew":
                    self._json({"ok": True, "count": renew_devices(macs, who)})
                elif action == "archive":
                    done = archive_devices(macs, "moved by user", who)
                    self._json({"ok": True, "count": len(done), "devices": done})
                elif action == "delete":
                    done = delete_devices(macs, who)
                    self._json({"ok": True, "count": len(done), "devices": done})
                elif action == "restore":
                    done = restore_devices(macs, who)
                    self._json({"ok": True, "count": len(done), "devices": done})
                else:
                    self._json({"ok": False, "error": "unknown action"})
            except Exception as e: self._json({"ok": False, "error": str(e)})

        elif self.path == "/api/presence/editing":
            # POST {active: bool} — announce to the other connected users that
            # this user is about to edit the map (or has finished).
            try:
                data = json.loads(body) if body else {}
                active = bool(data.get("active"))
                heartbeat_tick(editing=active)
                self._json({"ok": True, "active": active, "ttl": EDIT_NOTICE_TTL})
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
                # …and this PC's own list ("My history"), so it no longer
                # depends on which browser / port NetMap was opened in
                if FILTER_MINE_FILE:
                    allm = {}
                    if FILTER_MINE_FILE.exists():
                        try: allm = json.loads(FILTER_MINE_FILE.read_text(encoding='utf-8')) or {}
                        except Exception: allm = {}
                    if not isinstance(allm, dict): allm = {}
                    mine = [h for h in (allm.get(user) or []) if (h.get("query") or "").lower() != query.lower()]
                    mine.insert(0, {"query": query, "user": user, "ts": int(time.time())})
                    allm[user] = mine[:50]
                    atomic_write(FILTER_MINE_FILE, json.dumps(allm, indent=2))
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
                # Saved from Settings → empty PoE / DHCP lists now really mean none
                if isinstance(data.get("netmap"), dict):
                    data["netmap"]["vlan_defaults_v2"] = True
                else:
                    data["netmap"] = {"vlan_defaults_v2": True}
                with _site_cfg_lock:
                    save_site_config(data)
                # Rebind global runtime constants so changes take effect
                # immediately without a server restart.
                apply_runtime_config()
                # Device types follow the VLAN type map / switch IPs: re-read the
                # XML so a changed mapping shows on the map right away.
                if xml_path_store[0]:
                    try: merge_devices(load_xml(xml_path_store[0]))
                    except Exception as _e: print(f"[site-config] reload failed: {_e}")
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
            # POST body: {user, pass, mode: "full"|"new"|"fields"|"custom", steps?: {switches,names,strip,winrm,printer,new_only}}
            # Runs the full scan pipeline. Long-running (blocking response until done).
            # Credentials never persist beyond this handler.
            try:
                data = json.loads(body)
                user = data.get("user") or ""
                pw   = data.get("pass") or ""
                mode = data.get("mode") or "full"
                # mode "custom": firewall dump + only the steps ticked in `steps`
                steps = data.get("steps") if mode == "custom" else None
                if not user or not pw:
                    self._json({"ok": False, "error": "credentials required"}); return
                if mode not in ("full", "new", "fields", "custom"):
                    self._json({"ok": False, "error": "invalid mode"}); return
                if mode == "custom" and not isinstance(steps, dict):
                    self._json({"ok": False, "error": "custom scan needs a steps object"}); return
                try:
                    from inventory import run_full_scan
                except ImportError as e:
                    self._json({"ok": False, "error": f"inventory module missing: {e}"}); return
                cfg = get_site_config()
                if not cfg.get("firewall", {}).get("host"):
                    self._json({"ok": False, "error": "no firewall configured — set one in Settings"}); return
                # Use current XML path as scan output
                xml_target = xml_path_store[0] or cfg.get("output", {}).get("xml_file")
                if not scan_run_lock.acquire(blocking=False):
                    self._json({"ok": False, "error": "a scan is already running on this NetMap"}); return
                try:
                    scan_state.update({"active": True, "started": time.time(), "mode": mode,
                                       "lines": [], "counter": None, "error": None})
                    stats = run_full_scan(cfg, user, pw, mode=mode, xml_path=xml_target,
                                          steps=steps, progress_cb=_scan_progress_cb)
                except Exception as _scan_e:
                    scan_state["error"] = str(_scan_e)
                    raise
                finally:
                    scan_state.update({"active": False, "counter": None, "finished": time.time()})
                    scan_run_lock.release()
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

        elif self.path == "/api/live-ssh/open":
            # POST {sid?, switch_ips:[...], user, pass} → {sid, started:[...]}
            try:
                data = json.loads(body)
                ips = [str(x).strip() for x in (data.get("switch_ips") or []) if str(x).strip()]
                u = data.get("user") or ""; p = data.get("pass") or ""
                if not ips:
                    self._json({"ok": False, "error": "No switches picked"}); return
                if not (u and p):
                    self._json({"ok": False, "error": "Missing user/password"}); return
                if len(ips) > LIVE_SSH_MAX_SWITCHES:
                    self._json({"ok": False, "error": f"At most {LIVE_SSH_MAX_SWITCHES} switches at once"}); return
                sid, started = live_ssh_open(data.get("sid") or "", ips, u, p)
                log_admin("live-ssh-open", u, ",".join(started[:8]) + ("…" if len(started) > 8 else ""),
                          f"switches={len(started)}")
                u = p = None
                self._json({"ok": True, "sid": sid, "started": started})
            except Exception as e: self._error(str(e))

        elif self.path == "/api/live-ssh/poll":
            # POST {sid, offsets:{ip:{off, st}}, wait} → waits up to `wait` s for new output
            try:
                data = json.loads(body)
                panes = live_ssh_poll(data.get("sid") or "", data.get("offsets") or {},
                                      float(data.get("wait") or 0))
                if panes is None:
                    self._json({"ok": False, "gone": True, "error": "session ended"}); return
                self._json({"ok": True, "panes": panes})
            except Exception as e: self._error(str(e))

        elif self.path == "/api/live-ssh/send":
            # POST {sid, switch_ips:[...], data, log?, user?} — raw text/keys to the picked switches
            try:
                d = json.loads(body)
                text = str(d.get("data") or "")
                if len(text) > 65536:
                    self._json({"ok": False, "error": "too much text at once"}); return
                ips = [str(x) for x in (d.get("switch_ips") or [])]
                res = live_ssh_send(d.get("sid") or "", ips, text)
                if d.get("log"):          # whole lines typed in the shared box (never passwords)
                    log_admin("live-ssh-cmd", str(d.get("user") or ""),
                              ",".join(ips[:8]) + ("…" if len(ips) > 8 else ""), str(d["log"])[:300])
                self._json({"ok": True, "sent": res})
            except Exception as e: self._error(str(e))

        elif self.path == "/api/live-ssh/close":
            # POST {sid, switch_ips?} — no list = close the whole session
            try:
                d = json.loads(body)
                ips = d.get("switch_ips")
                live_ssh_close(d.get("sid") or "", [str(x) for x in ips] if ips else None)
                self._json({"ok": True})
            except Exception as e: self._error(str(e))

        elif self.path == "/api/admin/run-port-cmd":
            # POST {jobs:[{switch_ip, commands:[...], label?}], user, pass}
            # Custom commands for selected devices' switch ports. The page has
            # already put each device's port/IP/name into the command lines and
            # grouped them per switch: one SSH session per switch, lines run
            # exactly as typed. Different switches run side by side (max 4).
            try:
                data = json.loads(body)
                jobs = data.get("jobs") or []
                u    = data.get("user") or ""
                p    = data.get("pass") or ""
                if not (u and p):
                    self._json({"ok": False, "error": "Missing user/password"}); return
                clean = []
                for j in jobs:
                    sw = str(j.get("switch_ip") or "").strip()
                    cmds = [str(c) for c in (j.get("commands") or []) if str(c).strip()]
                    if sw and cmds:
                        clean.append({"switch_ip": sw, "commands": cmds,
                                      "label": str(j.get("label") or sw)})
                if not clean:
                    self._json({"ok": False, "error": "No commands to run"}); return
                if len(clean) > 100:
                    self._json({"ok": False, "error": f"Too many switches ({len(clean)}). Limit: 100."}); return
                big = max(len(j["commands"]) for j in clean)
                if big > 400:
                    self._json({"ok": False, "error": f"Too many command lines for one switch ({big}). Limit: 400."}); return
                from concurrent.futures import ThreadPoolExecutor
                def _run(j):
                    r = run_switch_commands(j["switch_ip"], j["commands"], u, p)
                    return {"switch_ip": j["switch_ip"], "label": j["label"],
                            "ok": bool(r.get("ok")), "output": r.get("output") or "",
                            "error": r.get("error") or ""}
                with ThreadPoolExecutor(max_workers=min(4, len(clean))) as ex:
                    results = list(ex.map(_run, clean))
                ok_count = sum(1 for r in results if r["ok"])
                lines = sum(len(j["commands"]) for j in clean)
                log_admin("ssh-port-cmd", u,
                          ",".join(j["switch_ip"] for j in clean[:5]) + ("…" if len(clean) > 5 else ""),
                          f"switches={len(clean)} lines={lines} ok={ok_count} fail={len(results)-ok_count}")
                u = p = None
                self._json({"ok": True, "ok_count": ok_count,
                            "fail_count": len(results) - ok_count, "results": results})
            except Exception as e: self._error(str(e))

        elif self.path == "/api/local/vnc":
            # POST {mac} → starts the VNC viewer on THIS computer, connected to
            # the device (by name or IP, Settings → Mapping → VNC).
            try:
                d = json.loads(body)
                mac = str(d.get("mac") or "").upper()
                dev = devices_by_mac.get(mac)
                if not dev:
                    self._json({"ok": False, "error": "device not found"}); return
                cfg = get_site_config() or {}
                nm = cfg.get("netmap") or {}
                vnc_vlans = {str(v).strip() for v in ((nm.get("admin_tools") or {}).get("vnc_vlans") or [])}
                if str(dev.get("vlan") or "").strip() not in vnc_vlans:
                    self._json({"ok": False, "error": "VNC is not enabled for this device's VLAN"}); return
                vc = nm.get("vnc") or {}
                name = str(dev.get("name") or "").strip()
                ip = str(dev.get("ip") or "").strip()
                if name.lower() in ("", "unknown", "none") or name == ip: name = ""
                if ip.lower() in ("unknown", "none"): ip = ""
                host = (name or ip) if (vc.get("by") or "name") != "ip" else (ip or name)
                ok_chars = re.compile(r"^[A-Za-z0-9._\-]+$")
                if not host or not ok_chars.match(host):
                    self._json({"ok": False, "error": "device has no usable name or IP", "host": host}); return
                viewer = str(vc.get("viewer") or "").strip().strip('"')
                if not viewer:
                    pf = [os.environ.get("ProgramFiles", r"C:\Program Files"),
                          os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")]
                    rel = [r"RealVNC\VNC Viewer\vncviewer.exe", r"TightVNC\tvnviewer.exe",
                           r"uvnc bvba\UltraVNC\vncviewer.exe", r"UltraVNC\vncviewer.exe",
                           r"TigerVNC\vncviewer.exe"]
                    for base in pf:
                        for r_ in rel:
                            cand = os.path.join(base, r_)
                            if os.path.isfile(cand): viewer = cand; break
                        if viewer: break
                    if not viewer:
                        viewer = shutil.which("vncviewer") or shutil.which("tvnviewer") or ""
                if not viewer or not os.path.isfile(viewer):
                    self._json({"ok": False, "host": host,
                                "error": "VNC viewer not found — set its path in Settings → Mapping → VNC viewer program"}); return
                args_t = str(vc.get("args") or "{host}")
                args = [a.replace("{host}", host).replace("{ip}", ip if ok_chars.match(ip or "-") else "")
                         .replace("{name}", name if ok_chars.match(name or "-") else "")
                        for a in args_t.split()]
                si = None
                if os.name == "nt":
                    si = subprocess.STARTUPINFO()
                    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                    si.wShowWindow = 1                       # SW_SHOWNORMAL
                proc = subprocess.Popen([viewer] + [a for a in args if a],
                                 creationflags=getattr(subprocess, "DETACHED_PROCESS", 0)
                                             | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 close_fds=True, startupinfo=si)
                # Windows keeps a window started by a background program behind
                # the browser. Watch for the viewer's windows (connect and
                # password dialogs too) and raise each one to the front.
                if os.name == "nt":
                    threading.Thread(target=_bring_to_front, args=(proc.pid, host), daemon=True).start()
                self._json({"ok": True, "host": host, "viewer": os.path.basename(viewer)})
            except Exception as e: self._error(str(e))

        elif self.path == "/api/cursor":
            # POST {tab, x, y, sel, sel_label, where, on_map, gone?}
            try:
                d = json.loads(body or "{}")
                tab = str(d.get("tab") or "")
                if d.get("gone"): cursor_drop(tab)
                else: cursor_put(tab, d)
                self._json({"ok": True})
            except Exception as e: self._error(str(e))

        elif self.path == "/api/local/flushdns":
            # Clears the DNS cache of THIS computer (the one running this NetMap),
            # so names that moved to a new IP resolve again. Windows only.
            try:
                if os.name != "nt":
                    self._json({"ok": False, "error": "ipconfig /flushdns only works on Windows"}); return
                r = subprocess.run(["ipconfig", "/flushdns"], capture_output=True, timeout=20,
                                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                raw = (r.stdout or b"") + (r.stderr or b"")
                try:    text = raw.decode("oem")
                except Exception: text = raw.decode("utf-8", errors="replace")
                text = "\n".join(l for l in text.splitlines() if l.strip())
                who = (self.headers.get("X-User-Host") or "").strip() or platform.node()
                log_admin("flushdns", who, "", f"rc={r.returncode}")
                self._json({"ok": r.returncode == 0, "output": text,
                            "error": "" if r.returncode == 0 else f"ipconfig exited with {r.returncode}"})
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

        elif self.path == "/api/devices/strip-names":
            # POST body: {macs:[...], strip:"...", case_insensitive:bool}
            # For each MAC, remove all occurrences of `strip` from the <name>
            # element in the XML. Silently skips devices whose name doesn't
            # contain the substring. Returns per-device results.
            try:
                data = json.loads(body)
                macs = data.get("macs", []) or []
                strip = str(data.get("strip", "") or "")
                ci = bool(data.get("case_insensitive", True))
                by_user = self.headers.get("X-User-Host","") or platform.node()
                if not strip:
                    self._json({"ok": False, "error": "Empty strip string"}); return
                if not macs:
                    self._json({"ok": False, "error": "No devices selected"}); return
                xp = xml_path_store[0]
                if not xp or not Path(xp).exists():
                    self._json({"ok": False, "error": "XML file not loaded"}); return
                # Snapshot layout first — cheap insurance for a bulk XML edit
                create_layout_snapshot(reason="prestrip", by_user=by_user)
                tree = ET.parse(xp)
                root = tree.getroot()
                mac_set = {m.upper().strip() for m in macs if m}
                results = []
                changed_count = 0
                for dev in root.findall("device"):
                    mac_el = dev.find("mac")
                    if mac_el is None or not (mac_el.text or "").strip(): continue
                    mac = mac_el.text.strip().upper()
                    if mac not in mac_set: continue
                    name_el = dev.find("name")
                    if name_el is None or name_el.text is None: continue
                    old = name_el.text
                    if ci:
                        pattern = re.compile(re.escape(strip), re.IGNORECASE)
                        new = pattern.sub("", old)
                    else:
                        new = old.replace(strip, "")
                    if new != old:
                        name_el.text = new
                        results.append({"mac": mac, "old": old, "new": new})
                        changed_count += 1
                if changed_count > 0:
                    tree.write(xp, encoding="utf-8", xml_declaration=True)
                    try:
                        new_devs = load_xml(xp)
                        merge_devices(new_devs)
                    except Exception as _e: print(f"[strip-names] reload failed: {_e}")
                    log_admin("bulk-strip-names", by_user, "",
                              f"stripped '{strip}' from {changed_count}/{len(macs)} devices")
                self._json({
                    "ok": True,
                    "changed": changed_count,
                    "requested": len(macs),
                    "skipped": len(macs) - changed_count,
                    "results": results,
                })
            except Exception as e:
                self._error(str(e))

        elif self.path == "/api/snapshot/create":
            # POST — take a manual snapshot right now.
            # Body: {reason: "manual"} (optional)
            try:
                by_user = self.headers.get("X-User-Host","") or platform.node()
                data = json.loads(body) if body else {}
                reason = (data.get("reason") or "manual").strip()[:10] or "manual"
                result = create_layout_snapshot(reason=reason, by_user=by_user)
                if result.get("ok"):
                    log_admin("snapshot-create", by_user, result["filename"],
                              f"manual snapshot ({result['size']} bytes)")
                self._json(result)
            except Exception as e:
                self._error(str(e))

        elif self.path == "/api/snapshot/restore":
            # POST body: {filename} — restore a snapshot as current layout.
            # Requires settings token (destructive operation).
            if not verify_settings_token(self.headers):
                self.send_response(403); self._cors(); self.end_headers(); return
            try:
                data = json.loads(body)
                filename = data.get("filename","")
                by_user = self.headers.get("X-User-Host","") or platform.node()
                result = restore_layout_snapshot(filename, by_user=by_user)
                self._json(result)
            except Exception as e:
                self._error(str(e))

        elif self.path == "/api/snapshot/delete":
            # POST body: {filename} — delete one snapshot. Requires settings token.
            if not verify_settings_token(self.headers):
                self.send_response(403); self._cors(); self.end_headers(); return
            try:
                data = json.loads(body)
                filename = data.get("filename","")
                fp = _snapshot_path(filename)
                if not fp or not fp.exists():
                    self._json({"ok": False, "error": "Not found"}); return
                fp.unlink()
                by_user = self.headers.get("X-User-Host","") or platform.node()
                log_admin("snapshot-delete", by_user, filename, "manual delete")
                self._json({"ok": True})
            except Exception as e:
                self._error(str(e))

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
        # If the client already closed the connection, don't spam the console
        # with SSL/pipe errors when we try to write the response.
        try:
            data = json.dumps({"error":msg}).encode()
            self.send_response(400)
            self.send_header("Content-Type","application/json")
            self._cors(); self.end_headers(); self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError,
                ConnectionAbortedError, OSError) as _e:
            pass
        except Exception as _e:
            # Any SSL layer error — client disconnected mid-response
            if 'SSL' in type(_e).__name__ or 'ssl' in str(_e).lower():
                pass
            else:
                raise

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin","*")
        self.send_header("Access-Control-Allow-Methods","GET,POST,OPTIONS")
        self.send_header("Access-Control-Allow-Headers","Content-Type")

    def log_message(self, fmt, *a):
        msg = fmt % a
        if ("/api/status" not in msg and "/api/history" not in msg
                and "/api/ping/progress" not in msg
                and "/api/scan/progress" not in msg
                and "/api/live-ssh/poll" not in msg
                and "/api/live-ssh/send" not in msg
                and "/api/cursor" not in msg):
            print(f"  {msg}")

# ── Main ────────────────────────────────────────────────────────────────────────
def main():
    """Server startup. Called from launcher.py or via __main__ below."""
    global PORT
    global LAYOUT_FILE, HISTORY_FILE, ALERTS_FILE, KNOWN_FILE, AUTH_FILE
    global ACTIONS_FILE, PRESENCE_FILE, ADMIN_LOG_FILE, FILTER_HIST_FILE
    global TOOLBAR_PREFS_FILE, LIVE_STATUS_FILE, XML_HISTORY_FILE
    global TEMPLATES_FILE, SITE_CONFIG_FILE, SNAPSHOTS_DIR, STALE_FILE, ARCHIVE_XML
    # Parse argv: first non-flag argument is the XML path.
    # Also honor --port=NNNN so multiple instances can run on one machine
    # (useful for testing cross-user sync from two cmd windows).
    xml_path = None
    port_override = 0
    for a in sys.argv[1:]:
        if a.startswith('--port='):
            try: port_override = int(a.split('=', 1)[1])
            except: pass
            continue
        if a.startswith('-'): continue
        if xml_path is None:
            xml_path = a
    # Strip stray quotes and whitespace — Windows CMD sometimes embeds literal
    # quote characters in argv when the path contains spaces.
    if xml_path:
        xml_path = xml_path.strip()
        while len(xml_path) >= 2 and xml_path[0] == xml_path[-1] and xml_path[0] in ('"', "'"):
            xml_path = xml_path[1:-1].strip()

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
    global FILTER_MINE_FILE
    FILTER_MINE_FILE = data_dir / "filter_history_mine.json"
    TOOLBAR_PREFS_FILE = data_dir / "toolbar_prefs.json"
    LIVE_STATUS_FILE = data_dir / "live_status.json"
    XML_HISTORY_FILE = data_dir / "xml_history.json"
    TEMPLATES_FILE = data_dir / "templates.json"
    STALE_FILE = data_dir / "stale.json"
    ARCHIVE_XML = data_dir / "old_data.xml"
    SITE_CONFIG_FILE = data_dir / "site_config.json"
    global CURSOR_DIR
    CURSOR_DIR = data_dir / "cursors"
    SNAPSHOTS_DIR = data_dir / "layout_snapshots"
    try: SNAPSHOTS_DIR.mkdir(exist_ok=True)
    except Exception as e: print(f"[snapshots] could not create dir: {e}")
    print(f"📁  Data directory:  {data_dir}")
    print(f"   auth.json     -> {AUTH_FILE}")
    print(f"   layout.json   -> {LAYOUT_FILE}")
    print(f"   presence.json -> {PRESENCE_FILE}")
    print(f"   admin.json    -> {ADMIN_LOG_FILE} (encrypted)")
    print(f"   live_status.json -> {LIVE_STATUS_FILE}")
    print(f"   xml_history.json -> {XML_HISTORY_FILE}")

    # Start presence heartbeat (announces this user to others on the same share)
    heartbeat_tick()
    threading.Thread(target=heartbeat_loop, daemon=True).start()
    # Start layout snapshot scheduler (auto-snapshot at configured time)
    threading.Thread(target=_snapshot_scheduler_loop, daemon=True).start()
    import atexit
    atexit.register(remove_my_presence)

    # load previously known MACs first so merge can detect removals
    known_macs.update(load_known_macs())

    if xml_path:
        # If the XML doesn't exist yet (new plant, first launch), create a
        # minimal valid file so save_layout/scan/etc. have something to write to.
        # Users then populate it via the ➕ scan flow or manual add.
        xp = Path(xml_path)
        if not xp.exists():
            print(f"🆕  {xml_path} not found — creating empty inventory")
            try:
                xp.parent.mkdir(parents=True, exist_ok=True)
                xp.write_text(
                    '<?xml version="1.0" encoding="utf-8"?>\n<inventory>\n</inventory>\n',
                    encoding='utf-8')
            except Exception as e:
                print(f"[!] Could not create empty XML: {e}")
        print(f"📂  Loading {xml_path} …")
        new_devs = load_xml(xml_path)
        merge_devices(new_devs)
        snapshot_xml_if_changed(new_devs)
    else:
        # No XML at all — start with zero devices. The launcher normally prompts
        # for a path before we get here, so this branch only runs if someone
        # invokes server.py directly with no arguments.
        print("⚠️   No XML file — starting with an empty inventory")
        print("    Usage: python server.py devices.xml")

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

        def handle_error(self, request, client_address):
            """Silence noisy but harmless client-disconnect exceptions.
            Real errors (bugs, crashes) still print with their traceback."""
            import traceback, io
            exc_type, exc_val, _ = sys.exc_info()
            if exc_type is None: return
            name = exc_type.__name__
            msg = str(exc_val)
            # These all mean "browser hung up mid-response" — cosmetic noise.
            if name in ("BrokenPipeError", "ConnectionResetError",
                        "ConnectionAbortedError", "SSLEOFError"):
                return
            if "SSL" in name or "BAD_LENGTH" in msg or "EOF occurred" in msg:
                return
            # Real error — print it
            super().handle_error(request, client_address)

    # Apply per-plant runtime settings (VLAN pause, timeouts, caps, etc.)
    # so they take effect BEFORE any request is served.
    apply_runtime_config()

    # Port resolution priority:
    #   1. --port=NNNN from command line (highest — for multi-instance testing)
    #   2. netmap.port from site_config.json
    #   3. Default PORT constant
    if port_override > 0:
        PORT = port_override
        print(f"[cli] Using port {PORT} from --port flag")
    else:
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