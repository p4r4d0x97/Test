"""
NetMap XML inventory builder — refactored to:
  • Use Python stdlib xml.etree.ElementTree (no lxml dependency; bundles cleanly)
  • Read all plant-specific configuration from site_config.json (no hardcoded values)
  • Skip optional collectors whose config is empty (printer, WinRM, rack mapping, ...)
  • Be importable as a module from NetMap's ➕ button (no more subprocess dance)
  • Never persist credentials anywhere

Callable entry points:
  • run_full_scan(cfg, username, password, port=22, mode='full', known_macs=None,
                  progress_cb=None)                     — full network scan
  • firewall_warmup(cfg, username, password, port=22)   — quick firewall ARP dump only
  • manual_add_device(cfg, mac, ip, name, vlan, ...)    — add one device by hand

For legacy standalone use, `python inventory.py` still works — it prompts for
credentials and reads config from site_config.json in the current directory
(or accepts a --config path).
"""

from __future__ import annotations
import getpass, re, time, socket, os, uuid, subprocess, argparse, json, sys
from dataclasses import dataclass, field
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from enum import Enum

# Optional deps — imported lazily so the module loads even without them.
# The scanner needs them; manual_add and config loading don't.
try:
    import paramiko
except ImportError:
    paramiko = None
try:
    import requests, urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    requests = None

import xml.etree.ElementTree as ET


# ─── Defaults ───────────────────────────────────────────────────────────
# These reproduce the original hardcoded values so a plant that hasn't
# customized anything still gets a working scan.
DEFAULT_CONFIG = {
    "firewall": {
        "host": "",
        "arp_command_sequence": [
            "config vdom",
            "edit 1_internal",
            "get sys arp",
        ],
        # Regex with three groups: ip, mac, vlan
        "arp_regex": (
            r"(192\.168\.[0-9]{1,3}\.[0-9]{1,3})"
            r"\s+[0-9]{1,8}"
            r"\s+([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}"
            r":[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})"
            r"\s+vl([0-9]{4})"
        ),
    },
    "switches": {
        "ips": [],
        "command_sequence": [
            "",
            "config terminal",
            "terminal more disable",
            "show i-sid mac-address-entry | exclude Port",
            "terminal more enable",
        ],
        # Regex with two groups: mac, port
        "mac_port_regex": r"[0-9]{8}\s+learned\s+([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}\s+).{1,5}:(1\/\/\b\d{1,2}\b)",
    },
    "rack_mapping": {},        # {"192.168.8.10": "Rack02"}
    "vlan_type_map": {},        # {"pc":["22","23"], "switch":["8","9"], ...}
    "vlan_icon_map": {},        # {"22":"💻","28":"🖨️"} — overrides default icon per VLAN
    "location_tag_map": {},     # {"C:\\Temp\\Production": "production_line"}
    "printer": {
        "vlan_whitelist": [],   # ["28","151"] — empty = collector disabled
        "model_map": {},        # {"HP": "hp", ...}
    },
    "winrm": {
        # If empty, the whole WinRM serial/second-NIC/designation collector is skipped
        "vlan_whitelist": [],   # ["21","22","23","24"]
        "name_prefixes":  [],   # ["C0","W"]
        # Editable PowerShell script — LOCATION_TAG_MAP placeholders get injected
        "ps_script": (
            "$serial = (Get-WmiObject Win32_BIOS).SerialNumber.Trim(); "
            "$ips = (Get-NetIPAddress -AddressFamily IPv4 "
            "        | Where-Object { $_.IPAddress -notlike '127.*' -and "
            "                         $_.IPAddress -notlike '169.*' } "
            "        | Select-Object -ExpandProperty IPAddress) -join ','; "
            "$designations = @(); "
            # {{FOLDER_CHECKS}} placeholder — replaced with per-plant folder checks
            "{{FOLDER_CHECKS}}"
            "Write-Output ('SERIAL:' + $serial); "
            "Write-Output ('IPS:' + $ips); "
            "Write-Output ('DESIGNATION:' + ($designations -join ','))"
        ),
    },
    "wifi_vlans": [],           # VLAN IDs skipped in port-uniqueness check
    "workers": {
        "general": 8,
        "switch":  30,
    },
    "timeouts": {
        # All in seconds
        "ping":         1,       # per-device ping timeout during scan
        "winrm":        30,      # WinRM Invoke-Command timeout per device
        "ssh_connect":  10,      # SSH handshake to firewall/switches
    },
    "output": {
        "xml_file": "inventory.xml",
    },
    "netmap": {
        # NetMap's own runtime settings that vary per plant
        "dhcp_vlans": [],       # ["1010","1088","1048"] — for ping mode selection
        # ── Runtime tuning (all in seconds unless noted) ──
        "port":                    8000,     # HTTPS listen port
        "vlan_pause":              15,       # ping pause between VLAN groups
        "presence_ttl":            60,       # user considered offline after N sec no heartbeat
        "status_freshness_max":  900,        # live-status entry stale after N sec (15 min default)
        "xml_history_max":        30,        # how many XML snapshots to retain
        "photo_max_mb":            5,        # per-photo upload cap in MB
        "photos_folder_gb":       10,        # total photos folder cap in GB
        "audit_log_max":       10000,        # audit log entry cap
        "layout_max_mb":          50,        # layout.json size cap in MB
    },
}


def load_config(path: str | Path | None = None) -> dict:
    """Load site_config.json, falling back to DEFAULT_CONFIG for missing keys.
    Never fails — returns defaults if the file is missing/corrupt."""
    if path is None:
        path = Path.cwd() / "site_config.json"
    else:
        path = Path(path)
    if not path.exists():
        return _deep_merge(DEFAULT_CONFIG, {})
    try:
        user = json.loads(path.read_text(encoding='utf-8'))
        return _deep_merge(DEFAULT_CONFIG, user)
    except Exception as e:
        print(f"[!] Could not parse {path}: {e} — using defaults")
        return _deep_merge(DEFAULT_CONFIG, {})


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge override into base without mutating either."""
    out = {}
    for k, v in base.items():
        if isinstance(v, dict) and isinstance(override.get(k), dict):
            out[k] = _deep_merge(v, override[k])
        elif k in override:
            out[k] = override[k]
        else:
            out[k] = v
    for k, v in override.items():
        if k not in out:
            out[k] = v
    return out


# ─── Helpers ────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.utcnow().isoformat() + "Z"

def _sub(parent: ET.Element, tag: str, text: str) -> ET.Element:
    el = ET.SubElement(parent, tag)
    el.text = text or ""
    return el

def _set_or_create(parent: ET.Element, tag: str, value: str):
    el = parent.find(tag)
    if el is None:
        el = ET.SubElement(parent, tag)
    el.text = value

def _update_field(el: ET.Element, tag: str, new_val: str) -> bool:
    if not new_val or new_val.strip() in ("", "unknown", "0", "None"):
        return False
    child = el.find(tag)
    if child is None:
        ET.SubElement(el, tag).text = new_val
        return True
    if child.text != new_val:
        child.text = new_val
        return True
    return False

def resolve_type(vlan: str, vlan_type_map: dict) -> str:
    lookup = {vid: dtype for dtype, vlans in vlan_type_map.items() for vid in vlans}
    return lookup.get(vlan.strip(), "")

def ping(ip: str, timeout: int = 1) -> bool:
    flag = "-n" if os.name == "nt" else "-c"
    wait = "-w" if os.name == "nt" else "-W"
    try:
        r = subprocess.run(["ping", flag, "1", wait, str(timeout), ip],
                           capture_output=True, timeout=timeout + 1)
        return r.returncode == 0
    except Exception:
        return False


# ─── Scan mode ──────────────────────────────────────────────────────────

class ScanMode(Enum):
    FULL   = "full"
    NEW    = "new"
    FIELDS = "fields"


# ─── Data model ─────────────────────────────────────────────────────────

@dataclass
class RawDevice:
    ip:          str
    mac:         str
    vlan:        str
    switch:      str  = ""
    port:        str  = ""
    name:        str  = ""
    rack:        str  = ""
    online:      bool = True
    serial:      str  = ""
    second_ip:   str  = ""
    designation: str  = ""
    model:       str  = ""
    type:        str  = field(default="", init=False)

    def resolve_type_from_cfg(self, cfg: dict):
        self.type = resolve_type(self.vlan, cfg.get("vlan_type_map", {}))


# ─── SSH collection ─────────────────────────────────────────────────────

def _ssh_shell(host: str, username: str, password: str, port: int):
    if paramiko is None:
        raise RuntimeError("paramiko not installed — install with: pip install paramiko")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(host, port, username, password)
    shell = client.invoke_shell()
    time.sleep(2)
    shell.recv(100_000)
    return shell, client


def collect_firewall(cfg: dict, username: str, password: str, port: int) -> list[RawDevice]:
    """SSH into firewall, run configured command sequence, extract with configured regex."""
    devices: list[RawDevice] = []
    host = cfg["firewall"]["host"]
    if not host:
        print("[!] No firewall host configured — skipping firewall collection")
        return devices
    client = None
    try:
        shell, client = _ssh_shell(host, username, password, port)
        for cmd in cfg["firewall"]["arp_command_sequence"]:
            shell.send(cmd + "\n")
            time.sleep(2)
        time.sleep(2.5)
        output = shell.recv(100_000).decode(errors='replace')
        pattern = cfg["firewall"]["arp_regex"]
        for ip, mac, vlan in re.findall(pattern, output):
            devices.append(RawDevice(ip=ip, mac=mac.upper(), vlan=vlan))
    except Exception as e:
        print(f"[!] Firewall error ({host}): {e}")
    finally:
        if client:
            client.close()
    return devices


def collect_switch(cfg: dict, host: str, devices: list[RawDevice],
                   username: str, password: str, port: int) -> None:
    """SSH into switch, cross-reference MACs, fill switch + port + rack."""
    client = None
    try:
        shell, client = _ssh_shell(host, username, password, port)
        for cmd in cfg["switches"]["command_sequence"]:
            shell.send((cmd or "") + "\n")
            time.sleep(1)
        time.sleep(1.5)
        output = shell.recv(10_000).decode(errors='replace')
        pattern = cfg["switches"]["mac_port_regex"]

        seen: set[str] = set()
        mac_port: list[tuple[str, str]] = []
        for m in re.findall(pattern, output):
            if not isinstance(m, tuple) or len(m) < 2: continue
            mac_u = m[0].upper().strip()
            port_str = m[1]
            if mac_u not in seen:
                mac_port.append((mac_u, port_str))
                seen.add(mac_u)

        rack = cfg.get("rack_mapping", {}).get(host, "")
        for device in devices:
            for mac, port_str in mac_port:
                if device.mac == mac:
                    device.switch = host
                    device.port   = port_str
                    if rack:
                        device.rack = rack
                    break
    except Exception as e:
        print(f"[!] Switch error ({host}): {e}")
    finally:
        if client:
            client.close()


def resolve_name(device: RawDevice, timeout: int = 1) -> None:
    if not ping(device.ip, timeout=timeout):
        device.online = False
        device.name = device.ip
        return
    try:
        device.name = socket.gethostbyaddr(device.ip.strip())[0]
    except Exception:
        device.name = device.ip


def collect_serial_and_second_nic(cfg: dict, device: RawDevice) -> None:
    """Optional WinRM collector. Skipped entirely if config is empty."""
    winrm = cfg.get("winrm", {})
    vlan_wl = set(str(v) for v in winrm.get("vlan_whitelist", []))
    prefixes = tuple(winrm.get("name_prefixes", []))
    location_map = cfg.get("location_tag_map", {})
    ping_timeout = int(cfg.get("timeouts", {}).get("ping", 1))
    winrm_timeout = int(cfg.get("timeouts", {}).get("winrm", 30))

    # Skip if collector disabled
    if not vlan_wl or not prefixes:
        return
    if device.vlan not in vlan_wl:
        return
    if not device.name or device.name == device.ip:
        return
    if not any(device.name.upper().startswith(p.upper()) for p in prefixes):
        return
    if not ping(device.ip, timeout=ping_timeout):
        device.online = False
        return

    # Build folder checks from LOCATION_TAG_MAP
    folder_checks = "".join([
        f"if (Test-Path '{path}') {{ $designations += '{val}' }}; "
        for path, val in location_map.items()
    ])
    ps_script = winrm.get("ps_script", DEFAULT_CONFIG["winrm"]["ps_script"])
    ps_script = ps_script.replace("{{FOLDER_CHECKS}}", folder_checks)

    try:
        result = subprocess.run(
            ["powershell", "-Command",
             f"Invoke-Command -ComputerName {device.name} "
             f"-ScriptBlock {{ {ps_script} }}"],
            capture_output=True, timeout=winrm_timeout
        )
        output = result.stdout.decode(errors='replace')
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("SERIAL:"):
                v = line[7:].strip()
                if v: device.serial = v
            elif line.startswith("IPS:"):
                ips = [i.strip() for i in line[4:].split(",") if i.strip()]
                other = [i for i in ips if i != device.ip]
                if other: device.second_ip = other[0]
            elif line.startswith("DESIGNATION:"):
                v = line[12:].strip()
                if v: device.designation = v
    except subprocess.TimeoutExpired:
        device.online = False
    except Exception as e:
        print(f"[!] WinRM failed for {device.ip}: {e}")
        device.online = False


# ─── Field collector (printer model, extensible) ────────────────────────

class TagCollector:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        # Build the list of collectors to run based on config
        self.enabled = []
        if cfg.get("printer", {}).get("vlan_whitelist") and \
           cfg.get("printer", {}).get("model_map"):
            self.enabled.append(self.collect_printer_model)

    def collect_all(self, dev: RawDevice) -> None:
        for collector in self.enabled:
            try: collector(dev)
            except Exception as e:
                print(f"[!] {collector.__name__} failed for {dev.ip}: {e}")

    def collect_printer_model(self, dev: RawDevice) -> None:
        if requests is None:
            return
        printer = self.cfg["printer"]
        vlan_wl = set(str(v) for v in printer.get("vlan_whitelist", []))
        model_map = printer.get("model_map", {})
        if dev.vlan not in vlan_wl:
            return
        try:
            response = requests.get(f"http://{dev.ip}", verify=False, timeout=5)
            content = response.text
            matched = [val for pat, val in model_map.items()
                       if pat.lower() in content.lower()]
            if matched:
                dev.model = ",".join(matched)
        except Exception as e:
            print(f"[!] Printer check failed for {dev.ip}: {e}")
            dev.online = False


# ─── Collection pipeline ────────────────────────────────────────────────

def run_collection(cfg: dict, username: str, password: str, port: int,
                   known_macs: set[str] | None = None,
                   progress_cb=None) -> list[RawDevice]:
    def _p(msg):
        print(msg)
        if progress_cb:
            try: progress_cb(msg)
            except: pass

    _p("[→] Firewall ARP dump...")
    devices = collect_firewall(cfg, username, password, port)
    _p(f"    {len(devices)} devices found")

    if not devices:
        _p("[!] No devices from firewall — check firewall config")
        return []

    # Resolve type for each device now that we have vlan
    for d in devices:
        d.resolve_type_from_cfg(cfg)

    _p("[→] Switch port cross-reference...")
    switch_ips = cfg.get("switches", {}).get("ips", [])
    if switch_ips:
        args_list = [(cfg, h, devices, username, password, port) for h in switch_ips]
        with ThreadPoolExecutor(max_workers=cfg["workers"]["switch"]) as pool:
            pool.map(lambda a: collect_switch(*a), args_list)
    else:
        _p("    (no switches configured — skipping)")

    for d in devices:
        if not d.switch:
            d.switch = "unknown"
            d.port   = "unknown"

    if known_macs:
        new_devices = [d for d in devices if d.mac.upper() not in known_macs]
        _p(f"    {len(devices)-len(new_devices)} known skipped, {len(new_devices)} new")
    else:
        new_devices = devices

    _p("[→] Name resolution...")
    ping_to = int(cfg.get("timeouts", {}).get("ping", 1))
    with ThreadPoolExecutor(max_workers=cfg["workers"]["general"]) as pool:
        pool.map(lambda d: resolve_name(d, timeout=ping_to), new_devices)

    winrm_cfg = cfg.get("winrm", {})
    if winrm_cfg.get("vlan_whitelist") and winrm_cfg.get("name_prefixes"):
        _p("[→] WinRM serial/second-NIC/designation...")
        with ThreadPoolExecutor(max_workers=cfg["workers"]["general"]) as pool:
            pool.map(lambda d: collect_serial_and_second_nic(cfg, d), new_devices)
    else:
        _p("    (WinRM collector disabled)")

    _p(f"[✓] Collection complete — {len(devices)} total, {len(new_devices)} processed")
    return devices


# ─── XML Inventory Manager ──────────────────────────────────────────────

class XMLInventoryManager:
    """Stdlib-only version of the XML merger."""
    def __init__(self, path: str, collector: TagCollector, cfg: dict):
        self.path = Path(path)
        self.collector = collector
        self.cfg = cfg
        self._load_or_create()

    def _load_or_create(self):
        if self.path.exists():
            self.tree = ET.parse(str(self.path))
            self.root = self.tree.getroot()
        else:
            self.root = ET.Element("network")
            self.root.set("schema-version", "1.0")
            self.root.set("generated", _now())
            ET.SubElement(self.root, "meta")
            self.tree = ET.ElementTree(self.root)

    def merge(self, devices: list[RawDevice], mode: ScanMode = ScanMode.FULL) -> dict:
        wifi_vlans = set(str(v) for v in self.cfg.get("wifi_vlans", []))

        mac_index = {el.findtext("mac", "").upper(): el
                     for el in self.root.findall("device")}
        port_index = {}
        for el in self.root.findall("device"):
            sw = el.findtext("switch", "")
            pt = el.findtext("port", "")
            if sw not in ("", "unknown") and pt not in ("", "unknown"):
                port_index[f"{sw}:{pt}"] = el

        stats = {"added": 0, "updated": 0, "unchanged": 0, "skipped": 0}
        for dev in devices:
            mac = dev.mac.upper()
            port_key = f"{dev.switch}:{dev.port}"

            if mac in mac_index:
                if mode == ScanMode.NEW:
                    stats["skipped"] += 1; continue
                self.collector.collect_all(dev)
                changed = self._update(mac_index[mac], dev)
                stats["updated" if changed else "unchanged"] += 1
            elif (port_key in port_index
                  and dev.switch not in ("", "unknown")
                  and dev.port not in ("", "unknown")
                  and dev.vlan not in wifi_vlans):
                # Device replaced on same port
                old_el = port_index[port_key]
                old_mac = old_el.findtext("mac", "")
                print(f"[!] Replaced on {dev.switch} port {dev.port}: {old_mac} → {dev.mac}")
                self.collector.collect_all(dev)
                new_el = self._build(dev)
                self._record_replaced_mac(new_el, old_mac, old_el)
                self.root.remove(old_el)
                self.root.append(new_el)
                mac_index[mac] = new_el
                port_index[port_key] = new_el
                stats["added"] += 1
            else:
                self.collector.collect_all(dev)
                new_el = self._build(dev)
                self.root.append(new_el)
                mac_index[mac] = new_el
                if dev.switch not in ("", "unknown") and dev.port not in ("", "unknown"):
                    port_index[port_key] = new_el
                stats["added"] += 1

        self._update_meta(stats, len(self.root.findall("device")))
        self._save()
        return stats

    def _build(self, dev: RawDevice) -> ET.Element:
        el = ET.Element("device")
        el.set("id", str(uuid.uuid4())[:8])
        for tag, val in [
            ("ip", dev.ip), ("mac", dev.mac), ("vlan", dev.vlan),
            ("last-vlan", ""), ("switch", dev.switch), ("port", dev.port),
            ("name", dev.name), ("rack", dev.rack), ("type", dev.type),
            ("serial", dev.serial), ("second-ip", dev.second_ip),
            ("last-ip", ""), ("designation", dev.designation),
            ("model", dev.model), ("previous-mac", ""),
            ("first-seen", _now()), ("history", ""),
            ("xml_change_status", f"added:{_now()}"),
        ]:
            _sub(el, tag, val)
        return el

    def _update(self, el: ET.Element, dev: RawDevice) -> bool:
        if not dev.online:
            return False
        changed = False
        current_ip = el.findtext("ip", "").strip()
        if current_ip and current_ip != dev.ip.strip():
            last_ip_el = el.find("last-ip") or ET.SubElement(el, "last-ip")
            existing = [v.strip() for v in (last_ip_el.text or "").split(",") if v.strip()]
            if current_ip not in existing:
                existing.insert(0, current_ip)
            last_ip_el.text = ",".join(existing)
            changed = True
        current_vlan = el.findtext("vlan", "").strip()
        if current_vlan and current_vlan != dev.vlan.strip():
            last_vlan_el = el.find("last-vlan") or ET.SubElement(el, "last-vlan")
            existing = [v.strip() for v in (last_vlan_el.text or "").split(",") if v.strip()]
            if current_vlan not in existing:
                existing.insert(0, current_vlan)
            last_vlan_el.text = ",".join(existing)
            changed = True

        fields = {
            "ip": dev.ip, "mac": dev.mac, "vlan": dev.vlan,
            "switch": dev.switch, "port": dev.port, "name": dev.name,
            "rack": dev.rack, "type": dev.type, "serial": dev.serial,
            "second-ip": dev.second_ip, "designation": dev.designation,
            "model": dev.model,
        }
        history_fields = {"designation", "model", "type", "rack"}
        history_el = el.find("history") or ET.SubElement(el, "history")
        for tag, new_val in fields.items():
            if not new_val or new_val.strip() in ("", "unknown", "0", "None"):
                continue
            child = el.find(tag)
            if child is not None and child.text and child.text.strip() != new_val.strip():
                if tag in history_fields:
                    entry = f"{tag}:{child.text}"
                    existing = [h.strip() for h in (history_el.text or "").split(",") if h.strip()]
                    if entry not in existing:
                        existing.insert(0, entry)
                        history_el.text = ",".join(existing)
            changed |= _update_field(el, tag, new_val)

        if changed:
            status = el.find("xml_change_status") or ET.SubElement(el, "xml_change_status")
            status.text = f"modified:{_now()}"
        return changed

    def _record_replaced_mac(self, new_el, old_mac, old_el):
        prev = new_el.find("previous-mac") or ET.SubElement(new_el, "previous-mac")
        prev.text = old_mac
        history = new_el.find("history") or ET.SubElement(new_el, "history")
        old_name = old_el.findtext("name", "")
        old_type = old_el.findtext("type", "")
        entry = f"replaced:{old_mac}:{old_name}:{old_type}:{_now()}"
        existing = [h.strip() for h in (history.text or "").split(",") if h.strip()]
        if entry not in existing:
            existing.insert(0, entry)
        history.text = ",".join(existing)

    def _update_meta(self, stats, total):
        meta = self.root.find("meta")
        _set_or_create(meta, "total-devices", str(total))
        _set_or_create(meta, "last-scan", _now())
        _set_or_create(meta, "last-scan-added", str(stats["added"]))
        _set_or_create(meta, "last-scan-updated", str(stats["updated"]))

    def devices_from_xml(self) -> list[RawDevice]:
        devices = []
        for el in self.root.findall("device"):
            devices.append(RawDevice(
                ip=el.findtext("ip", ""), mac=el.findtext("mac", ""),
                vlan=el.findtext("vlan", ""), switch=el.findtext("switch", ""),
                port=el.findtext("port", ""), name=el.findtext("name", ""),
                rack=el.findtext("rack", ""), serial=el.findtext("serial", ""),
                second_ip=el.findtext("second-ip", ""),
                designation=el.findtext("designation", ""),
                model=el.findtext("model", ""),
            ))
        return devices

    def _save(self):
        # Pretty-print with stdlib (Python 3.9+ has ET.indent)
        try: ET.indent(self.tree, space="  ")
        except AttributeError: pass
        self.tree.write(str(self.path), xml_declaration=True, encoding="UTF-8")


# ─── High-level entry points (called from NetMap) ───────────────────────

def run_full_scan(cfg: dict, username: str, password: str, port: int = 22,
                  mode: str = "full", known_macs: set[str] | None = None,
                  xml_path: str | None = None, progress_cb=None) -> dict:
    """Full scan pipeline. Called from NetMap's ➕ button.
    Returns dict {added, updated, unchanged, skipped, total}."""
    scan_mode = {"full": ScanMode.FULL, "new": ScanMode.NEW,
                 "fields": ScanMode.FIELDS}.get(mode, ScanMode.FULL)

    if xml_path is None:
        xml_path = cfg["output"]["xml_file"]

    collector = TagCollector(cfg)
    manager = XMLInventoryManager(xml_path, collector, cfg)

    if scan_mode == ScanMode.FIELDS:
        devices = manager.devices_from_xml()
    elif scan_mode == ScanMode.NEW:
        known = {el.findtext("mac", "").upper() for el in manager.root.findall("device")}
        devices = run_collection(cfg, username, password, port, known, progress_cb)
    else:
        devices = run_collection(cfg, username, password, port, None, progress_cb)

    stats = manager.merge(devices, mode=scan_mode)
    stats["total"] = len(manager.root.findall("device"))
    return stats


def firewall_warmup(cfg: dict, username: str, password: str, port: int = 22) -> dict:
    """Quick firewall-only dump — pulls current ARP table without full scan.
    Used by NetMap's ➕ button to refresh device list quickly."""
    devices = collect_firewall(cfg, username, password, port)
    for d in devices:
        d.resolve_type_from_cfg(cfg)
    return {
        "count": len(devices),
        "devices": [{
            "ip": d.ip, "mac": d.mac, "vlan": d.vlan, "type": d.type
        } for d in devices],
    }


def manual_add_device(cfg: dict, xml_path: str, mac: str, ip: str = "",
                      name: str = "", vlan: str = "", switch: str = "",
                      port: str = "", **extras) -> dict:
    """Add a single device to the XML. All fields optional except MAC."""
    mac = (mac or "").upper().strip()
    if not mac:
        return {"ok": False, "error": "MAC required"}
    collector = TagCollector(cfg)
    manager = XMLInventoryManager(xml_path, collector, cfg)
    dev = RawDevice(ip=ip, mac=mac, vlan=vlan, switch=switch, port=port, name=name)
    dev.resolve_type_from_cfg(cfg)
    for k, v in extras.items():
        if hasattr(dev, k) and v:
            setattr(dev, k, v)
    stats = manager.merge([dev], mode=ScanMode.FULL)
    return {"ok": True, "stats": stats, "mac": mac}


# ─── Legacy CLI entry point ─────────────────────────────────────────────

def _cli_prompt_mode() -> ScanMode:
    print("\nScan mode:")
    print("  [1] Full — update all devices + fields")
    print("  [2] New only — process only new MACs")
    print("  [3] Fields only — refresh fields on existing")
    return {"1": ScanMode.FULL, "2": ScanMode.NEW,
            "3": ScanMode.FIELDS}.get(input("Select [1/2/3]: ").strip(), ScanMode.FULL)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="site_config.json")
    ap.add_argument("--xml", default=None)
    ap.add_argument("--mode", default=None, choices=["full", "new", "fields"])
    args = ap.parse_args()

    cfg = load_config(args.config)
    if not cfg["firewall"]["host"]:
        print("[!] No firewall configured in", args.config)
        sys.exit(1)

    username = input("Username: ")
    password = getpass.getpass("Password: ")
    mode = args.mode or _cli_prompt_mode().value
    xml_path = args.xml or cfg["output"]["xml_file"]

    stats = run_full_scan(cfg, username, password, mode=mode, xml_path=xml_path)
    print(f"\n[✓] Done — {stats}")
