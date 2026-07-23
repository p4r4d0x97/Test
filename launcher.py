"""
NetMap launcher — the entry point PyInstaller wraps as NetMap.exe.

  1. Reads the XML path from argv[1] (or a saved default from netmap_last.txt).
  2. Starts the server thread (which serves HTTPS from netmap.crt).
  3. Waits for the port to be listening.
  4. Opens the default browser at https://localhost:PORT.

Nothing plant-specific lives here — plant config is in site_config.json
next to the XML, and is edited via NetMap's Settings UI.
"""

import sys, os, time, socket, threading, webbrowser
from pathlib import Path

# When bundled by PyInstaller, sys._MEIPASS is where our extra files land.
if getattr(sys, 'frozen', False):
    bundle_dir = Path(sys._MEIPASS)
    if str(bundle_dir) not in sys.path:
        sys.path.insert(0, str(bundle_dir))
else:
    bundle_dir = Path(__file__).parent


def resolve_xml_path() -> str:
    if len(sys.argv) > 1 and sys.argv[1].strip():
        p = Path(sys.argv[1]).expanduser().resolve()
        return str(p)
    memo = Path.cwd() / "netmap_last.txt"
    if memo.exists():
        p = Path(memo.read_text(encoding='utf-8').strip())
        if p.exists(): return str(p)
    print("No XML file specified.")
    entered = input("Path to inventory XML (leave blank to create new): ").strip()
    if not entered:
        entered = str(Path.cwd() / "inventory.xml")
        print(f"Will use: {entered}")
    return entered


def port_open(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.3)
        return s.connect_ex(('127.0.0.1', port)) == 0


def open_browser_when_ready(port: int):
    for _ in range(60):
        if port_open(port):
            webbrowser.open(f"https://localhost:{port}")
            return
        time.sleep(0.5)
    print(f"[!] Server not up on {port} within 30s. Open https://localhost:{port} manually.")


def main():
    xml_path = resolve_xml_path()
    try:
        Path.cwd().joinpath("netmap_last.txt").write_text(xml_path, encoding='utf-8')
    except Exception:
        pass

    sys.argv = [sys.argv[0], xml_path]

    import server
    port = getattr(server, 'PORT', 8000)

    threading.Thread(target=open_browser_when_ready, args=(port,), daemon=True).start()

    if hasattr(server, 'main'):
        server.main()


if __name__ == "__main__":
    main()
