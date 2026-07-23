"""
Build helper for NetMap.exe.

Run:      python build_launcher.py

  1. Checks that required Python packages are installed.
  2. Runs PyInstaller with netmap.spec.
  3. Copies netmap.spec output into a ready-to-ship folder.
  4. Prints instructions for first launch.
"""
import subprocess, sys, shutil, os
from pathlib import Path

REQUIRED = ["paramiko", "cryptography", "requests", "urllib3"]

def check_deps():
    missing = []
    for pkg in REQUIRED:
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)
    if missing:
        print(f"[!] Missing packages: {missing}")
        print(f"    Install with: pip install {' '.join(missing)}")
        sys.exit(1)
    # PyInstaller itself
    try:
        import PyInstaller
    except ImportError:
        print("[!] PyInstaller missing. Install with: pip install pyinstaller")
        sys.exit(1)

def check_files():
    required_files = ['launcher.py', 'server.py', 'inventory.py', 'netmap.spec',
                      'www/index.html']
    missing = [f for f in required_files if not Path(f).exists()]
    if missing:
        print(f"[!] Missing required files: {missing}")
        print(f"    Run this from the project root directory.")
        sys.exit(1)

def clean():
    for d in ['build', 'dist', '__pycache__']:
        if Path(d).exists():
            shutil.rmtree(d)
            print(f"[·] Cleaned {d}/")

def build():
    print("[→] Running PyInstaller...")
    result = subprocess.run(
        [sys.executable, "-m", "PyInstaller", "netmap.spec", "--clean"],
        capture_output=False
    )
    if result.returncode != 0:
        print("[!] PyInstaller failed.")
        sys.exit(1)

def show_result():
    exe = Path("dist/NetMap.exe")
    if exe.exists():
        size_mb = exe.stat().st_size / (1024*1024)
        print()
        print(f"[✓] Built: {exe.resolve()} ({size_mb:.1f} MB)")
        print()
        print("First launch:")
        print("  1. Copy NetMap.exe to the target machine (or shared drive)")
        print("  2. Run:  NetMap.exe path\\to\\devices.xml")
        print("     (or double-click and paste the path when prompted)")
        print("  3. On first run: netmap.crt + netmap.key auto-generate")
        print("  4. Browser opens at https://localhost:8000")
        print("     — click 'Advanced -> Proceed' on the security warning")
        print("  5. Click the settings icon (bottom-left) to configure firewall + switches")
        print()
    else:
        print("[!] Build produced no NetMap.exe — check errors above.")

if __name__ == "__main__":
    print("=== NetMap build ===")
    check_deps()
    check_files()
    clean()
    build()
    show_result()
