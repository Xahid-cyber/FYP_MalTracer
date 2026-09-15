import os
import socket
import subprocess
import sys
import time
import webbrowser
from pathlib import Path

BACKEND_PORT = 5055
FRONTEND_PORT = 5173


def find_root() -> Path:
    candidates = []

    if getattr(sys, "frozen", False):
        exe_dir = Path(sys.executable).resolve().parent
        candidates.extend([exe_dir, exe_dir.parent, exe_dir.parent.parent])

    candidates.extend([
        Path.cwd().resolve(),
        Path.home() / "Desktop" / "MalTracer",
    ])

    for root in candidates:
        if (
            (root / "Malsecure.py").exists()
            and (root / "Malsec_venv" / "Scripts" / "python.exe").exists()
            and (root / "frontend-react" / "package.json").exists()
        ):
            return root.resolve()

    raise FileNotFoundError(
        "MalTracer project folder could not be found. "
        "Keep the project at Desktop\\MalTracer or place MalTracer.exe inside the project folder."
    )


def port_open(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.35)
        return s.connect_ex(("127.0.0.1", port)) == 0


def clean_old_maltracer_processes(root: Path) -> None:
    root_text = str(root).replace("'", "''")
    ps = rf"""
$root = '{root_text}'
foreach ($port in 5055,5173) {{
  $conns = Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue
  foreach ($c in $conns) {{
    $p = Get-CimInstance Win32_Process -Filter ('ProcessId=' + $c.OwningProcess) -ErrorAction SilentlyContinue
    if ($p -and $p.CommandLine -and $p.CommandLine -like ('*' + $root + '*')) {{
      Stop-Process -Id $c.OwningProcess -Force -ErrorAction SilentlyContinue
    }}
  }}
}}
"""
    subprocess.run(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        check=False,
    )


def launch_backend(python_exe: Path, backend: Path, cwd: Path) -> None:
    subprocess.Popen(
        [str(python_exe), str(backend), "--ui"],
        cwd=str(cwd),
        creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0),
    )


def launch_frontend(cwd: Path) -> None:
    subprocess.Popen(
        ["cmd.exe", "/k", "npm run dev -- --port 5173 --strictPort"],
        cwd=str(cwd),
        creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0),
    )


def main() -> None:
    try:
        root = find_root()
    except Exception as exc:
        subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command",
             f"Add-Type -AssemblyName PresentationFramework; "
             f"[System.Windows.MessageBox]::Show('{str(exc).replace(chr(39), chr(39)*2)}','MalTracer')"],
            check=False,
        )
        return

    python_exe = root / "Malsec_venv" / "Scripts" / "python.exe"
    backend = root / "Malsecure.py"
    frontend = root / "frontend-react"

    clean_old_maltracer_processes(root)
    time.sleep(1.5)

    launch_backend(python_exe, backend, root)
    time.sleep(1.5)
    launch_frontend(frontend)

    # Wait briefly for frontend, then open browser.
    deadline = time.time() + 20
    while time.time() < deadline:
        if port_open(FRONTEND_PORT):
            break
        time.sleep(0.5)

    webbrowser.open("http://localhost:5173")


if __name__ == "__main__":
    main()
