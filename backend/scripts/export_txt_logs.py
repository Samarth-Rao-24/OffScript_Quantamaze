"""Write the Notepad-friendly logs from the evidence folder.

    python scripts/export_txt_logs.py                 # uses <project>/evidence
    python scripts/export_txt_logs.py path/to/evidence

Creates (or refreshes):
    evidence/txt/qpiai_usage_log.txt   every QpiAI Opt / QRNG / QAOA call and nonce derivation
    evidence/txt/test_data_log.txt     every Attack lab and Judge console test, pytest and final run

The running app refreshes both files automatically after each QpiAI call and each website
test; this script is for existing evidence or a manual refresh. Standard library only.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("txtlog", ROOT / "backend" / "satauth" / "common" / "txtlog.py")
txtlog = importlib.util.module_from_spec(spec)
spec.loader.exec_module(txtlog)

if __name__ == "__main__":
    ev = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "evidence"
    if not ev.is_dir():
        sys.exit(f"evidence folder not found: {ev}")
    res = txtlog.refresh(ev)
    if "error" in res:
        sys.exit(f"failed: {res['error']}")
    print(f"QpiAI entries: {res['qpiai_entries']}, test entries: {res['test_entries']}")
    for f in res["files"]:
        print(f"  wrote {ev / f}")
