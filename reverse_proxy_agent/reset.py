#!/usr/bin/env python3
"""
reset.py ─ 刪除 reverse_proxy.db（若存在）
"""
from pathlib import Path

DB_FILE = "reverse_proxy.db"

def main() -> None:
    db_path = Path(__file__).resolve().parent / DB_FILE
    if db_path.exists():
        db_path.unlink()
        print(f"✅ 已刪除 {db_path}")
    else:
        print(f"ℹ️ {db_path} 不存在，無需重置")

if __name__ == "__main__":
    main()
