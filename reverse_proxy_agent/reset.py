#!/usr/bin/env python3
"""
reset.py ─ 刪除 reverse_proxy.db（若存在）
"""
from reverse_proxy_agent.config import settings

def main() -> None:
    db_path = settings.DB_PATH
    if db_path.exists():
        db_path.unlink()
        print(f"✅ 已刪除 {db_path}")
    else:
        print(f"ℹ️ {db_path} 不存在，無需重置")

if __name__ == "__main__":
    main()
