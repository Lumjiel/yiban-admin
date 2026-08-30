#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
check_consistency.py — 签到用户数据一致性检查

触发：cron 6:32（主签到 6:31 之后 1 分钟，避开写盘竞态）

逻辑：
  1. 读 yiban-admin.db 的 users 表中 enable=1 的 phone 集合 → db_phones
  2. AST 解析 /opt/yiban/yiban/config/user_data.py 的 user_data 列表 → file_phones
  3. 对称差非空 → 不一致：
     - 写一条 sync_consistency_fail audit
     - 调 yiban_sync.sync_to_server() 自动修复
     - 发 ServerChan 告警
  4. 一致 → log 一行 OK 退出 0

为什么用 AST 而不是 import：
  user_data.py 是用户数据文件，git ignored，理论上不会含恶意代码，
  但 AST 解析不执行 import 副作用（万一以后有人手贱加 import），更稳。

调试：
  --dry-run  只检测 + 打印，不调 sync、不发 ServerChan、不写 audit
"""
import sys
import os
import ast
import sqlite3
import urllib.request
import urllib.parse
import argparse
from datetime import datetime, timedelta
from pathlib import Path

ADMIN_DIR = Path(__file__).parent
DB_PATH = ADMIN_DIR / "yiban-admin.db"
USER_DATA_PATH = Path("/opt/yiban/yiban/config/user_data.py")


def bj_now() -> datetime:
    return datetime.utcnow() + timedelta(hours=8)


def get_db_phones() -> set:
    """从 SQLite 读 enable=1 的 phone 集合"""
    con = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
    try:
        rows = con.execute("SELECT phone FROM users WHERE enable=1").fetchall()
        return {r[0] for r in rows}
    finally:
        con.close()


def get_file_phones() -> set:
    """AST 解析 user_data.py 取 Phone 集合（不执行代码）"""
    src = USER_DATA_PATH.read_text(encoding="utf-8")
    tree = ast.parse(src, filename=str(USER_DATA_PATH))

    user_data = None
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "user_data":
                    user_data = node.value

    if user_data is None or not isinstance(user_data, ast.List):
        raise ValueError("user_data.py 未找到 user_data = [...] 定义")

    phones = set()
    for item in user_data.elts:
        if isinstance(item, ast.Dict):
            for k, v in zip(item.keys, item.values):
                if (isinstance(k, ast.Constant) and k.value == "Phone"
                        and isinstance(v, ast.Constant)):
                    phones.add(str(v.value))
    return phones


def get_serverchan_key() -> str:
    """从 notify_config 读 serverchan_key"""
    con = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
    try:
        row = con.execute(
            "SELECT serverchan_key FROM notify_config WHERE id=1"
        ).fetchone()
        return row[0] if row and row[0] else ""
    finally:
        con.close()


def send_serverchan(key: str, title: str, msg: str) -> bool:
    if not key:
        return False
    try:
        data = urllib.parse.urlencode({"title": title, "desp": msg}).encode()
        req = urllib.request.Request(
            f"https://sctapi.ftqq.com/{key}.send", data=data
        )
        urllib.request.urlopen(req, timeout=10).read()
        return True
    except Exception as e:
        print(f"ServerChan 发送失败: {e}", flush=True)
        return False


def log_audit(detail: str) -> None:
    """写 audit_log，不依赖 flask（cron 跑没 flask 上下文）"""
    con = sqlite3.connect(str(DB_PATH))
    try:
        con.execute(
            "INSERT INTO audit_log (action, detail, ip) VALUES (?, ?, ?)",
            ("sync_consistency_fail", detail, "check_consistency"),
        )
        con.commit()
    finally:
        con.close()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true",
                        help="只检测，不调 sync、不发 ServerChan、不写 audit")
    args = parser.parse_args()

    stamp = bj_now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        db_phones = get_db_phones()
        file_phones = get_file_phones()
    except Exception as e:
        msg = f"[{stamp}] ⚠️ 一致性检查读取失败: {e}"
        print(msg, flush=True)
        send_serverchan(
            get_serverchan_key(),
            "⚠️ 易班签到一致性检查异常",
            f"**{stamp}** 读取用户数据时出错：\n\n```\n{e}\n```\n\n"
            "请登录 admin 后台点击「同步到服务器」按钮手动修复。",
        )
        return 1

    only_in_db = db_phones - file_phones
    only_in_file = file_phones - db_phones

    if not only_in_db and not only_in_file:
        print(f"[{stamp}] ✅ 一致: DB={len(db_phones)} 个, 文件={len(file_phones)} 个", flush=True)
        return 0

    # 不一致
    detail_lines = [
        f"[{stamp}] ❌ 一致性检查失败:",
        f"  DB 启用账号 ({len(db_phones)}): {sorted(db_phones)}",
        f"  文件账号 ({len(file_phones)}): {sorted(file_phones)}",
        f"  仅在 DB（应加入文件）: {sorted(only_in_db) or '无'}",
        f"  仅在文件（应从文件移除）: {sorted(only_in_file) or '无'}",
    ]
    detail_text = "\n".join(detail_lines)
    print(detail_text, flush=True)

    if args.dry_run:
        print("[dry-run] 不调 sync、不发 ServerChan、不写 audit", flush=True)
        return 2

    # 1. audit 留痕
    log_audit(
        f"DB={len(db_phones)} file={len(file_phones)} "
        f"only_db={sorted(only_in_db)} only_file={sorted(only_in_file)}"
    )

    # 2. 自动调 sync 修复
    try:
        sys.path.insert(0, str(ADMIN_DIR))
        import yiban_sync
        ok, msg = yiban_sync.sync_to_server()
        print(f"[auto-fix] sync_to_server: ok={ok} msg={msg}", flush=True)
        if not ok:
            log_audit(f"auto-fix sync 失败: {msg}")
    except Exception as e:
        log_audit(f"auto-fix 异常: {e}")
        print(f"[auto-fix] 异常: {e}", flush=True)

    # 3. ServerChan 告警
    serverchan_key = get_serverchan_key()
    title = "⚠️ 易班签到用户数据不一致"
    body = (
        f"**{stamp}** 检测到 users 表与 user_data.py 不一致：\n\n"
        f"- DB 启用账号: {sorted(db_phones)}\n"
        f"- 文件账号: {sorted(file_phones)}\n"
        f"- 仅在 DB: {sorted(only_in_db) or '无'}\n"
        f"- 仅在文件: {sorted(only_in_file) or '无'}\n\n"
        f"已尝试自动 sync 修复，详情见 admin 后台审计日志。"
    )
    sent = send_serverchan(serverchan_key, title, body)
    print(f"[notify] ServerChan 发送: {'成功' if sent else '失败（key 未配/网络问题）'}", flush=True)

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
