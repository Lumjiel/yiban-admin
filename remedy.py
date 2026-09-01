#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
易班 7:30 窗口内兜底补签

逻辑：
  1. 查本地 sign_logs：今天(北京时间)已成功签到的账号集合 done
  2. 查 users 表：启用账号集合 enabled
  3. pending = enabled - done  →  只对本地显示未签的账号精准补签
  4. 对每个 pending 调 trigger_sign_stream(phone) 一次（底层 start.py + ONLY_USER，
     由 start.py 内部写日志库；判定以 SSE 终态结果为准）。不做外层重试/退避——一次行就行，不行拉倒。
  5. 补完再查 sign_logs，发 QQ 邮件汇总（已补救 / 仍失败）
  6. 顺带清理 90 天前过期日志

cron：30 7 * * * cd /opt/yiban-admin && /usr/bin/python3 remedy.py >> /var/log/yiban-remedy.log 2>&1

调试开关：
  --dry-run     只检测并打印 pending，不实际补签、不发邮件
  --no-notify   实际补签但跳过邮件通知（用于验证补签链路不打扰）
"""
import sys
import os
import sqlite3
import subprocess
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from db import get_all_users, get_notify_config
import yiban_sync

DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "yiban-admin.db")
YIBAN_PY = "/opt/yiban/.venv/bin/python"


def bj_now():
    return datetime.utcnow() + timedelta(hours=8)


def today_cutoff():
    bj = bj_now()
    bj_mid = datetime(bj.year, bj.month, bj.day)
    return (bj_mid - timedelta(hours=8)).strftime("%Y-%m-%d %H:%M:%S")


def ro():
    return sqlite3.connect(f"file:{DB}?mode=ro", uri=True)


def main():
    dry = "--dry-run" in sys.argv
    no_notify = "--no-notify" in sys.argv
    cutoff = today_cutoff()
    stamp = bj_now().strftime("%Y-%m-%d %H:%M")

    con = ro()
    con.row_factory = sqlite3.Row
    done = {r["phone"] for r in con.execute(
        "SELECT DISTINCT phone FROM sign_logs WHERE created_at>=? AND status='success'", (cutoff,))}
    con.close()

    enabled = [u["phone"] for u in get_all_users() if u["enable"]]
    pending = [p for p in enabled if p not in done]

    if not pending:
        print(f"[{stamp}] 全部账号今日已签到，无需补签")
        cleanup_logs()
        return 0

    print(f"[{stamp}] 待补签账号({len(pending)}): {pending}")
    if dry:
        print(f"[{stamp}] [dry-run] 跳过实际补签与通知")
        cleanup_logs()
        return 0

    remedied, failed = [], []
    for phone in pending:
        # 精准补签一次：trigger_sign_stream 调 start.py(ONLY_USER)，不做外层重试
        result_status = None
        for ev in yiban_sync.trigger_sign_stream(phone):
            if ev.get("type") == "done":
                for r in ev.get("results", []):
                    if r.get("phone") == phone:
                        result_status = r.get("status")
        # 弱兜底：日志库最新一条（start.py 内部 _write_logs_to_db 写入；
        # 若 cron 未配置 YIBAN_API_KEY 则 401 无记录，以 result_status 为准）
        c2 = ro()
        c2.row_factory = sqlite3.Row
        row = c2.execute(
            "SELECT status FROM sign_logs WHERE phone=? AND created_at>=? ORDER BY id DESC LIMIT 1",
            (phone, cutoff)).fetchone()
        c2.close()
        if result_status == "success" or (row and row["status"] == "success"):
            remedied.append(phone)
        else:
            failed.append(phone)

    if not no_notify:
        notify(stamp, pending, remedied, failed)
    else:
        print(f"[{stamp}] [no-notify] 跳过邮件通知")
    print(f"[{stamp}] 补签完成: 已补救 {remedied}, 仍失败 {failed}")
    cleanup_logs()
    return 0 if not failed else 1


def notify(stamp, pending, remedied, failed):
    try:
        cfg = get_notify_config()
        if not cfg or not cfg["email_enable"]:
            print("[notify] 邮件未启用，跳过")
            return
        qq = cfg["qq"]
        auth = cfg["auth_code"]
    except Exception as e:
        print(f"[notify] 读取通知配置失败: {e}")
        return
    title = "易班补签：" + ("全部补救成功" if not failed else f"{len(failed)}个仍失败需人工")
    body = "\n".join([
        f"时间：{stamp}",
        f"待补签：{len(pending)} 个",
        f"已补救：{len(remedied)} 个 " + (" ".join(remedied) if remedied else "无"),
        f"仍失败：{len(failed)} 个 " + (" ".join(failed) if failed else "无"),
    ])
    code = ("from yiban.notify.mail import MailNotifier;"
            "n=MailNotifier(%r,%r);"
            "r=n.send_notification([%r],%r,%r);"
            "print('OK' if (r and r.get('success')) else str(r))") % (qq, auth, qq, body, title)
    try:
        r = subprocess.run([YIBAN_PY, "-c", code], cwd="/opt/yiban",
                           capture_output=True, text=True, timeout=30)
        out = (r.stdout or r.stderr or "").strip()
        print("[notify] 邮件发送:", "OK" if "OK" in out else out[:200])
    except Exception as e:
        print(f"[notify] 邮件发送异常: {e}")


def cleanup_logs():
    try:
        con = sqlite3.connect(DB)
        cutoff_90 = (datetime.utcnow() - timedelta(days=90)).strftime("%Y-%m-%d %H:%M:%S")
        cur = con.execute("DELETE FROM sign_logs WHERE created_at < ?", (cutoff_90,))
        con.commit()
        if cur.rowcount:
            print(f"[cleanup] 已清理 {cur.rowcount} 条过期日志(保留90天)")
        con.close()
    except Exception as e:
        print(f"[cleanup] 失败: {e}")


if __name__ == "__main__":
    raise SystemExit(main())
