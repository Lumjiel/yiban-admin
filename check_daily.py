#!/usr/bin/env python3
"""
每日签到兜底校验
- 检查今天（北京时间）是否有签到记录，没有则通过 ServerChan 发告警
- 顺带清理超过 90 天的过期日志
- 由 cron 每天 08:00 调用：0 8 * * * cd /opt/yiban-admin && /usr/bin/python3 check_daily.py >> /var/log/yiban-check.log 2>&1
"""
import sqlite3
import urllib.request
import urllib.parse
from datetime import datetime, timedelta
from pathlib import Path

DB = Path(__file__).parent / 'yiban-admin.db'


def send_serverchan(key: str, title: str, msg: str):
    data = urllib.parse.urlencode({'title': title, 'desp': msg}).encode()
    req = urllib.request.Request(f'https://sctapi.ftqq.com/{key}.send', data=data)
    try:
        resp = urllib.request.urlopen(req, timeout=15)
        print(f'ServerChan 推送响应: {resp.status}')
    except Exception as e:
        print(f'ServerChan 推送失败: {e}')


def main() -> int:
    now_bj = datetime.utcnow() + timedelta(hours=8)
    date_str = now_bj.strftime('%Y-%m-%d')
    # created_at 存 UTC；北京时间当日 0 点对应的 UTC 截断点
    cutoff = (datetime.utcnow() - timedelta(hours=8)).strftime('%Y-%m-%d') + ' 00:00:00'

    con = sqlite3.connect(f'file:{DB}?mode=ro', uri=True)
    con.row_factory = sqlite3.Row
    rows = con.execute(
        "SELECT status, COUNT(DISTINCT phone) as cnt FROM sign_logs "
        "WHERE created_at >= ? GROUP BY status", (cutoff,)).fetchall()
    key_row = con.execute(
        "SELECT serverchan_key FROM notify_config "
        "WHERE id = 1 AND serverchan_enable = 1 AND serverchan_key != ''").fetchone()
    con.close()

    stats = {r['status']: r['cnt'] for r in rows}
    total = sum(stats.values())

    if total == 0:
        print(f'[{date_str}] ⚠️ 今日无任何签到记录')
        if key_row:
            send_serverchan(
                key_row['serverchan_key'],
                '⚠️ 易班签到未执行',
                f'**{date_str}** 今日未检测到任何签到记录。\n\n'
                '定时任务可能没有执行（服务器停机/脚本异常），请登录后台检查。')
            return 1
        print('ServerChan 未配置或未启用，无法发送告警（仅记录日志）')
        return 1

    print(f'[{date_str}] ✓ 今日签到记录正常: {stats}')

    # 顺带清理过期日志
    try:
        con = sqlite3.connect(str(DB))
        cutoff_90 = (datetime.utcnow() - timedelta(days=90)).strftime('%Y-%m-%d %H:%M:%S')
        cur = con.execute('DELETE FROM sign_logs WHERE created_at < ?', (cutoff_90,))
        con.commit()
        if cur.rowcount:
            print(f'已清理 {cur.rowcount} 条过期日志（保留 90 天）')
        con.close()
    except Exception as e:
        print(f'日志清理失败: {e}')

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
