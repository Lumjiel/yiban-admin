import sqlite3
import os
import csv
import io
import json
import hashlib
import secrets
import re
import bcrypt
import uuid
from datetime import datetime, timedelta
from typing import Optional

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "yiban-admin.db")

# 固定 secret_key（从文件读取，不存在则生成）
SECRET_KEY_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".secret_key")

def get_secret_key() -> str:
    if os.path.exists(SECRET_KEY_PATH):
        with open(SECRET_KEY_PATH, 'r') as f:
            return f.read().strip()
    key = secrets.token_hex(32)
    with open(SECRET_KEY_PATH, 'w') as f:
        f.write(key)
    return key


def get_db() -> sqlite3.Connection:
    """同请求内复用，context 外新建"""
    import flask
    try:
        if hasattr(flask.g, "_database"):
            conn = flask.g._database
            try:
                conn.execute("SELECT 1")
                return conn
            except (sqlite3.ProgrammingError, sqlite3.OperationalError):
                pass
    except RuntimeError:
        pass
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    try:
        flask.g._database = conn
    except RuntimeError:
        pass
    return conn


def close_db(exception=None):
    """请求结束时关闭连接"""
    import flask
    try:
        db_conn = getattr(flask.g, "_database", None)
        if db_conn is not None:
            db_conn.close()
            del flask.g._database
    except RuntimeError:
        pass


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            phone TEXT UNIQUE NOT NULL,
            qq TEXT NOT NULL,
            password TEXT NOT NULL,
            sendkey TEXT DEFAULT '',
            address TEXT DEFAULT '',
            device_id TEXT DEFAULT '',
            phone_model TEXT DEFAULT 'iPhone-15-Pro-Max',
            enable INTEGER DEFAULT 1,
            success_notify INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS sign_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            phone TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('success', 'fail', 'skip')),
            message TEXT DEFAULT '',
            batch_id TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS admin_config (
            id INTEGER PRIMARY KEY CHECK(id = 1),
            username TEXT NOT NULL DEFAULT 'admin',
            password_hash TEXT NOT NULL DEFAULT '',
            salt TEXT NOT NULL DEFAULT '',
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS notify_config (
            id INTEGER PRIMARY KEY CHECK(id = 1),
            qq TEXT DEFAULT '',
            auth_code TEXT DEFAULT '',
            email_enable INTEGER DEFAULT 1,
            serverchan_key TEXT DEFAULT '',
            serverchan_enable INTEGER DEFAULT 0,
            summary_recipient TEXT DEFAULT '',
            template_a TEXT DEFAULT '',
            template_b TEXT DEFAULT '',
            template_success TEXT DEFAULT ''
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT NOT NULL,
            detail TEXT DEFAULT '',
            ip TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            username TEXT DEFAULT '',
            success INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );

        CREATE INDEX IF NOT EXISTS idx_sign_logs_phone ON sign_logs(phone);
        CREATE INDEX IF NOT EXISTS idx_sign_logs_created ON sign_logs(created_at);
        CREATE INDEX IF NOT EXISTS idx_sign_logs_batch ON sign_logs(batch_id);
        CREATE INDEX IF NOT EXISTS idx_audit_log_created ON audit_log(created_at);
        CREATE INDEX IF NOT EXISTS idx_login_attempts_ip ON login_attempts(ip);
    """)

    # 确保 admin 存在（只在为空时创建默认账户）
    row = conn.execute("SELECT * FROM admin_config WHERE id = 1").fetchone()
    if not row or not row['password_hash']:
        pw_hash = _hash_password('admin123')
        conn.execute("""INSERT OR REPLACE INTO admin_config (id, username, password_hash)
                        VALUES (1, 'admin', ?)""", (pw_hash,))

    conn.execute("INSERT OR IGNORE INTO notify_config (id) VALUES (1)")

    # 迁移：新增字段（已存在则忽略）
    try:
        conn.execute("ALTER TABLE notify_config ADD COLUMN summary_recipient TEXT DEFAULT ''")
    except: pass
    try:
        conn.execute("ALTER TABLE notify_config ADD COLUMN template_a TEXT DEFAULT ''")
    except: pass
    try:
        conn.execute("ALTER TABLE notify_config ADD COLUMN template_b TEXT DEFAULT ''")
    except: pass
    try:
        conn.execute("ALTER TABLE notify_config ADD COLUMN template_success TEXT DEFAULT ''")
    except: pass
    try:
        conn.execute("ALTER TABLE users ADD COLUMN success_notify INTEGER DEFAULT 0")
    except: pass
    # 首次初始化模板（仅当为空时）
    row = conn.execute("SELECT template_a FROM notify_config WHERE id = 1").fetchone()
    if row is not None and not row[0]:
        conn.execute("""UPDATE notify_config SET
                        template_a = '易班会话已过期\n自行登录易班完成图形验证，刷新会话即可正常签到\n请及时操作，防止漏签',
                        template_b = '易班校本化授权已失效。\n请前往易班首页，点击校本化入口，在弹出的授权弹窗中完成授权即可。\n授权剩余有效期可查看：我的 - 设置 - 授权管理 - 校本化 - 授权有效期。\n请留意自身签到状态，如有异常随时反馈。',
                        template_success = '易班签到成功通知\n\n账号: {phone}\n签到结果: {result}\n签到时间: {time}\n签到地址: {address}'
                        WHERE id = 1""")
    conn.commit()
    conn.close()


# ========== 密码哈希 ==========

def _hash_password(password: str, salt: str = None) -> str:
    """bcrypt 哈希"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def verify_admin(username: str, password: str) -> bool:
    conn = get_db()
    row = conn.execute("SELECT * FROM admin_config WHERE id = 1 AND username = ?", (username,)).fetchone()
    if not row or not row['password_hash']:
        return False
    stored_hash = row['password_hash']
    if _is_bcrypt_hash(stored_hash):
        return bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))
    salt = row['salt'] if 'salt' in row.keys() else None
    if salt and _hash_password_legacy(password, salt) == stored_hash:
        new_hash = _hash_password(password)
        conn2 = get_db()
        conn2.execute("UPDATE admin_config SET password_hash = ?, salt = '' WHERE id = 1", (new_hash,))
        conn2.commit()
        return True
    return False


def change_admin_password(old_pw: str, new_pw: str) -> tuple:
    if not verify_admin(get_admin_username(), old_pw):
        return False, "原密码错误"
    if len(new_pw) < 4:
        return False, "密码长度至少 4 位"
    new_hash = _hash_password(new_pw)
    conn = get_db()
    conn.execute("UPDATE admin_config SET password_hash = ?, updated_at = ? WHERE id = 1",
                 (new_hash, datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
    conn.commit()
    conn.close()
    return True, "密码修改成功"


def get_admin_username() -> str:
    conn = get_db()
    row = conn.execute("SELECT username FROM admin_config WHERE id = 1").fetchone()
    conn.close()
    return row['username'] if row else 'admin'


# ========== 输入过滤 ==========

# 常见连字符/破折号变体 -> 标准 ASCII 短横，防止从网页/文档复制时混入不可见字符
_HYPHEN_RE = re.compile(r'[\u00ad\u2010-\u2014\u2212\uff0d]')

def sanitize_str(value: str, max_len: int = 100) -> str:
    """过滤危险字符，防止注入"""
    if not value:
        return ''
    # 移除换行、单引号、双引号、反斜杠
    value = value.replace('\n', '').replace('\r', '').replace("'", '').replace('"', '').replace('\\', '')
    # 移除控制字符
    value = re.sub(r'[\x00-\x1f\x7f]', '', value)
    # 归一化连字符：不间断连字符(U+2011)/破折号等变体统一成 ASCII 短横，
    # 否则易班接口按 UUID 校验 device_id 会拒签(复制粘贴常见带入)
    value = _HYPHEN_RE.sub('-', value)
    return value[:max_len]


def validate_address(addr: str) -> tuple:
    """校验签到地址 JSON 格式"""
    if not addr:
        return True, ''
    try:
        data = json.loads(addr)
        if not isinstance(data, dict):
            return False, "签到地址必须是 JSON 对象"
        return True, ''
    except json.JSONDecodeError:
        return False, "签到地址格式错误：无效的 JSON"


def gen_device_id() -> str:
    """生成随机设备ID"""
    return str(uuid.uuid4())


# ========== 审计日志 ==========

def add_audit_log(action: str, detail: str = '', ip: str = ''):
    conn = get_db()
    conn.execute("INSERT INTO audit_log (action, detail, ip) VALUES (?, ?, ?)",
                 (action, detail, ip))
    conn.commit()
    conn.close()


def get_audit_logs(limit: int = 50) -> list:
    conn = get_db()
    rows = conn.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return rows


# ========== 登录限流 ==========

def check_login_rate_limit(ip: str) -> tuple:
    """检查是否被限流，返回 (是否允许, 剩余等待秒数)"""
    conn = get_db()
    # 15 分钟内失败次数
    since = (datetime.now() - timedelta(minutes=15)).strftime('%Y-%m-%d %H:%M:%S')
    fails = conn.execute(
        "SELECT COUNT(*) FROM login_attempts WHERE ip = ? AND success = 0 AND created_at >= ?",
        (ip, since)).fetchone()[0]
    conn.close()
    if fails >= 5:
        return False, 900  # 锁定 15 分钟
    return True, 0


def record_login_attempt(ip: str, username: str, success: bool):
    conn = get_db()
    conn.execute("INSERT INTO login_attempts (ip, username, success) VALUES (?, ?, ?)",
                 (ip, username, 1 if success else 0))
    conn.commit()
    # 清理 24 小时前的记录
    old = (datetime.now() - timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S')
    conn.execute("DELETE FROM login_attempts WHERE created_at < ?", (old,))
    conn.close()


# ========== User CRUD ==========

def get_all_users() -> list:
    conn = get_db()
    rows = conn.execute("SELECT * FROM users ORDER BY id ASC").fetchall()
    conn.close()
    return rows


def get_users_page(page: int = 1, per_page: int = 20, search: str = '') -> tuple:
    conn = get_db()
    where = ""
    params = []
    if search:
        where = "WHERE phone LIKE ? OR qq LIKE ? OR phone_model LIKE ?"
        params = [f'%{search}%', f'%{search}%', f'%{search}%']

    total = conn.execute(f"SELECT COUNT(*) FROM users {where}", params).fetchone()[0]
    pages = max(1, (total + per_page - 1) // per_page)
    page = max(1, min(page, pages))
    offset = (page - 1) * per_page

    rows = conn.execute(
        f"SELECT * FROM users {where} ORDER BY id ASC LIMIT ? OFFSET ?",
        params + [per_page, offset]
    ).fetchall()
    conn.close()
    return pages, page, total, rows


def get_user(phone: str) -> Optional[sqlite3.Row]:
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE phone = ?", (phone,)).fetchone()
    conn.close()
    return row


def add_user(phone, qq, password, sendkey='', address='', device_id='', phone_model='iPhone-15-Pro-Max', success_notify=0) -> tuple:
    # 输入过滤
    phone = sanitize_str(phone, 11)
    qq = sanitize_str(qq, 20)
    phone_model = sanitize_str(phone_model, 50)
    sendkey = sanitize_str(sendkey, 100)
    device_id = sanitize_str(device_id, 50)

    # 校验
    if not phone or not re.match(r'^\d{11}$', phone):
        return False, "手机号必须是 11 位数字"
    if not qq:
        return False, "QQ号不能为空"
    if not password:
        return False, "密码不能为空"

    # 校验 address JSON
    if address:
        ok, msg = validate_address(address)
        if not ok:
            return False, msg
    else:
        address = '{"Reason":"","AttachmentFileName":"","LngLat":"118.88,31.93","Address":""}'

    # 空 device_id 自动生成
    if not device_id:
        device_id = gen_device_id()

    conn = get_db()
    try:
        conn.execute("""INSERT INTO users (phone, qq, password, sendkey, address, device_id, phone_model, success_notify)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                     (phone, qq, password, sendkey, address, device_id, phone_model, success_notify))
        conn.commit()
        return True, "添加成功"
    except sqlite3.IntegrityError:
        return False, f"手机号 {phone} 已存在"
    finally:
        conn.close()


def batch_add_users(users: list) -> tuple:
    conn = get_db()
    success = 0
    failed = []
    for u in users:
        try:
            phone = sanitize_str(str(u.get('phone', '')), 11)
            qq = sanitize_str(str(u.get('qq', '')), 20)
            password = str(u.get('password', ''))
            sendkey = sanitize_str(str(u.get('sendkey', '')), 100)
            address = str(u.get('address', ''))
            device_id = sanitize_str(str(u.get('device_id', '')), 50)
            phone_model = sanitize_str(str(u.get('phone_model', 'iPhone-15-Pro-Max')), 50)

            if not phone or not re.match(r'^\d{11}$', phone):
                failed.append(f"{phone}: 手机号格式错误")
                continue
            if not password:
                failed.append(f"{phone}: 密码为空")
                continue
            if address:
                ok, msg = validate_address(address)
                if not ok:
                    failed.append(f"{phone}: {msg}")
                    continue
            else:
                address = '{"Reason":"","AttachmentFileName":"","LngLat":"118.88,31.93","Address":""}'
            if not device_id:
                device_id = gen_device_id()

            conn.execute("""INSERT INTO users (phone, qq, password, sendkey, address, device_id, phone_model)
                            VALUES (?, ?, ?, ?, ?, ?, ?)""",
                         (phone, qq, password, sendkey, address, device_id, phone_model))
            success += 1
        except sqlite3.IntegrityError:
            failed.append(f"{phone} 已存在")
        except Exception as e:
            failed.append(f"{phone}: {str(e)}")
    conn.commit()
    conn.close()
    return success, failed


def update_user(phone: str, **kwargs) -> tuple:
    allowed = {'qq', 'password', 'sendkey', 'address', 'device_id', 'phone_model', 'enable', 'success_notify'}
    fields = {}
    for k, v in kwargs.items():
        if k in allowed:
            fields[k] = sanitize_str(str(v), 100) if isinstance(v, str) else v

    if not fields:
        return False, "无有效字段"

    # 校验 address
    if 'address' in fields and fields['address']:
        ok, msg = validate_address(fields['address'])
        if not ok:
            return False, msg

    fields['updated_at'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    set_clause = ", ".join(f"{k} = ?" for k in fields)
    values = list(fields.values()) + [phone]
    conn = get_db()
    conn.execute(f"UPDATE users SET {set_clause} WHERE phone = ?", values)
    conn.commit()
    conn.close()
    return True, "更新成功"


def delete_user(phone: str):
    conn = get_db()
    conn.execute("DELETE FROM users WHERE phone = ?", (phone,))
    conn.commit()
    conn.close()


def batch_delete_users(phones: list):
    if not phones:
        return
    conn = get_db()
    placeholders = ",".join("?" * len(phones))
    conn.execute(f"DELETE FROM users WHERE phone IN ({placeholders})", phones)
    conn.commit()


def toggle_user(phone: str):
    conn = get_db()
    conn.execute("UPDATE users SET enable = NOT enable WHERE phone = ?", (phone,))
    conn.commit()
    conn.close()


def export_users_json() -> str:
    users = get_all_users()
    data = []
    for u in users:
        data.append({
            'phone': u['phone'], 'qq': u['qq'], 'password': u['password'],
            'sendkey': u['sendkey'], 'address': u['address'],
            'device_id': u['device_id'], 'phone_model': u['phone_model'],
            'enable': bool(u['enable'])
        })
    return json.dumps(data, ensure_ascii=False, indent=2)


def parse_import_csv(content: str) -> list:
    reader = csv.DictReader(io.StringIO(content))
    users = []
    for row in reader:
        if 'phone' in row:
            u = {'phone': row.get('phone', '').strip(), 'qq': row.get('qq', '').strip(),
                 'password': row.get('password', '').strip(), 'sendkey': row.get('sendkey', '').strip(),
                 'address': row.get('address', '').strip(), 'device_id': row.get('device_id', '').strip(),
                 'phone_model': row.get('phone_model', 'iPhone-15-Pro-Max').strip()}
        elif 'Phone' in row:
            u = {'phone': row.get('Phone', '').strip(), 'qq': row.get('QQ', '').strip(),
                 'password': row.get('PassWord', '').strip(), 'sendkey': row.get('SendKey', '').strip(),
                 'address': row.get('Address', '').strip(), 'device_id': row.get('DeviceID', '').strip(),
                 'phone_model': row.get('PhoneModel', 'iPhone-15-Pro-Max').strip()}
        else:
            continue
        if u['phone'] and u['password']:
            users.append(u)
    return users


def parse_import_json(content: str) -> list:
    data = json.loads(content)
    users = []
    for item in data:
        u = {'phone': str(item.get('phone', item.get('Phone', ''))).strip(),
             'qq': str(item.get('qq', item.get('QQ', ''))).strip(),
             'password': str(item.get('password', item.get('PassWord', ''))).strip(),
             'sendkey': str(item.get('sendkey', item.get('SendKey', ''))).strip(),
             'address': str(item.get('address', item.get('Address', ''))).strip(),
             'device_id': str(item.get('device_id', item.get('DeviceID', ''))).strip(),
             'phone_model': str(item.get('phone_model', item.get('PhoneModel', 'iPhone-15-Pro-Max'))).strip()}
        if u['phone'] and u['password']:
            users.append(u)
    return users


# ========== 通知配置 ==========

def get_notify_config() -> Optional[sqlite3.Row]:
    conn = get_db()
    row = conn.execute("SELECT * FROM notify_config WHERE id = 1").fetchone()
    conn.close()
    return row


def set_notify_config(qq: str, auth_code: str, email_enable: int = 1,
                      serverchan_key: str = '', serverchan_enable: int = 0,
                      summary_recipient: str = '',
                      template_a: str = '', template_b: str = '', template_success: str = ''):
    conn = get_db()
    conn.execute("""INSERT OR REPLACE INTO notify_config (id, qq, auth_code, email_enable, serverchan_key, serverchan_enable,
                    summary_recipient, template_a, template_b, template_success)
                    VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                 (qq, auth_code, email_enable, serverchan_key, serverchan_enable,
                  summary_recipient, template_a, template_b, template_success))
    conn.commit()
    conn.close()


# ========== Sign Logs ==========

def add_sign_log(phone: str, status: str, message: str = '', batch_id: str = ''):
    conn = get_db()
    conn.execute("INSERT INTO sign_logs (phone, status, message, batch_id) VALUES (?, ?, ?, ?)",
                 (phone, status, message, batch_id))
    conn.commit()
    conn.close()


def get_recent_logs(limit: int = 100) -> list:
    conn = get_db()
    rows = conn.execute("SELECT *, datetime(created_at, '+8 hours') as created_at_bj FROM sign_logs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return rows


def get_logs_by_phone(phone: str, limit: int = 30) -> list:
    conn = get_db()
    rows = conn.execute("SELECT * FROM sign_logs WHERE phone = ? ORDER BY id DESC LIMIT ?",
                        (phone, limit)).fetchall()
    conn.close()
    return rows


def get_logs_by_date(date_str: str) -> list:
    conn = get_db()
    # date_str 是北京时间日期；created_at 存 UTC，换算成 UTC 区间查询
    try:
        d = datetime.strptime(date_str, '%Y-%m-%d')
    except ValueError:
        return []
    start_utc = (d - timedelta(hours=8)).strftime('%Y-%m-%d %H:%M:%S')
    end_utc = (d + timedelta(hours=16)).strftime('%Y-%m-%d %H:%M:%S')
    rows = conn.execute(
        "SELECT *, datetime(created_at, '+8 hours') as created_at_bj "
        "FROM sign_logs WHERE created_at >= ? AND created_at < ? ORDER BY id ASC",
        (start_utc, end_utc)).fetchall()
    conn.close()
    return rows


def get_date_stats(days: int = 30) -> list:
    conn = get_db()
    # start 是北京时间日期；按北京时间日期分组（created_at 存 UTC）
    start = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d')
    rows = conn.execute("""
        SELECT DATE(created_at, '+8 hours') as date,
               COUNT(DISTINCT CASE WHEN status='success' THEN phone END) as success,
               COUNT(DISTINCT CASE WHEN status='fail' THEN phone END) as fail,
               COUNT(DISTINCT phone) as total
        FROM sign_logs WHERE DATE(created_at, '+8 hours') >= ?
        GROUP BY DATE(created_at, '+8 hours') ORDER BY date ASC
    """, (start,)).fetchall()
    conn.close()
    return rows


def _bj_day_start_utc(dt=None) -> str:
    """created_at 存 UTC。返回北京时间某日 00:00 对应的 UTC 时刻字符串。

    Beijing day D 00:00 = UTC (D-1) 16:00。
    """
    base = dt or datetime.utcnow()
    bj = base + timedelta(hours=8)
    start_bj = datetime(bj.year, bj.month, bj.day)
    start_utc = start_bj - timedelta(hours=8)
    return start_utc.strftime('%Y-%m-%d %H:%M:%S')


# ========== Stats ==========

def get_stats() -> dict:
    conn = get_db()
    # created_at 存 UTC；用北京时间当日 0 点对应的 UTC 时刻作截断点
    today_cutoff = _bj_day_start_utc()
    week_cutoff = (datetime.utcnow() - timedelta(days=7)).strftime('%Y-%m-%d %H:%M:%S')

    total_users = conn.execute("SELECT COUNT(*) FROM users WHERE enable = 1").fetchone()[0]
    total_all = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]

    today_success = conn.execute(
        "SELECT COUNT(DISTINCT phone) FROM sign_logs WHERE status='success' AND created_at >= ?",
        (today_cutoff,)).fetchone()[0]
    today_fail = conn.execute(
        "SELECT COUNT(DISTINCT phone) FROM sign_logs WHERE status='fail' AND created_at >= ?",
        (today_cutoff,)).fetchone()[0]
    today_skip = conn.execute(
        "SELECT COUNT(DISTINCT phone) FROM sign_logs WHERE status='skip' AND created_at >= ?",
        (today_cutoff,)).fetchone()[0]

    week_stats = conn.execute(
        "SELECT status, COUNT(DISTINCT phone) as cnt FROM sign_logs WHERE created_at >= ? GROUP BY status",
        (week_cutoff,)).fetchall()

    conn.close()

    week_success = sum(r['cnt'] for r in week_stats if r['status'] == 'success')
    week_fail = sum(r['cnt'] for r in week_stats if r['status'] == 'fail')
    rate = f"{(today_success / total_users * 100):.1f}%" if total_users > 0 else "0%"

    return {
        "total_users": total_users, "total_all": total_all,
        "today_success": today_success, "today_fail": today_fail,
        "today_skip": today_skip, "today_rate": rate,
        "week_success": week_success, "week_fail": week_fail,
    }


# ========== 密码哈希迁移（旧 SHA256 → bcrypt）==========

def _hash_password_legacy(password: str, salt: str) -> str:
    """旧 SHA256 哈希"""
    import hashlib
    key = (password + salt).encode('utf-8')
    for _ in range(10000):
        key = hashlib.sha256(key).digest()
    return key.hex()


def _is_bcrypt_hash(hash_str: str) -> bool:
    """检查 bcrypt 格式"""
    return hash_str.startswith('$2b$') or hash_str.startswith('$2a$') or hash_str.startswith('$2y$')

# ========== 日志管理 ==========

def delete_sign_log(log_id: int):
    """删除单条签到记录，返回是否成功删除"""
    conn = get_db()
    cur = conn.execute("DELETE FROM sign_logs WHERE id = ?", (log_id,))
    conn.commit()
    return cur.rowcount > 0

def clear_sign_logs():
    """清空所有签到记录，返回删除条数"""
    conn = get_db()
    n = conn.execute("SELECT COUNT(*) FROM sign_logs").fetchone()[0]
    conn.execute("DELETE FROM sign_logs")
    conn.commit()
    return n

def cleanup_old_logs(days: int = 90):
    """清理超过指定天数的签到日志，返回删除条数"""
    conn = get_db()
    cutoff = (datetime.utcnow() - timedelta(days=days)).strftime('%Y-%m-%d %H:%M:%S')
    cur = conn.execute("DELETE FROM sign_logs WHERE created_at < ?", (cutoff,))
    conn.commit()
    n = cur.rowcount
    conn.close()
    return n

def get_logs_page(page: int = 1, per_page: int = 20, phone: str = '') -> tuple:
    """分页获取签到日志，返回 (logs, total)。phone 为空则不过滤"""
    conn = get_db()
    where, params = '', []
    if phone:
        where, params = 'WHERE phone = ?', [phone]
    total = conn.execute(f'SELECT COUNT(*) FROM sign_logs {where}', params).fetchone()[0]
    offset = (page - 1) * per_page
    logs = conn.execute(
        f'SELECT *, datetime(created_at, \'+8 hours\') as created_at_bj FROM sign_logs {where} ORDER BY id DESC LIMIT ? OFFSET ?',
        params + [per_page, offset]).fetchall()
    conn.close()
    return logs, total
