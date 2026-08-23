from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, Response
import db
import yiban_sync
import json
import os
import secrets
import hashlib
import time
from datetime import datetime, timedelta
from functools import wraps


# 加载 .env
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

app = Flask(__name__)
app.secret_key = os.environ.get("HOMEPAGE_SECRET_KEY") or db.get_secret_key()
app.config['APPLICATION_ROOT'] = '/yiban'
with app.app_context():
    db.init_db()

# Session cookie security
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PERMANENT_SESSION_LIFETIME"] = 3600

# Register DB teardown
app.teardown_appcontext(db.close_db)

# ========== CSRF ==========
CSRF_TOKEN_NAME = '_csrf_token'

def generate_csrf_token():
    if CSRF_TOKEN_NAME not in session:
        session[CSRF_TOKEN_NAME] = secrets.token_hex(32)
    return session[CSRF_TOKEN_NAME]

def validate_csrf_token():
    if request.method != 'POST':
        return True
    token = request.form.get(CSRF_TOKEN_NAME, "") or request.headers.get("X-CSRFToken", "")
    return token and token == session.get(CSRF_TOKEN_NAME)

app.jinja_env.globals['csrf_token'] = generate_csrf_token

@app.before_request
def csrf_protect():
    # API 路由用 X-API-Key 鉴权，跳过 CSRF
    if request.path.startswith('/api/'):
        return
    if request.method == 'POST' and not validate_csrf_token():
        flash('安全验证失败，请重试', 'error')
        return redirect(request.referrer or url_for('index'))


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        ip = request.remote_addr or 'unknown'
        # 限流检查
        allowed, wait = db.check_login_rate_limit(ip)
        if not allowed:
            flash(f'登录尝试过多，请 {wait // 60} 分钟后再试', 'error')
            return render_template('login.html')

        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        if db.verify_admin(username, password):
            session['logged_in'] = True
            session['username'] = username
            session.regenerate() if hasattr(session, 'regenerate') else None
            db.record_login_attempt(ip, username, True)
            db.add_audit_log('login', f'用户 {username} 登录', ip)
            return redirect(url_for('index'))
        else:
            db.record_login_attempt(ip, username, False)
            flash('用户名或密码错误', 'error')
    return render_template('login.html')


@app.route('/logout')
def logout():
    ip = request.remote_addr or 'unknown'
    db.add_audit_log('logout', f'用户 {session.get("username", "?")} 退出', ip)
    session.clear()
    return redirect(url_for('login'))


@app.route('/health')
def health():
    return jsonify({"status": "ok", "service": "yiban-admin"})


@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        old_pw = request.form.get('old_password', '')
        new_pw = request.form.get('new_password', '')
        confirm_pw = request.form.get('confirm_password', '')
        ip = request.remote_addr or 'unknown'
        if new_pw != confirm_pw:
            flash('两次输入的新密码不一致', 'error')
        elif len(new_pw) < 4:
            flash('密码长度至少 4 位', 'error')
        else:
            ok, msg = db.change_admin_password(old_pw, new_pw)
            flash(msg, 'success' if ok else 'error')
            if ok:
                db.add_audit_log('change_password', '修改密码', ip)
                return redirect(url_for('index'))
    return render_template('settings.html', username=db.get_admin_username())


@app.route('/')
@login_required
def index():
    stats = db.get_stats()
    recent_logs = db.get_recent_logs(15)
    users = db.get_all_users()
    # 今日状态横幅
    if stats['today_success'] > 0:
        banner = ('success', '✅', f"今日签到完成 · 成功 {stats['today_success']} 人")
    elif stats['today_fail'] > 0:
        banner = ('danger', '❌', f"今日有 {stats['today_fail']} 个失败，请检查通知配置")
    elif stats['today_skip'] > 0:
        banner = ('warning', '⏭️', '今日已跳过（未到签到时间或无需签到）')
    else:
        banner = ('muted', '⚪', '今日暂无签到记录')
    return render_template('index.html', stats=stats, recent_logs=recent_logs,
                           users=users, banner=banner)


@app.route('/users')
@login_required
def user_list():
    page = request.args.get('page', 1, type=int)
    search = request.args.get('search', '').strip()
    per_page = 20
    pages, cur_page, total, users = db.get_users_page(page, per_page, search)
    return render_template('users.html', users=users, pages=pages, cur_page=cur_page,
                           total=total, search=search, per_page=per_page)


@app.route('/user/add', methods=['GET', 'POST'])
@login_required
def add_user():
    form_data = {}
    if request.method == 'POST':
        ip = request.remote_addr or 'unknown'
        ok, msg = db.add_user(
            phone=request.form.get('phone', ''),
            qq=request.form.get('qq', ''),
            password=request.form.get('password', ''),
            sendkey=request.form.get('sendkey', ''),
            address=request.form.get('address', ''),
            device_id=request.form.get('device_id', ''),
            phone_model=request.form.get('phone_model', 'iPhone-15-Pro-Max'),
            success_notify=1 if request.form.get('success_notify') else 0
        )
        if ok:
            db.add_audit_log('add_user', f'添加用户 {request.form.get("phone", "")}', ip)
            flash(msg, 'success')
            return redirect(url_for('user_list'))
        else:
            flash(msg, 'error')
            form_data = request.form.to_dict()
    return render_template('add_user.html', form=form_data)


@app.route('/user/import', methods=['GET', 'POST'])
@login_required
def import_users():
    if request.method == 'POST':
        file = request.files.get('file')
        content = request.form.get('content', '').strip()
        fmt = request.form.get('format', 'auto')
        ip = request.remote_addr or 'unknown'

        if file and file.filename:
            content = file.read().decode('utf-8')
            if file.filename.endswith('.json'):
                fmt = 'json'
            elif file.filename.endswith('.csv'):
                fmt = 'csv'

        if not content:
            flash('请上传文件或粘贴内容', 'error')
            return redirect(url_for('import_users'))

        if fmt == 'json' or (fmt == 'auto' and content.strip().startswith('[')):
            users = db.parse_import_json(content)
        else:
            users = db.parse_import_csv(content)

        if not users:
            flash('未解析到有效用户数据', 'error')
            return redirect(url_for('import_users'))

        success, failed = db.batch_add_users(users)
        db.add_audit_log('import_users', f'批量导入: 成功 {success} 个', ip)
        flash(f'导入完成：成功 {success} 个', 'success')
        if failed:
            for f_msg in failed[:10]:
                flash(f'跳过: {f_msg}', 'error')
        return redirect(url_for('user_list'))

    return render_template('import.html')


@app.route('/user/export')
@login_required
def export_users():
    data = db.export_users_json()
    return Response(data, mimetype='application/json',
                    headers={'Content-Disposition': 'attachment; filename=users.json'})


@app.route('/user/<phone>/edit', methods=['GET', 'POST'])
@login_required
def edit_user(phone):
    user = db.get_user(phone)
    if not user:
        flash('用户不存在', 'error')
        return redirect(url_for('user_list'))

    if request.method == 'POST':
        ip = request.remote_addr or 'unknown'
        fields = {}
        for f in ['qq', 'password', 'sendkey', 'address', 'device_id', 'phone_model']:
            val = request.form.get(f, '').strip()
            if val:
                fields[f] = val
        fields['success_notify'] = 1 if request.form.get('success_notify') else 0
        ok, msg = db.update_user(phone, **fields)
        if ok:
            db.add_audit_log('edit_user', f'编辑用户 {phone}', ip)
        flash(msg, 'success' if ok else 'error')
        return redirect(url_for('user_list'))

    return render_template('edit_user.html', user=user)


@app.route('/user/<phone>/delete', methods=['POST'])
@login_required
def delete_user(phone):
    ip = request.remote_addr or 'unknown'
    db.delete_user(phone)
    db.add_audit_log('delete_user', f'删除用户 {phone}', ip)
    flash(f'已删除用户 {phone}', 'success')
    return redirect(url_for('user_list'))


@app.route('/user/<phone>/toggle', methods=['POST'])
@login_required
def toggle_user(phone):
    db.toggle_user(phone)
    return redirect(url_for('user_list'))


@app.route('/user/batch_delete', methods=['POST'])
@login_required
def batch_delete_users():
    ip = request.remote_addr or 'unknown'
    phones = request.form.getlist('phones')
    if phones:
        db.batch_delete_users(phones)
        db.add_audit_log('batch_delete', f'批量删除 {len(phones)} 个用户', ip)
        flash(f'已删除 {len(phones)} 个用户', 'success')
    return redirect(url_for('user_list'))


@app.route('/sign/trigger')
@login_required
def trigger_sign_sse():
    phone = request.args.get('phone', '').strip() or None
    test_mode = request.args.get('test') == '1'

    def generate():
        for event in yiban_sync.trigger_sign_stream(phone=phone, test_mode=test_mode):
            yield f"data: {json.dumps(event, ensure_ascii=False)}\n\n"
    return Response(generate(), mimetype='text/event-stream',
                    headers={'Cache-Control': 'no-cache', 'X-Accel-Buffering': 'no'})


@app.route('/sign/sync', methods=['POST'])
@login_required
def sync_users():
    ok, msg = yiban_sync.sync_to_server()
    return jsonify({"ok": ok, "message": msg})


@app.route('/logs')
@login_required
def logs():
    phone = request.args.get('phone', '').strip()
    try:
        page = max(1, int(request.args.get('page', 1)))
    except ValueError:
        page = 1
    per_page = 20
    logs, total = db.get_logs_page(page, per_page, phone)
    pages = (total + per_page - 1) // per_page or 1
    return render_template('logs.html', logs=logs, filter_phone=phone,
                           cur_page=page, pages=pages, total=total)


@app.route('/calendar')
@login_required
def calendar():
    date_stats = db.get_date_stats(30)
    stats_map = {d['date']: d for d in date_stats} if date_stats else {}

    today = datetime.now().date()
    start = today - timedelta(days=29)
    start -= timedelta(days=start.weekday())  # 对齐到周一

    days = []
    cur = start
    while cur <= today:
        ds = cur.strftime('%Y-%m-%d')
        st = stats_map.get(ds)
        total = st['total'] if st else 0
        if total > 0:
            rate = round((st['success'] or 0) / total * 100)
            if rate >= 100:
                level = 'perfect'
            elif rate >= 80:
                level = 'high'
            elif rate >= 50:
                level = 'mid'
            else:
                level = 'low'
        else:
            rate = None
            level = '0'
        days.append({
            'date': ds, 'day': cur.day, 'level': level, 'rate': rate,
            'success': st['success'] if st else 0,
            'fail': st['fail'] if st else 0,
            'total': total,
        })
        cur += timedelta(days=1)

    active_days = sum(1 for d in days if d['total'] > 0)
    return render_template('calendar.html', days=days, active_days=active_days)


@app.route('/calendar/date/<date_str>')
@login_required
def calendar_date(date_str):
    logs = db.get_logs_by_date(date_str)
    return render_template('calendar_date.html', logs=logs, date=date_str)


@app.route('/mail', methods=['GET', 'POST'])
@login_required
def notify_config():
    if request.method == 'POST':
        qq = request.form.get('qq', '').strip()
        auth_code = request.form.get('auth_code', '').strip()
        email_enable = 1 if request.form.get('email_enable') else 0
        serverchan_key = request.form.get('serverchan_key', '').strip()
        serverchan_enable = 1 if request.form.get('serverchan_enable') else 0
        summary_recipient = request.form.get('summary_recipient', '').strip()
        template_a = request.form.get('template_a', '').strip()
        template_b = request.form.get('template_b', '').strip()
        template_success = request.form.get('template_success', '').strip()
        db.set_notify_config(qq, auth_code, email_enable, serverchan_key, serverchan_enable,
                             summary_recipient, template_a, template_b, template_success)
        flash('通知配置已保存', 'success')
        return redirect(url_for('notify_config'))

    notify = db.get_notify_config()
    # 汇总通知和Server酱默认启用（首次）
    if notify and notify['serverchan_enable'] is None:
        db.set_notify_config(notify['qq'], notify['auth_code'], notify['email_enable'] or 1, notify['serverchan_key'], 1)
        notify = db.get_notify_config()
    first_user_qq = db.get_db().execute("SELECT qq FROM users WHERE enable = 1 ORDER BY id ASC LIMIT 1").fetchone()
    first_user_qq = first_user_qq[0] if first_user_qq else ''
    success_notify_count = db.get_db().execute("SELECT COUNT(*) FROM users WHERE success_notify = 1 AND enable = 1").fetchone()[0]
    return render_template('mail.html', notify=notify, success_notify_count=success_notify_count, first_user_qq=first_user_qq)

@app.route('/notify/test_email', methods=['POST'])
@login_required
def notify_test_email():
    qq = request.form.get('qq', '').strip()
    auth_code = request.form.get('auth_code', '').strip()
    if not qq or not auth_code:
        return jsonify({"ok": False, "message": "请填写QQ和授权码"})
    ok, msg = yiban_sync.test_email(qq, auth_code)
    return jsonify({"ok": ok, "message": msg})


@app.route('/notify/test_serverchan', methods=['POST'])
@login_required
def notify_test_serverchan():
    sendkey = request.form.get('sendkey', '').strip()
    if not sendkey:
        return jsonify({"ok": False, "message": "请填写SendKey"})
    ok, msg = yiban_sync.test_serverchan(sendkey)
    return jsonify({"ok": ok, "message": msg})


@app.route('/notify/test_template', methods=['POST'])
@login_required
def notify_test_template():
    qq = request.form.get('qq', '').strip()
    auth_code = request.form.get('auth_code', '').strip()
    template_a = request.form.get('template_a', '').strip()
    template_b = request.form.get('template_b', '').strip()
    template_success = request.form.get('template_success', '').strip()
    if not qq or not auth_code:
        return jsonify({"ok": False, "message": "请填写QQ和授权码"})
    ok, msg = yiban_sync.test_template(qq, auth_code, template_a, template_b, template_success)
    return jsonify({"ok": ok, "message": msg})


@app.route('/api/stats')
@login_required
def api_stats():
    """获取实时统计数据"""
    return jsonify(db.get_stats())


@app.route('/api/logs/delete/<int:log_id>', methods=['POST'])
@login_required
def api_delete_log(log_id):
    """删除单条签到记录"""
    deleted = db.delete_sign_log(log_id)
    if deleted:
        db.add_audit_log('delete_log', f'删除签到记录 #{log_id}', request.remote_addr or 'unknown')
    return jsonify({"ok": deleted})


@app.route('/api/logs/clear', methods=['POST'])
@login_required
def api_clear_logs():
    """清空所有签到记录"""
    n = db.clear_sign_logs()
    db.add_audit_log('clear_logs', f'清空全部签到记录（{n} 条）', request.remote_addr or 'unknown')
    return jsonify({"ok": True, "deleted": n})


# 子路径部署中间件
class PrefixMiddleware:
    def __init__(self, app, prefix='/yiban'):
        self.app = app
        self.prefix = prefix

    def __call__(self, environ, start_response):
        environ['SCRIPT_NAME'] = self.prefix
        path = environ.get('PATH_INFO', '')
        if path.startswith(self.prefix):
            environ['PATH_INFO'] = path[len(self.prefix):] or '/'
        return self.app(environ, start_response)
app.wsgi_app = PrefixMiddleware(app.wsgi_app, prefix='/yiban')





# ========== API 日志接口（供签到脚本调用）==========
API_KEY = os.environ.get("YIBAN_API_KEY") or "yiban-cron-2026"

def api_key_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("X-API-Key") or request.args.get("api_key")
        if key != API_KEY:
            return jsonify({"ok": False, "message": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated

@app.route('/api/logs/add', methods=['POST'])
@api_key_required
def api_add_log():
    """签到脚本写入单条签到记录"""
    data = request.get_json(force=True)
    phone = data.get("phone", "")
    status = data.get("status", "")
    message = data.get("message", "")
    batch_id = data.get("batch_id", "")
    if not phone or not status:
        return jsonify({"ok": False, "message": "phone and status required"}), 400
    log_id = db.add_sign_log(phone, status, message, batch_id)
    return jsonify({"ok": True, "log_id": log_id})

@app.route('/api/logs/batch', methods=['POST'])
@api_key_required
def api_add_logs_batch():
    """签到脚本批量写入签到记录"""
    data = request.get_json(force=True)
    logs = data.get("logs", [])
    if not logs:
        return jsonify({"ok": False, "message": "logs array required"}), 400
    count = 0
    for log in logs:
        phone = log.get("phone", "")
        status = log.get("status", "")
        message = log.get("message", "")
        batch_id = log.get("batch_id", "")
        if phone and status:
            db.add_sign_log(phone, status, message, batch_id)
            count += 1
    return jsonify({"ok": True, "count": count})


if __name__ == '__main__':
    try:
        _n = db.cleanup_old_logs(90)
        if _n:
            print(f'[startup] 已清理 {_n} 条过期签到日志（保留 90 天）')
    except Exception as e:
        print(f'[startup] 日志清理失败: {e}')
    app.run(host='0.0.0.0', port=5000, debug=False)
