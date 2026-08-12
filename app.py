from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, Response
import db
import yiban_sync
import json
import os
import secrets
import hashlib
import time

app = Flask(__name__)
app.secret_key = db.get_secret_key()
app.config['APPLICATION_ROOT'] = '/yiban'
db.init_db()

# ========== CSRF ==========
CSRF_TOKEN_NAME = '_csrf_token'

def generate_csrf_token():
    if CSRF_TOKEN_NAME not in session:
        session[CSRF_TOKEN_NAME] = secrets.token_hex(32)
    return session[CSRF_TOKEN_NAME]

def validate_csrf_token():
    if request.method != 'POST':
        return True
    token = request.form.get(CSRF_TOKEN_NAME, '')
    return token and token == session.get(CSRF_TOKEN_NAME)

app.jinja_env.globals['csrf_token'] = generate_csrf_token

@app.before_request
def csrf_protect():
    if request.method == 'POST' and not validate_csrf_token():
        flash('安全验证失败，请重试', 'error')
        return redirect(request.referrer or url_for('index'))


def login_required(f):
    from functools import wraps
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
    return render_template('index.html', stats=stats, recent_logs=recent_logs, users=users)


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
            phone_model=request.form.get('phone_model', 'iPhone-15-Pro-Max')
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
    if phone:
        logs = db.get_logs_by_phone(phone, 50)
    else:
        logs = db.get_recent_logs(50)
    return render_template('logs.html', logs=logs, filter_phone=phone)


@app.route('/calendar')
@login_required
def calendar():
    date_stats = db.get_date_stats(30)
    return render_template('calendar.html', date_stats=date_stats)


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
        db.set_notify_config(qq, auth_code, email_enable, serverchan_key, serverchan_enable)
        flash('通知配置已保存', 'success')
        return redirect(url_for('notify_config'))

    notify = db.get_notify_config()
    return render_template('mail.html', notify=notify)


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


# 子路径部署中间件
class PrefixMiddleware:
    def __init__(self, app, prefix='/yiban'):
        self.app = app
        self.prefix = prefix

    def __call__(self, environ, start_response):
        environ['SCRIPT_NAME'] = self.prefix
        return self.app(environ, start_response)


app.wsgi_app = PrefixMiddleware(app.wsgi_app, prefix='/yiban')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
