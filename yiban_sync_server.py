import os
import subprocess
import re
import json
from datetime import datetime
from typing import Optional, Generator

from db import get_all_users, get_notify_config, add_sign_log

SERVER_PATH = "/opt/yiban"
SERVER_PYTHON = "/opt/yiban/.venv/bin/python"
LOCAL_OUTPUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output_user_data.py")


def generate_user_data_content() -> str:
    users = get_all_users()
    notify = get_notify_config()

    # mail_config
    mail_config_str = "mail_config = {\n"
    if notify:
        mail_config_str += f'    "enabled": {"True" if notify["email_enable"] else "False"},\n'
        mail_config_str += f'    "qq": "{notify["qq"]}",\n'
        mail_config_str += f'    "auth_code": "{notify["auth_code"]}"\n'
    else:
        mail_config_str += '    "enabled": True,\n    "qq": "",\n    "auth_code": ""\n'
    mail_config_str += "}\n\n"

    # serverchan global key
    serverchan_key = notify['serverchan_key'] if notify and notify.get('serverchan_key') else ''
    mail_config_str += f'SERVERCHAN_KEY = "{serverchan_key}"\n\n'

    user_data_str = "user_data = [\n"
    for u in users:
        if not u['enable']:
            continue
        user_data_str += "    {\n"
        user_data_str += f"        'Phone': '{u['phone']}',\n"
        user_data_str += f"        'QQ': '{u['qq']}',\n"
        user_data_str += f"        'PassWord': '{u['password']}',\n"
        user_data_str += f"        'SendKey': '{u['sendkey'] or ''}',\n"
        user_data_str += f"        'Address': '{u['address']}',\n"
        user_data_str += f"        'DeviceID': '{u['device_id']}',\n"
        user_data_str += f"        'PhoneModel': '{u['phone_model']}',\n"
        user_data_str += f"        'enable': True,\n"
        user_data_str += "    },\n"
    user_data_str += "]\n"
    return mail_config_str + user_data_str


def write_local():
    content = generate_user_data_content()
    with open(LOCAL_OUTPUT, 'w', encoding='utf-8') as f:
        f.write(content)
    return LOCAL_OUTPUT


def sync_to_server() -> tuple:
    """直接写入本地文件"""
    content = generate_user_data_content()
    try:
        target = f"{SERVER_PATH}/yiban/config/user_data.py"
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, 'w', encoding='utf-8') as f:
            f.write(content)
        return True, "同步成功"
    except Exception as e:
        return False, f"同步失败: {str(e)}"


def trigger_sign_stream(phone: Optional[str] = None, test_mode: bool = False) -> Generator:
    ok, msg = sync_to_server()
    if not ok:
        yield {"type": "error", "message": msg}
        yield {"type": "done", "results": []}
        return

    batch_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    if phone:
        batch_id += f"_{phone}"

    env_vars = "APP_ENV=prod"
    if test_mode:
        env_vars += " TEST_LOGIN=true"
    if phone:
        env_vars += f" ONLY_USER={phone}"

    cmd = f"cd {SERVER_PATH} && {env_vars} {SERVER_PYTHON} scripts/start.py"
    yield {"type": "info", "message": f"执行: {cmd}"}

    try:
        proc = subprocess.Popen(
            cmd, shell=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
        )
        results = []
        for line in iter(proc.stdout.readline, ''):
            line = line.rstrip('\n')
            if not line:
                continue
            yield {"type": "log", "message": line}
            r = parse_line(line, batch_id)
            if r:
                results.append(r)
        proc.wait(timeout=10)
        yield {"type": "done", "results": results, "batch_id": batch_id, "returncode": proc.returncode}
    except Exception as e:
        yield {"type": "error", "message": str(e)}
        yield {"type": "done", "results": []}


def parse_line(line: str, batch_id: str) -> Optional[dict]:
    if '签到成功:' in line or '签到成功]' in line:
        phone = extract_phone(line)
        msg = line.split('签到成功:')[-1].strip() if '签到成功:' in line else '签到成功'
        add_sign_log(phone, 'success', msg, batch_id)
        return {"phone": phone, "status": "success", "message": msg}
    elif '签到失败' in line or '出现错误' in line or '错误类型' in line:
        phone = extract_phone(line)
        add_sign_log(phone, 'fail', line, batch_id)
        return {"phone": phone, "status": "fail", "message": line}
    elif '无需签到' in line or '在跳过列表' in line:
        phone = extract_phone(line)
        add_sign_log(phone, 'skip', line, batch_id)
        return {"phone": phone, "status": "skip", "message": line}
    return None


def extract_phone(line: str) -> str:
    m = re.search(r'(\d{11})', line)
    return m.group(1) if m else 'unknown'


# ========== 通知测试 ==========

def test_email(qq: str, auth_code: str) -> tuple:
    try:
        cmd = (
            f"cd {SERVER_PATH} && {SERVER_PYTHON} -c \""
            f"from yiban.notify.mail import MailNotifier; "
            f"n = MailNotifier('{qq}', '{auth_code}'); "
            f"n.send_notification(['{qq}'], '易班签到管理后台 - 测试邮件', '测试邮件'); "
            f"print('OK')\""
        )
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
        if "OK" in proc.stdout:
            return True, "测试邮件已发送"
        return False, proc.stderr or proc.stdout
    except Exception as e:
        return False, str(e)


def test_serverchan(sendkey: str) -> tuple:
    try:
        cmd = (
            f"cd {SERVER_PATH} && {SERVER_PYTHON} -c \""
            f"from yiban.notify.server_chan import ServerChanNotifier; "
            f"n = ServerChanNotifier('{sendkey}'); "
            f"n.send_notification('易班签到管理后台 - 测试推送', '测试推送'); "
            f"print('OK')\""
        )
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=15)
        if "OK" in proc.stdout:
            return True, "测试推送已发送"
        return False, proc.stderr or proc.stdout
    except Exception as e:
        return False, str(e)
