import os
import subprocess
import re
import json
from datetime import datetime
from typing import Optional, Generator

from db import get_all_users, get_notify_config, add_sign_log, sanitize_str

# 错误关键词（与 yiban/sign/core.py 保持一致）
ERR_KEYWORDS_SIGN = ["Get Night Attendance Sign Tasks Error", "校本化", "未登录或登录已经超时"]
ERR_KEYWORDS_AUTH = ["登录失败", "密码错误", "401", "403", "token"]
ERR_KEYWORDS_FAIL = ["签到失败", "出现错误", "错误类型"]

SERVER_PATH = "/opt/yiban"
SERVER_PYTHON = "/opt/yiban/.venv/bin/python"
USER_DATA_PATH = os.path.join(SERVER_PATH, "yiban", "config", "user_data.py")

# Address 默认值（合法 JSON）
DEFAULT_ADDRESS = '{"Reason":"","AttachmentFileName":"","LngLat":"118.88,31.93","Address":""}'


def _row_to_dict(row):
    """sqlite3.Row 转 dict，方便用 .get()"""
    if row is None:
        return {}
    return {k: row[k] for k in row.keys()}


def _json_to_python(text):
    """json.dumps 输出 true/false/null，替换为 Python 的 True/False/None"""
    return text.replace(": true", ": True").replace(": false", ": False").replace(": null", ": None")


def generate_user_data_content() -> str:
    """从 SQLite 生成 user_data.py 文件内容（用 json.dumps 保证格式安全）"""
    users = get_all_users()
    notify = _row_to_dict(get_notify_config())

    # mail_config
    mail_cfg = {
        "enabled": bool(notify.get("email_enable")),
        "qq": notify.get("qq", ""),
        "auth_code": notify.get("auth_code", ""),
        "summary_recipient": notify.get("summary_recipient", ""),
        "template_a": notify.get("template_a", ""),
        "template_b": notify.get("template_b", ""),
        "template_success": notify.get("template_success", ""),
    }
    raw_mail = _json_to_python(json.dumps(mail_cfg, ensure_ascii=False, indent=4))
    mail_config_str = "mail_config = " + raw_mail + "\n\n"

    # serverchan key
    serverchan_key = notify.get("serverchan_key", "")
    mail_config_str += "SERVERCHAN_KEY = " + json.dumps(serverchan_key, ensure_ascii=False) + "\n\n"

    # user_data（Address 不走 sanitize_str，保留 JSON 字符串完整性）
    user_list = []
    for u in users:
        u = _row_to_dict(u)
        if not u.get("enable", 1):
            continue
        address = u.get("address", "") or DEFAULT_ADDRESS
        # 验证 address 是合法 JSON，不合法则用默认
        try:
            json.loads(address)
        except (json.JSONDecodeError, TypeError):
            address = DEFAULT_ADDRESS
        user_dict = {
            "Phone": sanitize_str(u.get("phone", ""), 11),
            "QQ": sanitize_str(u.get("qq", ""), 20),
            "PassWord": sanitize_str(u.get("password", ""), 50),
            "SendKey": sanitize_str(u.get("sendkey", ""), 100),
            "Address": address,
            "DeviceID": sanitize_str(u.get("device_id", ""), 50),
            "PhoneModel": sanitize_str(u.get("phone_model", ""), 50),
            "enable": True,
            "success_notify": 1 if u.get("success_notify") else 0,
        }
        user_list.append(user_dict)

    raw = _json_to_python(json.dumps(user_list, ensure_ascii=False, indent=4))
    user_data_str = "user_data = " + raw + "\n"
    return mail_config_str + user_data_str


def sync_to_server() -> tuple:
    """同步用户数据到签到脚本的 user_data.py（本地写入）"""
    content = generate_user_data_content()
    try:
        os.makedirs(os.path.dirname(USER_DATA_PATH), exist_ok=True)
        with open(USER_DATA_PATH, "w", encoding="utf-8") as f:
            f.write(content)
        return True, "同步成功"
    except Exception as e:
        return False, "同步失败: " + str(e)


def trigger_sign_stream(phone: Optional[str] = None, test_mode: bool = False) -> Generator:
    """本地执行签到脚本，SSE 流式返回结果"""
    ok, msg = sync_to_server()
    if not ok:
        yield {"type": "error", "message": msg}
        yield {"type": "done", "results": []}
        return

    batch_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    if phone:
        batch_id += "_" + phone

    env = os.environ.copy()
    env["APP_ENV"] = "prod"
    if test_mode:
        env["TEST_LOGIN"] = "true"
    if phone:
        env["ONLY_USER"] = phone

    cmd = [SERVER_PYTHON, "-u", "scripts/start.py"]
    yield {"type": "info", "message": "执行: " + " ".join(cmd)}

    try:
        proc = subprocess.Popen(
            cmd, cwd=SERVER_PATH, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1,
        )
        results = []
        for line in iter(proc.stdout.readline, ""):
            line = line.rstrip("\n")
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
    """解析签到输出行，写入日志表"""
    if any(k in line for k in ERR_KEYWORDS_FAIL):
        phone = extract_phone(line)
        add_sign_log(phone, "fail", line, batch_id)
        return {"phone": phone, "status": "fail", "message": line}

    if "签到成功:" in line or "签到成功]" in line:
        phone = extract_phone(line)
        if "签到成功:" in line:
            msg = line.split("签到成功:")[-1].strip()
        else:
            msg = line.split("签到成功]")[-1].strip()
        is_fail = any(k in msg for k in ERR_KEYWORDS_SIGN + ERR_KEYWORDS_AUTH)
        status = "fail" if is_fail else "success"
        add_sign_log(phone, status, msg, batch_id)
        return {"phone": phone, "status": status, "message": msg}

    if "无需签到" in line or "在跳过列表" in line:
        phone = extract_phone(line)
        add_sign_log(phone, "skip", line, batch_id)
        return {"phone": phone, "status": "skip", "message": line}

    return None


def extract_phone(line: str) -> str:
    m = re.search(r"(\d{11})", line)
    return m.group(1) if m else "unknown"


# ========== 通知测试 ==========

def test_email(qq: str, auth_code: str) -> tuple:
    """本地发送测试邮件"""
    try:
        code = (
            "from yiban.notify.mail import MailNotifier; "
            "n = MailNotifier(%s, %s); "
            "n.send_notification([%s], '测试邮件', '测试邮件'); "
            "print('OK')"
        ) % (json.dumps(qq), json.dumps(auth_code), json.dumps(qq))
        proc = subprocess.run(
            [SERVER_PYTHON, "-c", code],
            capture_output=True, text=True, timeout=30, cwd=SERVER_PATH,
        )
        if "OK" in proc.stdout:
            return True, "测试邮件已发送"
        return False, proc.stderr or proc.stdout
    except Exception as e:
        return False, str(e)


def test_serverchan(sendkey: str) -> tuple:
    """本地发送 ServerChan 测试推送"""
    try:
        code = (
            "from yiban.notify.server_chan import ServerChan; "
            "n = ServerChan('测试推送', %s); "
            "n.log('测试推送').send_msg(); "
            "print('OK')"
        ) % json.dumps(sendkey)
        proc = subprocess.run(
            [SERVER_PYTHON, "-c", code],
            capture_output=True, text=True, timeout=15, cwd=SERVER_PATH,
        )
        if "OK" in proc.stdout:
            return True, "测试推送已发送"
        return False, proc.stderr or proc.stdout
    except Exception as e:
        return False, str(e)


def test_template(qq: str, auth_code: str, template_a: str, template_b: str, template_success: str) -> tuple:
    """用示例数据渲染模板并发送测试邮件（本地执行）"""
    try:
        import base64
        sample = {
            "phone": "13800138000",
            "qq": "123456789",
            "result": "签到成功（示例）",
            "time": "2026-01-01 08:00:00",
            "address": "江苏省南京市南京工程学院"
        }
        content = "=== 模板预览测试 ===\n\n"
        content += "【A类通知 - 会话过期】\n" + (template_a or "（未配置）").format(**sample) + "\n\n"
        content += "【B类通知 - 校本化失效】\n" + (template_b or "（未配置）").format(**sample) + "\n\n"
        content += "【单独成功通知】\n" + (template_success or "（未配置）").format(**sample) + "\n\n"
        content += "--- 以上为模板预览，使用示例数据渲染 ---"
        content_b64 = base64.b64encode(content.encode()).decode()

        code = (
            "import base64; "
            "from yiban.notify.mail import MailNotifier; "
            "n = MailNotifier(%s, %s); "
            "c = base64.b64decode(%s).decode(); "
            "n.send_notification([%s], c, '模板预览测试'); "
            "print('OK')"
        ) % (json.dumps(qq), json.dumps(auth_code), json.dumps(content_b64), json.dumps(qq))
        proc = subprocess.run(
            [SERVER_PYTHON, "-c", code],
            capture_output=True, text=True, timeout=30, cwd=SERVER_PATH,
        )
        if "OK" in proc.stdout:
            return True, "模板预览邮件已发送"
        return False, proc.stderr or proc.stdout
    except Exception as e:
        return False, str(e)
