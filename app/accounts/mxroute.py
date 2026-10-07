"""MXroute 邮箱托管 API 客户端（api.mxroute.com）。

认证需要三个 header：X-Server / X-Username / X-API-Key。
文档：https://api.mxroute.com/docs
"""

import json
import logging
import urllib.error
import urllib.parse
import urllib.request

from app.settings import (
    MXROUTE_API_BASE_URL,
    MXROUTE_API_KEY,
    MXROUTE_SERVER,
    MXROUTE_USERNAME,
)

logger = logging.getLogger(__name__)


class MXRouteError(Exception):
    """MXroute API 调用失败（携带 HTTP 状态码与响应体）。"""

    def __init__(self, status: int, message: str, code: str = ""):
        self.status = status
        self.code = code
        super().__init__(message)


def _check_credentials():
    missing = [
        name
        for name, val in (
            ("MXROUTE_SERVER", MXROUTE_SERVER),
            ("MXROUTE_USERNAME", MXROUTE_USERNAME),
            ("MXROUTE_API_KEY", MXROUTE_API_KEY),
        )
        if not val
    ]
    if missing:
        raise MXRouteError(0, "MXroute 凭据未配置：" + ", ".join(missing))


def _request(path: str, method: str = "GET", payload=None, timeout: int = 30) -> tuple:
    """向 MXroute API 发请求，返回 (status, parsed_json_or_None, raw_text)。"""
    _check_credentials()
    base = (MXROUTE_API_BASE_URL or "https://api.mxroute.com").rstrip("/")
    url = f"{base}{path}"
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {
        "Accept": "application/json",
        "X-Server": MXROUTE_SERVER,
        "X-Username": MXROUTE_USERNAME,
        "X-API-Key": MXROUTE_API_KEY,
    }
    if data is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
            text = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        status = e.code
        text = e.read().decode("utf-8", errors="replace") if e.fp else str(e)
    except Exception as e:
        raise MXRouteError(0, f"请求异常 {method} {path}: {e}")
    try:
        parsed = json.loads(text) if text else None
    except ValueError:
        parsed = None
    return status, parsed, text


def _raise_for_status(status: int, parsed, text: str, ok=(200, 201, 204)):
    if status in ok:
        return
    code = ""
    message = text[:300]
    if isinstance(parsed, dict):
        err = parsed.get("error") or {}
        if isinstance(err, dict):
            code = err.get("code", "")
            message = err.get("message") or message
    raise MXRouteError(status, message, code)


def list_email_accounts(domain: str, timeout: int = 30) -> list:
    """列出域名下的邮箱账号，返回 EmailAccount 列表。"""
    dom = urllib.parse.quote(domain, safe="")
    status, parsed, text = _request(f"/domains/{dom}/email-accounts", "GET", timeout=timeout)
    _raise_for_status(status, parsed, text, ok=(200,))
    if isinstance(parsed, dict):
        return parsed.get("data") or []
    return []


def create_email_account(domain: str, username: str, password: str,
                         quota: int = None, limit: int = None, timeout: int = 30) -> dict:
    """创建邮箱账号。username 为 @ 前的本地部分。"""
    payload = {"username": username, "password": password}
    if quota is not None:
        payload["quota"] = int(quota)
    if limit is not None:
        payload["limit"] = int(limit)
    dom = urllib.parse.quote(domain, safe="")
    status, parsed, text = _request(f"/domains/{dom}/email-accounts", "POST", payload, timeout)
    _raise_for_status(status, parsed, text, ok=(200, 201))
    return parsed if isinstance(parsed, dict) else {}


def delete_email_account(domain: str, username: str, timeout: int = 30) -> None:
    """删除邮箱账号。username 为 @ 前的本地部分。"""
    dom = urllib.parse.quote(domain, safe="")
    user = urllib.parse.quote(username, safe="")
    status, parsed, text = _request(
        f"/domains/{dom}/email-accounts/{user}", "DELETE", timeout=timeout
    )
    _raise_for_status(status, parsed, text, ok=(200, 204))


def get_email_account(domain: str, username: str, timeout: int = 30) -> dict:
    """获取单个邮箱账号详情。"""
    dom = urllib.parse.quote(domain, safe="")
    user = urllib.parse.quote(username, safe="")
    status, parsed, text = _request(
        f"/domains/{dom}/email-accounts/{user}", "GET", timeout=timeout
    )
    _raise_for_status(status, parsed, text, ok=(200,))
    if isinstance(parsed, dict):
        return parsed.get("data") or {}
    return {}


def split_email(addr: str, default_domain: str = "") -> tuple:
    """把 'user@domain' 拆成 (local, domain)；无 @ 时用 default_domain。"""
    addr = addr.strip()
    if "@" in addr:
        local, _, domain = addr.partition("@")
        return local, domain
    return addr, (default_domain or "")
