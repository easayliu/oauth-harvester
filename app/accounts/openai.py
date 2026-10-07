"""OpenAI / ChatGPT OAuth（Codex CLI PKCE 流）：授权、换 token、刷新、组装导入格式、推送 admin。

登录走的是 ChatGPT「Sign in with ChatGPT」(Codex CLI) 的 PKCE OAuth：
  authorize → 浏览器登录 → 回调 localhost:1455 拿 code → token 端点换 access/id/refresh。
导入格式（platform=openai, type=oauth）里的字段几乎都能从 access_token / id_token 两个
JWT 里解出来，所以只要拿到 token 响应就能反推出完整记录。
"""

import base64
import hashlib
import json
import logging
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from app.settings import (
    OPENAI_API_ADMIN_TOKEN,
    OPENAI_API_BASE_URL,
    OPENAI_API_DEFAULT_GROUP_IDS,
    OPENAI_OAUTH_CLIENT_ID,
    OPENAI_OAUTH_CONCURRENCY,
    OPENAI_OAUTH_PRIORITY,
)

logger = logging.getLogger(__name__)

# Codex CLI 的固定 OAuth 参数（与 access_token 里的 client_id 一致）
OPENAI_AUTHORIZE_URL = "https://auth.openai.com/oauth/authorize"
OPENAI_TOKEN_URL = "https://auth.openai.com/oauth/token"
OPENAI_REDIRECT_URI = "http://localhost:1455/auth/callback"
OPENAI_SCOPE = "openid profile email offline_access"


def _b64url(data: bytes) -> str:
    """base64url 编码且去掉 padding（PKCE / state 用）。"""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def generate_pkce() -> tuple[str, str]:
    """生成 PKCE (code_verifier, code_challenge)，challenge = base64url(sha256(verifier))。"""
    verifier = _b64url(os.urandom(64))
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


def generate_state() -> str:
    """生成随机 state（防 CSRF，回调时用来核对）。"""
    return _b64url(os.urandom(32))


def build_authorize_url(code_challenge: str, state: str, client_id: str = "") -> str:
    """拼出 ChatGPT 授权链接（Codex CLI simplified flow）。"""
    params = {
        "response_type": "code",
        "client_id": client_id or OPENAI_OAUTH_CLIENT_ID,
        "redirect_uri": OPENAI_REDIRECT_URI,
        "scope": OPENAI_SCOPE,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "id_token_add_organizations": "true",
        "codex_cli_simplified_flow": "true",
        "state": state,
    }
    return f"{OPENAI_AUTHORIZE_URL}?{urllib.parse.urlencode(params)}"


def _token_request(form: dict, timeout: int = 30) -> dict:
    """POST 到 OpenAI token 端点（form-urlencoded），返回解析后的 JSON 字典；失败返回 None。"""
    body = urllib.parse.urlencode(form).encode("utf-8")
    req = urllib.request.Request(
        OPENAI_TOKEN_URL,
        data=body,
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            text = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        text = e.read().decode("utf-8", errors="replace") if e.fp else str(e)
        logger.warning(f"token 端点返回 {e.code}: {text[:300]}")
        return None
    except Exception as e:
        logger.warning(f"token 请求异常: {e}")
        return None
    try:
        data = json.loads(text)
    except ValueError:
        logger.warning(f"token 响应非 JSON: {text[:300]}")
        return None
    if not data.get("access_token"):
        logger.warning(f"token 响应缺少 access_token: {text[:300]}")
        return None
    return data


def openai_exchange_code(code: str, code_verifier: str, client_id: str = "") -> dict:
    """用授权 code + code_verifier 换 token，返回 {access_token, id_token, refresh_token, ...}。"""
    return _token_request({
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": OPENAI_REDIRECT_URI,
        "client_id": client_id or OPENAI_OAUTH_CLIENT_ID,
        "code_verifier": code_verifier,
    })


def openai_refresh_tokens(refresh_token: str, client_id: str = "") -> dict:
    """用 refresh_token 换一组新 token（不需要浏览器），返回 token 响应字典。"""
    return _token_request({
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": client_id or OPENAI_OAUTH_CLIENT_ID,
        "scope": OPENAI_SCOPE,
    })


def decode_jwt(token: str) -> dict:
    """解出 JWT 的 payload（不验签，只为读字段）；失败返回 {}。"""
    if not token or token.count(".") < 2:
        return {}
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    try:
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return {}


def email_to_key(email: str) -> str:
    """把 email 转成 email_key：非字母数字一律替换成下划线。"""
    return re.sub(r"[^a-zA-Z0-9]", "_", email or "")


def _default_org_id(id_claims: dict) -> str:
    """从 id_token 的 organizations 里取默认组织 id（没有 is_default 就取第一个）。"""
    auth = id_claims.get("https://api.openai.com/auth") or {}
    orgs = auth.get("organizations") or []
    if not orgs:
        return ""
    for org in orgs:
        if org.get("is_default"):
            return org.get("id", "")
    return orgs[0].get("id", "")


def build_openai_oauth_record(token_data: dict, name: str = "",
                              concurrency: int = -1, priority: int = -1) -> dict:
    """把 token 响应拼成可直接导入的账号记录（platform=openai, type=oauth）。

    access_token / id_token 两个 JWT 里解出 email、chatgpt_account_id、chatgpt_user_id、
    plan_type、organization_id；expires_at 取 access_token 的 exp，expires_in 取「exp - 当前时间」。
    """
    if not token_data or not token_data.get("access_token"):
        raise ValueError("token_data 为空或缺少 access_token")

    access_token = token_data.get("access_token", "")
    id_token = token_data.get("id_token", "")
    refresh_token = token_data.get("refresh_token", "")

    ac = decode_jwt(access_token)
    idc = decode_jwt(id_token)
    auth = ac.get("https://api.openai.com/auth") or {}
    profile = ac.get("https://api.openai.com/profile") or {}

    email = (profile.get("email") or idc.get("email")
             or token_data.get("email") or "")
    chatgpt_account_id = auth.get("chatgpt_account_id", "")
    chatgpt_user_id = auth.get("chatgpt_user_id", "")
    plan_type = auth.get("chatgpt_plan_type", "")
    organization_id = _default_org_id(idc) or _default_org_id(ac)

    exp = ac.get("exp")
    if isinstance(exp, (int, float)):
        expires_at = datetime.fromtimestamp(int(exp), tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.000Z")
        expires_in = max(0, int(exp) - int(time.time()))
    else:
        expires_at = ""
        expires_in = token_data.get("expires_in", 0)

    if concurrency < 0:
        concurrency = OPENAI_OAUTH_CONCURRENCY
    if priority < 0:
        priority = OPENAI_OAUTH_PRIORITY

    credentials = {
        "access_token": access_token,
        "chatgpt_account_id": chatgpt_account_id,
        "chatgpt_user_id": chatgpt_user_id,
        "email": email,
        "expires_at": expires_at,
        "expires_in": expires_in,
        "id_token": id_token,
        "organization_id": organization_id,
        "plan_type": plan_type,
        "refresh_token": refresh_token,
    }

    return {
        "name": name or email,
        "platform": "openai",
        "type": "oauth",
        "concurrency": concurrency,
        "priority": priority,
        "credentials": credentials,
        "extra": {
            "email": email,
            "email_key": email_to_key(email),
        },
    }


def register_openai_oauth_account(record: dict, base_url: str = "", token: str = "",
                                  group_ids=None, timeout: int = 30) -> bool:
    """把组装好的 openai oauth 记录 POST 到 admin /api/v1/admin/accounts。

    需要 config.py 配置 OPENAI_API_BASE_URL / OPENAI_API_ADMIN_TOKEN，未配置则跳过返回 False。
    """
    base_url = (base_url or OPENAI_API_BASE_URL).rstrip("/")
    token = token or OPENAI_API_ADMIN_TOKEN
    group_ids = group_ids if group_ids is not None else OPENAI_API_DEFAULT_GROUP_IDS

    if not base_url or not token:
        logger.info("OPENAI_API_BASE_URL / OPENAI_API_ADMIN_TOKEN 未配置，跳过推送")
        return False
    if not record or not record.get("credentials", {}).get("access_token"):
        logger.warning("记录缺少 access_token，跳过推送")
        return False

    payload = dict(record)
    payload.setdefault("notes", "")
    payload["proxy_id"] = None
    payload["auto_pause_on_expired"] = True
    if group_ids:
        payload["group_ids"] = list(group_ids)

    url = f"{base_url}/api/v1/admin/accounts"
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-API-Key": token,
        },
        method="POST",
    )
    name = record.get("name", "")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
            text = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        status = e.code
        text = e.read().decode("utf-8", errors="replace") if e.fp else str(e)
    except Exception as e:
        logger.warning(f"openai 推送请求异常 ({name}): {e}")
        return False

    if 200 <= status < 300:
        logger.info(f"openai 推送成功 [{status}] {name}: {text[:160]}")
        return True
    logger.warning(f"openai 推送失败 [{status}] {name}: {text[:300]}")
    return False
