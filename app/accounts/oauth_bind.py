"""claude-bind：把一个已登录的 Claude 账号通过 OAuth 授权加到 oauth-accounts 后台。

两步：
  1. GET  /api/admin/oauth-accounts/auth-url  —— 拿到授权链接 auth_url + pending_state
  2. 在已登录 Claude 的浏览器里打开 auth_url，点「Authorize」后回跳 callback 带回 code
  3. POST /api/admin/oauth-accounts/exchange  —— 用 code + pending_state 换取并落库

鉴权方式与 disabled 模式完全一致：优先 access_token，401 时用 refresh_token 刷新后重试。
"""

import json
import logging
import urllib.error
import urllib.parse
import urllib.request

from app.settings import (
    OAUTH_ADMIN_API_BASE_URL,
    OAUTH_ADMIN_API_REFRESH_TOKEN,
    OAUTH_ADMIN_API_TOKEN,
    OAUTH_BIND_BACKEND,
    OAUTH_BIND_GROUP_IDS,
    OAUTH_BIND_INFERENCE_BACKEND,
    OAUTH_BIND_MAX_CONCURRENT,
    OAUTH_BIND_MAX_RPM,
    OAUTH_BIND_MAX_SESSIONS,
    OAUTH_BIND_MAX_TPM,
    OAUTH_BIND_OUTBOUND_PROXY_ID,
    OAUTH_BIND_OUTBOUND_PROXY_MODE,
    OAUTH_BIND_POLICY_TEMPLATE_ID,
    OAUTH_BIND_GROUP_NAMES,
    OAUTH_BIND_POLICY_TEMPLATE_NAME,
    LUBAN_ADMIN_PASSWORD,
    LUBAN_BASE_URL,
    LUBAN_BIND_LABEL,
    LUBAN_BIND_PROXY,
    LUBAN_BIND_PROXY_ID,
)

logger = logging.getLogger(__name__)

AUTH_URL_PATH = "/api/admin/oauth-accounts/auth-url"
EXCHANGE_PATH = "/api/admin/oauth-accounts/exchange"
# 分组 / 策略模板列表（vendor 可读；注意模板用 account-policy-templates，/policy-templates 是 admin 专属）
GROUPS_PATH = "/api/admin/groups"
ACCOUNT_POLICY_TEMPLATES_PATH = "/api/admin/account-policy-templates"

# luban 后端的接口路径（鉴权为 Authorization: Bearer <管理员密码>）
LUBAN_AUTHORIZE_PATH = "/api/authorize"
LUBAN_EXCHANGE_PATH = "/api/exchange"
LUBAN_PROXIES_PATH = "/api/proxies"

# LUBAN_BIND_PROXY_ID 解析出的代理 URL，进程内只查一次
_luban_proxy_url_cache: dict = {}


def _state_from_url(url: str) -> str:
    """从授权 URL 的 state 查询参数里取 pending_state。"""
    try:
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
        return (qs.get("state") or [""])[0]
    except Exception:
        return ""


def _refresh_access_token(base_url: str, refresh_token: str) -> str | None:
    """用 refresh_token 刷新 access_token（与 disabled 模式同一接口）。"""
    url = f"{base_url}/api/auth/refresh"
    req = urllib.request.Request(
        url,
        data=b"",
        headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Cookie": f"refresh_token={refresh_token}",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            text = resp.read().decode("utf-8", errors="replace")
            data = json.loads(text)
            token = (data.get("accessToken")
                     or data.get("access_token")
                     or data.get("token")
                     or (data.get("data") or {}).get("accessToken")
                     or (data.get("data") or {}).get("access_token"))
            if token:
                logger.info("refresh_token 刷新成功，已获取新 access_token")
                return token
            for val in (resp.headers.get_all("Set-Cookie") or []):
                if "access_token=" in val or "token=" in val:
                    for part in val.split(";"):
                        k, _, v = part.strip().partition("=")
                        if k in ("access_token", "token") and v:
                            return v
            logger.warning(f"refresh 响应中未找到 token: {text[:300]}")
            return None
    except Exception as e:
        logger.warning(f"refresh_token 刷新失败: {e}")
        return None


def _auth_headers(token: str) -> dict:
    headers = {"Accept": "application/json"}
    if token:
        if token.lower().startswith("bearer "):
            token = token[7:].strip()
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _request(base_url: str, path: str, token: str, refresh_token: str = "",
             method: str = "GET", body: dict = None) -> tuple:
    """向 admin API 发请求，返回 (parsed_json, raw_text)。401 且有 refresh_token 时自动刷新重试一次。"""
    url = f"{base_url}{path}"
    data = json.dumps(body).encode("utf-8") if body is not None else (b"" if method == "POST" else None)
    headers = _auth_headers(token)
    if body is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            text = resp.read().decode("utf-8", errors="replace")
            return (json.loads(text) if text.strip() else {}), text
    except urllib.error.HTTPError as e:
        status = e.code
        err_text = e.read().decode("utf-8", errors="replace") if e.fp else str(e)
        if status == 401 and refresh_token:
            new_token = _refresh_access_token(base_url, refresh_token)
            if new_token:
                return _request(base_url, path, new_token, "", method, body)
        raise RuntimeError(f"请求失败 [{status}] {path}: {err_text[:500]}")


def get_access_token(base_url: str = None, token: str = None, refresh_token: str = None) -> str:
    """拿到可用的 access_token：优先传入/配置的 token，否则用 refresh_token 刷新。"""
    base_url = (base_url or OAUTH_ADMIN_API_BASE_URL).rstrip("/")
    token = token if token is not None else OAUTH_ADMIN_API_TOKEN
    refresh_token = refresh_token if refresh_token is not None else OAUTH_ADMIN_API_REFRESH_TOKEN
    if token:
        return token
    if refresh_token:
        new_token = _refresh_access_token(base_url, refresh_token)
        if new_token:
            return new_token
        raise RuntimeError("refresh_token 刷新失败，请检查 OAUTH_ADMIN_API_REFRESH_TOKEN 是否过期")
    raise RuntimeError("未配置 OAUTH_ADMIN_API_TOKEN / OAUTH_ADMIN_API_REFRESH_TOKEN")


def get_auth_url(*args, backend: str = None, **kwargs) -> tuple:
    """按后端类型分发：拿授权链接，返回 (auth_url, pending_state)。

    backend 省略时取 config 的 OAUTH_BIND_BACKEND（default / luban）。
    """
    backend = backend or OAUTH_BIND_BACKEND
    if backend == "luban":
        return _get_auth_url_luban()
    return _get_auth_url_default(*args, **kwargs)


def exchange(code: str, pending_state: str, *args, backend: str = None, **kwargs) -> dict:
    """按后端类型分发：用 code 换取并落库，返回解析后的 JSON。"""
    backend = backend or OAUTH_BIND_BACKEND
    if backend == "luban":
        return _exchange_luban(code)
    return _exchange_default(code, pending_state, *args, **kwargs)


# ---------- luban 后端：GET /api/authorize + POST /api/exchange，Bearer <管理员密码> ----------

def _get_auth_url_luban() -> tuple:
    """luban：GET /api/authorize（Bearer 管理员密码）→ {url}；pending_state 从 url 的 state 取。"""
    if not LUBAN_ADMIN_PASSWORD:
        raise RuntimeError("未配置 LUBAN_ADMIN_PASSWORD（luban 网页『接入设置』里设的管理员密码）")
    base_url = LUBAN_BASE_URL.rstrip("/")
    data, raw = _request(base_url, LUBAN_AUTHORIZE_PATH, LUBAN_ADMIN_PASSWORD, "", method="GET")
    auth_url = data.get("url") if isinstance(data, dict) else None
    if not auth_url:
        raise RuntimeError(f"luban authorize 响应缺少 url: {raw[:500]}")
    pending_state = _state_from_url(auth_url)
    if not pending_state:
        raise RuntimeError(f"luban authorize 的 url 里没有 state 参数: {auth_url[:300]}")
    return auth_url, pending_state


def _exchange_luban(code: str) -> dict:
    """luban：POST /api/exchange（Bearer 管理员密码），body {code, label?, proxy?}。

    proxy 取 LUBAN_BIND_PROXY；为空时用 LUBAN_BIND_PROXY_ID 从代理池解析出 URL
    （exchange 只认 URL，luban 按 URL 把账号关联回代理池那一条）。

    luban 的 exchange 从 code 自己解析 state，不需要单独传 pending_state；
    group/template/限额由 luban 用 /credentials 单独管理，此处不带。
    """
    if not LUBAN_ADMIN_PASSWORD:
        raise RuntimeError("未配置 LUBAN_ADMIN_PASSWORD")
    base_url = LUBAN_BASE_URL.rstrip("/")
    payload = {"code": code}
    if LUBAN_BIND_LABEL:
        payload["label"] = LUBAN_BIND_LABEL
    proxy = LUBAN_BIND_PROXY or _luban_proxy_url_by_id(base_url, LUBAN_BIND_PROXY_ID)
    if proxy:
        payload["proxy"] = proxy
    data, raw = _request(base_url, LUBAN_EXCHANGE_PATH, LUBAN_ADMIN_PASSWORD, "", method="POST", body=payload)
    return data if isinstance(data, dict) else {"raw": raw}


def _luban_proxy_url_by_id(base_url: str, proxy_id) -> str | None:
    """按 luban 代理池 id 查完整代理 URL（GET /api/proxies，管理员 Bearer 拿到的 URL 带密码）。"""
    if proxy_id in (None, ""):
        return None
    try:
        pid = int(proxy_id)
    except (TypeError, ValueError):
        raise RuntimeError(f"LUBAN_BIND_PROXY_ID 不是整数: {proxy_id!r}")
    if pid in _luban_proxy_url_cache:
        return _luban_proxy_url_cache[pid]
    data, raw = _request(base_url, LUBAN_PROXIES_PATH, LUBAN_ADMIN_PASSWORD, "", method="GET")
    if not isinstance(data, list):
        raise RuntimeError(f"luban /api/proxies 响应无法解析: {raw[:500]}")
    for p in data:
        if isinstance(p, dict) and p.get("id") == pid:
            url = p.get("url")
            if not url:
                raise RuntimeError(f"luban 代理池 id={pid} 没有 url")
            logger.info(f"luban 代理池 id={pid} ({p.get('label')}) 已解析为出站代理")
            _luban_proxy_url_cache[pid] = url
            return url
    available = ", ".join(f"{p.get('id')}={p.get('label')}" for p in data if isinstance(p, dict)) or "（代理池为空）"
    raise RuntimeError(f"luban 代理池里没有 id={pid}；可选: {available}")


# ---------- default 后端：oauth-accounts 后台（POST auth-url + POST exchange） ----------

def _get_auth_url_default(base_url: str = None, token: str = None, refresh_token: str = None,
                          provider: str = "anthropic", oauth_flow: str = "login",
                          name: str = None) -> tuple:
    """POST auth-url，返回 (auth_url, pending_state)。

    请求体与后台前端一致（vendor 账号必须走 POST，GET 会 403 Not available for vendor accounts）：
      {outbound_proxy_mode, outbound_proxy_id, provider, oauth_flow, name,
       inference_backend, overwrite_existing}
    返回体字段为 {url, state}（做了多名兼容）。
    """
    base_url = (base_url or OAUTH_ADMIN_API_BASE_URL).rstrip("/")
    token = token if token is not None else OAUTH_ADMIN_API_TOKEN
    refresh_token = refresh_token if refresh_token is not None else OAUTH_ADMIN_API_REFRESH_TOKEN
    body = {
        "outbound_proxy_mode": OAUTH_BIND_OUTBOUND_PROXY_MODE,
        "outbound_proxy_id": OAUTH_BIND_OUTBOUND_PROXY_ID,
        "provider": provider,
        "oauth_flow": oauth_flow,
        "name": name,
        "inference_backend": OAUTH_BIND_INFERENCE_BACKEND,
        "overwrite_existing": False,
    }
    data, raw = _request(base_url, AUTH_URL_PATH, token, refresh_token, method="POST", body=body)

    container = data.get("data") if isinstance(data, dict) and isinstance(data.get("data"), dict) else data
    if not isinstance(container, dict):
        raise RuntimeError(f"auth-url 响应无法解析: {raw[:500]}")

    auth_url = (container.get("auth_url") or container.get("authUrl")
                or container.get("authorize_url") or container.get("authorizeUrl")
                or container.get("url"))
    pending_state = (container.get("pending_state") or container.get("pendingState")
                     or container.get("state"))

    # 兜底：pending_state 没单独给，就从 auth_url 的 state 参数里取
    if auth_url and not pending_state:
        try:
            qs = urllib.parse.parse_qs(urllib.parse.urlparse(auth_url).query)
            pending_state = (qs.get("state") or [None])[0]
        except Exception:
            pass

    if not auth_url or not pending_state:
        raise RuntimeError(f"auth-url 响应缺少 auth_url / pending_state: {raw[:500]}")
    return auth_url, pending_state


# 列表项里表示「已授权给当前 vendor」的布尔字段名（不同后端命名不一，能命中就按它过滤）
_GRANTED_FLAGS = ("granted", "is_granted", "isGranted", "vendor_granted",
                  "vendorGranted", "allowed", "is_allowed")


def _list_raw(base_url: str, path: str, token: str, refresh_token: str) -> list:
    """GET 一个 {items:[...]} 或 [...] 列表接口，返回原始 dict 列表。"""
    data, raw = _request(base_url, path, token, refresh_token, method="GET")
    items = data.get("items") if isinstance(data, dict) else (data if isinstance(data, list) else [])
    return [it for it in (items or []) if isinstance(it, dict)]


def _to_id_name(it: dict) -> tuple:
    name = it.get("name") or it.get("title") or it.get("label") or ""
    return str(it["id"]), str(name)


def _granted_only(items: list) -> list:
    """若列表项带「已授权」布尔字段，仅保留为真的；都不带该字段则原样返回。
    过滤后为空时退回原列表，避免把能用的也误删。"""
    flagged = [it for it in items if any(f in it for f in _GRANTED_FLAGS)]
    if not flagged:
        return items
    kept = [it for it in items if any(it.get(f) for f in _GRANTED_FLAGS)]
    return kept or items


def _list_items(base_url: str, path: str, token: str, refresh_token: str) -> list:
    """GET 一个 {items:[{id,name}...]} 列表接口，返回 [(id, name), ...]。"""
    return [_to_id_name(it) for it in _list_raw(base_url, path, token, refresh_token)
            if it.get("id") is not None]


def list_groups(base_url: str = None, token: str = None, refresh_token: str = None) -> list:
    """列出后台分组，返回 [(id, name), ...]。"""
    base_url = (base_url or OAUTH_ADMIN_API_BASE_URL).rstrip("/")
    token = token if token is not None else OAUTH_ADMIN_API_TOKEN
    refresh_token = refresh_token if refresh_token is not None else OAUTH_ADMIN_API_REFRESH_TOKEN
    return _list_items(base_url, GROUPS_PATH, token, refresh_token)


def list_policy_templates(base_url: str = None, token: str = None, refresh_token: str = None) -> list:
    """列出后台策略模板（vendor 可读的 account-policy-templates），返回 [(id, name), ...]。
    若接口返回里带「已授权」标记，只保留授权给当前 vendor 的，避免挑到没授权的模板。"""
    base_url = (base_url or OAUTH_ADMIN_API_BASE_URL).rstrip("/")
    token = token if token is not None else OAUTH_ADMIN_API_TOKEN
    refresh_token = refresh_token if refresh_token is not None else OAUTH_ADMIN_API_REFRESH_TOKEN
    raw = _granted_only(_list_raw(base_url, ACCOUNT_POLICY_TEMPLATES_PATH, token, refresh_token))
    return [_to_id_name(it) for it in raw if it.get("id") is not None]


def _pick_ids(items: list, wanted_names, kind: str) -> list:
    """从 [(id,name)] 里按名称挑 id；名称为空时若只有一个就自动选，多个则报错列出。"""
    names = [n for n in (wanted_names if isinstance(wanted_names, list) else [wanted_names]) if n]
    if names:
        by_name = {n: i for i, n in items}
        missing = [n for n in names if n not in by_name]
        if missing:
            avail = "、".join(n for _, n in items) or "(空)"
            raise RuntimeError(f"{kind}名称未找到: {missing}；后台可选: {avail}")
        return [by_name[n] for n in names]
    if len(items) == 1:
        logger.info(f"自动选择{kind}: {items[0][1]}={items[0][0]}")
        return [items[0][0]]
    listing = "；".join(f"{n}={i}" for i, n in items) or "(空)"
    raise RuntimeError(
        f"{kind}有 {len(items)} 个，无法自动确定，请在 config 填 id 或名称。可选: {listing}")


def resolve_bind_targets(token: str = None, refresh_token: str = None,
                         group_ids: list = None, policy_template_id: str = None) -> tuple:
    """补齐 (group_ids, policy_template_id)：显式 id > config id > 按名称查 > 唯一则自动选。

    只在缺失时才请求对应列表接口。
    """
    gids = group_ids if group_ids else (list(OAUTH_BIND_GROUP_IDS) if OAUTH_BIND_GROUP_IDS else [])
    tpl = policy_template_id or OAUTH_BIND_POLICY_TEMPLATE_ID or ""
    if not gids:
        gids = _pick_ids(list_groups(token=token, refresh_token=refresh_token),
                         OAUTH_BIND_GROUP_NAMES, "分组")
    if not tpl:
        tpl = _pick_ids(list_policy_templates(token=token, refresh_token=refresh_token),
                        OAUTH_BIND_POLICY_TEMPLATE_NAME, "策略模板")[0]
    return gids, tpl


def _exchange_default(code: str, pending_state: str, base_url: str = None,
                      token: str = None, refresh_token: str = None,
                      group_ids: list = None, policy_template_id: str = None) -> dict:
    """POST exchange，用 code + pending_state 换取并落库。返回解析后的 JSON。

    group_ids / policy_template_id 未显式传、config 里也空时，用 token 自动查后台 id。
    """
    base_url = (base_url or OAUTH_ADMIN_API_BASE_URL).rstrip("/")
    token = token if token is not None else OAUTH_ADMIN_API_TOKEN
    refresh_token = refresh_token if refresh_token is not None else OAUTH_ADMIN_API_REFRESH_TOKEN
    group_ids, policy_template_id = resolve_bind_targets(
        token, refresh_token, group_ids, policy_template_id)
    logger.info(f"exchange 使用 group_ids={group_ids} policy_template_id={policy_template_id}")
    payload = {
        "code": code,
        "pending_state": pending_state,
        "inference_backend": OAUTH_BIND_INFERENCE_BACKEND,
        "outbound_proxy_mode": OAUTH_BIND_OUTBOUND_PROXY_MODE,
        "outbound_proxy_id": OAUTH_BIND_OUTBOUND_PROXY_ID,
        "max_rpm": OAUTH_BIND_MAX_RPM,
        "max_tpm": OAUTH_BIND_MAX_TPM,
        "max_concurrent": OAUTH_BIND_MAX_CONCURRENT,
        "max_sessions": OAUTH_BIND_MAX_SESSIONS,
        "group_ids": group_ids,
        "policy_template_id": policy_template_id,
    }
    try:
        data, raw = _request(base_url, EXCHANGE_PATH, token, refresh_token, method="POST", body=payload)
    except RuntimeError as e:
        # 配的 / 默认的 policy_template_id 没授权给当前 vendor（常见于换后端后旧 id 失效）：
        # 忽略它，从后台「已授权」模板里重新挑一个重试一次。
        if "policy_template_id is not granted" not in str(e):
            raise
        logger.warning(f"策略模板 {policy_template_id} 未授权给当前 vendor，改从后台可用模板自动挑选重试...")
        avail = list_policy_templates(token=token, refresh_token=refresh_token)
        retry_tpl = _pick_ids(avail, OAUTH_BIND_POLICY_TEMPLATE_NAME, "策略模板")[0]
        if retry_tpl == policy_template_id:
            raise RuntimeError(
                f"{e}；且后台可用模板里仍只挑到同一个 {retry_tpl}，"
                f"请在后台确认当前 vendor 已被授予可用策略模板，或在 config 的 "
                f"OAUTH_BIND_POLICY_TEMPLATE_NAME 指定授权的模板名")
        logger.info(f"改用策略模板 {retry_tpl} 重试 exchange")
        payload["policy_template_id"] = retry_tpl
        data, raw = _request(base_url, EXCHANGE_PATH, token, refresh_token, method="POST", body=payload)
    return data if isinstance(data, dict) else {"raw": raw}
