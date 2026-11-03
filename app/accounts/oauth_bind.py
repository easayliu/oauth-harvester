"""claude-bind：把一个已登录的 Claude 账号通过 OAuth 授权加到 oauth-accounts 后台。

两步：
  1. GET  /api/admin/oauth-accounts/auth-url  —— 拿到授权链接 auth_url + pending_state
  2. 在已登录 Claude 的浏览器里打开 auth_url，点「Authorize」后回跳 callback 带回 code
  3. POST /api/admin/oauth-accounts/exchange  —— 用 code + pending_state 换取并落库

鉴权方式与 disabled 模式完全一致：优先 access_token，401 时用 refresh_token 刷新后重试。
"""

import json
import logging
import threading
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
    LUBAN_BIND_GROUP_IDS,
    LUBAN_BIND_GROUP_NAMES,
    LUBAN_PROVISION_KEY,
    LUBAN_USERNAME,
)

logger = logging.getLogger(__name__)

AUTH_URL_PATH = "/api/admin/oauth-accounts/auth-url"
EXCHANGE_PATH = "/api/admin/oauth-accounts/exchange"
# 分组 / 策略模板列表（vendor 可读；注意模板用 account-policy-templates，/policy-templates 是 admin 专属）
GROUPS_PATH = "/api/admin/groups"
ACCOUNT_POLICY_TEMPLATES_PATH = "/api/admin/account-policy-templates"

# luban 后端的接口路径（鉴权见下方 luban 小节）
LUBAN_LOGIN_PATH = "/api/auth/login"
LUBAN_AUTHORIZE_PATH = "/api/authorize"
LUBAN_EXCHANGE_PATH = "/api/exchange"
LUBAN_GROUPS_PATH = "/api/groups"
# luban 上号 Key 的前缀（store::PROVISION_KEY_PREFIX）
LUBAN_PROVISION_KEY_PREFIX = "lbp-"


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


class RequestError(RuntimeError):
    """admin API 返回非 2xx；status 供调用方区分 401 等。"""

    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


def _request(base_url: str, path: str, token: str, refresh_token: str = "",
             method: str = "GET", body: dict = None, timeout: float = 30) -> tuple:
    """向 admin API 发请求，返回 (parsed_json, raw_text)。401 且有 refresh_token 时自动刷新重试一次。"""
    url = f"{base_url}{path}"
    data = json.dumps(body).encode("utf-8") if body is not None else (b"" if method == "POST" else None)
    headers = _auth_headers(token)
    if body is not None:
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            text = resp.read().decode("utf-8", errors="replace")
            return (json.loads(text) if text.strip() else {}), text
    except urllib.error.HTTPError as e:
        status = e.code
        err_text = e.read().decode("utf-8", errors="replace") if e.fp else str(e)
        if status == 401 and refresh_token:
            new_token = _refresh_access_token(base_url, refresh_token)
            if new_token:
                return _request(base_url, path, new_token, "", method, body, timeout)
        raise RequestError(status, f"请求失败 [{status}] {path}: {err_text[:500]}")


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
        return _get_auth_url_luban(token=kwargs.get("token"))
    return _get_auth_url_default(*args, **kwargs)


def exchange(code: str, pending_state: str, *args, backend: str = None, **kwargs) -> dict:
    """按后端类型分发：用 code 换取并落库，返回解析后的 JSON。"""
    backend = backend or OAUTH_BIND_BACKEND
    if backend == "luban":
        return _exchange_luban(code, token=kwargs.get("token"))
    return _exchange_default(code, pending_state, *args, **kwargs)


# ---------- luban 后端：GET /api/authorize + POST /api/exchange ----------
#
# luban 控制台已改成「用户名 + 密码登录换会话 token」，管理员密码不能再直接当 Bearer。
# Bearer 按优先级取：
#   1. 命令行 --admin-token= 传入的（上号 Key 或会话 token）
#   2. LUBAN_PROVISION_KEY：上号 Key（lbp-…，网页账号菜单「上号 Key」里建）。只能取授权链接、
#      交授权码、列分组与代理池，泄露了也只能往这个人名下添号；不指定代理时 luban 从本人代理池
#      按挂号从少到多自动挑一条测通的（池空才直连）
#   3. LUBAN_USERNAME + LUBAN_ADMIN_PASSWORD：POST /api/auth/login 换会话 token，进程内缓存，
#      401（改过密码 / 会话过期）时重登一次
# 授权链接按发起人隔离：authorize 与 exchange 必须是同一个人（同一把 Key 或同一用户）。

_luban_session: dict = {"token": None}
_luban_session_lock = threading.Lock()
# LUBAN_BIND_GROUP_NAMES 解析出的分组 id，进程内只查一次
_luban_group_ids_cache: list | None = None


def _luban_base_url() -> str:
    return LUBAN_BASE_URL.rstrip("/")


def _luban_static_token(token: str = None) -> str | None:
    """不用登录就能直接当 Bearer 的：命令行 token > LUBAN_PROVISION_KEY；
    LUBAN_ADMIN_PASSWORD 里填的若是上号 Key（lbp- 开头）也认。"""
    for t in (token, LUBAN_PROVISION_KEY):
        if t and t.strip():
            return t.strip()
    pw = (LUBAN_ADMIN_PASSWORD or "").strip()
    if pw.startswith(LUBAN_PROVISION_KEY_PREFIX):
        return pw
    return None


def _luban_login(stale: str = None) -> str:
    """用户名 + 密码换会话 token。stale 是刚被 401 的那个：缓存仍是它才重登，
    否则说明别的线程已经重登过，直接用新的。"""
    with _luban_session_lock:
        cur = _luban_session["token"]
        if cur and cur != stale:
            return cur
        if not LUBAN_ADMIN_PASSWORD:
            raise RuntimeError("未配置 luban 鉴权：填 LUBAN_PROVISION_KEY（上号 Key，推荐），"
                               "或 LUBAN_USERNAME + LUBAN_ADMIN_PASSWORD")
        username = LUBAN_USERNAME or "admin"
        try:
            data, raw = _request(_luban_base_url(), LUBAN_LOGIN_PATH, "", method="POST",
                                 body={"username": username, "password": LUBAN_ADMIN_PASSWORD})
        except RequestError as e:
            raise RuntimeError(f"luban 登录失败（用户名 {username}）: {e}") from e
        tok = data.get("token") if isinstance(data, dict) else None
        if not tok:
            raise RuntimeError(f"luban 登录响应缺少 token: {raw[:300]}")
        logger.info(f"luban 已登录: {data.get('username') or username} ({data.get('role')})")
        _luban_session["token"] = tok
        return tok


def _luban_request(path: str, method: str = "GET", body: dict = None,
                   token: str = None, timeout: float = 30) -> tuple:
    """带 luban 鉴权发请求；走会话 token 时 401 自动重登重试一次。"""
    base_url = _luban_base_url()
    static = _luban_static_token(token)
    if static:
        return _request(base_url, path, static, "", method, body, timeout)
    tok = _luban_login()
    try:
        return _request(base_url, path, tok, "", method, body, timeout)
    except RequestError as e:
        if e.status != 401:
            raise
        logger.info("luban 会话失效，重新登录后重试")
        return _request(base_url, path, _luban_login(stale=tok), "", method, body, timeout)


def _luban_proxy_id() -> int | None:
    if LUBAN_BIND_PROXY_ID in (None, ""):
        return None
    try:
        return int(LUBAN_BIND_PROXY_ID)
    except (TypeError, ValueError):
        raise RuntimeError(f"LUBAN_BIND_PROXY_ID 不是整数: {LUBAN_BIND_PROXY_ID!r}")


def _luban_group_ids(token: str = None) -> list:
    """exchange 的 group_ids：LUBAN_BIND_GROUP_IDS 直接用；否则按 LUBAN_BIND_GROUP_NAMES
    查 GET /api/groups 解析；都没填返回 []（luban 放进默认分组）。"""
    global _luban_group_ids_cache
    if LUBAN_BIND_GROUP_IDS:
        try:
            return [int(g) for g in LUBAN_BIND_GROUP_IDS]
        except (TypeError, ValueError):
            raise RuntimeError(f"LUBAN_BIND_GROUP_IDS 必须是整数列表: {LUBAN_BIND_GROUP_IDS!r}")
    names = [n.strip() for n in (LUBAN_BIND_GROUP_NAMES or []) if n and n.strip()]
    if not names:
        return []
    if _luban_group_ids_cache is not None:
        return _luban_group_ids_cache
    data, raw = _luban_request(LUBAN_GROUPS_PATH, token=token)
    if not isinstance(data, list):
        raise RuntimeError(f"luban /api/groups 响应无法解析: {raw[:500]}")
    by_name = {g.get("name"): g.get("id") for g in data if isinstance(g, dict)}
    missing = [n for n in names if n not in by_name]
    if missing:
        available = ", ".join(f"{g.get('id')}={g.get('name')}" for g in data if isinstance(g, dict)) or "（无可选分组）"
        raise RuntimeError(f"luban 分组里没有 {missing}；可选: {available}")
    _luban_group_ids_cache = [by_name[n] for n in names]
    logger.info(f"luban 分组 {names} → id {_luban_group_ids_cache}")
    return _luban_group_ids_cache


def _get_auth_url_luban(token: str = None) -> tuple:
    """luban：GET /api/authorize → {url}；pending_state 从 url 的 state 取。

    分组名 / 代理 id 在这里先校验：配错了在开浏览器授权之前就报，不白跑一趟授权。
    """
    _luban_proxy_id()
    _luban_group_ids(token)
    data, raw = _luban_request(LUBAN_AUTHORIZE_PATH, token=token)
    auth_url = data.get("url") if isinstance(data, dict) else None
    if not auth_url:
        raise RuntimeError(f"luban authorize 响应缺少 url: {raw[:500]}")
    pending_state = _state_from_url(auth_url)
    if not pending_state:
        raise RuntimeError(f"luban authorize 的 url 里没有 state 参数: {auth_url[:300]}")
    return auth_url, pending_state


def _exchange_luban(code: str, token: str = None) -> dict:
    """luban：POST /api/exchange，body {code, label?, proxy? | proxy_id?, group_ids?}。

    proxy 与 proxy_id 二选一：LUBAN_BIND_PROXY（URL）优先，否则 LUBAN_BIND_PROXY_ID
    （本人代理池里的 id，别人的 luban 回 404）；都不填时上号 Key 由 luban 自动分配、
    会话 token 直连。luban 从 code 自己解析 state，不需要单独传 pending_state。
    """
    payload = {"code": code}
    if LUBAN_BIND_LABEL:
        payload["label"] = LUBAN_BIND_LABEL
    proxy_id = _luban_proxy_id()
    if LUBAN_BIND_PROXY:
        payload["proxy"] = LUBAN_BIND_PROXY
    elif proxy_id is not None:
        payload["proxy_id"] = proxy_id
    group_ids = _luban_group_ids(token)
    if group_ids:
        payload["group_ids"] = group_ids
    # 自动分配代理时 luban 会逐条测通（最多 5 条 × 10s）再换码，超时放宽
    data, raw = _luban_request(LUBAN_EXCHANGE_PATH, method="POST", body=payload,
                               token=token, timeout=120)
    return data if isinstance(data, dict) else {"raw": raw}


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
