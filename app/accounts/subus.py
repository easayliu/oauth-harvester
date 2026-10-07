"""subus / bedrock 平台的 HTTP 注册接口（由 main.py 拆分而来）"""

import json
import logging
import urllib.error
import urllib.parse
import urllib.request

from app.settings import (
    BEDROCK_API_ADMIN_TOKEN,
    BEDROCK_API_BASE_URL,
    BEDROCK_API_DEFAULT_CONCURRENCY,
    BEDROCK_API_DEFAULT_GROUP_IDS,
    BEDROCK_API_DEFAULT_PRIORITY,
    BEDROCK_MODEL_MAPPING,
    SUBUS_API_ADMIN_TOKEN,
    SUBUS_API_BASE_URL,
    SUBUS_API_DEFAULT_AUTO_PAUSE_ON_EXPIRED,
    SUBUS_API_DEFAULT_AWS_REGION,
    SUBUS_API_DEFAULT_BASE_RPM,
    SUBUS_API_DEFAULT_CONCURRENCY,
    SUBUS_API_DEFAULT_EXPIRES_AT,
    SUBUS_API_DEFAULT_GROUP_IDS,
    SUBUS_API_DEFAULT_LOAD_FACTOR,
    SUBUS_API_DEFAULT_NOTES,
    SUBUS_API_DEFAULT_PRIORITY,
    SUBUS_API_DEFAULT_PROXY_ID,
    SUBUS_API_DEFAULT_RATE_MULTIPLIER,
    SUBUS_API_DEFAULT_RPM_STICKY_BUFFER,
    SUBUS_API_DEFAULT_RPM_STRATEGY,
    SUBUS_API_DEFAULT_STATUS,
    SUBUS_API_DEFAULT_TEMP_UNSCHEDULABLE_ENABLED,
    SUBUS_API_DEFAULT_TEMP_UNSCHEDULABLE_RULES,
    SUBUS_OAUTH_BASE_RPM,
    SUBUS_OAUTH_CONCURRENCY,
    SUBUS_OAUTH_DEFAULT_GROUP_IDS,
    SUBUS_OAUTH_DEVICE_IDLE_TIMEOUT_MINUTES,
    SUBUS_OAUTH_ENABLE_TLS_FINGERPRINT,
    SUBUS_OAUTH_MAX_DEVICES,
    SUBUS_OAUTH_PRIORITY,
    SUBUS_OAUTH_RATE_MULTIPLIER,
    SUBUS_OAUTH_RPM_STRATEGY,
    SUBUS_OAUTH_TLS_FINGERPRINT_PROFILE_ID,
    SUBUS_OAUTH_USER_MSG_QUEUE_MODE,
)

logger = logging.getLogger(__name__)


def register_subus_account(email: str, api_key: str, workspace_id: str,
                            region: str = "", group_ids=None, base_url: str = "",
                            token: str = "", concurrency: int = -1, priority: int = -1,
                            timeout: int = 30) -> bool:
    """把抓到的 AWS Claude long-term key + workspace_id 注册到 subus admin /api/v1/admin/accounts"""
    base_url = (base_url or SUBUS_API_BASE_URL).rstrip("/")
    token = token or SUBUS_API_ADMIN_TOKEN
    region = region or SUBUS_API_DEFAULT_AWS_REGION
    group_ids = group_ids if group_ids is not None else SUBUS_API_DEFAULT_GROUP_IDS
    if concurrency < 0:
        concurrency = SUBUS_API_DEFAULT_CONCURRENCY
    if priority < 0:
        priority = SUBUS_API_DEFAULT_PRIORITY

    if not token:
        logger.info("SUBUS_API_ADMIN_TOKEN 未配置，跳过 subus 推送")
        return False
    if not api_key or not workspace_id:
        logger.info(f"api_key 或 workspace_id 为空 (api_key={bool(api_key)}, wid={bool(workspace_id)})，跳过 subus 推送")
        return False

    credentials = {
        "api_key": api_key,
        "workspace_id": workspace_id,
        "aws_region": region,
    }
    if SUBUS_API_DEFAULT_TEMP_UNSCHEDULABLE_RULES:
        credentials["temp_unschedulable_rules"] = list(SUBUS_API_DEFAULT_TEMP_UNSCHEDULABLE_RULES)
        credentials["temp_unschedulable_enabled"] = bool(SUBUS_API_DEFAULT_TEMP_UNSCHEDULABLE_ENABLED)

    payload = {
        "name": email,
        "notes": SUBUS_API_DEFAULT_NOTES,
        # proxy_id 是 accounts 表上的外键，0 在 proxies 表里不存在会触发
        # foreign key constraint 失败让服务端返回 500，所以 falsy 时必须传 null。
        "proxy_id": SUBUS_API_DEFAULT_PROXY_ID if SUBUS_API_DEFAULT_PROXY_ID else None,
        "platform": "anthropic",
        "type": "aws-anthropic",
        "credentials": credentials,
        "extra": {
            "base_rpm": SUBUS_API_DEFAULT_BASE_RPM,
            "rpm_strategy": SUBUS_API_DEFAULT_RPM_STRATEGY,
            "rpm_sticky_buffer": SUBUS_API_DEFAULT_RPM_STICKY_BUFFER,
        },
        "concurrency": concurrency,
        "load_factor": SUBUS_API_DEFAULT_LOAD_FACTOR,
        "priority": priority,
        "rate_multiplier": SUBUS_API_DEFAULT_RATE_MULTIPLIER,
        "status": SUBUS_API_DEFAULT_STATUS,
        "expires_at": SUBUS_API_DEFAULT_EXPIRES_AT,
        "auto_pause_on_expired": SUBUS_API_DEFAULT_AUTO_PAUSE_ON_EXPIRED,
    }
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
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
            text = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        status = e.code
        text = e.read().decode("utf-8", errors="replace") if e.fp else str(e)
    except Exception as e:
        logger.warning(f"subus 推送请求异常: {e}")
        return False

    if 200 <= status < 300:
        logger.info(f"subus 推送成功 [{status}] {email}: {text[:160]}")
        return True
    logger.warning(f"subus 推送失败 [{status}] {email}: {text[:300]}")
    return False


def _subus_admin_request(path: str, payload=None, method: str = "POST",
                          base_url: str = "", token: str = "", timeout: int = 30) -> tuple:
    """向 subus admin API 发请求，返回 (status, parsed_json_or_None, raw_text)。
    payload 为 None 时不带 body；带 X-API-Key 头。"""
    base_url = (base_url or SUBUS_API_BASE_URL).rstrip("/")
    token = token or SUBUS_API_ADMIN_TOKEN
    url = f"{base_url}{path}"
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    headers = {"Accept": "application/json", "X-API-Key": token}
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
        logger.warning(f"subus 请求异常 {method} {path}: {e}")
        return 0, None, str(e)
    try:
        parsed = json.loads(text)
    except ValueError:
        parsed = None
    return status, parsed, text


def subus_generate_auth_url(base_url: str = "", token: str = "") -> tuple:
    """请求 /api/v1/admin/accounts/generate-auth-url，返回 (auth_url, session_id)。失败返回 (None, None)。"""
    status, parsed, text = _subus_admin_request(
        "/api/v1/admin/accounts/generate-auth-url", payload={}, base_url=base_url, token=token
    )
    if not (200 <= status < 300) or not parsed or parsed.get("code") != 0:
        logger.warning(f"generate-auth-url 失败 [{status}]: {text[:300]}")
        return None, None
    data = parsed.get("data") or {}
    auth_url = data.get("auth_url")
    session_id = data.get("session_id")
    if not auth_url or not session_id:
        logger.warning(f"generate-auth-url 返回缺少字段: {text[:300]}")
        return None, None
    logger.info(f"已获取 auth_url（session_id={session_id}）")
    return auth_url, session_id


def subus_exchange_code(session_id: str, code: str, base_url: str = "", token: str = "") -> dict:
    """请求 /api/v1/admin/accounts/exchange-code，返回 OAuth token data 字典。失败返回 None。"""
    status, parsed, text = _subus_admin_request(
        "/api/v1/admin/accounts/exchange-code",
        payload={"session_id": session_id, "code": code},
        base_url=base_url, token=token,
    )
    if not (200 <= status < 300) or not parsed or parsed.get("code") != 0:
        logger.warning(f"exchange-code 失败 [{status}]: {text[:300]}")
        return None
    data = parsed.get("data") or {}
    if not data.get("access_token"):
        logger.warning(f"exchange-code 返回缺少 access_token: {text[:300]}")
        return None
    logger.info(f"exchange-code 成功，账号: {data.get('email_address')}")
    return data


def register_subus_oauth_account(token_data: dict, name: str = "", notes: str = "",
                                  group_ids=None, base_url: str = "", token: str = "",
                                  concurrency: int = -1, priority: int = -1) -> bool:
    """把 exchange-code 拿到的 OAuth token data 注册到 subus admin /api/v1/admin/accounts（type=oauth）。"""
    if not token_data or not token_data.get("access_token"):
        logger.warning("token_data 为空或缺少 access_token，跳过 oauth 推送")
        return False

    group_ids = group_ids if group_ids is not None else SUBUS_OAUTH_DEFAULT_GROUP_IDS
    if concurrency < 0:
        concurrency = SUBUS_OAUTH_CONCURRENCY
    if priority < 0:
        priority = SUBUS_OAUTH_PRIORITY

    email_address = token_data.get("email_address", "")
    org_uuid = token_data.get("org_uuid", "")
    account_uuid = token_data.get("account_uuid", "")
    name = name or email_address or "claude-oauth"

    # credentials = exchange-code 返回的完整 token data
    credentials = {
        "access_token": token_data.get("access_token"),
        "token_type": token_data.get("token_type", "Bearer"),
        "expires_in": token_data.get("expires_in"),
        "expires_at": token_data.get("expires_at"),
        "refresh_token": token_data.get("refresh_token"),
        "scope": token_data.get("scope"),
        "org_uuid": org_uuid,
        "account_uuid": account_uuid,
        "email_address": email_address,
    }

    payload = {
        "name": name,
        "notes": notes or SUBUS_API_DEFAULT_NOTES,
        "platform": "anthropic",
        "type": "oauth",
        "credentials": credentials,
        "extra": {
            "org_uuid": org_uuid,
            "account_uuid": account_uuid,
            "email_address": email_address,
            "max_devices": SUBUS_OAUTH_MAX_DEVICES,
            "device_idle_timeout_minutes": SUBUS_OAUTH_DEVICE_IDLE_TIMEOUT_MINUTES,
            "base_rpm": SUBUS_OAUTH_BASE_RPM,
            "rpm_strategy": SUBUS_OAUTH_RPM_STRATEGY,
            "user_msg_queue_mode": SUBUS_OAUTH_USER_MSG_QUEUE_MODE,
            "enable_tls_fingerprint": bool(SUBUS_OAUTH_ENABLE_TLS_FINGERPRINT),
            "tls_fingerprint_profile_id": SUBUS_OAUTH_TLS_FINGERPRINT_PROFILE_ID,
        },
        # proxy_id falsy 时必须传 null，否则外键约束 500
        "proxy_id": SUBUS_API_DEFAULT_PROXY_ID if SUBUS_API_DEFAULT_PROXY_ID else None,
        "concurrency": concurrency,
        "priority": priority,
        "rate_multiplier": SUBUS_OAUTH_RATE_MULTIPLIER,
        "expires_at": None,
        "auto_pause_on_expired": SUBUS_API_DEFAULT_AUTO_PAUSE_ON_EXPIRED,
    }
    if group_ids:
        payload["group_ids"] = list(group_ids)

    status, _, text = _subus_admin_request(
        "/api/v1/admin/accounts", payload=payload, base_url=base_url, token=token
    )
    if 200 <= status < 300:
        logger.info(f"subus oauth 推送成功 [{status}] {name}: {text[:160]}")
        return True
    logger.warning(f"subus oauth 推送失败 [{status}] {name}: {text[:300]}")
    return False


def aws_region_to_geo(region: str) -> str:
    """把 AWS region 映射到 Bedrock cross-region inference 的 geo 前缀。

    返回 us/eu/jp/au/apac/other（根据 Claude 4.5+ 模型卡的 source region 表）。
    - us-*, ca-*  → us  （ca-central-1 是 us. profile 的 source region）
    - eu-*        → eu
    - ap-northeast-1/3                            → jp
    - ap-southeast-2/4/6                          → au
    - ap-* 其它（singapore, mumbai 等）           → apac（旧 prefix, 4.5+ 已不支持）
    - sa-*/af-*/me-*/mx-*/il-* 等                 → other（无 geo CRIS，只能 global. 或单 region）
    """
    if region.startswith("us-") or region.startswith("ca-"):
        return "us"
    if region.startswith("eu-"):
        return "eu"
    if region in ("ap-northeast-1", "ap-northeast-3"):
        return "jp"
    if region in ("ap-southeast-2", "ap-southeast-4", "ap-southeast-6"):
        return "au"
    if region.startswith("ap-"):
        return "apac"
    return "other"


def register_bedrock_account(api_key: str, region: str, name: str,
                              base_url: str = "", token: str = "",
                              group_ids=None, concurrency: int = -1,
                              priority: int = -1, model_mapping: dict = None,
                              force_global: bool = False,
                              timeout: int = 30) -> bool:
    """把 Bedrock API Key 注册到 gptus admin /api/v1/admin/accounts。
    payload 结构（type=bedrock, auth_mode=apikey），每个 (api_key, region) 推一条。
    force_global=True 时在 credentials 里加 aws_force_global="true"，
    让 gptus 用 global. 前缀路由（destination = 所有商用 region）。
    """
    base_url = (base_url or BEDROCK_API_BASE_URL).rstrip("/")
    token = token or BEDROCK_API_ADMIN_TOKEN
    group_ids = group_ids if group_ids is not None else BEDROCK_API_DEFAULT_GROUP_IDS
    if concurrency < 0:
        concurrency = BEDROCK_API_DEFAULT_CONCURRENCY
    if priority < 0:
        priority = BEDROCK_API_DEFAULT_PRIORITY
    model_mapping = model_mapping if model_mapping is not None else BEDROCK_MODEL_MAPPING

    if not token:
        logger.warning("BEDROCK_API_ADMIN_TOKEN 未配置，跳过 gptus 推送")
        return False
    if not api_key or not region or not name:
        logger.warning(f"参数缺失 (api_key={bool(api_key)}, region={region!r}, name={name!r})，跳过")
        return False

    credentials = {
        "auth_mode": "apikey",
        "aws_region": region,
        "api_key": api_key,
        "model_mapping": model_mapping,
    }
    if force_global:
        credentials["aws_force_global"] = "true"

    payload = {
        "name": name,
        "notes": "",
        "platform": "anthropic",
        "type": "bedrock",
        "credentials": credentials,
        "proxy_id": None,
        "concurrency": concurrency,
        "priority": priority,
        "rate_multiplier": 1,
        "group_ids": list(group_ids) if group_ids else [],
        "expires_at": None,
        "auto_pause_on_expired": True,
    }

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
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
            text = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        status = e.code
        text = e.read().decode("utf-8", errors="replace") if e.fp else str(e)
    except Exception as e:
        logger.warning(f"gptus 推送请求异常 ({name} @ {region}): {e}")
        return False

    tag = "[global]" if force_global else ""
    if 200 <= status < 300:
        logger.info(f"gptus 推送成功 [{status}] {name} @ {region}{tag}: {text[:160]}")
        return True
    logger.warning(f"gptus 推送失败 [{status}] {name} @ {region}{tag}: {text[:300]}")
    return False


