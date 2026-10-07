"""Kiro：HTTP API（token 刷新、用量、overage、IDC OIDC device flow）与本地 sqlite（由 main.py 拆分而来）"""

import contextvars
import json
import logging
import os
import re
import sqlite3
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

logger = logging.getLogger(__name__)


KIRO_SQLITE_PATH = os.path.expanduser(
    "~/Library/Application Support/kiro-cli/data.sqlite3"
)

# 并发隔离用：每个协程可把 kiro-cli 的 auth_kv 库指向自己独立的 $HOME 副本，
# 避免多账号并发登录时 token 互相覆盖/串号（logout/login/读回都走这个路径）。
# 默认 None → 落回全局主库 KIRO_SQLITE_PATH（串行/单条流程行为不变）。
_kiro_sqlite_path_var: contextvars.ContextVar = contextvars.ContextVar(
    "kiro_sqlite_path", default=None
)


def current_kiro_sqlite_path() -> str:
    """当前协程该读写的 kiro-cli sqlite 路径：隔离态返回隔离库，否则主库。"""
    return _kiro_sqlite_path_var.get() or KIRO_SQLITE_PATH


def set_kiro_sqlite_path(path):
    """把当前协程的 kiro-cli sqlite 指向 path（None 恢复主库）。返回 token 供 reset。"""
    return _kiro_sqlite_path_var.set(path)


def is_kiro_sqlite_isolated() -> bool:
    """当前协程是否处于隔离态（用了独立库，而非全局主库）。"""
    return _kiro_sqlite_path_var.get() is not None
KIRO_OUTPUT_FILE = "kiro.json"
KIRO_PROFILE_ARN_DEFAULT = "arn:aws:codewhisperer:us-east-1:699475941385:profile/EHGA3GRVQMUK"


KIRO_AUTH_KEYS = (
    "kirocli:odic:token",
    "kirocli:odic:device-registration",
    "kirocli:social:token",
    "kirocli:external-idp:token",
)


def run_kiro_logout():
    """清理本地 kiro-cli 会话（不走 kiro-cli logout，避免 server-side revocation
    把已入库的历史 token 一并作废）。
    做两件事：
      1) DELETE from sqlite auth_kv
      2) 清 macOS keychain 中对应的 generic-password 条目
    """
    # sqlite
    sqlite_path = current_kiro_sqlite_path()
    if os.path.isfile(sqlite_path):
        try:
            conn = sqlite3.connect(sqlite_path)
            try:
                for k in KIRO_AUTH_KEYS:
                    conn.execute("DELETE FROM auth_kv WHERE key=?", (k,))
                conn.commit()
            finally:
                conn.close()
        except Exception as e:
            logger.debug(f"清理 kiro sqlite 异常: {e}")

    # keychain（macOS）：隔离态跳过 —— keychain 条目是用户级全局单例，
    # key 固定（kirocli:odic:token 等），并发删除会互相抹掉别的账号刚写的凭据。
    # kiro-cli 2.x 主凭据存 sqlite（已隔离），keychain 是历史兜底；隔离并发下不碰它。
    if sys.platform == "darwin" and not is_kiro_sqlite_isolated():
        for k in KIRO_AUTH_KEYS:
            try:
                subprocess.run(
                    ["/usr/bin/security", "delete-generic-password", "-s", k],
                    capture_output=True, timeout=5,
                )
            except Exception as e:
                logger.debug(f"清理 keychain {k} 异常: {e}")


def read_kiro_social_token() -> dict:
    """从 kiro-cli sqlite 读出登录 token。
    kiro-cli 2.0.1+ Builder ID/Google 都存在 kirocli:odic:token；
    旧版 social 登录存在 kirocli:social:token。两者都试。
    """
    sqlite_path = current_kiro_sqlite_path()
    if not os.path.isfile(sqlite_path):
        raise RuntimeError(f"kiro-cli sqlite 不存在: {sqlite_path}")
    conn = sqlite3.connect(sqlite_path)
    try:
        for key in ("kirocli:odic:token", "kirocli:social:token"):
            row = conn.execute(
                "SELECT value FROM auth_kv WHERE key=?", (key,)
            ).fetchone()
            if row and row[0]:
                return json.loads(row[0])
    finally:
        conn.close()
    raise RuntimeError("kirocli:odic:token 和 kirocli:social:token 都未在 auth_kv 中找到")


def read_kiro_auth_kv(key: str) -> dict:
    """读 kiro-cli auth_kv 里某个 key 的 JSON value；不存在/解析失败返回 {}。
    用于登录后读回 kiro-cli 自己写的 kirocli:odic:token / :device-registration。
    """
    sqlite_path = current_kiro_sqlite_path()
    if not os.path.isfile(sqlite_path):
        return {}
    try:
        conn = sqlite3.connect(sqlite_path)
        try:
            row = conn.execute(
                "SELECT value FROM auth_kv WHERE key=?", (key,)
            ).fetchone()
        finally:
            conn.close()
        if row and row[0]:
            return json.loads(row[0])
    except Exception as e:
        logger.debug(f"读 auth_kv[{key}] 异常: {e}")
    return {}


def _kiro_auth_kv_upsert(pairs: dict) -> None:
    """把若干 (key, 明文 JSON value) upsert 进 kiro-cli 本地凭据库(auth_kv)。
    DB/表不存在时创建（kiro-cli 已装则 DB 已在，CREATE IF NOT EXISTS 为空操作）。
    """
    sqlite_path = current_kiro_sqlite_path()
    os.makedirs(os.path.dirname(sqlite_path), exist_ok=True)
    conn = sqlite3.connect(sqlite_path)
    try:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS auth_kv (key TEXT PRIMARY KEY, value TEXT)"
        )
        for k, v in pairs.items():
            conn.execute(
                "INSERT INTO auth_kv(key, value) VALUES(?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (k, v),
            )
        conn.commit()
    finally:
        conn.close()


def write_kiro_idc_cli_session(access_token, refresh_token, token_expires_at,
                               region, start_url, client_id, client_secret,
                               client_secret_expires_at, scopes=None) -> None:
    """把 IdC OIDC device flow 拿到的凭据写进 kiro-cli 本地库(auth_kv)，
    让 kiro-cli / Kiro IDE 本地直接处于该账号登录态。

    IdC 模式默认只写 kiro.json、跳过 kiro-cli；本函数补上 kiro-cli 这一侧。写两条
    （格式对齐 Amazon Q Developer CLI（kiro-cli fork）serde，camelCase）：
      kirocli:odic:device-registration → client 注册（clientId/secret/过期/scopes）
      kirocli:odic:token               → 登录 token（access/refresh/过期/startUrl）
    注意：kiro-cli 单会话，批量登录时只有最后一个账号会留在 kiro-cli。
    region 用 OIDC region（token/refresh 生效区，IdC 这里恒 us-east-1），非实例区。
    """
    scopes = list(scopes) if scopes else list(KIRO_IDC_DEFAULT_SCOPES)
    registration = {
        "clientId": client_id,
        "clientSecret": client_secret,
        "clientSecretExpiresAt": client_secret_expires_at,
        "region": region,
        "oauthFlow": "DeviceCode",
        "scopes": scopes,
    }
    token = {
        "accessToken": access_token,
        "expiresAt": token_expires_at,
        "refreshToken": refresh_token,
        "region": region,
        "startUrl": start_url,
        "oauthFlow": "DeviceCode",
        "scopes": scopes,
    }
    _kiro_auth_kv_upsert({
        "kirocli:odic:device-registration": json.dumps(registration),
        "kirocli:odic:token": json.dumps(token),
    })
    logger.info(
        f"已写入 kiro-cli 本地登录态(auth_kv): region={region} startUrl={start_url}"
    )


def _cw_endpoint(region: str) -> str:
    """CodeWhisperer/Q 控制面端点：us-east-1 有 legacy `codewhisperer.us-east-1`
    主机；其余区该主机不存在（TLS 直接 EOF），须用 Amazon Q 区域端点
    `q.<region>`。两者都接受 awsJson-1.0 + X-Amz-Target 协议。
    """
    if region == "us-east-1":
        return "https://codewhisperer.us-east-1.amazonaws.com/"
    return f"https://q.{region}.amazonaws.com/"


def kiro_list_first_profile_arn(access_token: str, region: str = "us-east-1") -> str:
    """调用 CodeWhisperer ListAvailableProfiles，返回第一个 profile 的 ARN。
    Pro/IDC 账号 ARN 与 Free 默认值不同，必须从此处取。
    全部失败时返回 ""，调用方应回退到默认 ARN。
    region 必须是 SSO 实例所在区——IdC token 按实例区签发，跨区调会判 invalid bearer。
    """
    if not access_token:
        return ""
    url = _cw_endpoint(region)
    payload = json.dumps({}).encode("utf-8")
    targets = [
        "AWSCodeWhispererService.ListAvailableProfiles",
        "AmazonCodeWhispererService.ListAvailableProfiles",
        "CodeWhispererService.ListAvailableProfiles",
    ]
    last_err = None
    for target in targets:
        req = urllib.request.Request(
            url, data=payload, method="POST",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/x-amz-json-1.0",
                "X-Amz-Target": target,
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                text = resp.read().decode("utf-8", errors="replace")
                data = json.loads(text)
                profiles = data.get("profiles") or data.get("Profiles") or []
                for p in profiles:
                    arn = p.get("arn") or p.get("Arn") or p.get("profileArn")
                    if arn:
                        return arn
                return ""
        except urllib.error.HTTPError as e:
            body = ""
            try:
                body = e.read().decode("utf-8", errors="replace") if e.fp else ""
            except Exception:
                pass
            last_err = f"HTTP {e.code} target={target}: {body[:200]}"
            if e.code in (400, 404):
                continue
            logger.warning(f"ListAvailableProfiles 失败: {last_err}")
            return ""
        except Exception as e:
            last_err = f"{target}: {e}"
            continue
    logger.warning(f"ListAvailableProfiles 全部 target 失败: {last_err}")
    return ""


def kiro_get_usage_limits(access_token: str, profile_arn: str,
                          region: str = "us-east-1") -> dict:
    """调用 CodeWhisperer GetUsageLimits 获取 userId + usageData，失败返回 {}。
    region 须与 profile_arn 的区一致、且为 SSO 实例区，否则会判 invalid bearer。
    """
    url = _cw_endpoint(region)
    payload = json.dumps({"profileArn": profile_arn}).encode("utf-8")
    # 不同 CLI 版本用的 target 名称可能不同，依次尝试
    targets = [
        "AWSCodeWhispererService.GetUsageLimits",
        "AmazonCodeWhispererService.GetUsageLimits",
        "CodeWhispererService.GetUsageLimits",
    ]
    last_err = None
    for target in targets:
        req = urllib.request.Request(
            url, data=payload, method="POST",
            headers={
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/x-amz-json-1.0",
                "X-Amz-Target": target,
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                text = resp.read().decode("utf-8", errors="replace")
                return json.loads(text)
        except urllib.error.HTTPError as e:
            body = ""
            try:
                body = e.read().decode("utf-8", errors="replace") if e.fp else ""
            except Exception:
                pass
            last_err = f"HTTP {e.code} target={target}: {body[:200]}"
            # 400/404 说明 target 名称错误，继续试下一个；其他错误直接返回
            if e.code in (400, 404):
                continue
            logger.warning(f"GetUsageLimits 失败: {last_err}")
            return {}
        except Exception as e:
            last_err = f"{target}: {e}"
            continue
    logger.warning(f"GetUsageLimits 全部 target 失败: {last_err}")
    return {}


def kiro_refresh_access_token(refresh_token: str) -> dict:
    """用 refreshToken 调用 Kiro 自家中转接口换新的 accessToken。
    Kiro 服务端封装了 AWS SSO OIDC，客户端无需 clientId/secret。
    成功返回 {accessToken, refreshToken, expiresIn, profileArn}；失败返回 {}。
    """
    if not refresh_token:
        return {}
    url = "https://prod.us-east-1.auth.desktop.kiro.dev/refreshToken"
    payload = json.dumps({"refreshToken": refresh_token}).encode("utf-8")
    req = urllib.request.Request(
        url, data=payload, method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        except Exception:
            pass
        logger.warning(f"refreshToken 失败 HTTP {e.code}: {body[:200]}")
        return {}
    except Exception as e:
        logger.warning(f"refreshToken 异常: {e}")
        return {}


def kiro_set_overage(access_token: str, profile_arn: str, enabled: bool) -> bool:
    """切换 Kiro overage（超额计费）开关。成功返回 True。"""
    if not access_token or not profile_arn:
        return False
    url = "https://q.us-east-1.amazonaws.com/setUserPreference"
    payload = json.dumps({
        "overageConfiguration": {
            "overageStatus": "ENABLED" if enabled else "DISABLED",
        },
        "profileArn": profile_arn,
    }).encode("utf-8")
    req = urllib.request.Request(
        url, data=payload, method="POST",
        headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            resp.read()
            return 200 <= resp.status < 300
    except urllib.error.HTTPError as e:
        body = ""
        try:
            body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        except Exception:
            pass
        logger.warning(f"setUserPreference 失败 HTTP {e.code}: {body[:200]}")
        return False
    except Exception as e:
        logger.warning(f"setUserPreference 异常: {e}")
        return False


def kiro_ensure_overage(record: dict, enabled: bool) -> bool:
    """给一条 kiro 记录切 overage。优先用记录里的 accessToken+profileArn；
    缺什么就用 refreshToken 现刷 + ListAvailableProfiles 补。成功返回 True。
    """
    access_token = record.get("accessToken") or ""
    profile_arn = record.get("profileArn") or ""
    if not access_token or not profile_arn:
        refresh_token = record.get("refreshToken") or ""
        if refresh_token:
            refreshed = kiro_refresh_access_token(refresh_token)
            if not access_token:
                access_token = refreshed.get("accessToken") or ""
            if not profile_arn:
                profile_arn = refreshed.get("profileArn") or ""
    if access_token and not profile_arn:
        profile_arn = kiro_list_first_profile_arn(access_token)
    if not (access_token and profile_arn):
        return False
    return kiro_set_overage(access_token, profile_arn, enabled)


def _idc_region_from_start_url(start_url: str) -> str:
    """从 IDC start URL 推断 region。
    - https://*.portal.<region>.app.aws → 取 <region>
    - https://d-xxxx.awsapps.com/start → 推不出，回落 config 的 AWS_IDC_REGION（默认 us-east-1）
    """
    m = re.search(r"\.portal\.([a-z0-9-]+)\.app\.aws", start_url)
    if m:
        return m.group(1)
    from app.settings import AWS_IDC_REGION
    return AWS_IDC_REGION or "us-east-1"


# AWS region 形态：us-east-1 / eu-central-1 / ap-southeast-2 ...
_AWS_REGION_RE = r"([a-z]{2}-[a-z]+-\d+)"


def _idc_instance_region_from_url(url: str) -> str:
    """从登录流程途经的 URL 解析 Identity Center 实例 region。

    实例 region 与 OIDC region 不是一回事：Q Developer 的 OIDC client 恒注册在
    us-east-1（clientId 内嵌 us-east-1），但 Identity Center 目录可落在任意区，
    导出记录里的 `region` 要的是后者。区域访问门户前端（*.awsapps.com/start）渲染
    "Allow access to AWS accounts" 时会请求区域化后端，URL 里带实例 region：
      - https://portal.sso.<region>.amazonaws.com/...
      - https://<sub>.portal.<region>.app.aws/...
    注意：<region>.signin.aws 是全局登录入口（恒 us-east-1），不代表实例 region，忽略。
    无法识别时返回 ""。
    """
    if not url:
        return ""
    m = re.search(r"portal\.sso\." + _AWS_REGION_RE + r"\.amazonaws\.com", url)
    if m:
        return m.group(1)
    m = re.search(r"\.portal\." + _AWS_REGION_RE + r"\.app\.aws", url)
    if m:
        return m.group(1)
    return ""


KIRO_IDC_DEFAULT_SCOPES = ["codewhisperer:analysis", "codewhisperer:completions"]


def _idc_oidc_post(region: str, path: str, payload: dict) -> dict:
    """对 IDC OIDC endpoint 发 JSON POST。HTTP 错误把响应体一起带回来（含 _error/_body/_code）。"""
    url = f"https://oidc.{region}.amazonaws.com{path}"
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as e:
        err_body = ""
        try:
            err_body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        except Exception:
            pass
        return {"_error": str(e), "_code": e.code, "_body": err_body}


def idc_register_client(region: str,
                        client_name: str = "kiro-easay-login",
                        scopes: list = None) -> dict:
    """OIDC RegisterClient → 拿 clientId/clientSecret。"""
    return _idc_oidc_post(region, "/client/register", {
        "clientName": client_name,
        "clientType": "public",
        "scopes": scopes or KIRO_IDC_DEFAULT_SCOPES,
    })


def idc_start_device_authorization(region: str, client_id: str,
                                   client_secret: str, start_url: str) -> dict:
    """OIDC StartDeviceAuthorization → 拿 deviceCode/userCode/verificationUriComplete/interval/expiresIn。"""
    return _idc_oidc_post(region, "/device_authorization", {
        "clientId": client_id,
        "clientSecret": client_secret,
        "startUrl": start_url,
    })


def idc_create_token(region: str, client_id: str, client_secret: str,
                     device_code: str) -> dict:
    """OIDC CreateToken (device_code grant)。
    成功返回 {accessToken, refreshToken?, expiresIn, tokenType, idToken?}
    待审批时 _body 包含 'authorization_pending'，用 slow_down 时增加 interval。
    """
    return _idc_oidc_post(region, "/token", {
        "clientId": client_id,
        "clientSecret": client_secret,
        "grantType": "urn:ietf:params:oauth:grant-type:device_code",
        "deviceCode": device_code,
    })


# ==========================================================================
# Kiro 控制面（management.<region>.kiro.dev）—— apikey（ksk_）建/列/删。
# 认证：Authorization: Bearer <IDC accessToken>（aoa... 前缀）；awsJson-1.0 协议。
# 实测（2026-07-17）：必需头仅 Authorization / Content-Type / X-Amz-Target，
# 无需 cookie / csrf。响应 rawKey 即完整 ksk_（网页"只显示一次"的那个）。
# ==========================================================================

KIRO_MGMT_SERVICE = "KiroControlPlaneBearerService"


def region_from_profile_arn(profile_arn: str) -> str:
    """从 profileArn（arn:aws:codewhisperer:<region>:<acct>:profile/<id>）解析 region。
    management 端点区域必须与 profileArn 的区域一致，否则控制面判 AccessDenied/Invalid token。
    解析不出返回 ""。
    """
    m = re.match(r"arn:aws[a-z-]*:codewhisperer:([a-z0-9-]+):", profile_arn or "")
    return m.group(1) if m else ""


def kiro_management_url(region: str = "us-east-1") -> str:
    return f"https://management.{region}.kiro.dev/"


def _kiro_management_post(access_token: str, target: str, payload: dict,
                          region: str = "us-east-1") -> dict:
    """对 Kiro 控制面发 awsJson-1.0 POST。HTTP 错误把响应体带回来（含 _error/_code/_body）。"""
    url = kiro_management_url(region)
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/x-amz-json-1.0",
            "X-Amz-Target": f"{KIRO_MGMT_SERVICE}.{target}",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as e:
        err_body = ""
        try:
            err_body = e.read().decode("utf-8", errors="replace") if e.fp else ""
        except Exception:
            pass
        return {"_error": str(e), "_code": e.code, "_body": err_body}


def kiro_management_create_apikey(access_token: str, profile_arn: str, label: str,
                                  region: str = "us-east-1") -> dict:
    """CreateApiKey → 建一个 ksk_ key。
    成功返回 {createdAt, keyId(kskid_...), keyPrefix(ksk_xxxx), rawKey(完整 ksk_)}；
    失败返回带 _error/_code/_body 的 dict。
    """
    return _kiro_management_post(
        access_token, "CreateApiKey", {"profileArn": profile_arn, "label": label}, region)


def kiro_management_list_apikeys(access_token: str, profile_arn: str,
                                 region: str = "us-east-1") -> dict:
    """ListApiKeys → {keys:[{keyId, keyPrefix, label, createdAt}]}（不含完整 key）。"""
    return _kiro_management_post(
        access_token, "ListApiKeys", {"profileArn": profile_arn}, region)


def kiro_management_delete_apikey(access_token: str, profile_arn: str, key_id: str,
                                  region: str = "us-east-1") -> dict:
    """DeleteApiKey → {}（成功）。key_id 是 kskid_ 前缀的那个。"""
    return _kiro_management_post(
        access_token, "DeleteApiKey", {"profileArn": profile_arn, "keyId": key_id}, region)


