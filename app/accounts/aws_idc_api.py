"""AWS IAM Identity Center (IDC) 用户开通 —— 纯 API 版（SigV4，无浏览器）。

替代 aws_idc.py 的浏览器点击流。实测确认（见对话/memory）：控制台"生成一次性密码"
没有独立接口，OTP 直接由**内部** API `AWSIdentityStoreService.CreateUser`（带
`PasswordMode:OTP`）在响应 `Password` 字段返回。该 endpoint 认 SigV4，root AK/SK 可直调。

主入口：provision_idc_user_api(...) —— 返回与 aws_idc.provision_idc_user_on_page 同构的 dict，
调用方（aws-kiro 模式）可零成本替换。

依赖：仅标准库（复用本文件内的 SigV4 签名，不引 boto3）。
"""

import datetime
import hashlib
import hmac
import json
import logging
import urllib.error
import urllib.request

from app.accounts.aws_idc import gen_idc_user, gen_new_password

logger = logging.getLogger(__name__)

_ALGORITHM = "AWS4-HMAC-SHA256"
_TIMEOUT = 30


def _sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _signing_key(secret: str, datestamp: str, region: str, service: str) -> bytes:
    k = _sign(("AWS4" + secret).encode("utf-8"), datestamp)
    k = _sign(k, region)
    k = _sign(k, service)
    return _sign(k, "aws4_request")


def _sigv4(
    ak: str, sk: str, service: str, region: str, host: str, body: str,
    *, target: str, path: str = "/",
    content_type: str = "application/x-amz-json-1.1", session_token: str = "",
) -> tuple[int, str]:
    """对 POST <path> 做 SigV4 签名并发送，返回 (http_status, body_text)。

    支持自定义 canonical path（内部 identitystore 接口是 `/identitystore/`）与 content-type
    （内部接口是 json-1.0）。session_token 非空则带上（用于 STS 临时凭证；root AK/SK 不需要）。
    """
    now = datetime.datetime.utcnow()
    amzdate = now.strftime("%Y%m%dT%H%M%SZ")
    datestamp = now.strftime("%Y%m%d")
    payload_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()

    header_pairs = [
        ("content-type", content_type),
        ("host", host),
        ("x-amz-content-sha256", payload_hash),
        ("x-amz-date", amzdate),
        ("x-amz-target", target),
    ]
    if session_token:
        header_pairs.append(("x-amz-security-token", session_token))
    header_pairs.sort(key=lambda kv: kv[0])
    canonical_headers = "".join(f"{k}:{v}\n" for k, v in header_pairs)
    signed_headers = ";".join(k for k, _ in header_pairs)

    canonical_request = "\n".join(
        ["POST", path, "", canonical_headers, signed_headers, payload_hash]
    )
    scope = f"{datestamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(
        [_ALGORITHM, amzdate, scope,
         hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()]
    )
    signature = hmac.new(
        _signing_key(sk, datestamp, region, service),
        string_to_sign.encode("utf-8"), hashlib.sha256,
    ).hexdigest()
    authorization = (
        f"{_ALGORITHM} Credential={ak}/{scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )

    headers = {
        "Content-Type": content_type,
        "X-Amz-Date": amzdate,
        "X-Amz-Content-Sha256": payload_hash,
        "X-Amz-Target": target,
        "Authorization": authorization,
    }
    if session_token:
        headers["X-Amz-Security-Token"] = session_token

    req = urllib.request.Request(
        f"https://{host}{path}", data=body.encode("utf-8"), headers=headers, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            return resp.status, resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8")


def _err(data: dict, raw: str) -> str:
    """从 AWS JSON 错误响应里提出可读信息。"""
    t = (data.get("__type") or "").split("#")[-1]
    m = data.get("message") or data.get("Message") or ""
    return f"{t or 'Error'}: {m}" if (t or m) else raw[:200]


# ── 探实例 ────────────────────────────────────────────────────────────────
def idc_list_instance(ak: str, sk: str, region: str, session_token: str = "") -> dict:
    """sso-admin:ListInstances → {identity_store_id, instance_arn, primary_region}。
    未探到实例返回 {error:...}。"""
    status, raw = _sigv4(
        ak, sk, "sso", region, f"sso.{region}.amazonaws.com",
        json.dumps({"MaxResults": 10}),
        target="SWBExternalService.ListInstances", path="/",
        content_type="application/x-amz-json-1.1", session_token=session_token,
    )
    try:
        data = json.loads(raw)
    except Exception:
        return {"error": f"ListInstances 解析失败 (HTTP {status}): {raw[:200]}"}
    insts = data.get("Instances")
    if not insts:
        return {"error": _err(data, raw) if status != 200 else
                f"region={region} 没有 IAM Identity Center 实例（换 AWS_IDC_REGION 再试）"}
    inst = insts[0]
    return {
        "identity_store_id": inst.get("IdentityStoreId"),
        "instance_arn": inst.get("InstanceArn"),
        "primary_region": inst.get("PrimaryRegion") or region,
        "error": "",
    }


def idc_portal_url(identity_store_id: str) -> str:
    """默认 access portal URL。自定义子域会覆盖它（实现层若需权威值可另查），
    但默认实例即 https://<identity_store_id>.awsapps.com/start。"""
    return f"https://{identity_store_id}.awsapps.com/start"


# ── 建用户（内部接口，含一次性密码）─────────────────────────────────────────
def idc_create_user_otp(
    ak: str, sk: str, region: str, identity_store_id: str, user: dict,
    session_token: str = "",
) -> dict:
    """内部 AWSIdentityStoreService.CreateUser + PasswordMode=OTP。
    返回 {user_id, one_time_password, user_status, error}。"""
    body = json.dumps({
        "IdentityStoreId": identity_store_id,
        "UserName": user["username"],
        "UserAttributes": {
            "emails": {"ComplexListValue": [{
                "value": {"StringValue": user["email"]},
                "type": {"StringValue": "work"},
                "primary": {"BooleanValue": True},
            }]},
            "name": {"ComplexValue": {
                "givenName": {"StringValue": user["first_name"]},
                "familyName": {"StringValue": user["last_name"]},
            }},
            "displayName": {"StringValue": user["display_name"]},
        },
        "Active": True,
        "PasswordMode": "OTP",
    })
    status, raw = _sigv4(
        ak, sk, "identitystore", region, f"identitystore.{region}.amazonaws.com", body,
        target="AWSIdentityStoreService.CreateUser", path="/identitystore/",
        content_type="application/x-amz-json-1.0", session_token=session_token,
    )
    try:
        data = json.loads(raw)
    except Exception:
        return {"error": f"CreateUser 解析失败 (HTTP {status}): {raw[:200]}"}
    otp = data.get("Password")
    if not otp:
        return {"error": _err(data, raw)}
    u = data.get("User") or {}
    return {
        "user_id": u.get("UserId"),
        "one_time_password": otp,
        "user_status": u.get("UserStatus"),
        "error": "",
    }


# ── 加组（公开接口）─────────────────────────────────────────────────────────
def idc_find_group_id(ak: str, sk: str, region: str, identity_store_id: str,
                      group_name: str, session_token: str = "") -> str:
    """公开 identitystore:ListGroups 按 DisplayName 找 GroupId（分页）。找不到返回空串。"""
    host = f"identitystore.{region}.amazonaws.com"
    next_token = ""
    while True:
        payload = {"IdentityStoreId": identity_store_id, "MaxResults": 100}
        if next_token:
            payload["NextToken"] = next_token
        status, raw = _sigv4(
            ak, sk, "identitystore", region, host, json.dumps(payload),
            target="AWSIdentityStore.ListGroups", path="/",
            content_type="application/x-amz-json-1.1", session_token=session_token,
        )
        try:
            data = json.loads(raw)
        except Exception:
            return ""
        for g in data.get("Groups") or []:
            if (g.get("DisplayName") or "") == group_name:
                return g.get("GroupId") or ""
        next_token = data.get("NextToken") or ""
        if not next_token:
            return ""


def idc_create_group(ak: str, sk: str, region: str, identity_store_id: str,
                     group_name: str, session_token: str = "") -> dict:
    """公开 identitystore:CreateGroup（按 DisplayName 建组）。返回 {group_id, error}。

    若组已存在（ConflictException），退回 ListGroups 取现有 GroupId，不当作错误。
    """
    body = json.dumps({
        "IdentityStoreId": identity_store_id,
        "DisplayName": group_name,
    })
    status, raw = _sigv4(
        ak, sk, "identitystore", region, f"identitystore.{region}.amazonaws.com", body,
        target="AWSIdentityStore.CreateGroup", path="/",
        content_type="application/x-amz-json-1.1", session_token=session_token,
    )
    try:
        data = json.loads(raw)
    except Exception:
        return {"group_id": "", "error": f"CreateGroup 解析失败 (HTTP {status}): {raw[:200]}"}
    if status == 200:
        return {"group_id": data.get("GroupId") or "", "error": ""}
    # 并发/重复：组已存在则回退查现有 GroupId
    if "ConflictException" in (data.get("__type") or ""):
        gid = idc_find_group_id(ak, sk, region, identity_store_id, group_name, session_token)
        if gid:
            return {"group_id": gid, "error": ""}
    return {"group_id": "", "error": _err(data, raw)}


def idc_find_or_create_group(ak: str, sk: str, region: str, identity_store_id: str,
                             group_name: str, session_token: str = "") -> dict:
    """按名字找组，找不到则创建。返回 {group_id, created, error}。"""
    gid = idc_find_group_id(ak, sk, region, identity_store_id, group_name, session_token)
    if gid:
        return {"group_id": gid, "created": False, "error": ""}
    r = idc_create_group(ak, sk, region, identity_store_id, group_name, session_token)
    if r.get("error"):
        return {"group_id": "", "created": False, "error": r["error"]}
    return {"group_id": r["group_id"], "created": True, "error": ""}


def idc_add_to_group(ak: str, sk: str, region: str, identity_store_id: str,
                     group_id: str, user_id: str, session_token: str = "") -> dict:
    """公开 identitystore:CreateGroupMembership。返回 {membership_id, error}。"""
    body = json.dumps({
        "IdentityStoreId": identity_store_id,
        "GroupId": group_id,
        "MemberId": {"UserId": user_id},
    })
    status, raw = _sigv4(
        ak, sk, "identitystore", region, f"identitystore.{region}.amazonaws.com", body,
        target="AWSIdentityStore.CreateGroupMembership", path="/",
        content_type="application/x-amz-json-1.1", session_token=session_token,
    )
    try:
        data = json.loads(raw)
    except Exception:
        return {"error": f"CreateGroupMembership 解析失败 (HTTP {status}): {raw[:200]}"}
    if status != 200:
        return {"error": _err(data, raw)}
    return {"membership_id": data.get("MembershipId"), "error": ""}


# ── 批量绑定 Kiro 订阅（把 IDC 用户 assign 到 KiroProfile application）─────────
def idc_list_users(ak: str, sk: str, region: str, identity_store_id: str,
                   session_token: str = "") -> dict:
    """公开 identitystore:ListUsers 全量分页。返回 {users:[{user_id,user_name}], error}。
    出错时把已收集到的 users 一并返回（尽力而为）。"""
    host = f"identitystore.{region}.amazonaws.com"
    users: list = []
    next_token = ""
    while True:
        payload = {"IdentityStoreId": identity_store_id, "MaxResults": 100}
        if next_token:
            payload["NextToken"] = next_token
        status, raw = _sigv4(
            ak, sk, "identitystore", region, host, json.dumps(payload),
            target="AWSIdentityStore.ListUsers", path="/",
            content_type="application/x-amz-json-1.1", session_token=session_token,
        )
        try:
            data = json.loads(raw)
        except Exception:
            return {"users": users, "error": f"ListUsers 解析失败 (HTTP {status}): {raw[:200]}"}
        if status != 200:
            return {"users": users, "error": _err(data, raw)}
        for u in data.get("Users") or []:
            users.append({"user_id": u.get("UserId"), "user_name": u.get("UserName")})
        next_token = data.get("NextToken") or ""
        if not next_token:
            return {"users": users, "error": ""}


def idc_list_kiro_profile_apps(ak: str, sk: str, region: str, instance_arn: str,
                               session_token: str = "") -> dict:
    """列出该实例下的 Kiro 订阅 application（provider=codewhisperer 且 AssignmentRequired=true，
    即 `KiroProfile-<region>`；排除仅登录用、AssignmentRequired=false 的 `Kiro Sign-In`）。

    返回 {apps:[{arn,name}], error}。分页用 sso-admin `SWBExternalService.ListApplications`。
    """
    host = f"sso.{region}.amazonaws.com"
    apps: list = []
    next_token = ""
    while True:
        payload = {"InstanceArn": instance_arn, "MaxResults": 50}
        if next_token:
            payload["NextToken"] = next_token
        status, raw = _sigv4(
            ak, sk, "sso", region, host, json.dumps(payload),
            target="SWBExternalService.ListApplications", path="/",
            content_type="application/x-amz-json-1.1", session_token=session_token,
        )
        try:
            data = json.loads(raw)
        except Exception:
            return {"apps": apps, "error": f"ListApplications 解析失败 (HTTP {status}): {raw[:200]}"}
        if status != 200:
            return {"apps": apps, "error": _err(data, raw)}
        for a in data.get("Applications") or []:
            provider = a.get("ApplicationProviderArn") or ""
            required = (a.get("AssignmentConfig") or {}).get("AssignmentRequired")
            if provider.endswith("/codewhisperer") and required:
                apps.append({"arn": a.get("ApplicationArn"), "name": a.get("Name")})
        next_token = data.get("NextToken") or ""
        if not next_token:
            return {"apps": apps, "error": ""}


def idc_create_application_assignment(
    ak: str, sk: str, region: str, application_arn: str, principal_id: str,
    principal_type: str = "USER", session_token: str = "",
) -> dict:
    """sso-admin CreateApplicationAssignment：把 user/group 绑到 application（= 加 Kiro 订阅）。
    该接口天然幂等（重复绑同一 principal 也回 200）；ConflictException 亦视为已绑。返回 {error}。"""
    body = json.dumps({
        "ApplicationArn": application_arn,
        "PrincipalId": principal_id,
        "PrincipalType": principal_type,
    })
    status, raw = _sigv4(
        ak, sk, "sso", region, f"sso.{region}.amazonaws.com", body,
        target="SWBExternalService.CreateApplicationAssignment", path="/",
        content_type="application/x-amz-json-1.1", session_token=session_token,
    )
    if status == 200:
        return {"error": ""}
    try:
        data = json.loads(raw)
    except Exception:
        return {"error": f"CreateApplicationAssignment 解析失败 (HTTP {status}): {raw[:200]}"}
    if "ConflictException" in (data.get("__type") or ""):
        return {"error": ""}  # 已绑
    return {"error": _err(data, raw)}


def idc_delete_application_assignment(
    ak: str, sk: str, region: str, application_arn: str, principal_id: str,
    principal_type: str = "USER", session_token: str = "",
) -> dict:
    """sso-admin DeleteApplicationAssignment（解绑/回滚订阅）。"""
    body = json.dumps({
        "ApplicationArn": application_arn,
        "PrincipalId": principal_id,
        "PrincipalType": principal_type,
    })
    status, raw = _sigv4(
        ak, sk, "sso", region, f"sso.{region}.amazonaws.com", body,
        target="SWBExternalService.DeleteApplicationAssignment", path="/",
        content_type="application/x-amz-json-1.1", session_token=session_token,
    )
    return {"error": "" if status == 200 else _err(json.loads(raw) if raw else {}, raw)}


# ── 开通 Kiro 付费订阅（q:CreateAssignment，标准 IdC 实例账号可 AK 直调）──────────
# subscriptionType 权威枚举（服务端 ValidationException 返回）。POWER = Kiro Power。
KIRO_SUBSCRIPTION_TIERS = (
    "Q_DEVELOPER_STANDALONE_FREE", "Q_DEVELOPER_STANDALONE_STUDENT",
    "Q_DEVELOPER_STANDALONE", "Q_DEVELOPER_STANDALONE_PRO",
    "Q_DEVELOPER_STANDALONE_PRO_PLUS", "Q_DEVELOPER_STANDALONE_PRO_MAX",
    "Q_DEVELOPER_STANDALONE_POWER", "CREDIT_POOL",
)
KIRO_SUBSCRIPTION_DEFAULT = "Q_DEVELOPER_STANDALONE_POWER"


def q_create_assignment(
    ak: str, sk: str, region: str, profile_arn: str, principal_id: str,
    principal_type: str = "USER", subscription_type: str = KIRO_SUBSCRIPTION_DEFAULT,
    session_token: str = "",
) -> dict:
    """AmazonQDeveloperService.CreateAssignment：给 IdC 用户/组开通 Kiro 付费订阅（真实计费）。

    这与 sso-admin 的 idc_create_application_assignment 是**两回事**：后者只挂 SSO 应用，
    此接口才真正创建付费座位。`principal_type` = USER|GROUP|BUILDER_ID；传 GROUP 时**一条
    请求即覆盖组内全体成员**（批量最优）。非幂等：重复对同一 principal 调回 ConflictException。

    返回 {error, already}；already=True 表示已订阅（ConflictException，视为成功）。
    仅「标准 IdC 实例」账号可用 AK 直调；企业/org 实例会 AccessDenied，需回退 sso-admin。
    profile_arn 形如 arn:aws:codewhisperer:<region>:<acct>:profile/<ID>（从该号已登录用户的
    accessToken 经 app.kiro.api.kiro_list_first_profile_arn 取）。
    """
    body = json.dumps({
        "profileArn": profile_arn,
        "principalId": principal_id,
        "principalType": principal_type,
        "subscriptionType": subscription_type,
    })
    status, raw = _sigv4(
        ak, sk, "q", region, f"q.{region}.amazonaws.com", body,
        target="AmazonQDeveloperService.CreateAssignment", path="/",
        content_type="application/x-amz-json-1.0", session_token=session_token,
    )
    if status == 200:
        return {"error": "", "already": False}
    try:
        data = json.loads(raw)
    except Exception:
        return {"error": f"CreateAssignment 解析失败 (HTTP {status}): {raw[:200]}", "already": False}
    if "ConflictException" in (data.get("__type") or ""):
        return {"error": "", "already": True}  # 已订阅（含"invalid state"=已存在）
    return {"error": _err(data, raw), "already": False}


def q_delete_assignment(
    ak: str, sk: str, region: str, profile_arn: str, principal_id: str,
    principal_type: str = "USER", session_token: str = "",
) -> dict:
    """AmazonQDeveloperService.DeleteAssignment：撤销 Kiro 订阅（回滚/停费）。"""
    body = json.dumps({
        "profileArn": profile_arn,
        "principalId": principal_id,
        "principalType": principal_type,
    })
    status, raw = _sigv4(
        ak, sk, "q", region, f"q.{region}.amazonaws.com", body,
        target="AmazonQDeveloperService.DeleteAssignment", path="/",
        content_type="application/x-amz-json-1.0", session_token=session_token,
    )
    return {"error": "" if status == 200 else _err(json.loads(raw) if raw else {}, raw)}


def idc_delete_user(ak: str, sk: str, region: str, identity_store_id: str,
                    user_id: str, session_token: str = "") -> dict:
    """公开 identitystore:DeleteUser（清理/回滚用）。"""
    status, raw = _sigv4(
        ak, sk, "identitystore", region, f"identitystore.{region}.amazonaws.com",
        json.dumps({"IdentityStoreId": identity_store_id, "UserId": user_id}),
        target="AWSIdentityStore.DeleteUser", path="/",
        content_type="application/x-amz-json-1.1", session_token=session_token,
    )
    return {"error": "" if status == 200 else _err(json.loads(raw) if raw else {}, raw)}


# ── 主入口：建 1 个用户，产出与浏览器版同构的 dict ─────────────────────────────
def provision_idc_user_api(
    ak: str, sk: str, region: str, identity_store_id: str, start_url: str,
    email_domain: str, username_prefix: str, group_name: str = "",
    username: str = "", group_id: str = "", session_token: str = "",
) -> dict:
    """纯 API 建 1 个 IDC 用户（含一次性密码），可选加组。

    与 aws_idc.provision_idc_user_on_page 返回同构 dict：
      {username, email, start_url, one_time_password, new_password,
       login_info, group, idc_line, error}
    group_id 传入可省一次 ListGroups；否则 group_name 非空时自动查。
    """
    user = gen_idc_user(username_prefix, email_domain, username)
    new_password = gen_new_password()
    logger.info(f"建 IDC 用户(API): username={user['username']} email={user['email']}")

    r = idc_create_user_otp(ak, sk, region, identity_store_id, user, session_token)
    if r.get("error"):
        return {"username": user["username"], "email": user["email"], "start_url": start_url,
                "one_time_password": "", "new_password": new_password, "login_info": "",
                "group": group_name, "idc_line": "", "error": r["error"]}

    one_time_password = r["one_time_password"]
    user_id = r["user_id"]

    # 加组（可选）：组不存在则自动创建；失败不影响已建用户，仅记 warning
    grp_done = ""
    if group_name:
        gid = group_id
        if not gid:
            fc = idc_find_or_create_group(ak, sk, region, identity_store_id,
                                          group_name, session_token)
            gid = fc.get("group_id") or ""
            if fc.get("error"):
                logger.warning(f"查/建组 {group_name!r} 失败（用户已建）: {fc['error']}")
            elif fc.get("created"):
                logger.info(f"组 {group_name!r} 不存在，已自动创建 GroupId={gid}")
        if gid:
            gr = idc_add_to_group(ak, sk, region, identity_store_id, gid, user_id, session_token)
            if gr.get("error"):
                logger.warning(f"加组 {group_name} 失败（用户已建）: {gr['error']}")
            else:
                grp_done = group_name

    idc_line = f"idc::{start_url}----{user['username']}----{one_time_password}----{new_password}"
    login_info = (f"Sign-in URL: {start_url}\nUsername: {user['username']}\n"
                  f"One-time password: {one_time_password}")
    return {
        "username": user["username"],
        "email": user["email"],
        "user_id": user_id,
        "start_url": start_url,
        "one_time_password": one_time_password,
        "new_password": new_password,
        "login_info": login_info,
        "group": grp_done,
        "idc_line": idc_line,
        "error": "",
    }
