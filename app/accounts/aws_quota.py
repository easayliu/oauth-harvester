"""用 AK/SK 直连 AWS API 查配额（纯标准库 SigV4，不依赖 boto3 / AWS CLI）。

- STS GetCallerIdentity 先验证 AK/SK；
- Service Quotas ListServiceQuotas（applied + QuotaAppliedAtLevel=ACCOUNT，即控制台的
  "Applied account-level quota value"，账号当前生效值）取 EC2 与 Bedrock 的配额；
  ListAWSDefaultServiceQuotas 仅做名字/存在性兜底——它返回的是 AWS 官方默认值、不是本账号
  已生效值，所以兜底项会标 is_default=True 且 value=None（默认值另存 default_value）。

对外主入口：aws_fetch_quotas(access_key_id, secret_access_key, region, service_codes)
返回 dict：{ok, account, arn, error,
  quotas:{service_code:[{code,name,value,default_value,is_default,unit,adjustable,global}]}}
其中 value 是账号级已生效值（is_default=True 的兜底项 value=None，实际默认值见 default_value）。
"""

import datetime
import hashlib
import hmac
import json
import socket
import ssl
import time
import urllib.error
import urllib.request

_ALGORITHM = "AWS4-HMAC-SHA256"
_TIMEOUT = 30
_MAX_RETRIES = 3
_RETRY_BASE_DELAY = 1.0  # 秒，指数退避：1s / 2s / 4s

# 高并发下偶发的瞬时网络错误（SSL 握手中断、连接被重置、超时等），重试可自愈；
# HTTPError（含 4xx/5xx 业务错误）不在此列，交给上层按响应体处理。
_RETRYABLE_EXCEPTIONS = (
    ssl.SSLError,
    socket.timeout,
    ConnectionError,
    urllib.error.URLError,
)


def _sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _signing_key(secret: str, datestamp: str, region: str, service: str) -> bytes:
    k = _sign(("AWS4" + secret).encode("utf-8"), datestamp)
    k = _sign(k, region)
    k = _sign(k, service)
    return _sign(k, "aws4_request")


def _sigv4_post(
    access_key_id: str,
    secret_access_key: str,
    service: str,
    region: str,
    host: str,
    body: str,
    *,
    target: str = "",
    content_type: str = "application/x-amz-json-1.1",
    session_token: str = "",
) -> str:
    """对 POST / 做 SigV4 签名并发送，返回响应体文本（HTTP 错误时返回错误响应体）。"""
    now = datetime.datetime.utcnow()
    amzdate = now.strftime("%Y%m%dT%H%M%SZ")
    datestamp = now.strftime("%Y%m%d")

    payload_hash = hashlib.sha256(body.encode("utf-8")).hexdigest()
    # canonical headers 必须按 header 名字典序排列
    header_pairs = [
        ("content-type", content_type),
        ("host", host),
        ("x-amz-date", amzdate),
    ]
    if target:
        header_pairs.append(("x-amz-target", target))
    header_pairs.sort(key=lambda kv: kv[0])
    canonical_headers = "".join(f"{k}:{v}\n" for k, v in header_pairs)
    signed_headers = ";".join(k for k, _ in header_pairs)

    canonical_request = "\n".join(
        ["POST", "/", "", canonical_headers, signed_headers, payload_hash]
    )
    scope = f"{datestamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(
        [
            _ALGORITHM,
            amzdate,
            scope,
            hashlib.sha256(canonical_request.encode("utf-8")).hexdigest(),
        ]
    )
    signature = hmac.new(
        _signing_key(secret_access_key, datestamp, region, service),
        string_to_sign.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    authorization = (
        f"{_ALGORITHM} Credential={access_key_id}/{scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )

    headers = {
        "Content-Type": content_type,
        "X-Amz-Date": amzdate,
        "Authorization": authorization,
    }
    if target:
        headers["X-Amz-Target"] = target
    if session_token:
        headers["X-Amz-Security-Token"] = session_token

    req = urllib.request.Request(
        f"https://{host}/", data=body.encode("utf-8"), headers=headers, method="POST"
    )
    for attempt in range(_MAX_RETRIES + 1):
        try:
            with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
                return resp.read().decode("utf-8")
        except urllib.error.HTTPError as e:
            return e.read().decode("utf-8")
        except _RETRYABLE_EXCEPTIONS:
            if attempt == _MAX_RETRIES:
                raise
            time.sleep(_RETRY_BASE_DELAY * (2 ** attempt))


def _sts_caller_identity(access_key_id: str, secret_access_key: str) -> tuple[str, str, str]:
    """返回 (account, arn, error)。error 非空表示 AK/SK 无效或调用失败（含重试耗尽的网络错误）。"""
    try:
        raw = _sigv4_post(
            access_key_id,
            secret_access_key,
            "sts",
            "us-east-1",
            "sts.amazonaws.com",
            "Action=GetCallerIdentity&Version=2011-06-15",
            content_type="application/x-www-form-urlencoded",
        )
    except Exception as e:
        return "", "", f"NetworkError: {e}"
    # STS 返回 XML；用轻量正则/切片取值，避免引额外依赖
    def _tag(name: str) -> str:
        open_t, close_t = f"<{name}>", f"</{name}>"
        i = raw.find(open_t)
        if i == -1:
            return ""
        j = raw.find(close_t, i)
        return raw[i + len(open_t):j].strip() if j != -1 else ""

    if "<Error>" in raw or "GetCallerIdentityResult" not in raw:
        code = _tag("Code") or "Unknown"
        msg = _tag("Message") or raw[:200]
        return "", "", f"{code}: {msg}"
    return _tag("Account"), _tag("Arn"), ""


def _list_quotas_one(
    access_key_id: str,
    secret_access_key: str,
    region: str,
    service_code: str,
    default: bool,
    quota_applied_at_level: str = "",
) -> list[dict]:
    """拉一个 service 的配额（分页取全量）。default=True 走 AWS 官方默认配额接口。

    quota_applied_at_level 仅对 applied 接口（default=False）有效，可传 ACCOUNT/RESOURCE/ALL；
    AWS 默认即 ACCOUNT（账号级已生效值）。default 接口不接受该参数，会被忽略。
    """
    action = "ListAWSDefaultServiceQuotas" if default else "ListServiceQuotas"
    target = f"ServiceQuotasV20190624.{action}"
    host = f"servicequotas.{region}.amazonaws.com"
    quotas: list[dict] = []
    next_token = ""
    while True:
        payload = {"ServiceCode": service_code, "MaxResults": 100}
        if not default and quota_applied_at_level:
            payload["QuotaAppliedAtLevel"] = quota_applied_at_level
        if next_token:
            payload["NextToken"] = next_token
        raw = _sigv4_post(
            access_key_id, secret_access_key, "servicequotas", region, host,
            json.dumps(payload), target=target,
        )
        data = json.loads(raw)
        if "Quotas" not in data:
            # 错误响应（如 AccessDenied）：抛出让上层记录
            raise RuntimeError(
                f'{data.get("__type", "Error")}: {data.get("message") or data.get("Message") or raw[:200]}'
            )
        quotas.extend(data["Quotas"])
        next_token = data.get("NextToken") or ""
        if not next_token:
            break
    return quotas


def _quotas_for_service(
    access_key_id: str, secret_access_key: str, region: str, service_code: str
) -> list[dict]:
    """取账号级 applied（当前生效）配额值。

    applied 用 ListServiceQuotas + QuotaAppliedAtLevel=ACCOUNT，返回的就是 AWS 控制台
    "Applied account-level quota value"。default（ListAWSDefaultServiceQuotas）只做名字/
    存在性兜底，且**其 value 是 AWS 官方默认值、不是本账号已生效值**，因此对兜底进来的项
    标记 is_default=True 并把 value 单独存到 default_value，调用方据此避免把默认值当实际值用。
    """
    by_code: dict[str, dict] = {}
    for q in _list_quotas_one(
        access_key_id, secret_access_key, region, service_code,
        default=False, quota_applied_at_level="ACCOUNT",
    ):
        q["_is_default"] = False
        by_code[q.get("QuotaCode")] = q
    try:
        for q in _list_quotas_one(access_key_id, secret_access_key, region, service_code, default=True):
            # applied 里没有的配额才用 default 补：补进来的 value 是官方默认值，非本账号生效值
            if q.get("QuotaCode") not in by_code:
                q["_is_default"] = True
                by_code[q.get("QuotaCode")] = q
    except Exception:
        pass  # default 接口失败不影响 applied 结果
    out = []
    for q in by_code.values():
        is_default = bool(q.get("_is_default"))
        out.append({
            "code": q.get("QuotaCode"),
            "name": q.get("QuotaName"),
            # applied 项：value 即账号级已生效值；default 兜底项：value 置 None（未知），
            # 官方默认值另存 default_value，避免被当成实际配额参与可用性判断。
            "value": None if is_default else q.get("Value"),
            "default_value": q.get("Value") if is_default else None,
            "is_default": is_default,
            "unit": q.get("Unit"),
            "adjustable": q.get("Adjustable"),
            "global": q.get("GlobalQuota"),
        })
    out.sort(key=lambda x: (x.get("name") or "").lower())
    return out


def aws_fetch_quotas(
    access_key_id: str,
    secret_access_key: str,
    region: str = "us-east-1",
    service_codes: tuple[str, ...] = ("ec2", "bedrock"),
) -> dict:
    """用 AK/SK 直连查配额（纯 SigV4，无 boto3）。同步函数，调用方可用 asyncio.to_thread 包裹。"""
    result = {"ok": False, "account": "", "arn": "", "error": "", "quotas": {}, "errors": {}}

    account, arn, err = _sts_caller_identity(access_key_id, secret_access_key)
    if err:
        result["error"] = err  # AK/SK 无效等，直接返回
        return result
    result["account"], result["arn"], result["ok"] = account, arn, True

    for code in service_codes:
        try:
            result["quotas"][code] = _quotas_for_service(
                access_key_id, secret_access_key, region, code)
        except Exception as e:
            result["quotas"][code] = []
            result["errors"][code] = str(e)
    return result
