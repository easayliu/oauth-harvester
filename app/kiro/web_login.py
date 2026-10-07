"""Kiro 网页模式（app.kiro.dev / signin.aws USI）—— 纯 API 登录换 Bearer。

2026-07-17 逆向 + 实测打通：不再驱动浏览器 SPA、不再抓 SPA 弹窗，用纯 HTTP 复刻整条
IdC/USI 登录链，最终拿到能建 apikey 的 `aoa...` Bearer + profileArn。

链路（全部纯 Python urllib + cbor2 + cryptography 实测）：
  1. InitiateLogin(CBOR)  → 组织的 authorize URL（含一次性 PAR request_uri）+ 本地 PKCE code_verifier
  2. GET authorize → 302…→ login?workflowStateHandle=<h>（拿 handle + platform-ubid cookie）
  3. USI 状态机 api/execute（同一 CookieJar）：
       step "" → start → get-identity-user(username) → get-password(JWE 密码)
       首登号 get-password 后会进"改密"步：提交 new_password 完成激活
     成功那步返回 redirect.url = app.kiro.dev/signin/oauth?code=<authCode>
  4. ExchangeToken(CBOR, code+idp+codeVerifier) → 下发 AccessToken/SessionToken/ProfileArn… cookie
  5. GetToken(CBOR, cookie 认证) → 干净的 `aoa...` Bearer

**关键约束（都是实测踩出来的）**：
  - **fingerprint 目录绑定**：`get-password` 步必须带【该 d-* 目录】的真实 fingerprint（浏览器该目录
    login 的 get-identity-user 请求体里那个 `ECdITeCs:<b64>`，~6KB）。空串 / 跨目录复用 → 密码步被
    风控判 AUTHENTICATION_FAILED / SIGNIN_BAD_REQUEST_ERROR。start/get-identity 步不严格（可空）。
    → 每个目录用浏览器抓一次真实 fingerprint 缓存复用（不验新鲜度，可长期缓存）；同目录所有账号共用。
  - **cookie jar 必需**：每步 api/execute 都 Set-Cookie（login-interview-token/workflow-*-token/
    aws-usi-authn），下一步要带回。
  - InitiateLogin 字段名是 `startUrl`（普通 awsapps start URL）+ `idcRegion`（不是 issuerUrl/region）。

参见 memory: kiro-web-login-pure-api-progress。
"""

import base64
import hashlib
import http.cookiejar
import json
import logging
import os
import re
import urllib.error
import urllib.parse
import urllib.request

import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)

_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) "
       "Gecko/20100101 Firefox/135.0")
_KIRO_SVC = "https://app.kiro.dev/service/KiroWebPortalService/operation"
_REDIRECT_URI = "https://app.kiro.dev/signin/oauth"
# 每目录 fingerprint 缓存目录：<repo>/kiro_fingerprints/<dir_id>.txt
_FP_CACHE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "kiro_fingerprints")


# --------------------------------------------------------------------------
# 小工具
# --------------------------------------------------------------------------
def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _dir_id_from_start_url(start_url: str) -> str:
    """从 start_url（https://d-xxxx.awsapps.com/start）取目录 id d-xxxx。"""
    m = re.search(r"https?://([a-z0-9-]+)\.awsapps\.com", start_url or "")
    return m.group(1) if m else ""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


# --------------------------------------------------------------------------
# 每目录 fingerprint 缓存
# --------------------------------------------------------------------------
def fingerprint_cache_path(dir_id: str) -> str:
    return os.path.join(_FP_CACHE_DIR, f"{dir_id}.txt")


def load_fingerprint(dir_id: str) -> str:
    """读该目录缓存的真实 fingerprint（ECdITeCs:...）。没有返回 ""。"""
    p = fingerprint_cache_path(dir_id)
    if os.path.exists(p):
        return open(p, encoding="utf-8").read().strip()
    return ""


def save_fingerprint(dir_id: str, fingerprint: str) -> None:
    """缓存该目录的真实 fingerprint（浏览器抓一次后写入，供纯 API 长期复用）。"""
    os.makedirs(_FP_CACHE_DIR, exist_ok=True)
    with open(fingerprint_cache_path(dir_id), "w", encoding="utf-8") as f:
        f.write(fingerprint.strip())


# --------------------------------------------------------------------------
# CBOR RPC（Smithy rpc-v2-cbor）到 app.kiro.dev
# --------------------------------------------------------------------------
def _kiro_cbor(operation: str, payload: dict, opener=None,
               extra_headers: dict = None) -> dict:
    """对 KiroWebPortalService 发一个 rpc-v2-cbor 请求，返回解码后的 dict。
    HTTPError 把响应体解出来带回（含 __type/message）。"""
    data = cbor2.dumps(payload)
    headers = {
        "User-Agent": _UA,
        "Accept": "application/cbor",
        "Content-Type": "application/cbor",
        "smithy-protocol": "rpc-v2-cbor",
        "Origin": "https://app.kiro.dev",
        "Referer": "https://app.kiro.dev/signin",
    }
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(f"{_KIRO_SVC}/{operation}", data=data,
                                 method="POST", headers=headers)
    _open = opener.open if opener else urllib.request.urlopen
    try:
        with _open(req, timeout=30) as r:
            return cbor2.loads(r.read())
    except urllib.error.HTTPError as e:
        body = e.read() if e.fp else b""
        try:
            return {"_httperror": e.code, **cbor2.loads(body)}
        except Exception:
            return {"_httperror": e.code, "_body": body[:300].decode("latin1")}


# --------------------------------------------------------------------------
# 1) InitiateLogin → authorize URL + code_verifier
# --------------------------------------------------------------------------
def initiate_login(start_url: str, region: str = "us-east-1") -> tuple:
    """纯 Python InitiateLogin。返回 (authorize_url, code_verifier)。

    实测字段：idp=AWSIdC、startUrl=普通 awsapps start URL、idcRegion=region、
    codeChallengeMethod=S256、redirectUri/state/codeChallenge 本地生成。
    """
    verifier = _b64u(os.urandom(32))
    challenge = _b64u(hashlib.sha256(verifier.encode()).digest())
    state = _b64u(os.urandom(16))
    body = {
        "idp": "AWSIdC",
        "redirectUri": _REDIRECT_URI,
        "state": state,
        "codeChallenge": challenge,
        "codeChallengeMethod": "S256",
        "startUrl": start_url,
        "idcRegion": region,
    }
    r = _kiro_cbor("InitiateLogin", body)
    authz = r.get("redirectUrl")
    if not authz:
        raise RuntimeError(f"InitiateLogin 失败: {str(r)[:200]}")
    return authz, verifier


# --------------------------------------------------------------------------
# 2) 跟 authorize → login，拿 workflowStateHandle + 基础 cookie
# --------------------------------------------------------------------------
def mint_workflow_handle(authorize_url: str) -> tuple:
    """GET authorize 跟 302 到 login?workflowStateHandle=<h>。
    返回 (dir_id, handle, opener)（opener 带同一个 CookieJar，已含 platform-ubid）。"""
    cj = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(
        _NoRedirect, urllib.request.HTTPCookieProcessor(cj))

    url = authorize_url
    final = url
    for _ in range(8):
        req = urllib.request.Request(
            url, headers={"User-Agent": _UA,
                          "Accept": "text/html,application/xhtml+xml"})
        try:
            resp = opener.open(req, timeout=30)
            loc = resp.getheader("Location")
            resp.read()
        except urllib.error.HTTPError as e:
            loc = e.getheader("Location")
            if e.fp:
                e.read()
        final = url
        if not loc:
            break
        url = loc if loc.startswith("http") else \
            "https://us-east-1.signin.aws" + loc
        final = url

    m = re.search(r"/platform/(d-[a-z0-9]+)/login\?.*workflowStateHandle="
                  r"([0-9a-f-]{36})", final)
    if not m:
        raise RuntimeError(f"未拿到 workflowStateHandle，落地: {final[:120]}")
    dir_id, handle = m.group(1), m.group(2)
    # 确保基础 cookie（platform-ubid / directory-csrf）已就位：再 GET 一次 login 页
    try:
        opener.open(urllib.request.Request(
            final, headers={"User-Agent": _UA, "Accept": "text/html"}),
            timeout=30).read()
    except urllib.error.HTTPError:
        pass
    return dir_id, handle, opener


# --------------------------------------------------------------------------
# 3) USI 状态机（api/execute）
# --------------------------------------------------------------------------
def _jwe_encrypt_password(public_key: dict, password: str) -> str:
    """RSA-OAEP-256 包 CEK + A256GCM 加密密码，输出 JWE compact（5 段）。
    public_key 是 api/execute 响应里 encryptionContextResponse.publicKey（JWK）。"""
    def bd(s):
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    n = int.from_bytes(bd(public_key["n"]), "big")
    e = int.from_bytes(bd(public_key["e"]), "big")
    pub = RSAPublicNumbers(e, n).public_key()
    header = {"alg": "RSA-OAEP-256", "kid": public_key["kid"],
              "enc": "A256GCM", "cty": "enc",
              "typ": "application/aws+signin+jwe"}
    aad = _b64u(json.dumps(header, separators=(",", ":")).encode()).encode()
    cek = os.urandom(32)
    iv = os.urandom(12)
    enc_cek = pub.encrypt(cek, padding.OAEP(
        mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(),
        label=None))
    ct_full = AESGCM(cek).encrypt(iv, password.encode(), aad)
    ct, tag = ct_full[:-16], ct_full[-16:]
    return ".".join([aad.decode(), _b64u(enc_cek), _b64u(iv),
                     _b64u(ct), _b64u(tag)])


def _execute(opener, dir_id: str, handle: str, step: str, inputs: list,
             extra: dict = None) -> dict:
    """对 signin.aws USI 发一步 api/execute（application/json）。返回响应 dict。"""
    login_ref = (f"https://us-east-1.signin.aws/platform/{dir_id}/login"
                 f"?workflowStateHandle={handle}")
    body = {"stepId": step, "workflowStateHandle": handle, "inputs": inputs}
    if extra:
        body.update(extra)
    req = urllib.request.Request(
        f"https://us-east-1.signin.aws/platform/{dir_id}/api/execute",
        data=json.dumps(body).encode(), method="POST",
        headers={"User-Agent": _UA,
                 "Accept": "application/json, text/plain, */*",
                 "Content-Type": "application/json; charset=UTF-8",
                 "Origin": "https://us-east-1.signin.aws",
                 "Referer": login_ref})
    try:
        with opener.open(req, timeout=30) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        body_txt = e.read().decode("utf-8", "replace") if e.fp else ""
        try:
            return {"_httperror": e.code, **json.loads(body_txt)}
        except Exception:
            return {"_httperror": e.code, "_body": body_txt[:200]}


def usi_authenticate(opener, dir_id: str, handle: str, username: str,
                     password: str, fingerprint: str,
                     new_password: str = None) -> str:
    """驱动 USI 状态机到登录成功，返回 authCode（app.kiro.dev/signin/oauth?code=<>）。

    fingerprint 必须是该目录的真实值（见模块头）。start/get-identity 步用空 fp 即可，
    get-password 步用真实 fp。首登号 get-password 后会进"改密"步，用 new_password 完成。
    """
    def fp(inp):
        return inp + [{"input_type": "FingerPrintRequestInput",
                       "fingerPrint": fingerprint}]

    empty_fp = [{"input_type": "FingerPrintRequestInput", "fingerPrint": ""}]

    def _pk(resp):
        return (((resp.get("workflowResponseData") or {})
                 .get("encryptionContextResponse") or {}).get("publicKey"))

    def _err(resp, where):
        code = (resp.get("message") or {}).get("errorCode") or \
            resp.get("_httperror")
        raise RuntimeError(f"USI {where} 失败: {code} / {str(resp)[:160]}")

    # step "" → start
    r = _execute(opener, dir_id, handle, "", empty_fp)
    if r.get("stepId") != "start":
        _err(r, "step''")
    handle = r["workflowStateHandle"]

    # start → get-identity-user（或直接 get-password，若会话 cookie 已记住用户名）
    r = _execute(opener, dir_id, handle, "start", fp([]))
    step = r.get("stepId")
    if step not in ("get-identity-user", "get-password"):
        _err(r, "start")
    handle = r["workflowStateHandle"]

    if step == "get-identity-user":
        r = _execute(opener, dir_id, handle, "get-identity-user",
                     fp([{"input_type": "UserRequestInput",
                          "username": username},
                         {"input_type": "ApplicationTypeRequestInput",
                          "applicationType": "SSO"}]),
                     {"actionId": "SUBMIT"})
        if r.get("stepId") != "get-password":
            _err(r, "get-identity-user")
        handle = r["workflowStateHandle"]

    pk = _pk(r)
    if not pk:
        _err(r, "get-password(publicKey)")

    # get-password（提交密码；首登号可能返回改密步）。
    # 实测（2026-07-18 抓包对齐）：真实 SPA 的 start 响应常直接给 get-password（无单独
    # get-identity-user 步），此时【用户名必须在本步以 UserRequestInput 内联提交】，否则 USI
    # 不知道认证主体。这里无条件带 username（有 get-identity-user 分支时重复带也无害）。
    r = _execute(opener, dir_id, handle, "get-password",
                 fp([{"input_type": "PasswordRequestInput",
                      "password": _jwe_encrypt_password(pk, password),
                      "passwordString": None,
                      "successfullyEncrypted": "SUCCESSFUL",
                      "errorLog": None},
                     {"input_type": "UserPreferencesRequestInput"},
                     {"input_type": "UserRequestInput",
                      "username": username}]),
                 {"actionId": "SUBMIT"})

    # 首登强制改密：response 会返回 get-new-password-for-change-password 步；用 new_password 完成
    if not r.get("redirect") and _needs_password_reset(r):
        if not new_password:
            _err(r, "get-password(需改密但未给 new_password)")
        handle = r.get("workflowStateHandle", handle)
        pk2 = _pk(r) or pk
        r = _submit_new_password(opener, dir_id, handle, pk2, new_password,
                                 username, fp)

    redirect = r.get("redirect")
    if not redirect or not redirect.get("url"):
        _err(r, "get-password")
    m = re.search(r"[?&]code=([^&]+)", redirect["url"])
    if not m:
        raise RuntimeError(f"登录成功但未取到 authCode: {redirect['url'][:120]}")
    return urllib.parse.unquote(m.group(1))


def _needs_password_reset(resp: dict) -> bool:
    """判断 get-password 响应是否要求首登改密。

    实测（2026-07-18 抓包对齐）：首登号 get-password 后 USI 返回
    stepId=`get-new-password-for-change-password`。同时兜住 NEW_PASSWORD/RESET 类 errorCode。
    """
    step = str(resp.get("stepId") or "").lower()
    code = str((resp.get("message") or {}).get("errorCode") or "")
    return ("new-password" in step or "change-password" in step) or \
        "NEW_PASSWORD" in code.upper() or "RESET" in code.upper()


def _submit_new_password(opener, dir_id, handle, public_key, new_password,
                         username, fp):
    """提交新密码完成首登改密。

    实测抓包字段（2026-07-18）：stepId=`get-new-password-for-change-password`，
    actionId=SUBMIT，input=`UpdatePasswordRequestInput`（字段 newPassword=JWE /
    successfullyEncrypted / errorLog），另需 `UserRequestInput`(username) + fingerprint。
    """
    jwe = _jwe_encrypt_password(public_key, new_password)
    return _execute(
        opener, dir_id, handle, "get-new-password-for-change-password",
        fp([{"input_type": "UpdatePasswordRequestInput", "newPassword": jwe,
             "successfullyEncrypted": "SUCCESSFUL", "errorLog": None},
            {"input_type": "UserRequestInput", "username": username}]),
        {"actionId": "SUBMIT"})


# --------------------------------------------------------------------------
# 4-5) authCode → Bearer（ExchangeToken + GetToken）
# --------------------------------------------------------------------------
def exchange_token(opener, code: str, code_verifier: str) -> dict:
    """ExchangeToken(CBOR)：code+idp+codeVerifier → 服务端下发 AccessToken/SessionToken/
    ProfileArn… httpOnly cookie（进 opener 的 CookieJar）。返回响应 dict。"""
    return _kiro_cbor("ExchangeToken",
                      {"code": code, "idp": "AWSIdC",
                       "codeVerifier": code_verifier}, opener=opener)


def get_bearer(opener) -> dict:
    """GetToken(CBOR, cookie 认证) → 干净的 aoa Bearer（+ 可能的 profileArn）。

    需 CSRF：从 CookieJar 里取 workflow/csrf 类 cookie 作 x-csrf-token 头（实际字段接入时校准）。
    """
    csrf = ""
    # 从 opener 的 cookiejar 找 csrf token
    for handler in opener.handlers:
        cj = getattr(handler, "cookiejar", None)
        if cj:
            for c in cj:
                if "csrf" in c.name.lower():
                    csrf = c.value
                    break
    return _kiro_cbor("GetToken", {}, opener=opener,
                      extra_headers={"x-csrf-token": csrf} if csrf else None)


# --------------------------------------------------------------------------
# 顶层编排
# --------------------------------------------------------------------------
def web_login_get_bearer(start_url: str, username: str, password: str,
                         region: str = "us-east-1", fingerprint: str = "",
                         new_password: str = None) -> dict:
    """纯 API 网页登录换 Bearer。fingerprint 空则从每目录缓存读。

    返回 {bearer, profileArn, authCode, dir_id}。缺 fingerprint 会报错并提示先抓。
    """
    dir_id = _dir_id_from_start_url(start_url)
    if not fingerprint:
        fingerprint = load_fingerprint(dir_id)
    if not fingerprint:
        raise RuntimeError(
            f"目录 {dir_id} 没有缓存 fingerprint。请先用浏览器登录该目录抓一次真实 "
            f"fingerprint（signin.aws login 页 get-identity-user 请求体里的 ECdITeCs:…），"
            f"save_fingerprint('{dir_id}', fp) 缓存后再纯 API 复用。")

    authz, verifier = initiate_login(start_url, region)
    dir_id, handle, opener = mint_workflow_handle(authz)
    code = usi_authenticate(opener, dir_id, handle, username, password,
                            fingerprint, new_password=new_password)

    # ExchangeToken 直接 Set-Cookie 下发 AccessToken(aoa…)/SessionToken/ProfileArn。
    # 实测（2026-07-18 抓包）：这个 AccessToken cookie 值就是 management.kiro.dev 的 Bearer，
    # 无需再走 GetToken CBOR。GetToken 仅在 cookie 缺失时兜底。
    exchange_token(opener, code, verifier)
    cookies = _cookie_map(opener)
    bearer = cookies.get("AccessToken", "")
    profile_arn = urllib.parse.unquote(cookies.get("ProfileArn", "")) or None

    if not bearer:
        tok = get_bearer(opener)
        bearer = tok.get("accessToken") or tok.get("token") or tok.get("bearer")
        profile_arn = profile_arn or tok.get("profileArn")

    return {"bearer": bearer, "profileArn": profile_arn,
            "authCode": code, "dir_id": dir_id}


def _cookie_map(opener) -> dict:
    """从 opener 的 CookieJar 抽出 {name: value}（用于取 AccessToken/ProfileArn）。"""
    out = {}
    for handler in opener.handlers:
        cj = getattr(handler, "cookiejar", None)
        if cj:
            for c in cj:
                out[c.name] = c.value
    return out
