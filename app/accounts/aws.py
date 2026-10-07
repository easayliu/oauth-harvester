"""AWS：登录、账号诊断、Claude platform workspace、长期 API key（由 main.py 拆分而来）"""

import asyncio
import json
import logging
import re
import time
import urllib.error
import urllib.parse
import urllib.request

from playwright.async_api import Page, BrowserContext

from app.core.browser import get_totp_code, human_delay, screenshot_path
from app.accounts.claude import claude_console_via_magic_link

logger = logging.getLogger(__name__)


AWS_CLAUDE_PLATFORM_URL = "https://us-east-1.console.aws.amazon.com/claude-platform/access?region=us-east-1"
AWS_CLAUDE_API_KEYS_URL = "https://us-east-1.console.aws.amazon.com/claude-platform/api-keys?region=us-east-1"
AWS_CLAUDE_WORKSPACES_URL = "https://us-east-1.console.aws.amazon.com/claude-platform/workspaces?region=us-east-1"
AWS_OUTPUT_FILE = "aws_api_keys.txt"


async def _aws_dismiss_feedback(page: Page) -> None:
    """AWS signin 页面右上角 "Provide feedback" 会渲染一个隐藏的 Feedback 弹窗。
    若误触打开，关掉它，避免遮挡后续控件。"""
    try:
        modal = page.locator('div[role="dialog"]:has-text("Feedback for AWS Sign-in")')
        if await modal.count() > 0 and await modal.first.is_visible():
            close_btn = modal.locator('button:has-text("Cancel"), button[aria-label="Close"], button[aria-label="close"]')
            if await close_btn.count() > 0:
                await close_btn.first.click()
                await page.wait_for_timeout(500)
    except Exception:
        pass


async def _aws_wait_captcha(page: Page, email: str, stage: str, timeout_s: int = 180) -> None:
    """AWS Root 登录常出图形验证码。检测到后截图并等待人工填写、自动通过。"""
    captcha_locator = page.locator('#captcha_image, img[id*="captcha"], input#captchaGuess, input[name="captchaGuess"]')
    try:
        await captcha_locator.first.wait_for(state="visible", timeout=3000)
    except Exception:
        return

    logger.warning(f"⚠️  检测到 AWS 图形验证码（{stage}），需要人工填写")
    await page.screenshot(path=screenshot_path(f"aws_captcha_{stage}", email))

    # 轮询直到验证码控件消失或超时
    end = time.time() + timeout_s
    while time.time() < end:
        await page.wait_for_timeout(2000)
        if await captcha_locator.first.count() == 0:
            logger.info("AWS 图形验证码已通过")
            return
        try:
            if not await captcha_locator.first.is_visible():
                logger.info("AWS 图形验证码已通过")
                return
        except Exception:
            return
    logger.warning("AWS 图形验证码等待超时，继续后续步骤")


def _aws_build_federation_login_url(
    access_key_id: str,
    secret_access_key: str,
    destination_url: str,
    duration_seconds: int = 43200,
    session_name: str = "claude-platform-login",
) -> str:
    """用 IAM user AK/SK 走 STS GetFederationToken 拿临时凭证 → 换 SigninToken →
    返回 AWS Console 联邦登录 URL。浏览器 goto 该 URL 即可完成登录。

    要求 AK/SK 属于 IAM user 且具备 sts:GetFederationToken 权限。
    Root 账号 AK 不支持联邦登录（AWS 限制），调用会抛错。
    """
    try:
        import boto3
    except ImportError as e:
        raise RuntimeError("缺少 boto3 依赖：pip install boto3") from e

    sts = boto3.client(
        "sts",
        aws_access_key_id=access_key_id,
        aws_secret_access_key=secret_access_key,
        region_name="us-east-1",
    )
    inline_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    })
    resp = sts.get_federation_token(
        Name=session_name,
        Policy=inline_policy,
        DurationSeconds=duration_seconds,
    )
    creds = resp["Credentials"]
    session_payload = json.dumps({
        "sessionId": creds["AccessKeyId"],
        "sessionKey": creds["SecretAccessKey"],
        "sessionToken": creds["SessionToken"],
    })
    qs_get = urllib.parse.urlencode({
        "Action": "getSigninToken",
        "SessionDuration": str(duration_seconds),
        "Session": session_payload,
    })
    with urllib.request.urlopen(
        f"https://signin.aws.amazon.com/federation?{qs_get}", timeout=20
    ) as r:
        signin_token = json.loads(r.read().decode())["SigninToken"]
    qs_login = urllib.parse.urlencode({
        "Action": "login",
        "Issuer": "main.py",
        "Destination": destination_url,
        "SigninToken": signin_token,
    })
    return f"https://signin.aws.amazon.com/federation?{qs_login}"


def aws_diagnose_account(
    access_key_id: str,
    secret_access_key: str,
    email: str = "",
    region: str = "us-east-1",
) -> dict:
    """用 AK/SK 诊断 AWS 账号，区分"AK/SK 权限不足"与"账号被 AWS 限制"。

    依次执行（同步，调用方用 asyncio.to_thread 包裹）：
      1) sts:GetCallerIdentity   —— AK/SK 是否有效、是 root 还是 IAM user
      2) sts:GetFederationToken  —— main 的 AWS 登录正是走这个机制（见 login_aws）
      3) bedrock:ListFoundationModels（用联邦临时凭证）—— 探测账号层面限制
      4) service-quotas:ListServiceQuotas（bedrock）—— 查询指定模型的 TPM/RPM 配额

    返回 dict：{email, account, arn, is_root, verdict, steps:[{step, ok, detail/error}],
               quotas:{model_kw:{tpm, rpm, tpm_names, rpm_names}}}
    verdict ∈ {ak_invalid, root_no_federation, federation_denied,
               account_restricted, ok, error}
    """
    try:
        import boto3
        from botocore.exceptions import ClientError, BotoCoreError
    except ImportError:
        return {"email": email, "verdict": "error",
                "steps": [{"step": "import", "ok": False, "error": "缺少 boto3：pip install boto3"}]}

    result = {"email": email, "account": "", "arn": "", "is_root": False,
              "verdict": "ok", "steps": []}

    def _err(e) -> str:
        """抽取 botocore ClientError 的 Code + Message"""
        try:
            return f'{e.response["Error"]["Code"]}: {e.response["Error"]["Message"]}'
        except Exception:
            return f"{type(e).__name__}: {e}"

    def _is_account_restricted(text: str) -> bool:
        """账号层面被限制的话术：'...not authorized... create a support case...'"""
        return "support case" in (text or "").lower()

    # 1) GetCallerIdentity —— 验证 AK/SK 并区分 root / iam user
    sts = boto3.client("sts", aws_access_key_id=access_key_id,
                       aws_secret_access_key=secret_access_key, region_name=region)
    try:
        ident = sts.get_caller_identity()
        result["account"] = ident.get("Account", "")
        result["arn"] = ident.get("Arn", "")
        result["is_root"] = result["arn"].endswith(":root")
        result["steps"].append({"step": "get_caller_identity", "ok": True, "detail": result["arn"]})
    except ClientError as e:
        result["steps"].append({"step": "get_caller_identity", "ok": False, "error": _err(e)})
        result["verdict"] = "ak_invalid"
        return result
    except BotoCoreError as e:
        result["steps"].append({"step": "get_caller_identity", "ok": False, "error": str(e)})
        result["verdict"] = "error"
        return result

    # 2) GetFederationToken —— main 的 AWS 登录机制
    inline_policy = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    })
    try:
        resp = sts.get_federation_token(
            Name="claude-platform-diag", Policy=inline_policy, DurationSeconds=900)
        fed_creds = resp["Credentials"]
        result["steps"].append({"step": "get_federation_token", "ok": True})
    except ClientError as e:
        msg = _err(e)
        result["steps"].append({"step": "get_federation_token", "ok": False, "error": msg})
        if _is_account_restricted(msg):
            result["verdict"] = "account_restricted"
        elif result["is_root"]:
            result["verdict"] = "root_no_federation"
        else:
            result["verdict"] = "federation_denied"
        return result
    except BotoCoreError as e:
        result["steps"].append({"step": "get_federation_token", "ok": False, "error": str(e)})
        result["verdict"] = "error"
        return result

    # 3) 用联邦临时凭证探测账号层面限制（与真实 console session 权限一致）。
    #    重点打"请求模型访问/开通"这条链路：页面点"Request model access"时走的就是
    #    GetFoundationModelAvailability / agreement 这组接口，账号被限制时它们返回
    #    "...not authorized... create a support case" 话术。
    probe = boto3.client(
        "bedrock",
        aws_access_key_id=fed_creds["AccessKeyId"],
        aws_secret_access_key=fed_creds["SecretAccessKey"],
        aws_session_token=fed_creds["SessionToken"],
        region_name=region,
    )

    # 3a) 先取一个 Anthropic Claude 的 modelId（顺带探测控制面是否整体被封）
    model_id = ""
    try:
        models = probe.list_foundation_models(byProvider="Anthropic")
        summaries = models.get("modelSummaries", [])
        model_id = summaries[0]["modelId"] if summaries else ""
        result["steps"].append({"step": "bedrock:ListFoundationModels(Anthropic)", "ok": True,
                                 "detail": f"{len(summaries)} 个模型"})
    except ClientError as e:
        msg = _err(e)
        result["steps"].append({"step": "bedrock:ListFoundationModels(Anthropic)", "ok": False, "error": msg})
        if _is_account_restricted(msg):
            result["verdict"] = "account_restricted"
            return result
    except BotoCoreError as e:
        result["steps"].append({"step": "bedrock:ListFoundationModels(Anthropic)", "ok": False, "error": str(e)})

    # 3b) model-access 请求接口——页面点"请求模型访问/开通"命中的就是这里
    if not model_id:
        model_id = "anthropic.claude-3-5-sonnet-20240620-v1:0"  # 兜底
    try:
        avail = probe.get_foundation_model_availability(modelId=model_id)
        result["steps"].append({
            "step": "bedrock:GetFoundationModelAvailability",
            "ok": True,
            "detail": (f'model={model_id} '
                       f'auth={avail.get("authorizationStatus")} '
                       f'agreement={avail.get("agreementAvailability", {}).get("status")} '
                       f'entitlement={avail.get("entitlementAvailability")}'),
        })
    except ClientError as e:
        msg = _err(e)
        result["steps"].append({"step": "bedrock:GetFoundationModelAvailability", "ok": False, "error": msg})
        # 只有"support case"话术才算账号被限制；普通 AccessDenied 是 IAM 层面，
        # 不改写 verdict（联邦机制本身正常）。
        if _is_account_restricted(msg):
            result["verdict"] = "account_restricted"
    except BotoCoreError as e:
        result["steps"].append({"step": "bedrock:GetFoundationModelAvailability", "ok": False, "error": str(e)})

    # 4) Service Quotas —— 查询指定模型的 TPM(tokens/min) 与 RPM(requests/min)。
    #    Bedrock 的 TPM/RPM 不在 bedrock API，而是 Service Quotas 的 bedrock 配额，
    #    名称形如 "... tokens per minute for Anthropic Claude Opus 4.7"。
    #    用联邦临时凭证读取，反映 console session 的实际权限。
    TARGET_MODELS = ["Opus 4.7", "Sonnet 4.6", "Opus 4.6"]
    result["quotas"] = {}

    def _fmt_num(v) -> str:
        if v is None:
            return "—"
        try:
            f = float(v)
            return f"{int(f):,}" if f.is_integer() else f"{f:,}"
        except Exception:
            return str(v)

    try:
        sq = boto3.client(
            "service-quotas",
            aws_access_key_id=fed_creds["AccessKeyId"],
            aws_secret_access_key=fed_creds["SecretAccessKey"],
            aws_session_token=fed_creds["SessionToken"],
            region_name=region,
        )
        # applied（账号当前生效值）优先；未调整过的配额用 default 兜底
        by_code = {}
        for pg in sq.get_paginator("list_service_quotas").paginate(ServiceCode="bedrock"):
            for q in pg.get("Quotas", []):
                by_code[q.get("QuotaCode")] = q
        try:
            for pg in sq.get_paginator("list_aws_default_service_quotas").paginate(ServiceCode="bedrock"):
                for q in pg.get("Quotas", []):
                    by_code.setdefault(q.get("QuotaCode"), q)
        except Exception:
            pass
        all_quotas = list(by_code.values())
        result["steps"].append({
            "step": "service-quotas:ListServiceQuotas(bedrock)",
            "ok": True, "detail": f"{len(all_quotas)} 条配额",
        })

        def _match(model_kw: str, metric_kw: str):
            mk = model_kw.lower()
            out = []
            for q in all_quotas:
                low = (q.get("QuotaName") or "").lower()
                if mk in low and metric_kw in low:
                    out.append((q.get("QuotaName"), q.get("Value")))
            return out

        for kw in TARGET_MODELS:
            tpm = _match(kw, "tokens per minute")
            rpm = _match(kw, "requests per minute")
            tpm_val = tpm[0][1] if tpm else None
            rpm_val = rpm[0][1] if rpm else None
            result["quotas"][kw] = {
                "tpm": tpm_val, "rpm": rpm_val,
                "tpm_names": [n for n, _ in tpm],
                "rpm_names": [n for n, _ in rpm],
            }
            note = ""
            if not (tpm or rpm):
                note = "  (未找到匹配配额)"
            elif len(tpm) > 1 or len(rpm) > 1:
                note = f"  (TPM×{len(tpm)} RPM×{len(rpm)} 取首条)"
            result["steps"].append({
                "step": f"quota:{kw}",
                "ok": bool(tpm or rpm),
                "detail": f"TPM={_fmt_num(tpm_val)}  RPM={_fmt_num(rpm_val)}{note}",
            })
    except ClientError as e:
        result["steps"].append({"step": "service-quotas:ListServiceQuotas(bedrock)",
                                 "ok": False, "error": _err(e)})
    except BotoCoreError as e:
        result["steps"].append({"step": "service-quotas:ListServiceQuotas(bedrock)",
                                 "ok": False, "error": str(e)})

    return result


AWS_CONSOLE_HOME_URL = "https://us-east-1.console.aws.amazon.com/console/home?region=us-east-1"


async def aws_console_login(context: BrowserContext, email: str, password: str, totp_secret: str,
                            access_key_id: str = "", secret_access_key: str = "",
                            destination_url: str = AWS_CONSOLE_HOME_URL) -> Page:
    """登录 AWS，返回一个已登录 console 的 Page（落在 destination_url 或被重定向后的 console 页）。

    默认优先用 Root 邮箱+密码+TOTP 浏览器登录。仅当未提供 password 时，才回退到
    AK/SK 走 STS 联邦登录直接拿到 console session。

    由 login_aws 抽取，供 claude-platform 与 IDC/Kiro 两条后续流程共用：差异只在
    destination_url（登录后想落地的控制台页面）。
    """
    page = await context.new_page()

    federated = False
    # 默认走账号密码登录；只有在没有 password 的情况下才尝试 AK/SK 联邦登录
    if not password and access_key_id and secret_access_key:
        logger.info(f"未提供 password，尝试 AK/SK 联邦登录 (AccessKeyID={access_key_id[:8]}...)")
        try:
            login_url = await asyncio.to_thread(
                _aws_build_federation_login_url,
                access_key_id,
                secret_access_key,
                destination_url,
            )
            await page.goto(login_url, wait_until="domcontentloaded")
            await human_delay(page, "navigate")
            await page.screenshot(path=screenshot_path("aws_step_0_federation_landing", email))
            if "signin.aws.amazon.com" in page.url:
                logger.warning(f"联邦登录被退回 signin 页 (URL={page.url})，回退 Root 密码登录")
            else:
                logger.info(f"联邦登录成功，落地 URL: {page.url}")
                federated = True
        except Exception as e:
            logger.warning(f"联邦登录失败: {e}；回退 Root 密码登录")

    if not federated and not password:
        raise RuntimeError(
            "未提供 password/TOTP，且 AK/SK 联邦登录失败或未配置，无法登录。"
            "请提供 Root 邮箱密码，或检查 AK/SK 是否有效（sts:GetCallerIdentity 能调通）"
        )

    if not federated:
        logger.info("打开目标控制台，等待 AWS 重定向到 signin...")
        await page.goto(destination_url, wait_until="domcontentloaded")
        # domcontentloaded 后 AWS 还会异步 302 到 signin，再立刻判断 URL 会误判"已登录"。
        # 多给一点时间观察是否会跳到 signin（最多 10s，跳到了就提前结束）。
        try:
            await page.wait_for_url(re.compile(r"signin\.aws\.amazon\.com"), timeout=10000)
        except Exception:
            pass
        await human_delay(page, "navigate")
        await page.screenshot(path=screenshot_path("aws_step_0_landing", email))

        current_url = page.url
        logger.info(f"重定向后 URL: {current_url}")

        # 已经登录态？直接到 console
        if "signin.aws.amazon.com" not in current_url:
            logger.info("未触发登录，已直接到达控制台")
            await page.screenshot(path=screenshot_path("aws_console_landed", email))
            return page

        # 强制走「Root user + 邮箱」登录：页面有时默认/被切到 IAM user，必须显式选 Root user。
        # 原生 radio 常视觉隐藏，只 check 它不可靠——优先点可见的「Root user」卡片/label，再兜底 check radio。
        await _aws_dismiss_feedback(page)
        try:
            root_radio = page.locator(
                '#section_root_account_radio_button, input[type="radio"][value="root"]')
            already = (await root_radio.count() > 0 and await root_radio.first.is_checked())
            if not already:
                for sel in [
                    'label:has-text("Root user")',
                    'label:has-text("根用户")', 'label:has-text("根用戶")',
                    '#section_root_account_radio_button',
                    'input[type="radio"][value="root"]',
                ]:
                    try:
                        loc = page.locator(sel).first
                        if await loc.count() > 0 and await loc.is_visible():
                            await loc.click()
                            break
                    except Exception:
                        continue
                # 仍未选中就直接 check radio
                try:
                    if await root_radio.count() > 0 and not await root_radio.first.is_checked():
                        await root_radio.first.check()
                except Exception:
                    pass
                await human_delay(page, "click")
            await page.screenshot(path=screenshot_path("aws_step_0_root_selected", email))
        except Exception:
            pass

        logger.info("输入 Root 邮箱...")
        email_input = page.locator('#resolving_input')
        await email_input.wait_for(state="visible", timeout=15000)
        await email_input.fill(email)
        await human_delay(page, "type")

        next_btn = page.locator('#next_button')
        await next_btn.wait_for(state="visible", timeout=10000)
        await next_btn.click()
        await human_delay(page, "navigate")

        # 邮箱步骤可能弹图形验证码
        await _aws_wait_captcha(page, email, "after_email")
        await _aws_dismiss_feedback(page)

        logger.info("输入 Root 密码...")
        password_input = page.locator('#password')
        await password_input.wait_for(state="visible", timeout=20000)
        await password_input.fill(password)
        await human_delay(page, "type")

        signin_btn = page.locator('#signin_button')
        await signin_btn.wait_for(state="visible", timeout=10000)
        await signin_btn.click()
        await human_delay(page, "navigate")
        await page.screenshot(path=screenshot_path("aws_step_1_after_password", email))

        pwd_err = page.locator('div:has-text("password is incorrect"), div:has-text("密码不正确"), #password_error')
        if await pwd_err.count() > 0 and await pwd_err.first.is_visible():
            raise RuntimeError("AWS Root 密码错误")

        await _aws_wait_captcha(page, email, "after_password")
        await _aws_dismiss_feedback(page)

        # MFA: Root 账号通常用 TOTP
        mfa_input = page.locator('#mfaCode')
        try:
            await mfa_input.wait_for(state="visible", timeout=15000)
            mfa_visible = True
        except Exception:
            mfa_visible = False

        if mfa_visible and totp_secret:
            logger.info("需要 MFA 验证码，本地生成 TOTP...")
            totp_code = await get_totp_code(secret=totp_secret)

            await mfa_input.fill(totp_code)
            await human_delay(page, "type")
            mfa_submit = page.locator('#mfa_submit_button')
            if await mfa_submit.count() > 0:
                await mfa_submit.click()
            else:
                await page.keyboard.press("Enter")
            await human_delay(page, "navigate")
            await page.screenshot(path=screenshot_path("aws_step_2_after_mfa", email))

        # 登录完成后 AWS 会 302 回 console.aws.amazon.com，再跳到我们最初请求的 destination
        try:
            await page.wait_for_url(re.compile(r"console\.aws\.amazon\.com"), timeout=90000)
        except Exception:
            logger.warning(f"等待跳回 console 超时，当前 URL: {page.url}")

    return page


async def login_aws(context: BrowserContext, email: str, password: str, totp_secret: str,
                    access_key_id: str = "", secret_access_key: str = "") -> str:
    """仅登录 AWS，落到 console 首页。Claude Platform 后续流程见 login_aws_claude。"""
    page = await aws_console_login(
        context, email, password, totp_secret,
        access_key_id, secret_access_key,
        destination_url=AWS_CONSOLE_HOME_URL,
    )
    final_url = page.url
    logger.info(f"AWS 登录完成，最终 URL: {final_url}")
    return final_url


async def login_aws_claude(context: BrowserContext, email: str, password: str, totp_secret: str,
                           access_key_id: str = "", secret_access_key: str = "") -> str:
    """登录 AWS，落到 Claude Platform access 控制台，完成开通/抓 key/workspace_id。"""
    page = await aws_console_login(
        context, email, password, totp_secret,
        access_key_id, secret_access_key,
        destination_url=AWS_CLAUDE_PLATFORM_URL,
    )

    # 兜底：如果停在 console 首页而不是 claude-platform，再 goto 一次
    if "claude-platform" not in page.url:
        logger.info("当前不在 claude-platform，主动跳转...")
        await page.goto(AWS_CLAUDE_PLATFORM_URL, wait_until="domcontentloaded")
        await human_delay(page, "navigate")

    await human_delay(page, "load")
    await page.screenshot(path=screenshot_path("aws_claude_platform", email))

    # 黄色横幅"需要访问权限" → 点击"开始使用 / 继续"开通访问
    clicked_start = await _aws_click_get_started(page, email)

    # 首次/恢复路径才需要走 onboarding。已开通账号直接跳过这段
    if clicked_start:
        await _aws_click_continue_activation(page, email)
        landed = await _aws_wait_anthropic_redirect(page, email)
        if landed:
            try:
                await claude_console_via_magic_link(page, email)
            except Exception as e:
                logger.warning(f"Claude Console magic-link 流程失败: {e}")
            try:
                await _aws_click_create_workspace(page, email)
            except Exception as e:
                logger.warning(f'"创建工作区" 流程失败: {e}')

    # —— 统一收尾：不论是否走过 onboarding，都检查 api-keys，没 key 就生成；再抓 workspace_id ——
    api_key = ""
    workspace_id = ""
    try:
        api_key = await _aws_ensure_longterm_key(page, email)
    except Exception as e:
        logger.warning(f'"长期密钥" 检查/生成失败: {e}')
    try:
        workspace_id = await _aws_get_workspace_id(page, email)
    except Exception as e:
        logger.warning(f"workspace_id 抓取失败: {e}")

    if api_key or workspace_id:
        line = f"{email}----{api_key}----{workspace_id}\n"
        with open(AWS_OUTPUT_FILE, "a") as f:
            f.write(line)
        logger.info(f"已写入 {AWS_OUTPUT_FILE}: api_key={api_key[:18] if api_key else '(已存在)'}... wrkspc={workspace_id}")

    # subus 推送已拆到独立 `subus` 子命令：python main.py subus aws_api_keys.txt
    # 这里不再自动调用，避免与文件批量推送重复

    final_url = page.url
    logger.info(f"Claude Platform 最终 URL: {final_url}")
    return final_url


async def _aws_click_create_workspace(page: Page, email: str) -> bool:
    """组织设置完成后回到 claude-platform/access，点击黄色横幅里的"创建工作区"按钮"""
    logger.info("回到 AWS Claude Platform access 页面...")
    await page.goto(AWS_CLAUDE_PLATFORM_URL, wait_until="domcontentloaded")
    await human_delay(page, "navigate")
    await human_delay(page, "load")
    await page.screenshot(path=screenshot_path("aws_back_to_access", email))

    selectors = [
        'button:has-text("创建工作区")',
        'a:has-text("创建工作区")',
        'button:has-text("Create workspace")',
        'a:has-text("Create workspace")',
    ]
    for sel in selectors:
        btn = page.locator(sel)
        try:
            if await btn.count() > 0 and await btn.first.is_visible():
                logger.info(f'点击 "创建工作区" (selector={sel})...')
                await btn.first.click()
                await human_delay(page, "navigate")
                await page.screenshot(path=screenshot_path("aws_after_create_workspace", email))
                return True
        except Exception as e:
            logger.debug(f"selector {sel} 检查异常: {e}")
    logger.info('未发现"创建工作区"按钮，可能已创建过工作区')
    return False


async def _aws_generate_longterm_key(page: Page, email: str) -> bool:
    """跳到 claude-platform/api-keys 页面，点 "生成长期密钥" 按钮"""
    logger.info("打开 API 密钥页面...")
    await page.goto(AWS_CLAUDE_API_KEYS_URL, wait_until="domcontentloaded")
    await human_delay(page, "navigate")
    await human_delay(page, "load")
    await page.screenshot(path=screenshot_path("aws_api_keys_landing", email))

    selectors = [
        'button:has-text("生成长期密钥")',
        'a:has-text("生成长期密钥")',
        'button:has-text("Generate long-term key")',
        'button:has-text("Generate long-lived key")',
        'a:has-text("Generate long-term key")',
        'a:has-text("Generate long-lived key")',
    ]
    for sel in selectors:
        btns = page.locator(sel)
        count = await btns.count()
        if count == 0:
            continue
        # 页面上可能有 2 个（右上角 + 中间），选第一个可见且可点击的
        for i in range(count):
            cand = btns.nth(i)
            try:
                if await cand.is_visible() and await cand.is_enabled():
                    logger.info(f'点击 "生成长期密钥" (selector={sel}, idx={i})...')
                    await cand.click()
                    await human_delay(page, "click")
                    await page.screenshot(path=screenshot_path("aws_after_generate_longterm", email))
                    return True
            except Exception as e:
                logger.debug(f"selector {sel}[{i}] 异常: {e}")
    logger.info('未发现"生成长期密钥"按钮，可能已无入口')
    return False


async def _aws_ensure_longterm_key(page: Page, email: str) -> str:
    """跳到 api-keys 页，先判断是否已有长期 key：
      - 已有：跳过生成，返回空串（key 只在生成那一次可见，无法回溯）
      - 没有：点 "生成长期密钥" → 抓 key → 关闭弹窗
    """
    logger.info("打开 API 密钥页面，检查长期密钥状态...")
    await page.goto(AWS_CLAUDE_API_KEYS_URL, wait_until="domcontentloaded")
    await human_delay(page, "navigate")
    await human_delay(page, "load")
    try:
        await page.wait_for_load_state("networkidle", timeout=15000)
    except Exception:
        pass
    await page.screenshot(path=screenshot_path("aws_api_keys_landing", email))

    body_text = ""
    try:
        body_text = await page.locator("body").inner_text()
    except Exception:
        pass

    no_key_signals = [
        "没有长期密钥",
        "尚未生成长期密钥",
        "No long-term keys",
        "No long-lived keys",
        "长期密钥 (0)",
        "Long-term keys (0)",
        "Long-lived keys (0)",
    ]
    if not any(s in body_text for s in no_key_signals):
        logger.info("已有长期密钥，跳过生成（AWS 不会再展示历史 key 值，仅记录 workspace_id）")
        return ""

    logger.info("尚未生成长期密钥，开始生成...")
    selectors = [
        'button:has-text("生成长期密钥")',
        'a:has-text("生成长期密钥")',
        'button:has-text("Generate long-term key")',
        'button:has-text("Generate long-lived key")',
        'a:has-text("Generate long-term key")',
        'a:has-text("Generate long-lived key")',
    ]
    clicked = False
    for sel in selectors:
        btns = page.locator(sel)
        count = await btns.count()
        for i in range(count):
            cand = btns.nth(i)
            try:
                if await cand.is_visible() and await cand.is_enabled():
                    logger.info(f'点击 "生成长期密钥" (selector={sel}, idx={i})...')
                    await cand.click()
                    await human_delay(page, "click")
                    clicked = True
                    break
            except Exception as e:
                logger.debug(f"selector {sel}[{i}] 异常: {e}")
        if clicked:
            break
    if not clicked:
        logger.warning('未发现"生成长期密钥"按钮（页面状态可能异常）')
        return ""

    return await _aws_capture_longterm_key(page, email)


async def _aws_capture_longterm_key(page: Page, email: str) -> str:
    """点击"生成长期密钥"后，从弹窗中提取 key。

    多策略：
      1) 弹窗内若有 name 输入框 + 生成按钮，先填名再点
      2) 轮询 body 文本 / input/code/pre 节点的内容，按多种 key 形态匹配
      3) 兜底：点 "复制" 按钮 → navigator.clipboard.readText()
    """
    # 把当前页面所在 context 的剪贴板权限打开（便于兜底读取）
    try:
        await page.context.grant_permissions(["clipboard-read", "clipboard-write"], origin="https://us-east-1.console.aws.amazon.com")
    except Exception as e:
        logger.debug(f"grant_permissions 失败（可忽略）: {e}")

    # 等待弹窗出现
    dialog = page.locator('[role="dialog"], dialog, [role="alertdialog"]').last
    try:
        await dialog.wait_for(state="visible", timeout=15000)
        scope = dialog
        logger.info("检测到弹窗，范围限定到 dialog")
    except Exception:
        scope = page.locator("body")
        logger.info("未检测到 dialog 元素，使用 body 作为查找范围")

    await page.screenshot(path=screenshot_path("aws_longterm_modal_step1", email))

    # 第一步：如果有名字输入框 + Generate/Create 按钮，先 fill + 点击
    name_input = scope.locator(
        'input[placeholder*="名称"], input[placeholder*="name"], input[placeholder*="Name"], '
        'input[type="text"]:visible'
    ).first
    if await name_input.count() > 0:
        try:
            if await name_input.is_visible():
                ph = (await name_input.get_attribute("placeholder")) or ""
                if any(k in ph.lower() for k in ("name", "named", "命名")) or "名称" in ph:
                    await name_input.fill(f"auto-{int(time.time())}")
                    await human_delay(page, "type")
        except Exception as e:
            logger.debug(f"name 输入框处理异常: {e}")

    gen_btn = scope.locator(
        'button:has-text("生成"), button:has-text("Generate"), '
        'button:has-text("创建"), button:has-text("Create"), '
        'button:has-text("确认"), button:has-text("Confirm")'
    ).first
    if await gen_btn.count() > 0:
        try:
            if await gen_btn.is_visible() and await gen_btn.is_enabled():
                await gen_btn.click()
                await human_delay(page, "click")
                await page.screenshot(path=screenshot_path("aws_longterm_modal_step2", email))
        except Exception as e:
            logger.debug(f"生成按钮处理异常: {e}")

    # 第二步：轮询 key
    # 容忍多种前缀：sk-ant-..., sk-..., AWS Bedrock 风格（base64 含 + / =）
    patterns = [
        re.compile(r"sk-ant[-_a-zA-Z0-9]{30,}"),
        re.compile(r"sk-[a-zA-Z0-9][-_a-zA-Z0-9]{30,}"),
        # 兜底：50+ 字符的 base64 token，可带 0-2 个 = padding
        re.compile(r"[A-Za-z0-9+/_-]{50,}={0,2}"),
    ]

    async def _scan_once() -> str:
        # body 文本
        try:
            body = await page.locator("body").inner_text()
        except Exception:
            body = ""
        for pat in patterns[:2]:  # body 用前两种严格模式
            m = pat.search(body)
            if m:
                return m.group(0)
        # input / textarea 的 value（inner_text 拿不到）
        for tag in ("input", "textarea"):
            els = page.locator(tag)
            try:
                n = await els.count()
            except Exception:
                n = 0
            for i in range(n):
                el = els.nth(i)
                try:
                    if not await el.is_visible():
                        continue
                    val = await el.input_value()
                except Exception:
                    val = ""
                for pat in patterns:
                    m = pat.search(val or "")
                    if m:
                        return m.group(0)
        # code/pre 的 inner_text
        for sel in ("code", "pre", "[class*='monospace']", "[class*='code']"):
            els = page.locator(sel)
            try:
                n = await els.count()
            except Exception:
                n = 0
            for i in range(n):
                el = els.nth(i)
                try:
                    if not await el.is_visible():
                        continue
                    txt = await el.inner_text()
                except Exception:
                    txt = ""
                for pat in patterns:
                    m = pat.search(txt or "")
                    if m:
                        return m.group(0)
        return ""

    api_key = ""
    for _ in range(60):  # ~30s
        api_key = await _scan_once()
        if api_key:
            break
        await page.wait_for_timeout(500)

    # 第三步：兜底 — 点 "复制" 按钮，再读剪贴板
    if not api_key:
        logger.info('未直接抓到 key，尝试点击"复制"按钮 + 读剪贴板...')
        copy_btn = scope.locator(
            'button:has-text("复制"), button:has-text("Copy"), '
            '[aria-label*="copy"], [aria-label*="Copy"], [aria-label*="复制"]'
        ).first
        try:
            if await copy_btn.count() > 0 and await copy_btn.is_visible():
                await copy_btn.click()
                await page.wait_for_timeout(500)
                try:
                    clip = await page.evaluate("() => navigator.clipboard.readText()")
                except Exception as e:
                    logger.debug(f"读取剪贴板失败: {e}")
                    clip = ""
                if clip:
                    for pat in patterns:
                        m = pat.search(clip)
                        if m:
                            api_key = m.group(0)
                            logger.info(f"从剪贴板提取到 key: {api_key[:25]}...")
                            break
        except Exception as e:
            logger.debug(f"复制按钮处理异常: {e}")

    if api_key:
        logger.info(f"提取到 long-term key: {api_key[:25]}... (len={len(api_key)})")
        await page.screenshot(path=screenshot_path("aws_longterm_key_visible", email))
    else:
        logger.warning("未抓到 long-term key（body/input/code/clipboard 均未命中）")
        await page.screenshot(path=screenshot_path("aws_longterm_key_missing", email))

    # 关闭弹窗：可能需要两次（确认已保存 + 关 modal）
    for i in range(2):
        close_btn = page.locator(
            'button:has-text("关闭"), button:has-text("Close"), '
            'button:has-text("完成"), button:has-text("Done"), '
            'button:has-text("我已保存"), button:has-text("I have saved")'
        ).first
        try:
            if await close_btn.count() > 0 and await close_btn.is_visible():
                logger.info(f"点击关闭弹窗 ({i + 1}/2)...")
                await close_btn.click()
                await page.wait_for_timeout(800)
            else:
                break
        except Exception as e:
            logger.debug(f"关闭按钮第 {i + 1} 次异常: {e}")
            break

    await page.screenshot(path=screenshot_path("aws_longterm_key_closed", email))
    return api_key


async def _aws_get_workspace_id(page: Page, email: str) -> str:
    """打开 workspaces 页，从表格里抓 wrkspc_xxx ID（取第一条）"""
    logger.info("打开 workspaces 页面...")
    await page.goto(AWS_CLAUDE_WORKSPACES_URL, wait_until="domcontentloaded")
    await human_delay(page, "navigate")
    await human_delay(page, "load")
    try:
        await page.wait_for_load_state("networkidle", timeout=15000)
    except Exception:
        pass
    await page.screenshot(path=screenshot_path("aws_workspaces_landing", email))

    wid_pattern = re.compile(r"wrkspc_[A-Za-z0-9]+")
    workspace_id = ""
    # 表格异步渲染，给最多 ~15s
    for _ in range(30):
        try:
            body = await page.locator("body").inner_text()
        except Exception:
            body = ""
        m = wid_pattern.search(body)
        if m:
            workspace_id = m.group(0)
            break
        await page.wait_for_timeout(500)

    if workspace_id:
        logger.info(f"提取到 workspace_id: {workspace_id}")
    else:
        logger.warning("workspaces 页面未找到 wrkspc_ 开头的 ID")
    return workspace_id


async def _aws_click_get_started(page: Page, email: str) -> bool:
    """Claude Platform on AWS 黄色横幅入口：
      - 首次访问：开始使用 / Get started
      - 上次设置中断后再次进入：继续 / Continue（"从上次中断的地方继续"）
    """
    selectors = [
        # 首次开通
        'button:has-text("开始使用")',
        'a:has-text("开始使用")',
        'button:has-text("Get started")',
        'a:has-text("Get started")',
        'button:has-text("Get Started")',
        # 中断恢复
        'button:has-text("继续")',
        'a:has-text("继续")',
        'button:has-text("Continue")',
        'a:has-text("Continue")',
    ]
    for sel in selectors:
        btn = page.locator(sel)
        try:
            if await btn.count() > 0 and await btn.first.is_visible():
                logger.info(f'点击 "开始使用" 按钮 (selector={sel})...')
                await btn.first.click()
                await human_delay(page, "navigate")
                await page.screenshot(path=screenshot_path("aws_after_get_started", email))
                return True
        except Exception as e:
            logger.debug(f"selector {sel} 检查异常: {e}")
    logger.info('未发现"开始使用"按钮，可能已开通访问')
    return False


async def _aws_click_continue_activation(page: Page, email: str) -> bool:
    """"让我们开始吧" 页面里点 "继续"，启动激活流程。"""
    selectors = [
        'button:has-text("继续")',
        'a:has-text("继续")',
        'button:has-text("Continue")',
        'a:has-text("Continue")',
    ]
    # 给页面加载留点时间
    try:
        await page.wait_for_load_state("networkidle", timeout=10000)
    except Exception:
        pass
    for sel in selectors:
        btn = page.locator(sel)
        try:
            if await btn.count() > 0 and await btn.first.is_visible():
                logger.info(f'点击 "继续" 按钮 (selector={sel})...')
                await btn.first.click()
                await human_delay(page, "navigate")
                await page.screenshot(path=screenshot_path("aws_after_continue", email))
                return True
        except Exception as e:
            logger.debug(f"selector {sel} 检查异常: {e}")
    logger.info('未发现"继续"按钮，跳过激活步骤')
    return False


async def _aws_wait_anthropic_redirect(page: Page, email: str, timeout_s: int = 360) -> bool:
    """激活可能需要几分钟，最终会跳转到 Anthropic / Claude 域名。轮询等待。"""
    logger.info(f"等待 Anthropic 跳转，最长 {timeout_s}s...")
    end = time.time() + timeout_s
    last_url = page.url
    while time.time() < end:
        await page.wait_for_timeout(5000)
        try:
            current = page.url
        except Exception:
            continue
        if current != last_url:
            logger.info(f"URL 变化: {current}")
            last_url = current
        if re.search(r"(anthropic\.com|claude\.com|claude\.ai)", current):
            logger.info(f"已跳转到 Anthropic / Claude: {current}")
            await page.screenshot(path=screenshot_path("aws_anthropic_landed", email))
            return True
    logger.warning(f"等待 Anthropic 跳转超时，停留在: {page.url}")
    await page.screenshot(path=screenshot_path("aws_anthropic_timeout", email))
    return False


