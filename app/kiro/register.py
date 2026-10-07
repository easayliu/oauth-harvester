"""Kiro：注册流程（Google/GitHub/IDC OAuth inline、kiro.dev 交互）（由 main.py 拆分而来）"""

from datetime import datetime
import asyncio
import json
import logging
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid

import pexpect

from playwright.async_api import Page, BrowserContext

from app.settings import AWS_IDC_EMAIL_DOMAIN, GOOGLE_NEW_PASSWORD, HEADLESS, PROXY
from app.core.browser import _promote_kiro_asset_cache, close_kiro_persistent_context, get_kiro_profile_dir, get_totp_code, human_delay, kiro_browser_backend, launch_kiro_persistent_context, screenshot_path
from app.core.waf import handle_aws_waf
from app.kiro.api import (
    KIRO_IDC_DEFAULT_SCOPES,
    KIRO_OUTPUT_FILE,
    KIRO_PROFILE_ARN_DEFAULT,
    KIRO_SQLITE_PATH,
    _idc_instance_region_from_url,
    _idc_region_from_start_url,
    current_kiro_sqlite_path,
    kiro_get_usage_limits,
    kiro_list_first_profile_arn,
    read_kiro_auth_kv,
    read_kiro_social_token,
    run_kiro_logout,
    set_kiro_sqlite_path,
)
from app.kiro.parsing import append_kiro_record

logger = logging.getLogger(__name__)


# 点 Continue 前的最小静置秒数。实测强相关：点击前静置够久的账号成功，秒点的账号易触发
# 'Kiro failed to load'——给 SPA 足够时间完成后台 prefetch/预请求是关键。
# 从 11s 下调到 7s 提速：现在已有 _kiro_recover_failed_to_load + 多轮重试兜底，偶发的
# failed-to-load 会被 Retry/换轮救回，不再需要用超长静置去 100% 规避。若发现 failed-to-load
# 明显变多，把这个值调回 9~11 即可。readiness 等待超时也与它对齐（见 _CONTINUE_READY_MS）。
_CONTINUE_DWELL_S = 7.0
_CONTINUE_READY_MS = 7000


async def _kshot(page, name: str, label: str = None) -> None:
    """kiro 内联登录用的尽力而为截图：禁用动画、超时 4s、吞异常，绝不阻塞登录。
    这些 inline 登录函数原本一张图都不拍，失败时是黑盒——加截图后能从
    screenshots/<label>/ 直接看出卡在哪一页。"""
    try:
        await page.screenshot(path=screenshot_path(name, label),
                              animations="disabled", timeout=4000)
    except Exception as e:
        logger.debug(f"截图 {name} 跳过（不影响流程）: {e}")


class InsecureBrowserBlocked(RuntimeError):
    """Google 登录页判定浏览器/环境不安全，跳过该账号。"""


_INSECURE_BROWSER_MARKERS = (
    "browser or app may not be secure",
    "this browser or app may not be secure",
    "try using a different browser",
    "此浏览器或应用可能不安全",
    "请尝试使用其他浏览器",
    "你使用的浏览器或应用可能不够安全",
)


async def _detect_insecure_browser(page) -> bool:
    """检查 Google 登录页是否显示"浏览器不安全"拦截。"""
    try:
        text = await page.locator("body").inner_text(timeout=2000)
    except Exception:
        return False
    lower = text.lower()
    return any(m in lower for m in _INSECURE_BROWSER_MARKERS)


async def kiro_google_oauth_inline(page: Page, context: BrowserContext,
                                   email: str, password: str, totp_secret: str):
    """在当前标签页内完成 Google 登录（被 kiro device flow 跳转到 Google 时调用）"""
    current_url = page.url
    if "accounts.google.com" not in current_url:
        return

    logger.info("kiro device flow → Google 登录页，开始自动填表")

    # 等页面稳定下来再操作（跳转瞬间 DOM 还没好）
    try:
        await page.wait_for_load_state("domcontentloaded", timeout=15000)
    except Exception as e:
        logger.warning(f"wait_for_load_state 异常: {e}")

    await _kshot(page, "kiro_google_landing", email)
    if await _detect_insecure_browser(page):
        raise InsecureBrowserBlocked("Google 登录页判定浏览器不安全（跳转前）")

    # email — 必须用 :visible 过滤：Google 在表单里埋了大量隐藏蜜罐 input（aria-hidden
    # 的 honeypot），裸 .first 会抓到 DOM 里第一个隐藏诱饵，wait_for(visible) 永远超时。
    try:
        email_input = page.locator(
            'input[type="email"]:visible, input#identifierId:visible, '
            'input[name="identifier"]:visible'
        ).first
        await email_input.wait_for(state="visible", timeout=15000)
        await email_input.fill(email)
        await human_delay(page, "type")
        next_btn = page.locator("#identifierNext")
        if await next_btn.count() > 0:
            await next_btn.first.click()
        else:
            await page.keyboard.press("Enter")
        logger.info("邮箱已提交")
        await human_delay(page, "navigate")
    except Exception as e:
        logger.warning(f"email 步骤异常: {e}")
    await _kshot(page, "kiro_google_after_email", email)

    if await _detect_insecure_browser(page):
        raise InsecureBrowserBlocked("Google 登录页判定浏览器不安全（邮箱提交后）")

    # password — 同样要 :visible 过滤掉隐藏蜜罐（日志里见到 44 个 name="hiddenPassword"
    # 的隐藏 input，裸 .first 抓的就是它们）
    try:
        pw_input = page.locator('input[type="password"]:visible').first
        await pw_input.wait_for(state="visible", timeout=20000)
        await pw_input.fill(password)
        await human_delay(page, "type")
        next_btn = page.locator("#passwordNext")
        if await next_btn.count() > 0:
            await next_btn.first.click()
        else:
            await page.keyboard.press("Enter")
        logger.info("密码已提交")
        await human_delay(page, "navigate")
    except Exception as e:
        logger.warning(f"password 步骤异常: {e}")
    await _kshot(page, "kiro_google_after_password", email)

    # 密码错误时试修改后的密码
    try:
        err = page.locator('span:has-text("Wrong password"), span:has-text("密码错误")')
        if await err.count() > 0:
            logger.info("密码错误，尝试使用 config.GOOGLE_NEW_PASSWORD")
            pw_input = page.locator('input[type="password"]:visible').first
            await pw_input.fill("")
            await pw_input.fill(GOOGLE_NEW_PASSWORD)
            await human_delay(page, "type")
            await page.keyboard.press("Enter")
            await human_delay(page, "navigate")
    except Exception:
        pass

    # 2FA — 密码提交后可能跳 challenge 页
    await human_delay(page, "load")
    try:
        current_url = page.url
        if "challenge" in current_url or "signin/v2" in current_url:
            logger.info("需要 TOTP 验证")
            otp_input = page.locator(
                'input[type="tel"]:visible, #totpPin:visible, '
                'input[name="totpPin"]:visible').first
            await otp_input.wait_for(state="visible", timeout=15000)
            totp_code = await get_totp_code(secret=totp_secret)
            await otp_input.fill(totp_code)
            nxt = page.locator("#totpNext")
            if await nxt.count() > 0:
                await nxt.first.click()
            else:
                await page.keyboard.press("Enter")
            logger.info("TOTP 已提交")
            await human_delay(page, "navigate")
    except Exception as e:
        logger.warning(f"2FA 步骤异常: {e}")


async def kiro_github_oauth_inline(page: Page, context: BrowserContext,
                                   username: str, password: str,
                                   totp_secret: str = "") -> None:
    """在当前标签页内完成 GitHub 登录（被 kiro device flow 跳转到 github.com 时调用）。

    依次处理：
      1) /login 用户名+密码表单（#login_field + #password）
      2) /sessions/two-factor/app TOTP 页（input[name="otp"]，用 totp_secret 算 6 位 code）
    """
    if "github.com" not in page.url:
        return

    logger.info("kiro device flow → GitHub 登录页，开始自动填表")

    try:
        await page.wait_for_load_state("domcontentloaded", timeout=15000)
    except Exception as e:
        logger.warning(f"wait_for_load_state 异常: {e}")

    # 等任意可识别的元素出现（登录表单 / 2FA 框 / OAuth 同意按钮），最多 20s
    try:
        await page.wait_for_selector(
            '#login_field, input[name="otp"], '
            'button[name="authorize"], form[action*="authorize"]',
            timeout=20000,
        )
    except Exception:
        pass

    # 1) 用户名 + 密码（cookie 已登录或直接跳到 2FA 时无 #login_field，跳过）
    if await page.locator('#login_field').count() > 0:
        try:
            user_input = page.locator(
                '#login_field, input[name="login"], input[autocomplete="username"]'
            ).first
            await user_input.wait_for(state="visible", timeout=20000)
            await user_input.fill(username)
            await human_delay(page, "type")

            pw_input = page.locator(
                '#password, input[name="password"], input[type="password"]'
            ).first
            await pw_input.wait_for(state="visible", timeout=10000)
            await pw_input.fill(password)
            await human_delay(page, "type")

            submit = page.locator(
                'input[type="submit"][name="commit"], '
                'button[type="submit"]:has-text("Sign in"), '
                'button:has-text("Sign in")'
            ).first
            if await submit.count() > 0:
                await submit.click()
            else:
                await page.keyboard.press("Enter")
            logger.info("GitHub: 用户名/密码已提交")
            await human_delay(page, "navigate")
        except Exception as e:
            logger.warning(f"GitHub 登录步骤异常: {e}")

    # 2) TOTP 双因素页 —— /sessions/two-factor/app 或 /sessions/two-factor
    try:
        await page.wait_for_load_state("domcontentloaded", timeout=10000)
    except Exception:
        pass

    on_two_factor = (
        "two-factor" in page.url
        or await page.locator('input[name="otp"]').count() > 0
    )
    if on_two_factor:
        if not totp_secret:
            logger.warning("GitHub 跳到 2FA 页但凭据里没 totp_secret，跳过")
            return
        try:
            otp_input = page.locator(
                'input[name="otp"], input#app_totp, input[autocomplete="one-time-code"]'
            ).first
            await otp_input.wait_for(state="visible", timeout=15000)
            totp_code = await get_totp_code(secret=totp_secret)
            await otp_input.fill(totp_code)
            await human_delay(page, "type")
            # GitHub 现在多数版本是输完 6 位自动提交；仍兜底点 Verify
            submit = page.locator(
                'button[type="submit"]:has-text("Verify"), '
                'button:has-text("Verify"), '
                'button[type="submit"]:has-text("Sign in"), '
                'input[type="submit"]'
            ).first
            if await submit.count() > 0 and await submit.first.is_visible():
                try:
                    await submit.click()
                except Exception:
                    pass
            logger.info(f"GitHub: TOTP {totp_code} 已提交")
            await human_delay(page, "navigate")
        except Exception as e:
            logger.warning(f"GitHub 2FA 步骤异常: {e}")


async def _idc_resolve_signin_page(context: BrowserContext, page: Page,
                                   on_provider, timeout_s: int = 25) -> Page:
    """kiro.dev IdC 页点 Continue 后，AWS 登录页可能是 (a) 当前 tab 直接跳转，或
    (b) 新开一个 tab/popup（us-east-1.signin.aws/platform/.../login）。轮询 context
    所有页面，返回应当继续驱动的那个 page（命中 on_provider 的）；超时未见则返回原 page。
    """
    for _ in range(timeout_s):
        try:
            if on_provider(page.url):
                return page
        except Exception:
            pass
        for p in list(context.pages):
            if p is page:
                continue
            try:
                if on_provider(p.url):
                    logger.info(f"IDC: 切到新 tab 的 AWS 登录页 {p.url[:90]}")
                    try:
                        await p.bring_to_front()
                    except Exception:
                        pass
                    return p
            except Exception:
                continue
        await page.wait_for_timeout(1000)
    # 超时未命中：dump CloakBrowser 所有 tab 的 URL，便于判断登录页到底开在哪
    try:
        urls = [p.url for p in context.pages]
        logger.warning(
            f"IDC: {timeout_s}s 内未在自动化浏览器里找到 AWS 登录页。"
            f"当前 context tabs={urls}。若登录页开在你的主 Chrome 而非这里，"
            f"说明 Continue 走了系统默认浏览器，需要改走 AppleScript 抓取。"
        )
    except Exception:
        pass
    return page


async def _kiro_click_signin_option(page: Page, text: str) -> bool:
    """在 app.kiro.dev/signin 选择页点击文字为 text 的入口（Google/GitHub/Builder ID/
    Your organization 等），并校验点击确实生效（离开了选择页）。

    为什么要校验：选择页是 SPA，纯 .click() 偶尔不触发跳转（命中错元素/事件没绑上），
    "点了"但页面没动。这里点完用「URL 变化 或 'Choose a way to sign' 文字消失」判定生效，
    没生效就升级到 force click → JS click 兜底重点。social 选 provider 和 idc 选
    Your organization 共用本方法。

    只匹配真正可交互元素（button/a/role=button），不用 div:has-text——那会命中包含该
    文字的最外层大容器，.first 取到它后点的是空白处。返回是否成功离开选择页。
    """
    loc = page.locator(
        f'button:has-text("{text}"), a:has-text("{text}"), '
        f'[role="button"]:has-text("{text}")'
    ).first
    try:
        if await loc.count() == 0 or not await loc.is_visible():
            return False
    except Exception:
        return False

    prev_url = page.url
    for attempt in range(3):
        try:
            await loc.scroll_into_view_if_needed(timeout=3000)
        except Exception:
            pass
        try:
            if attempt == 0:
                await loc.click(timeout=5000)
            elif attempt == 1:
                await loc.click(timeout=5000, force=True)
            else:
                await loc.evaluate("el => el.click()")
            logger.info(f"kiro.dev signin: 点击入口 '{text}'（尝试{attempt + 1}）")
        except Exception as e:
            logger.debug(f"kiro.dev signin: 点击 '{text}' 尝试{attempt + 1} 异常: {e}")
            continue
        try:
            await page.wait_for_function(
                "(prev) => location.href !== prev"
                " || !/Choose a way to sign/i.test(document.body.innerText)",
                arg=prev_url, timeout=6000,
            )
            logger.info(f"kiro.dev signin: '{text}' 点击生效，已离开选择页")
            await human_delay(page, "click")
            return True
        except Exception:
            logger.warning(
                f"kiro.dev signin: '{text}' 点击后页面未变，重试（尝试{attempt + 1}）"
            )
            continue
    return False


async def kiro_select_idc_on_kiro_dev(page: Page) -> bool:
    """在 https://app.kiro.dev/signin 页面上选择 IAM Identity Center 入口（标签 "Your
    organization"）。点击经 _kiro_click_signin_option 校验生效；找不到候选时 dump 页面
    所有按钮文字到日志，方便定位真实标签。
    """
    if "app.kiro.dev" not in page.url:
        return False
    try:
        await page.wait_for_load_state("domcontentloaded", timeout=10000)
    except Exception:
        pass

    candidates = (
        # app.kiro.dev/signin 实际标签：IdC 入口叫 "Your organization"
        "Your organization", "Your Organization",
        # 英文常见命名
        "IAM Identity Center", "Identity Center", "AWS Identity Center",
        "AWS IDC", "AWS IdC", "IdC", "AWS Access Portal", "Access Portal",
        "AWS SSO", "Single Sign-On", "Single sign-on",
        "Sign in with IAM Identity Center", "Sign in with Identity Center",
        "Sign in with IAM", "Sign in with AWS",
        "Continue with IAM Identity Center", "Continue with Identity Center",
        "Continue with IAM", "Continue with AWS",
        "Use IAM Identity Center", "Use Identity Center",
        "Pro", "Pro account", "Enterprise", "Company SSO", "Workforce",
        # 中文
        "您的组织", "你的组织", "所在组织",
        "身份中心", "IAM 身份中心", "企业账号", "公司账号", "通过 AWS",
        "使用 IAM 身份中心", "使用 AWS 身份中心",
    )
    for text in candidates:
        if await _kiro_click_signin_option(page, text):
            return True

    # 都没匹配上：dump 页面所有 button/a/role=button 的文字给诊断
    try:
        labels = await page.evaluate("""() => {
            const seen = new Set();
            const out = [];
            document.querySelectorAll('button, a, [role="button"], [role="tab"]').forEach(el => {
                const t = (el.innerText || el.textContent || '').trim().replace(/\\s+/g, ' ');
                if (t && t.length < 80 && !seen.has(t)) { seen.add(t); out.push(t); }
            });
            return out;
        }""")
        logger.warning(
            f"kiro.dev signin: 未识别 IDC 入口，页面候选 labels={labels[:40]}"
        )
    except Exception as e:
        logger.debug(f"dump labels 异常: {e}")
    return False


async def kiro_select_github_on_kiro_dev(page: Page) -> bool:
    """在 https://app.kiro.dev/signin 页面上选择 GitHub 入口。返回是否成功点击。"""
    if "app.kiro.dev" not in page.url:
        return False
    try:
        await page.wait_for_load_state("domcontentloaded", timeout=10000)
    except Exception:
        pass

    candidates = (
        "Continue with GitHub", "Sign in with GitHub", "Log in with GitHub",
        "Use GitHub", "GitHub",
        "使用 GitHub 继续", "通过 GitHub 登录", "用 GitHub 登录",
    )
    for text in candidates:
        if await _kiro_click_signin_option(page, text):
            return True
    return False


async def _click_continue_until_navigated(
        page: Page, cont, prev_url: str, attempts: int = 3) -> bool:
    """点 Continue 并校验是否真的跳走。逐级升级：直接 JS click → force click → Enter。

    关键：Continue 生效有两种形态 —— (a) 当前 tab 直接跳 AWS 登录页；(b) 新开 tab/popup
    到 AWS（kiro.dev 某些账号走 window.open）。旧实现只看当前 tab 的 location.href 变化，
    (b) 会被误判成"未跳转"→ 继续升级重点 → 可能开出重复 tab / 触发 'Kiro failed to load'。
    这里每次点完都跨 context 所有 tab 轮询：当前 tab 变址 或 任意 tab 到 AWS 就算成功，
    且下一轮点击前先复查，已生效就不再重复点。返回 True=已跳转，False=没跳转。
    """
    ctx = page.context

    def _navigated() -> bool:
        # 当前 tab 已离开原表单 URL
        try:
            if page.url != prev_url and _on_aws_signin_url(page.url):
                return True
        except Exception:
            pass
        # 或任意 tab（含新开 popup）已到 AWS 登录域
        for p in list(ctx.pages):
            try:
                if _on_aws_signin_url(p.url):
                    return True
            except Exception:
                continue
        return False

    for attempt in range(attempts):
        # 点击前先复查：上一轮点击可能已在新 tab 生效，别再重复点
        if _navigated():
            logger.info("kiro.dev signin: Continue 已生效（某 tab 已到 AWS），停止重复点击")
            await human_delay(page, "navigate")
            return True
        try:
            if await cont.count() > 0 and await cont.is_visible():
                # 直接点击：首选 JS el.click() 直接触发 onClick，不依赖 React 把按钮判成
                # enabled、也不受指针命中/遮罩影响（实测最稳）；再退到 force click / Enter 兜底。
                if attempt == 0:
                    await cont.evaluate("el => el.click()")
                elif attempt == 1:
                    await cont.click(timeout=4000, force=True)
                else:
                    await page.keyboard.press("Enter")
            else:
                await page.keyboard.press("Enter")
        except Exception as e:
            logger.debug(f"kiro.dev 点 Continue 尝试{attempt + 1} 异常: {e}")
            try:
                await page.keyboard.press("Enter")
            except Exception:
                pass
        # 点完 6s 内轮询任一 tab 是否到 AWS（500ms 一次，兼顾同 tab 跳转与新 tab）
        for _ in range(12):
            if _navigated():
                logger.info(f"kiro.dev signin: Continue 生效已跳转 → {page.url[:90]}")
                await human_delay(page, "navigate")
                return True
            await page.wait_for_timeout(500)
        logger.warning(
            f"kiro.dev signin: Continue 点击后页面未跳转，重试（尝试{attempt + 1}）")

    # 放弃前 dump 表单实况（error toast / 按钮态 / Region 值），即使外层被中断也留下根因
    try:
        diag = await page.evaluate(
            """() => {
              const reg = document.querySelector(
                'input[name*="region" i],input[id*="region" i],'
                + 'input[aria-label*="region" i],input[placeholder*="region" i],'
                + 'input[placeholder*="us-east-1" i]');
              const btn = [...document.querySelectorAll('button')].find(b =>
                b.type === 'submit'
                || /continue|next|sign in|继续|下一步|登录/i.test(b.textContent || ''));
              const errs = [...document.querySelectorAll(
                  '[role="alert"],[class*="error" i],[class*="Error"]')]
                .map(e => (e.textContent || '').trim()).filter(Boolean).slice(0, 3);
              return {
                region: reg ? (reg.value || '<empty>') : '<no-input>',
                btn: btn ? ((btn.textContent || '').trim().slice(0, 20)
                  + (btn.disabled ? ' [disabled]' : ' [enabled]')) : '<no-btn>',
                errors: errs,
              };
            }""")
        logger.warning(f"kiro.dev signin: Continue 放弃前实况: {diag}")
    except Exception as e:
        logger.debug(f"kiro.dev signin: Continue 放弃前 dump 失败: {e}")
    return False


async def _dismiss_kiro_consent_overlay(page: Page) -> bool:
    """点掉可能盖在表单上、拦截 Continue 点击的 cookie/consent 遮罩。

    仍在 app.kiro.dev 的 Start URL 表单阶段（尚未跳 AWS），这里出现的 "Accept" 基本是
    cookie/隐私同意横幅——之前诊断 dump 里 `continueBtn: 'Accept'` 就是它排在真正的
    Continue 前面。点掉它再点 Continue 即可，无需 reload。返回 True=点掉了一个。
    """
    for text in ("Accept all", "Accept All", "Accept cookies", "Accept",
                 "同意", "全部接受", "接受全部", "允许全部"):
        try:
            btn = page.locator(
                f'button:has-text("{text}"), [role="button"]:has-text("{text}")'
            ).first
            if await btn.count() > 0 and await btn.is_visible():
                await btn.click(timeout=3000)
                logger.info(f"kiro.dev signin: 点掉疑似遮罩按钮 '{text}'")
                await page.wait_for_timeout(400)
                return True
        except Exception:
            continue
    return False


async def _fill_kiro_region_combobox(page: Page, region_inp, region: str,
                                     attempts: int = 3) -> bool:
    """把 Region 值稳定填进 kiro.dev 的 Region combobox，并回读确认它没被 re-render 冲空。

    为什么不能用 fill / native-setter：Region 不是 Start URL 那种纯受控文本框，而是带下拉的
    combobox。用 setter 直接写 value 既不会打开下拉、也不会提交组件内部的“选中态”，一旦
    失焦或点 Continue 触发校验，输入框就回退成空（只剩灰色 placeholder）→ Continue 因必填
    项无提交值被静默拦下、页面不跳 AWS（本 bug 现象）。

    正确姿势：真实逐字符键盘输入（会触发下拉）→ 有下拉项就点/回车选中提交，没有就 blur
    让受控框提交当前值 → 回读 input_value 确认值真的留住。整套最多重试 attempts 次，
    每次失败都清空重来，直到回读匹配为止。
    """
    for i in range(attempts):
        try:
            await region_inp.click()
        except Exception:
            pass
        # 清空现有内容（上一轮残留或 placeholder 态）
        try:
            await region_inp.press("ControlOrMeta+a")
            await region_inp.press("Delete")
        except Exception:
            pass
        # 真实逐字符键盘输入：既触发 combobox 下拉，也确保受控 onChange 收到事件
        typed = False
        try:
            await region_inp.press_sequentially(region, delay=45)
            typed = True
        except Exception as e:
            logger.debug(f"kiro.dev signin: Region 键盘输入异常，退回 setter: {e}")
            await _react_safe_fill_input(region_inp, region)
        await page.wait_for_timeout(500)
        # 浮出下拉建议项就点选中它（combobox 才 commit、下拉才收起）。区域名可能带前缀
        # （如 "US East (N. Virginia) us-east-1"），用 has-text 子串匹配即可命中。
        committed = False
        option = page.locator(
            f'[role="option"]:has-text("{region}"), '
            f'li[role="option"]:has-text("{region}"), '
            f'[role="listbox"] li:has-text("{region}"), '
            f'[role="listbox"] [role="option"]:has-text("{region}")'
        ).first
        try:
            await option.wait_for(state="visible", timeout=2500)
            await option.click()
            committed = True
            logger.info(f"kiro.dev signin: 已从下拉选中 Region {region}")
        except Exception:
            # 无下拉项：若是真键盘输入，按 Enter 选中高亮项/提交；再不行就 blur 提交当前值
            if typed:
                try:
                    await region_inp.press("Enter")
                except Exception:
                    pass
            try:
                await region_inp.evaluate("el => el.blur()")
            except Exception:
                pass
        # 回读确认：等 re-render 尘埃落定后再读，避免读到还没回退的瞬时值。
        await page.wait_for_timeout(400)
        try:
            cur = (await region_inp.input_value()).strip()
        except Exception:
            cur = ""
        # 成功判定放宽：
        #   1) 点中过下拉项（committed）且框里还有值 → 已 commit（Select 版可能显示的是
        #      "US East (N. Virginia)" 这类 label 而非 "us-east-1"，不能要求精确等于）；
        #   2) 或框里内容包含目标 region（Autosuggest 自由文本版）。
        if (committed and cur) or (region.lower() in cur.lower()):
            return True
        logger.info(
            f"kiro.dev signin: Region 第{i + 1}/{attempts} 次填后回读="
            f"{'空' if not cur else cur[:24]}（committed={committed}），重试")
    return False


async def kiro_idc_enter_start_url_on_kiro_dev(
        page: Page, start_url: str, region: str = "us-east-1") -> bool:
    """在 app.kiro.dev 选完 "Your organization" 后，进入 IAM Identity Center 并填表。
    顺序：
      1) "Your organization" 后的页面默认可能是别的 IdP 入口，先点
         "Sign in via IAM Identity Center instead" 切到 Start URL 模式；
      2) 填 Start URL 输入框 + Region 输入框（Region 必填，默认 us-east-1）；
      3) 点 Continue，提交后 302 到 awsapps.com/start 设备授权页。
    找不到 Start URL 输入框就当作该版本不需要填（直接跳 awsapps），返回是否填了。
    """
    try:
        await page.wait_for_load_state("domcontentloaded", timeout=8000)
    except Exception:
        pass

    # 1) 切换到 IAM Identity Center 模式（"Sign in via IAM Identity Center instead"）
    for text in ("Sign in via IAM Identity Center instead",
                 "Sign in with IAM Identity Center instead",
                 "Sign in via IAM Identity Center",
                 "Sign in with IAM Identity Center",
                 "IAM Identity Center instead", "IAM Identity Center",
                 "改用 IAM 身份中心", "使用 IAM 身份中心登录", "通过 IAM 身份中心登录"):
        link = page.locator(
            f'a:has-text("{text}"), button:has-text("{text}"), '
            f'[role="button"]:has-text("{text}")'
        )
        try:
            if await link.count() > 0 and await link.first.is_visible():
                await link.first.click()
                logger.info(f"kiro.dev signin: 点击 '{text}' 切到 IAM Identity Center")
                await human_delay(page, "click")
                break
        except Exception:
            continue

    # 2) 填 Start URL（第一个输入框；Region 框 placeholder 是 us-east-1，不含 url/https/start，
    #    不会被这个选择器误中）
    url_inp = page.locator(
        'input[name="startUrl"], input[id="startUrl"], '
        'input[name="issuerUrl"], input[id="issuerUrl"], '
        'input[type="url"], '
        'input[placeholder*="start" i], input[placeholder*="https" i], '
        'input[aria-label*="URL" i], input[placeholder*="URL" i]'
    ).first
    try:
        await url_inp.wait_for(state="visible", timeout=6000)
    except Exception:
        logger.info("kiro.dev signin: 未见 Start URL 输入框，跳过（可能直接跳 awsapps）")
        return False
    # React-safe fill：kiro.dev 的 Start URL 是受控 React input，普通 Playwright fill
    # 不触发 React 的 value setter → state 仍为空 → 点 Continue 校验失败、页面不跳转（实测卡死）。
    if not await _react_safe_fill_input(url_inp, start_url):
        logger.warning("kiro.dev: Start URL React-safe 填值未确认（Continue 可能因空值失败）")
    await human_delay(page, "type")

    # 3) 填 Region（必填，placeholder "e.g., us-east-1"）
    region_inp = page.locator(
        'input[name*="region" i], input[id*="region" i], '
        'input[aria-label*="region" i], input[placeholder*="region" i], '
        'input[placeholder*="us-east-1" i]'
    ).first
    try:
        if await region_inp.count() > 0 and await region_inp.is_visible():
            # Region 是【combobox】，不是 Start URL 那种纯受控文本框：native setter 写进
            # DOM value 也不开下拉、更不提交内部选中态，失焦/校验时又回退成空 →
            # 框里只剩灰色 placeholder（本 bug 根因：失败截图里 Start URL 亮白已填、Region
            # 却是空 placeholder，Continue 因 Region 必填无提交值被静默拦下、不跳 AWS）。
            # 所以必须【真实逐字符键盘输入】触发下拉 → 点选/Enter 提交那一项 → 回读确认值
            # 真的留住，才算填好。_fill_kiro_region_combobox 内含最多 3 次重试。
            if not await _fill_kiro_region_combobox(page, region_inp, region):
                logger.warning(
                    "kiro.dev signin: Region 填值多次回读仍未留住（Continue 可能因空值失败）")
            else:
                logger.info(f"kiro.dev signin: 已填并确认 Region {region}")
        else:
            logger.info("kiro.dev signin: 未见 Region 输入框（该版本可能不需要）")
    except Exception as e:
        logger.warning(f"kiro.dev 填 Region 异常: {e}")

    # 4) 点 Continue（选完 Region 下拉收起后才会重新出现）。
    #    点完必须校验「真的跳走了」——SPA 里纯 .click() 偶发不触发提交（React onClick 没绑上/
    #    命中禁用态），页面停在 Start URL 表单上空等（实测卡死）。用 URL 变化判定生效，没生效
    #    就升级 force click → JS click → Enter 兜底重点。
    cont = page.locator(
        'button[type="submit"], button:has-text("Continue"), '
        'button:has-text("Next"), button:has-text("Sign in"), '
        'button:has-text("继续"), button:has-text("下一步"), '
        'button:has-text("登录")'
    ).first
    # 选完下拉后 React 要先把 Region 值提交进受控 state 并重新校验，Continue 才重新出现
    # 且变为可点（disabled→enabled），实测偶尔要 ~10s。过去只 human_delay(0.8~2s) 就抢着点，
    # 命中未就绪态 → 6s URL 没变 → warning 重试才成功，白白浪费。这里改成条件等待：
    # 「Region 值已写入 + Continue 可见且 enabled」就立刻继续，最长等 12s，快的账号 1~2s 就过。
    _ready_t0 = time.monotonic()
    try:
        await page.wait_for_function(
            """(want) => {
                const inp = document.querySelector(
                    'input[name*="region" i],input[id*="region" i],'
                    + 'input[aria-label*="region" i],input[placeholder*="region" i],'
                    + 'input[placeholder*="us-east-1" i]');
                const valOk = !inp || (inp.value || '')
                    .toLowerCase().includes(String(want).toLowerCase());
                // Start URL 必须仍有值：填 Region 触发的 re-render 可能把没进 React state
                // 的 Start URL 冲回空（本 bug 根因）。空值时 Continue 虽 enabled 但提交被
                // 校验静默拦下、页面不跳 → 这里不放行，交给下面的补填逻辑。
                const url = document.querySelector(
                    'input[name="startUrl"],input[id="startUrl"],'
                    + 'input[name="issuerUrl"],input[id="issuerUrl"],'
                    + 'input[type="url"],input[placeholder*="start" i],'
                    + 'input[placeholder*="https" i]');
                const urlOk = !url || (url.value || '').trim().length > 0;
                const btn = [...document.querySelectorAll('button')].find(b =>
                    b.type === 'submit'
                    || /continue|next|sign in|继续|下一步|登录/i.test(b.textContent || ''));
                // 不再靠 React 的 disabled/aria-disabled 判按钮是否可点（偶发一直判 disabled，
                // 白等到超时才点）——只要按钮已渲染且可见就放行，点击本身走下面的直接 JS click。
                const btnOk = btn && btn.offsetParent !== null;
                return valOk && urlOk && btnOk;
            }""",
            arg=region, timeout=_CONTINUE_READY_MS)
        logger.info("kiro.dev signin: Region 已提交且 Continue 就绪，直接点击")
    except Exception:
        # 兜底：条件没等到也不放弃，仍走下面的 3 次重试点击（原有安全网）
        logger.info(
            f"kiro.dev signin: 等 Continue 就绪超时({_CONTINUE_READY_MS // 1000}s)，仍尝试点击")

    # 点 Continue 前静置：readiness 秒过的账号若立刻点，会抢在 SPA 完成后台 prefetch/预请求
    # 之前 → 触发 'Kiro failed to load' 且 reload 救不回。补足到 _CONTINUE_DWELL_S 的最小静置，
    # 复现「点击前等够」的成功行为；readiness 本身已耗时超过此值的账号 remaining<=0、不额外拖延。
    _remaining = _CONTINUE_DWELL_S - (time.monotonic() - _ready_t0)
    if _remaining > 0:
        logger.info(
            f"kiro.dev signin: Continue 前静置 {_remaining:.0f}s（避免抢跑触发 Kiro failed to load）")
        await page.wait_for_timeout(int(_remaining * 1000))

    # 点 Continue 前最后一道保险：确认 Start URL 值还在（填 Region 的 re-render 有可能把
    # 未进 React state 的值冲空）。空了就 react-safe 补填一次，避免带空 Start URL 提交卡死。
    try:
        cur = (await url_inp.input_value()).strip()
        if cur != start_url:
            logger.warning(
                f"kiro.dev signin: Continue 前 Start URL 值异常"
                f"(当前={'空' if not cur else cur[:40]})，补填一次")
            await _react_safe_fill_input(url_inp, start_url)
    except Exception as e:
        logger.debug(f"kiro.dev signin: Continue 前校验 Start URL 异常: {e}")

    # 同款保险：确认 Region 值还在（Region 必填，空则 Continue 静默不跳——本 bug 的直接
    # 表现）。回读发现被冲空/不符就用 combobox 专用逻辑重填一次（不能用 setter，会再次不生效）。
    try:
        if await region_inp.count() > 0 and await region_inp.is_visible():
            cur_r = (await region_inp.input_value()).strip()
            # 宽松判定：只要框里为空才算异常（Select 版可能显示 label 而非 "us-east-1"，
            # 但只要非空即已选中；空才是本 bug 的“没提交值”态）。
            if not cur_r:
                logger.warning(
                    "kiro.dev signin: Continue 前 Region 仍为空，重填一次")
                await _fill_kiro_region_combobox(page, region_inp, region, attempts=2)
    except Exception as e:
        logger.debug(f"kiro.dev signin: Continue 前校验 Region 异常: {e}")

    # 5) 点 Continue：绝大多数账号、以及"只是被遮罩挡住"的账号到这一步就过了。
    prev_url = page.url
    if await _click_continue_until_navigated(page, cont, prev_url):
        logger.info(f"kiro.dev signin: 已填 Start URL={start_url} Region={region}，Continue 生效")
        return True

    # 兜底：可能是 cookie/consent 遮罩拦截了点击。点掉它再点一轮 Continue。
    if await _dismiss_kiro_consent_overlay(page):
        if await _click_continue_until_navigated(page, cont, page.url):
            logger.info("kiro.dev signin: 清除遮罩后 Continue 生效")
            return True

    # 仍未跳转：区分根因写日志
    reason = "未知"
    try:
        cur = ""
        try:
            cur = (await url_inp.input_value()).strip()
        except Exception:
            pass
        if not cur:
            reason = "Start URL 值为空（未进 React 受控 state，提交被校验静默拦下）"
        else:
            reason = f"Start URL 值在({cur[:40]})但仍未跳转（Continue onClick 可能未生效/被遮罩拦截）"
    except Exception:
        pass
    logger.warning(f"kiro.dev signin: Continue 多轮点击+兜底仍未跳转 —— {reason}")
    return False


# 提交临时密码后，这些按钮属于"已登录、进入审批流"的标志（出现即说明本次无需改密）。
# 不含裸 "Continue"/"Next"——它们可能是改密表单自己的提交按钮，会误判。
_IDC_APPROVAL_BTN_TEXTS = (
    "Skip for now", "Skip", "以后再说", "跳过",
    "Allow access", "Allow", "Approve", "Accept", "允许访问", "允许", "批准", "接受",
    "Confirm and continue", "确认并继续",
)


async def _idc_change_password_required(page: Page, timeout_s: float = 15.0) -> bool:
    """提交临时密码后判定本次登录是否真的要求强制改密。

    不是每个账号都强制改密，所以用短轮询取代过去对密码框的 20s 盲等：
      - 出现 >=2 个密码框（新密码 + 确认）→ True（要改密）
      - 先冒出审批/同意页按钮（Skip/Allow/确认并继续 等）→ False（已登录，跳过改密）
      - 超时仍两者皆无 → False（按无需改密处理）
    每轮先看密码框数量再看按钮：改密页即便submit写着Continue，也因 2 个密码框先判 True。
    """
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            if await page.locator('input[type="password"]').count() >= 2:
                return True
        except Exception:
            pass
        for text in _IDC_APPROVAL_BTN_TEXTS:
            try:
                btn = page.locator(
                    f'button:has-text("{text}"), a:has-text("{text}"), '
                    f'[role="button"]:has-text("{text}")'
                ).first
                if await btn.count() > 0 and await btn.is_visible():
                    return False
            except Exception:
                continue
        await page.wait_for_timeout(400)
    return False


async def _react_safe_fill_passwords(page: Page, values: list) -> int:
    """React-friendly 填多个 password 框，返回页面实际密码框数量。

    为什么不用 Playwright fill：Playwright 的 fill 内部 dispatch 的是普通 InputEvent，
    React 用了自己的 `Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set`
    override，普通 fill 不走 React 的 setter → state 不更新 → submit 时 React 拿到的 state
    是空 → 服务端看到只填了一个框（实测 step 4 改密 nth(1) 频繁丢失）。

    本函数用 native value setter 直接绕过 React override 后，再 dispatch 'input' 和
    'change' 两个 React 监听的事件，确保 React state 同步更新。

    values 长度 < 页面 password 框数量时，按序填前 N 个；多余的框留空。
    """
    actual_count = await page.evaluate(
        """
        (values) => {
          const inputs = Array.from(document.querySelectorAll('input[type="password"]'));
          const nativeSetter = Object.getOwnPropertyDescriptor(
            HTMLInputElement.prototype, 'value'
          ).set;
          for (let i = 0; i < Math.min(inputs.length, values.length); i++) {
            const inp = inputs[i];
            // 先 focus 让 React 的 onFocus handler 走完
            inp.focus();
            nativeSetter.call(inp, values[i]);
            inp.dispatchEvent(new Event('input', { bubbles: true }));
            inp.dispatchEvent(new Event('change', { bubbles: true }));
          }
          // 最后一个 blur 触发 validation
          if (inputs.length > 0) {
            inputs[Math.min(inputs.length, values.length) - 1].blur();
          }
          return inputs.length;
        }
        """,
        values,
    )
    return int(actual_count or 0)


async def _react_safe_fill_input(loc, value: str) -> bool:
    """React-friendly 填单个文本框，并回读确认值真落进 DOM。

    理由同 _react_safe_fill_passwords：Playwright 普通 fill 不走 React 的 value setter
    override，state 不更新 → 提交时 React 拿到空值（用户名/邮箱框同样中招）。这里用
    native setter + input/change 事件绕过；setter 路径异常再退回普通 fill 兜底。"""
    try:
        await loc.evaluate(
            """(el, v) => {
              const setter = Object.getOwnPropertyDescriptor(
                HTMLInputElement.prototype, 'value').set;
              const prev = el.value;
              el.focus();
              setter.call(el, v);
              // 关键：把 React 的 _valueTracker 强行改回旧值，让它在下一次 onChange 里
              // 检测到 node.value(新) !== tracked(旧) → 必定触发 setState。缺这一步时，
              // 某些 React 构建下 input 事件被判"值没变"而吞掉 → state 仍为空（本 bug 根因）。
              const tracker = el._valueTracker;
              if (tracker) tracker.setValue(prev);
              el.dispatchEvent(new Event('input', { bubbles: true }));
              el.dispatchEvent(new Event('change', { bubbles: true }));
            }""",
            value,
        )
    except Exception:
        try:
            await loc.fill(value)
        except Exception:
            return False
    try:
        if (await loc.input_value()) == value:
            return True
    except Exception:
        return False
    # setter 路径没落值：退回真实键盘输入（逐字符 keydown/input/keyup），React 一定收得到。
    try:
        await loc.fill("")
        await loc.press_sequentially(value, delay=15)
        return (await loc.input_value()) == value
    except Exception:
        return False


def _pwd_fingerprint(pwd: str) -> str:
    """脱敏密码指纹：长度 + 前 2 / 后 2 字符。
    用于诊断 fill 进去的密码是否被解析/转义/截断改坏，不暴露完整密码。
    """
    if not pwd:
        return "EMPTY"
    if len(pwd) <= 4:
        return f"len={len(pwd)} <too_short_to_show>"
    return f"len={len(pwd)} head='{pwd[:2]}' tail='{pwd[-2:]}'"


async def _idc_on_allow_consent_page(page: Page) -> bool:
    """严格判断当前页面是否已是真正的 Allow 同意页（"Allow Kiro CLI to access your
    data?" / "Allow access to AWS accounts"）。用于已登录态的 fast skip：
      - cookie 复用、admin 已登录 → 不需要 username/password/改密
      - 直接跳到审批序列，省 ~30s 的 wait_for timeout

    必须【同时】满足两条，缺一不可：
      (a) 页面文案含同意页专属措辞（"access your data" / "access the following" 等）；
      (b) 有终极 "Allow access" 按钮。
    只凭按钮文案会误判 —— 设备码确认页（"Confirm the following code"，带 Confirm/Next/
    甚至 Approve）和登录页都可能撞上旧的宽松匹配。一旦把这些页误判成"已登录"，就会跳过
    账号密码步骤，被打回 Sign in 页后空表单狂点 Next → "Invalid username" 永久卡死
    （实测 h1098621640 即此坑）。所以这里加文案闸门，把码确认页/登录页排除掉。
    """
    try:
        body_text = (await page.inner_text("body", timeout=1500)).lower()
    except Exception:
        body_text = ""
    consent_phrases = (
        "to access your data", "access the following", "access your data",
        "allow access to aws", "agree to allow",
        "访问您的数据", "访问以下", "授权访问",
    )
    if not any(p in body_text for p in consent_phrases):
        return False
    # 文案命中后，再确认终极同意按钮存在且可见（"Allow access"/"允许访问"，
    # 不用宽松的 "Allow"/"Approve"——避免再次撞到码确认页的按钮）。
    for text in ("Allow access", "允许访问"):
        try:
            btn = page.locator(
                f'button:has-text("{text}"), a:has-text("{text}"), '
                f'[role="button"]:has-text("{text}")'
            ).first
            if await btn.count() == 0:
                continue
            if await btn.is_visible():
                return True
        except Exception:
            continue
    return False


async def kiro_idc_signin_inline(page: Page, context: BrowserContext,
                                 username: str, temp_pwd: str,
                                 new_pwd: str, is_login_done=None) -> None:
    """在 IAM Identity Center (AWS Access Portal) 完成登录（按需改密）。
    调用时页面已落在 awsapps.com/start 或 portal.us-east-1.app.aws。
    成功后页面应跳到"Allow access to AWS accounts"同意页或直接 302 到回调。
    不是每个账号都强制改密：要求改时填 new_pwd，不要求就跳过。

    Fast skip：每个 step 失败/超时时检查是否已到 Allow 同意页，是则跳过后续 step。
    cookie 复用场景下整个登录序列可省 30+ 秒（原来 20s+20s+ 的 wait_for timeout）。
    """
    logger.info("kiro device flow → AWS IDC 登录页，开始自动填表")

    try:
        await page.wait_for_load_state("domcontentloaded", timeout=15000)
    except Exception as e:
        logger.warning(f"wait_for_load_state 异常: {e}")

    # 0) 登录页可能挂 AWS WAF "Security check" 人机校验，先过掉（CapSolver 或人工兜底）
    await handle_aws_waf(page, context)

    # 1) 设备代码确认页：button "Confirm and continue" / "Allow"
    #    注意：用户名页的提交按钮也是 "Next"/"下一步"，跟这里的设备确认按钮文案撞车。
    #    若当前已经是用户名页（页面上有 username 输入框），直接跳到第 2 步填用户名，
    #    不要点 "下一步"——否则会在没填用户名前就提交（见日志反馈：
    #    "不应该先点击下一步，而是直接输入用户名"）。
    #    同时这里只认明确的设备确认文案（Confirm and continue / Allow），
    #    去掉 Continue/Next/继续/下一步 这些跟用户名页撞车的泛词。
    username_box = page.locator(
        'input[name="username"], input[id="username"], '
        'input[name="signInName"], input[type="email"], '
        'input[type="text"]:not([disabled])'
    )
    on_username_page = False
    try:
        on_username_page = (await username_box.count() > 0
                            and await username_box.first.is_visible())
    except Exception:
        pass

    if on_username_page:
        logger.info("IDC: 当前已是用户名页，跳过设备确认按钮，直接输入用户名")
    else:
        for text in ("Confirm and continue", "确认并继续", "Confirm", "确认",
                     "Allow access", "Allow", "允许访问", "允许"):
            btn = page.locator(
                f'button:has-text("{text}"), [role="button"]:has-text("{text}"), '
                f'input[type="submit"][value="{text}"]'
            )
            if await btn.count() > 0:
                try:
                    if await btn.first.is_visible():
                        await btn.first.click()
                        logger.info(f"IDC: 点击设备确认按钮 '{text}'")
                        await human_delay(page, "click")
                        break
                except Exception:
                    pass

    # Fast skip 标志：检测到已是 Allow 同意页就跳过 username/password/改密
    already_at_allow = False
    # 直跳改密标志：已登录态但未改密 → 页面是 "Set new password"，有 2 个密码框（new + confirm）。
    # step 3 不能盲填 temp_pwd 到 new 框（错位、且 confirm 框空导致 form reject），必须直接
    # 进 step 4 改密逻辑用 new_pwd 同时填 new + confirm。
    at_set_password_page = False

    # 2) 用户名页 —— fast-detect：先快速看页面状态，再决定动作
    #    跳过条件（参考 step 3 的检测模式）：
    #      - 页面已是 Allow 同意页（cookie 复用）→ 跳过登录全流程
    #      - 页面已有密码框 = 已经过了 username 阶段 → 跳过 step 2，让 step 3 处理
    #      - 找不到 username input → 短超时（3s）后跳过，不再死等 8s
    user_input_selector = (
        'input[name="username"], input[id="username"], '
        'input[name="signInName"], input[type="email"], '
        'input[type="text"]:not([disabled])'
    )
    # 短轮询 3s 探测页面状态：username 框 / password 框 / Allow 按钮，谁先出现
    deadline = time.time() + 3.0
    detected_state = "unknown"
    while time.time() < deadline:
        try:
            if await page.locator('input[type="password"]').count() > 0:
                detected_state = "password_or_change"
                break
        except Exception:
            pass
        if await _idc_on_allow_consent_page(page):
            detected_state = "allow"
            break
        try:
            ui = page.locator(user_input_selector).first
            if await ui.count() > 0 and await ui.is_visible():
                detected_state = "username"
                break
        except Exception:
            pass
        await page.wait_for_timeout(300)
    logger.info(f"IDC: step 2 入口探测页面状态 = {detected_state}")

    if detected_state == "allow":
        already_at_allow = True
        logger.info("IDC: 探测到 Allow 同意页（已登录态），跳过 username/password/改密")
    elif detected_state == "password_or_change":
        logger.info("IDC: 探测到密码框存在，跳过 step 2 username（直接进 step 3 / step 4 由密码框数量判定）")
    elif detected_state == "username":
        # 正常用户名页，fill + 提交
        try:
            user_input = page.locator(user_input_selector).first
            if not await _react_safe_fill_input(user_input, username):
                logger.warning("IDC: username React-safe 填值未确认（提交可能因用户名为空失败）")
            await human_delay(page, "type")
            await handle_aws_waf(page, context)
            # click + Enter 双发：headless Firefox 下 React onClick 偶发失败
            await user_input.focus()
            submit = page.locator(
                'button[type="submit"], button:has-text("Next"), '
                'button:has-text("Sign in"), button:has-text("下一步"), '
                'button:has-text("登录")'
            ).first
            if await submit.count() > 0:
                try:
                    await submit.click(timeout=2000)
                except Exception:
                    pass
            await page.keyboard.press("Enter")
            logger.info("IDC: username 已提交 (click + Enter 双发)")
            await human_delay(page, "navigate")
            logger.info(f"IDC: username submit 后 URL: {page.url[:150]}")
        except Exception as e:
            logger.warning(f"IDC username 步骤异常: {e}（当前 URL: {page.url[:120]}）")
    else:
        logger.warning(
            f"IDC: 3s 内未识别页面状态（既无 username 框也无密码框也无 Allow 按钮），"
            f"当前 URL: {page.url[:120]}"
        )

    # 3) 临时密码页
    #    跳过条件：
    #      - already_at_allow：已在 Allow 同意页（cookie 复用，全跳）
    #      - 当前页 ≥2 个密码框：已是 Set new password 页（已登录但未改密），
    #        不要在 New password 框错位填 temp_pwd（截图实测：填错位 + Confirm 空 → form reject），
    #        直接跳到 step 4 用 new_pwd 填两个框
    if already_at_allow:
        logger.info("IDC: 已是 Allow 同意页，跳过临时密码步骤")
    else:
        # 先检测是不是直接到了 Set new password 页 —— 短轮询 1.5s 等 React hydration
        # 完成所有密码框（实测：第 1 次检测可能只有 New 框，~500ms 后 Confirm 框才 mount）
        deadline = time.time() + 1.5
        pwd_count_now = 0
        while time.time() < deadline:
            try:
                pwd_count_now = await page.locator('input[type="password"]').count()
            except Exception:
                pwd_count_now = 0
            if pwd_count_now >= 2:
                break
            await page.wait_for_timeout(150)
        logger.info(f"IDC: step 3 入口密码框数量 = {pwd_count_now}")
        if pwd_count_now >= 2:
            at_set_password_page = True
            logger.info(
                f"IDC: 检测到 {pwd_count_now} 个密码框，页面已是 Set new password 页"
                "（已登录态待改密），跳过临时密码步骤直接进改密"
            )
    if (not already_at_allow) and (not at_set_password_page):
        try:
            pw_input = page.locator('input[type="password"]').first
            await pw_input.wait_for(state="visible", timeout=8000)
            # 关键：WAF "Security check" 框会盖住密码框（pointer_events check 失败：
            # covered by <DIV>）。靠文字检测 WAF 是否解掉不够准，直接循环重试填密码——
            # 你手点 Verify 解掉 WAF、框消失露出密码框后，fill 就成功了。约 3 分钟内每 3s 一试。
            await handle_aws_waf(page, context)
            logger.info(f"IDC: 即将 fill 临时密码 fingerprint={_pwd_fingerprint(temp_pwd)}")
            # React-safe fill：先 Playwright fill 兜底 WAF 遮挡场景，成功后再用 native setter
            # + dispatch event 确保 React state 同步（原 fill 在 React 偶发不更新 state）
            filled = False
            for attempt in range(60):
                try:
                    await pw_input.fill(temp_pwd, timeout=2500)
                    filled = True
                    break
                except Exception:
                    if attempt == 0:
                        logger.warning(
                            "IDC: 密码框被 WAF 框遮挡，请在浏览器里手点 Verify 解掉校验，"
                            "解掉后会自动继续填密码...")
                    await page.wait_for_timeout(3000)
            if not filled:
                logger.warning("IDC: 密码框始终被遮挡，最后用 force 填一次")
                await pw_input.fill(temp_pwd, force=True)
            # React-safe 兜底：用 native setter + dispatch event 覆盖 fill 进去的值
            try:
                await _react_safe_fill_passwords(page, [temp_pwd])
            except Exception:
                pass
            # 校验：fill 后从 input value 读回，确认实际进入 DOM 的字符串与 temp_pwd 一致
            try:
                actual = await pw_input.evaluate("el => el.value")
                actual_len = len(actual or "")
                if actual_len != len(temp_pwd):
                    logger.warning(
                        f"IDC: ⚠ 密码 fill 后 input.value 长度不符 "
                        f"expected={len(temp_pwd)} actual={actual_len} "
                        f"input_head='{(actual or '')[:2]}' input_tail='{(actual or '')[-2:]}'"
                    )
                else:
                    logger.info(f"IDC: 密码 fill 校验通过 (input.value 长度 {actual_len})")
            except Exception as e:
                logger.debug(f"IDC: 密码 fill 校验异常（不影响后续）: {e}")
            await human_delay(page, "type")
            # 三重 submit：button.click + 直接 Enter + JS form.submit()，最大化触发
            # React state machine。Cloudscape 经常用 fancy <button> 不在 <form> 里，
            # 单纯 button.click 在 headless Firefox 下 React onClick 不触发。
            await pw_input.focus()
            submit = page.locator(
                'button[type="submit"], button:has-text("Sign in"), '
                'button:has-text("登录")'
            ).first
            if await submit.count() > 0:
                try:
                    await submit.click(timeout=2000)
                except Exception:
                    pass
            # 接力 Enter：触发 React keypress handler（input 已 focus）
            await page.keyboard.press("Enter")
            logger.info("IDC: 临时密码已提交 (click + Enter 双发)")
            await human_delay(page, "navigate")
            pwd_post_url = page.url
            logger.info(f"IDC: password submit 后 URL: {pwd_post_url[:150]}")

            # 关键诊断：检测密码 submit 是否真生效。新版 IDC 在 us-east-1.signin.aws/platform/
            # 下，headless Firefox + React form 偶发 onClick 没触发，URL 保持在 `/login`
            # 同 workflowStateHandle。兜底：用 JS 直接调原生 form.submit() 重试一次（绕过
            # React onClick handler）。
            await page.wait_for_timeout(1500)
            # temp_pwd 提交后，首登强制改密的**正常**流程会 SPA 内部跳到「Set new password」
            # 页（≥2 个密码框），但 URL 仍停在 /login?workflowStateHandle=。所以**不能**只凭
            # URL 仍是 /login 就判 submit 失败——否则会误触发下面两条兜底，而两条兜底都只
            # fill pw_input.first（单框），在已是 2 框的改密页上就成了「只填了一个框」
            # （用户反馈：每次改密只输入一个框，要兜底才走两框）。先探测密码框数量：
            #   ≥2 → 已到改密页 → 标记 at_set_password_page，跳过两条兜底直接进 step 4 改密。
            try:
                pwd_n_after = await page.locator('input[type="password"]').count()
            except Exception:
                pwd_n_after = 0
            if pwd_n_after >= 2:
                at_set_password_page = True
                logger.info(
                    f"IDC: temp_pwd 提交后页面已有 {pwd_n_after} 个密码框，已 SPA 跳到 "
                    "Set new password 页，跳过 form.submit/new_pwd 兜底直接进改密"
                )
            if (
                not at_set_password_page
                and "/login" in page.url and "workflowStateHandle" in page.url
            ):
                logger.warning(
                    f"IDC: temp_pwd submit 后 URL 仍是登录页（{page.url[:120]}），"
                    "JS form.submit() 兜底重试一次"
                )
                try:
                    submitted = await page.evaluate(
                        """
                        () => {
                          const pw = document.querySelector('input[type="password"]');
                          if (!pw) return false;
                          const form = pw.closest('form');
                          if (!form) return false;
                          if (typeof form.requestSubmit === 'function') {
                            form.requestSubmit();
                          } else {
                            form.submit();
                          }
                          return true;
                        }
                        """
                    )
                    if submitted:
                        await page.wait_for_timeout(3000)
                        logger.info(f"IDC: form.submit() 后 URL: {page.url[:150]}")
                        # form.submit() 也可能把页面推进到 Set new password 页 —— 同样
                        # 探测密码框数量，≥2 就跳过下面的 new_pwd 单框兜底直接进改密。
                        try:
                            if await page.locator('input[type="password"]').count() >= 2:
                                at_set_password_page = True
                                logger.info(
                                    "IDC: form.submit() 后页面已有 ≥2 个密码框，已进 Set new "
                                    "password 页，跳过 new_pwd 兜底直接进改密"
                                )
                        except Exception:
                            pass
                except Exception as e:
                    logger.warning(f"IDC: JS form.submit() 兜底异常: {e}")

            # 第二层兜底：如果 temp_pwd 怎么都登不上，可能账号**已改过密**，OTP 早已失效，
            # 当前用户输入的"临时密码"字段其实是 new_pwd（持久密码）。改填 new_pwd 重试一次。
            # 触发条件（满足其一即可）：
            #   a) URL 仍停在登录页（/login?workflowStateHandle=）—— React 未跳转的常见态；
            #   b) 页面冒出"密码错误"错误提示 —— AWS IDC 拒绝后会就地显示 error banner，
            #      URL 可能已变，单凭 a) 抓不到，需文案兜底（参考 Google 流程的 Wrong password 检测）。
            # 另要求：未进改密页 + new_pwd 非空且与 temp_pwd 不同。
            # AWS IDC 拒绝凭据时的真实文案（实测截图）：
            #   标题 "Something doesn't compute"
            #   正文 "We couldn't verify your sign-in credentials. Please try again."
            # 此时会保留用户名（"Username: xxx (not you?)"）并清空密码框，等重填。
            # 同时兼容历史/其它 locale 的 "incorrect password" / "密码错误" 文案。
            incorrect_pwd_error = False
            try:
                err_loc = page.locator(
                    ':is(span,p,div,h1,h2,[role="alert"]):has-text("couldn\'t verify your sign-in credentials"), '
                    ':is(span,p,div,h1,h2,[role="alert"]):has-text("Something doesn\'t compute"), '
                    ':is(span,p,div,[role="alert"]):has-text("Your password is incorrect"), '
                    ':is(span,p,div,[role="alert"]):has-text("Incorrect username or password"), '
                    ':is(span,p,div,[role="alert"]):has-text("password is incorrect"), '
                    ':is(span,p,div,[role="alert"]):has-text("密码错误"), '
                    ':is(span,p,div,[role="alert"]):has-text("密码不正确")'
                )
                if await err_loc.count() > 0 and await err_loc.first.is_visible():
                    incorrect_pwd_error = True
                    logger.warning(
                        "IDC: 检测到登录凭据被拒提示"
                        "（Something doesn't compute / 密码错误），准备改填 new_pwd 重试"
                    )
            except Exception:
                pass
            still_on_login = "/login" in page.url and "workflowStateHandle" in page.url
            if (
                not at_set_password_page
                and (still_on_login or incorrect_pwd_error)
                and new_pwd and new_pwd != temp_pwd
            ):
                logger.warning(
                    f"IDC: temp_pwd 仍登不上，账号可能已改过密。改填 new_pwd "
                    f"fingerprint={_pwd_fingerprint(new_pwd)} 重试登录"
                )
                try:
                    await pw_input.fill(new_pwd, timeout=2500)
                    actual2 = await pw_input.evaluate("el => el.value")
                    if len(actual2 or "") != len(new_pwd):
                        logger.warning(
                            f"IDC: new_pwd fill 后长度不符 expected={len(new_pwd)} actual={len(actual2 or '')}"
                        )
                    submit2 = page.locator(
                        'button[type="submit"], button:has-text("Sign in"), '
                        'button:has-text("登录")'
                    ).first
                    if await submit2.count() > 0:
                        await submit2.click()
                    else:
                        await page.keyboard.press("Enter")
                    logger.info("IDC: new_pwd 已提交")
                    await page.wait_for_timeout(3000)
                    logger.info(f"IDC: new_pwd submit 后 URL: {page.url[:150]}")
                except Exception as e:
                    logger.warning(f"IDC: new_pwd 兜底登录异常: {e}")
        except Exception as e:
            # 密码框 8s 内不可见：可能已被 step 2 的 submit 跳到 Allow 页（罕见但可能）
            if await _idc_on_allow_consent_page(page):
                already_at_allow = True
                logger.info("IDC: 密码框未出现，页面已是 Allow 同意页，跳过后续步骤")
            else:
                logger.warning(f"IDC 临时密码步骤异常: {e}（当前 URL: {page.url[:120]}）")

    # 4) 改密页（已登录态直接跳过；不是每次都强制改密——要求改才填新密码，不要求就跳过）
    if already_at_allow:
        logger.info("IDC: 已是 Allow 同意页，跳过改密步骤")
    else:
        logger.info(f"IDC: 进入改密判断阶段，当前 URL: {page.url[:150]}")
        # at_set_password_page=True 时跳过登录页检查（页面就在 Set new password 页，
        # URL 仍含 /login?workflowStateHandle= 是正常的，因为改密前还没真正登录完成）。
        if not at_set_password_page:
            # 防误判：如果仍停在登录页（URL 没变），有 3 种可能：
            #   a) SPA 内部路由 —— URL 没变但页面已跳到 Set new password 页（≥2 密码框）
            #   b) SPA 内部路由 —— URL 没变但页面已跳到 Allow 同意页
            #   c) 真失败 —— 密码错 / 账号锁 / React onClick 未触发
            # a/b 不能 raise，要继续走对应分支
            if "/login" in page.url and "workflowStateHandle" in page.url:
                # 再扫一遍当前页面状态
                try:
                    pwd_n_now = await page.locator('input[type="password"]').count()
                except Exception:
                    pwd_n_now = 0
                if pwd_n_now >= 2:
                    at_set_password_page = True
                    logger.info(
                        f"IDC: URL 仍是登录页但页面有 {pwd_n_now} 个密码框（SPA 内部路由），"
                        "实际已是 Set new password 页，继续走改密"
                    )
                elif await _idc_on_allow_consent_page(page):
                    already_at_allow = True
                    logger.info(
                        "IDC: URL 仍是登录页但已有 Allow 系按钮（SPA 内部路由），"
                        "实际已是 Allow 同意页，跳过改密"
                    )
                else:
                    raise RuntimeError(
                        f"IDC: 临时密码 submit 失败，页面仍停在登录页 (url={page.url[:120]})。"
                        "可能原因：密码错误 / 账号被锁 / headless Firefox 下 React onClick 未触发。"
                        "建议：HEADLESS=False 重跑确认"
                    )
        try:
            # at_set_password_page=True 时不再调 _idc_change_password_required，
            # 直接当作需改密处理（页面就是 Set new password，已确认）
            if at_set_password_page or await _idc_change_password_required(page):
                await page.wait_for_timeout(500)  # 给 React 一点 mount 时间
                pwd_inputs = page.locator('input[type="password"]')
                n = await pwd_inputs.count()
                # 按密码框数量决定填充值序列：
                #   n >= 3: [旧密码, 新密码, 确认新密码]
                #   n == 2: [新密码, 确认新密码]
                if n >= 3:
                    values = [temp_pwd, new_pwd, new_pwd]
                elif n == 2:
                    values = [new_pwd, new_pwd]
                else:
                    values = []
                    logger.info(f"IDC: 仅 {n} 个密码框，按无需改密跳过")

                if values:
                    # 用 React-safe fill 一次性填所有框：native setter + dispatch input/change
                    # 事件，绕过 React 的 value setter override。原 Playwright fill 在
                    # nth(0) → nth(1) 顺序填时，React state 第 2 个框频繁丢失（用户反馈：
                    # "他只输入了一个框，第二个密码框没输入"）。
                    actual_n = await _react_safe_fill_passwords(page, values)
                    logger.info(
                        f"IDC: React-safe fill {len(values)} 个密码框（页面共 {actual_n} 个）"
                    )
                    # 逐个校验 value 长度，发现不符立刻 warning
                    for i, expected in enumerate(values):
                        try:
                            actual = await pwd_inputs.nth(i).evaluate("el => el.value")
                            actual_len = len(actual or "")
                            if actual_len != len(expected):
                                logger.warning(
                                    f"IDC: ⚠ 第 {i+1} 个密码框 fill 后长度不符 "
                                    f"expected={len(expected)} actual={actual_len}"
                                )
                        except Exception:
                            pass
                    await human_delay(page, "type")
                    submit = page.locator(
                        'button[type="submit"], '
                        'button:has-text("Set new password"), '
                        'button:has-text("Change password"), '
                        'button:has-text("Update password"), '
                        'button:has-text("Confirm"), '
                        'button:has-text("设置新密码"), '
                        'button:has-text("修改密码"), '
                        'button:has-text("确认")'
                    ).first
                    # click + Enter 双发（同 step 2/3 理由）
                    if await submit.count() > 0:
                        try:
                            await submit.click(timeout=2000)
                        except Exception:
                            pass
                    # focus 到最后一个密码框再按 Enter，确保 React keypress 触发 form submit
                    try:
                        await pwd_inputs.nth(len(values) - 1).focus()
                    except Exception:
                        pass
                    await page.keyboard.press("Enter")
                    logger.info("IDC: 需改密，新密码已提交 (click + Enter 双发)")
                    await human_delay(page, "navigate")
            else:
                logger.info("IDC: 本次登录无需改密，跳过改密步骤")
        except Exception as e:
            logger.warning(f"IDC 改密步骤异常: {e}")

    # 5) 登录后的审批序列
    logger.info(f"IDC: 进入审批序列阶段，当前 URL: {page.url[:150]}")
    # 顺序/出现与否都不定，可能依次是
    #      【Skip MFA 注册】→【"已请求授权" 设备码确认页：确认并继续】→
    #      【"Allow access to AWS accounts" 同意页：Allow/允许】
    #    Allow 页在"确认并继续"之后由 AWS 跳转，可能慢（实测 ~30s）。所以：
    #      - 点到 Allow（最终同意）→ 立即结束；
    #      - 没东西可点时，按"距上次成功点击超过 45s"才判定结束（给 Allow 慢加载留足时间），
    #        而不是连续 N 轮空转就退（否则慢加载会被提前 break、漏点 Allow）。
    skip_texts = ("Skip for now", "Skip", "跳过", "以后再说")
    # 真正终结 device authorize 的按钮 —— 点了立即 break
    allow_terminal = ("Allow access", "Allow", "允许访问", "允许")
    # 中间步骤按钮（Accept Terms / Approve Request 之类）—— 点了不 break，继续找终极 Allow
    # AWS IDC 实测：改密之后可能先跳到一个 "Accept Authorization Request" 页，按钮叫 Accept，
    # 点完才到 "Allow access to AWS accounts"。如果把 Accept 当终极按钮直接 break，OIDC
    # server 永远不会被 mark authorized，kiro-cli polling 不到 token。
    allow_intermediate = ("Approve", "Accept", "批准", "接受")
    confirm_texts = ("Confirm and continue", "确认并继续",
                     "Continue", "Next", "继续", "下一步", "Confirm", "确认")

    # 审批阶段不要拟人延迟：WAF 已过，按钮一可见就立刻点（点不动就 force），
    # 否则 human_delay + click 自带可操作性等待会把"明明已显示的允许访问"拖很久。
    #
    # 点击后的统一收尾全部收口到 _click_one 里，各调用分支不再各自处理，避免漏写等待导致
    # 同一个按钮被连点重复提交（曾出现连刷 3 条「点击审批按钮 Next」→ OIDC 设备确认表单
    # 被重复提交 → 设备没被 mark authorized → kiro-cli polling 静默卡死）。两道防线：
    #   ① 同名按钮在「同一 URL」上只点一次（last_click_sig 去重）——没跳转就不再连点；
    #   ② 每次成功点击后等 networkidle（超时退回固定等待），让页面真的跳转/重渲染再回循环。
    last_click_sig = None  # 上次成功点击的 (按钮文案, 点击时 URL)

    async def _click_one(texts) -> bool:
        nonlocal last_click_sig
        for text in texts:
            btn = page.locator(
                f'button:has-text("{text}"), a:has-text("{text}"), '
                f'[role="button"]:has-text("{text}"), '
                f'input[type="submit"][value="{text}"]'
            ).first
            try:
                if await btn.count() == 0 or not await btn.is_visible():
                    continue
            except Exception:
                continue
            sig = (text, page.url)
            if sig == last_click_sig:
                # 同一页面上刚点过同名按钮、且页面没跳转（URL 没变）→ 这一般就是重复提交源，
                # 本轮跳过不再点；真需要再点时页面通常已变（URL 变 / 按钮消失）会自然放行。
                continue
            try:
                await btn.click(timeout=2000)
            except Exception:
                try:
                    await btn.click(timeout=2000, force=True)
                except Exception:
                    continue
            last_click_sig = sig
            logger.info(f"IDC: 点击审批按钮 '{text}'（URL: {page.url[:120]}）")
            # 点完统一等页面跳转/重渲染，再交回循环重新扫描按钮。
            try:
                await page.wait_for_load_state("networkidle", timeout=8000)
            except Exception:
                await page.wait_for_timeout(800)
            return True
        return False

    # —— 审批流被打回凭据页时的自愈 ——
    # fast-skip 误判 / cookie 过期重登 / 设备码确认后才要求登录，都会让审批流落到
    # Sign in / 临时密码 / 改密页。此时绝不能让下面的 confirm_texts 在空表单上盲点 Next
    # （空 username 点 Next → "Invalid username" 永久卡死，实测 h1098621640）。
    # 检测到凭据页就把账号/密码填回去并提交，让流程自己走回 Allow 同意页。
    recover_done = set()  # 已处理过的 (动作, URL)，避免同一页重复填/重复提交

    async def _submit_credential(input_loc) -> None:
        try:
            await input_loc.focus()
        except Exception:
            pass
        submit = page.locator(
            'button[type="submit"], button:has-text("Next"), '
            'button:has-text("Sign in"), button:has-text("Continue"), '
            'button:has-text("下一步"), button:has-text("登录")'
        ).first
        try:
            if await submit.count() > 0 and await submit.is_visible():
                await submit.click(timeout=2000)
        except Exception:
            pass
        try:
            await page.keyboard.press("Enter")  # click + Enter 双发（同 step2/3）
        except Exception:
            pass
        try:
            await page.wait_for_load_state("networkidle", timeout=8000)
        except Exception:
            await page.wait_for_timeout(800)

    async def _recover_credentials_if_login_page() -> bool:
        """在凭据页则填回账号/密码并提交，返回 True（本轮已处理）；不在凭据页返回 False。"""
        url = page.url
        try:
            n_pwd = await page.locator('input[type="password"]').count()
        except Exception:
            n_pwd = 0
        # 密码框数量定动作：≥2=改密页(new_pwd 两遍)，==1=临时密码页(temp_pwd)
        if n_pwd >= 2 and ("setpwd", url) not in recover_done:
            recover_done.add(("setpwd", url))
            boxes = page.locator('input[type="password"]')
            try:
                await handle_aws_waf(page, context)
                await _react_safe_fill_input(boxes.nth(0), new_pwd)
                await _react_safe_fill_input(boxes.nth(1), new_pwd)
                logger.info(f"IDC: [审批流恢复] 改密页填 new_pwd fp={_pwd_fingerprint(new_pwd)}")
                await _submit_credential(boxes.nth(1))
            except Exception as e:
                logger.warning(f"IDC: [审批流恢复] 改密填值异常: {e}")
            return True
        if n_pwd == 1 and ("temppwd", url) not in recover_done:
            recover_done.add(("temppwd", url))
            box = page.locator('input[type="password"]').first
            try:
                await handle_aws_waf(page, context)
                await _react_safe_fill_input(box, temp_pwd)
                logger.info(f"IDC: [审批流恢复] 密码页填 temp_pwd fp={_pwd_fingerprint(temp_pwd)}")
                await _submit_credential(box)
            except Exception as e:
                logger.warning(f"IDC: [审批流恢复] 密码填值异常: {e}")
            return True
        # 用户名页：有可见 username 框且当前为空（截图里的 "Invalid username" 即空表单点 Next）
        if ("username", url) not in recover_done:
            try:
                ub = page.locator(user_input_selector).first
                if await ub.count() > 0 and await ub.is_visible():
                    try:
                        cur = (await ub.input_value()) or ""
                    except Exception:
                        cur = ""
                    if not cur.strip():
                        recover_done.add(("username", url))
                        await handle_aws_waf(page, context)
                        await _react_safe_fill_input(ub, username)
                        logger.info(f"IDC: [审批流恢复] Sign in 页填 username={username!r}")
                        await _submit_credential(ub)
                        return True
            except Exception as e:
                logger.warning(f"IDC: [审批流恢复] username 填值异常: {e}")
        return False

    approve_deadline = time.time() + 240  # 整个审批序列最多 4 分钟：改密后 AWS 跳到
    # device 同意页实测可慢至 ~130s（先经 #/workflowResultHandle 中转再渲染 Allow）。
    # 旧的 2 分钟上限会在 device 页出现前就截断，漏点 Allow → kiro-cli 永远 polling 不到 token。
    last_action = time.time()
    last_url = page.url
    # 这些 URL 片段表示"AWS 仍在内部跳转、device 同意页尚未渲染"。处于这些状态时
    # 绝不能用 no-action 计时提前结束 —— Allow 按钮还没出现，一旦提前退出就再没人
    # 点 Allow（这正是本次卡死的根因：在 #/workflowResultHandle 上空等 45s 被误判结束）。
    transitional_url_hints = ("workflowresulthandle", "/mfa", "/password",
                              "oauth", "authorize", "saml", "/login")
    while time.time() < approve_deadline:
        # kiro-cli 已拿到 token = 设备授权已生效，审批目的已达成，立刻收尾。
        # 这是消除"45s 空转"的关键：终极 Allow 的按钮文案没匹配上（已自动批准 /
        # 页面文案变体）时，过去只能干等 45s no-action 才退出；现在 token 一落库即退。
        if is_login_done is not None and is_login_done():
            logger.info("IDC: kiro-cli 已拿到 token，审批已生效，提前结束审批序列")
            break
        # AWS 仍在推进流程（URL 变化）= 有进展，顺延 no-action 计时，避免把"页面正慢慢
        # 跳向 device 同意页"误判成卡死。hash 路由（#/workflowResultHandle → #/device）
        # 的变化 page.url 同样能感知到。
        if page.url != last_url:
            logger.info(f"IDC: 审批流 URL 变化 → {page.url[:120]}")
            last_url = page.url
            last_action = time.time()
        if await _click_one(skip_texts):
            last_action = time.time()
            continue
        # 终极 Allow：点完即结束（_click_one 内已等过 networkidle，form submit 已 flush）
        if await _click_one(allow_terminal):
            logger.info("IDC: 已点最终 Allow 同意授权，审批完成")
            break
        # 被打回登录/改密页 → 先把凭据填回去，绝不让下面 confirm_texts 在空表单上盲点 Next。
        if await _recover_credentials_if_login_page():
            last_action = time.time()
            continue
        # 中间步骤的 Accept/Approve：点了不 break，继续循环找终极 Allow（可能在下一页）
        if await _click_one(allow_intermediate):
            last_action = time.time()
            logger.info(f"IDC: 中间步骤已点，当前 URL: {page.url[:120]}")
            continue
        if await _click_one(confirm_texts):
            last_action = time.time()
            continue
        # 没按钮可点：token 已落库立即退；否则距上次成功点击 >45s 才结束
        # （45s 覆盖"确认并继续"后 Allow 页慢加载窗口，实测 ~30s，不能轻易缩短；
        #  但 token 信号已能在成功路径上秒退，这个 45s 现在只在真失败/真无按钮时兜底）。
        if is_login_done is not None and is_login_done():
            logger.info("IDC: 无按钮可点但 kiro-cli 已拿到 token，结束审批序列")
            break
        url_now = (page.url or "").lower()
        on_device_page = ("user_code=" in url_now) or ("/device" in url_now)
        in_transition = any(h in url_now for h in transitional_url_hints)
        # 仅当"既不在 device 同意页、也不在中转跳转态"时，no-action 兜底退出才成立。
        #   - 在 device 同意页却没匹配到 Allow 文案 → 多等（Allow 按钮可能仍在渲染）；
        #   - 在中转页（workflowResultHandle / login 等）→ 必然还没到 Allow，绝不能退。
        # 否则会重演本次卡死：device 页慢加载期间被 45s no-action 提前 break、漏点 Allow。
        if not on_device_page and not in_transition and time.time() - last_action > 45:
            logger.info("IDC: 审批页 45s 无新按钮且非中转/同意态，结束审批序列")
            break
        await page.wait_for_timeout(400)  # 快轮询：按钮一出现就秒点


_KIRO_URL_AS_SCRIPT = '''
tell application "Google Chrome"
  set out to ""
  repeat with w in every window
    repeat with t in every tab of w
      set u to URL of t
      if (u contains "redirect_from=kirocli") or (u contains "awsapps.com/start") or (u contains ".portal.us-east-1.app.aws") or (u contains "user_code=") then
        set out to out & u & linefeed
      end if
    end repeat
  end repeat
  return out
end tell
'''


def _list_kiro_signin_urls_in_main_chrome() -> list:
    """返回主 Chrome 中所有含 redirect_from=kirocli 的 URL 列表。"""
    try:
        res = subprocess.run(["osascript", "-e", _KIRO_URL_AS_SCRIPT],
                             capture_output=True, text=True, timeout=5)
        urls = [u.strip() for u in (res.stdout or "").splitlines() if u.strip()]
        return urls
    except Exception as e:
        logger.debug(f"osascript 枚举 kiro URL 异常: {e}")
        return []


def capture_new_kiro_signin_url(timeout_s: int = 90) -> str:
    """等待主 Chrome 出现 kiro signin URL。调用前必须已经调用
    close_kiro_signin_tabs_in_main_chrome() 清空过，所以任何新出现的 URL 都是当前 kiro-cli 产生的。
    """
    deadline = time.time() + timeout_s
    last_tick = 0
    start = time.time()
    while time.time() < deadline:
        urls = _list_kiro_signin_urls_in_main_chrome()
        if urls:
            logger.info(f"主 Chrome 中发现 {len(urls)} 个 kiro signin URL")
            return urls[0]
        # 每 5 秒打一次心跳，附带主 Chrome 当前 tab 总数，便于诊断
        elapsed = int(time.time() - start)
        if elapsed >= last_tick + 5:
            last_tick = elapsed
            try:
                r = subprocess.run(
                    ["osascript", "-e",
                     'tell application "Google Chrome" to return '
                     '(count of windows) & "|" & (count of tabs of every window)'],
                    capture_output=True, text=True, timeout=5)
                logger.info(f"[{elapsed}s] 主 Chrome windows/tabs: {r.stdout.strip()}")
            except Exception:
                pass
        time.sleep(0.5)
    return ""


_SIGNIN_AWS_AS_SCRIPT = '''
tell application "Google Chrome"
  set out to ""
  repeat with w in every window
    repeat with t in every tab of w
      set u to URL of t
      if (u contains "signin.aws") then
        set out to out & u & linefeed
      end if
    end repeat
  end repeat
  return out
end tell
'''


def capture_signin_aws_url_from_main_chrome(timeout_s: int = 30) -> str:
    """IDC：kiro.dev 点 Continue 后，AWS 新版登录页（us-east-1.signin.aws/platform/...）
    会开在系统默认浏览器（主 Chrome）。这里轮询主 Chrome 抓那个 signin.aws URL，
    复制到 CloakBrowser 里打开来驱动（跟最初抓 kiro.dev verify URL 同一套机制）。
    URL 里的 workflowStateHandle 是 AWS 服务端 workflow 状态令牌，跨浏览器可延续。
    """
    deadline = time.time() + timeout_s
    start = time.time()
    last_tick = 0
    while time.time() < deadline:
        try:
            res = subprocess.run(["osascript", "-e", _SIGNIN_AWS_AS_SCRIPT],
                                 capture_output=True, text=True, timeout=5)
            urls = [u.strip() for u in (res.stdout or "").splitlines() if u.strip()]
            if urls:
                logger.info(f"主 Chrome 中发现 signin.aws 登录 URL: {urls[0][:90]}")
                return urls[0]
        except Exception as e:
            logger.debug(f"osascript 枚举 signin.aws URL 异常: {e}")
        elapsed = int(time.time() - start)
        if elapsed >= last_tick + 5:
            last_tick = elapsed
            logger.info(f"[{elapsed}s] 等待主 Chrome 出现 signin.aws 登录页...")
        time.sleep(0.5)
    return ""


def close_signin_aws_tabs_in_main_chrome():
    """关闭主 Chrome 里遗留的 signin.aws 登录标签（已复制到 CloakBrowser 后清理）。"""
    script = '''
    tell application "Google Chrome"
      repeat with w in every window
        set tabsToClose to {}
        repeat with t in every tab of w
          set u to URL of t
          if (u contains "signin.aws") then
            set end of tabsToClose to t
          end if
        end repeat
        repeat with t in tabsToClose
          try
            close t
          end try
        end repeat
      end repeat
    end tell
    '''
    try:
        subprocess.run(["osascript", "-e", script], capture_output=True, timeout=5)
    except Exception as e:
        logger.debug(f"关闭 signin.aws 标签异常: {e}")


def close_terminal_window_by_id(window_id: str):
    """关闭指定 id 的 Terminal 窗口（kiro-cli 结束后清理遗留窗口）。
    使用 saving no 避免出现"进程仍在运行，确认退出?"对话框。
    """
    if not window_id:
        return
    try:
        subprocess.run(
            ["osascript", "-e",
             f'tell application "Terminal" to close '
             f'(every window whose id is {window_id}) saving no'],
            capture_output=True, timeout=5,
        )
    except Exception as e:
        logger.debug(f"关闭 Terminal 窗口 {window_id} 异常: {e}")


def close_kiro_signin_tabs_in_main_chrome():
    """关闭主 Chrome 里遗留的 kiro signin / localhost:3128 callback 标签。"""
    script = '''
    tell application "Google Chrome"
      repeat with w in every window
        set tabsToClose to {}
        repeat with t in every tab of w
          set u to URL of t
          if (u contains "redirect_from=kirocli") or (u contains "localhost:3128") or (u contains "awsapps.com/start") or (u contains ".portal.us-east-1.app.aws") or (u contains "signin.aws") or (u contains "user_code=") then
            set end of tabsToClose to t
          end if
        end repeat
        repeat with t in tabsToClose
          try
            close t
          end try
        end repeat
      end repeat
    end tell
    '''
    try:
        subprocess.run(["osascript", "-e", script],
                       capture_output=True, text=True, timeout=5)
    except Exception as e:
        logger.debug(f"关闭主 Chrome kiro 标签异常: {e}")


def _kiro_cli_send_enters(presses: int = 4, first_delay: float = 2.0,
                          interval: float = 3.5):
    """给 Terminal 里 kiro-cli 的交互确认 gate 自动发回车（DEPRECATED）。

    旧 IDC 流程用 osascript + System Events keystroke return 发回车，依赖 macOS
    Accessibility 权限且会抢前台焦点，失败率高。新方案见 _spawn_kiro_cli_pty：直接
    用 PTY 拉 kiro-cli 子进程，识别到 prompt 后向 PTY master 写 b'\\n'，准时、静默、
    并发安全、跨平台。本函数仅保留以防其它路径仍依赖。
    """
    parts = [f"delay {first_delay}"]
    for i in range(presses):
        if i > 0:
            parts.append(f"delay {interval}")
        parts.append('tell application "Terminal" to activate')
        parts.append('tell application "System Events" to keystroke return')
    script = "\n".join(parts)
    try:
        subprocess.run(["osascript", "-e", script], capture_output=True,
                       timeout=first_delay + presses * interval + 15)
    except Exception as e:
        logger.debug(f"向 kiro-cli 发回车异常: {e}")


# ANSI 转义：颜色码 / 光标控制。kiro-cli 在 TTY 下会输出彩色，去掉再 grep。
_ANSI_RE = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
# Device flow Code（kiro-cli 2.2.1 实测）：`Code: XXXX-XXXX` 4+ 个 A-Z0-9-
# 字符。kiro-cli **不**把 verify URL 打到 stdout，只打 Code；URL 由我们按 AWS IDC
# device flow 协议固定模板自己拼：https://device.sso.<region>.amazonaws.com/?user_code=<code>
_KIRO_CLI_CODE_RE = re.compile(r"Code:\s*([A-Z0-9-]{4,})", re.IGNORECASE)
# Spinner 帧：▰▱▱▱▱▱▱ Logging in... 每 ~100ms 一帧，1 秒能刷 10 行；不静默会淹日志。
_KIRO_CLI_SPINNER_RE = re.compile(
    r"^[▰▱\s]+(?:logging\s+in|loading|fetching|waiting|please\s+wait)",
    re.IGNORECASE,
)


def _aws_idc_device_url(start_url: str, code: str) -> str:
    """从 IDC start_url + user_code 拼 AWS IAM Identity Center device flow 验证 URL。

    实测 kiro-cli 在主浏览器弹的 URL 形态：
      `{start_url}/#/device?user_code={code}`
    （例：`https://d-9066737b12.awsapps.com/start/#/device?user_code=TPRH-BSXF`）

    协议层 verification_uri_complete 还有另一种合法形态
      `https://device.sso.<region>.amazonaws.com/?user_code=<code>`
    两种 URL 都被 AWS IDC 接受。我们用 awsapps 形态因为它跟 kiro-cli 实际弹的一致，
    跨过 AWS WAF Security check 时浏览器的 referrer / cookie 检查更稳。
    """
    return f"{start_url.rstrip('/')}/#/device?user_code={code}"


def _strip_ansi(s: str) -> str:
    return _ANSI_RE.sub("", s)


async def _periodic_send_enter(child: "pexpect.spawn", stop_event: asyncio.Event,
                               schedule=(2.0, 4.5, 7.0, 10.0, 14.0)) -> None:
    """无差别盲发回车 —— 替代 prompt 文本识别那种"猜得准才发"的脆弱路径。

    `kiro-cli login --use-device-flow` 的回车 gate 实测约两次，prompt 文本可能因
    版本变动（"Press enter to open URL" / "Press any key to continue" / 无文本只闪光标
    等）正则匹配不到 → 我们直接按时间表盲发：第 2.0/4.5/7.0/10.0/14.0 秒各一次。
    URL 抓到后由外层 set stop_event 提前结束，少发的几次不发；多发的回车 kiro-cli
    会忽略，无害。
    """
    try:
        for t in schedule:
            try:
                # 等到指定时刻，期间若 url 已拿到立刻退出
                await asyncio.wait_for(stop_event.wait(), timeout=t)
                return
            except asyncio.TimeoutError:
                pass
            if not child.isalive():
                return
            try:
                child.sendline("")
                logger.info(f"[kiro-cli] 按表盲发回车 @ t={t}s")
            except Exception as e:
                logger.debug(f"sendline 失败: {e}")
                return
    except Exception as e:
        logger.debug(f"周期发回车协程异常: {e}")


class _PexpectLogger:
    """pexpect.spawn 的 logfile_read 转发到 logger，同时抓 Code 拼 URL。

    关键职责：
      1. 逐字节进来、按 \\r/\\n 切行、去 ANSI 后转 logger.info
      2. 静默 spinner 帧（▰▱ Logging in...）—— kiro-cli device flow 期间 100ms/帧
         无限刷，不静默会把日志彻底淹没
      3. 抓 `Code: XXXX-XXXX` 行，按 `{start_url}/#/device?user_code={code}` 模板
         拼 URL → set code_future（这是主路；AppleScript 抓主 Chrome 已废弃）
    """

    def __init__(self, identity_label: str, start_url: str, code_future: asyncio.Future,
                 loop: asyncio.AbstractEventLoop):
        self.identity_label = identity_label
        self.start_url = start_url
        self.code_future = code_future
        # write() 在专门的读取线程里被调用（见 _drain_child_output），而 code_future 属于
        # asyncio 事件循环 —— 跨线程 set_result 必须走 loop.call_soon_threadsafe，直接 set
        # 会破坏 future 状态且不唤醒等待方。
        self.loop = loop
        self._buf = ""
        self._spinner_last_heartbeat = 0.0
        self._spinner_count_since_heartbeat = 0

    def _resolve_code(self, url: str) -> None:
        """线程安全地把 verify URL 交给等待中的 code_future。"""
        def _set():
            if not self.code_future.done():
                self.code_future.set_result(url)
        self.loop.call_soon_threadsafe(_set)

    def _handle_line(self, line: str) -> None:
        stripped = _strip_ansi(line).strip()
        if not stripped:
            return
        if _KIRO_CLI_SPINNER_RE.search(stripped):
            # 静默 spinner 防日志爆炸，但每 10s 打一条心跳确认 kiro-cli 还活着
            # （Allow 点完之后 spinner 全静默会让人误以为卡死，实际是 polling 中）
            self._spinner_count_since_heartbeat += 1
            now = time.monotonic()
            if now - self._spinner_last_heartbeat > 10:
                logger.info(
                    f"[kiro-cli|{self.identity_label}] "
                    f"polling 中…（过去 {now - self._spinner_last_heartbeat:.0f}s 静默 "
                    f"{self._spinner_count_since_heartbeat} 帧 spinner）"
                )
                self._spinner_last_heartbeat = now
                self._spinner_count_since_heartbeat = 0
            return
        logger.info(f"[kiro-cli|{self.identity_label}] {stripped}")
        if not self.code_future.done():
            m = _KIRO_CLI_CODE_RE.search(stripped)
            if m:
                code = m.group(1)
                url = _aws_idc_device_url(self.start_url, code)
                logger.info(
                    f"[kiro-cli|{self.identity_label}] 抓到 device code={code} → 拼 verify URL"
                )
                self._resolve_code(url)

    def write(self, data) -> None:
        if isinstance(data, bytes):
            data = data.decode("utf-8", "replace")
        self._buf += data
        # kiro-cli prompt / spinner 常用 \r 原地刷新，同时按 \r 和 \n 切。
        lines = re.split(r"[\r\n]", self._buf)
        self._buf = lines.pop()
        for line in lines:
            self._handle_line(line)

    def flush(self) -> None:
        if self._buf:
            self._handle_line(self._buf)
            self._buf = ""


# 并发写 kiro.json 的互斥锁：append_kiro_record 是 read-modify-write，两个协程
# 同时读到旧数组各自追加再落盘会丢记录（后写覆盖先写）。os.replace 只保证不留半截
# 文件，挡不住这种竞争。并发批量登录时用它把每次“读-加-写”串起来。
_kiro_json_write_lock = asyncio.Lock()

# kiro-cli 数据目录里跟账号无关的共享运行时：隔离 HOME 时软链回主目录，
# 只让 data.sqlite3（auth_kv/token）独立。缺这些 kiro-cli 起不来（bun 是 JS 运行时）。
_KIRO_SHARED_RUNTIME = ("bun", "bun.sha256", "feed.json", "knowledge_bases")


def _init_isolated_keychain(home_dir: str) -> None:
    """在隔离 HOME 下建一个全新空钥匙串并设为默认（macOS 专用，best-effort）。

    kiro-cli 2.10 的登录态存在 macOS 钥匙串（secret store，svce=kirocli:odic:token
    等），不只 sqlite。若隔离 HOME 无钥匙串会弹「找不到钥匙串」；若软链回真实钥匙串
    又会读到上次登录的残留 token → kiro-cli 报「Already logged in」拒登。经真机验证
    钥匙串可按 $HOME 隔离：隔离 HOME 里新建的钥匙串既看不到真实钥匙串的条目、写入也
    不漏出去。于是给每账号开一个全新空钥匙串 → 无残留、无弹窗、不串号。
    """
    if sys.platform != "darwin":
        return
    kc_dir = os.path.join(home_dir, "Library", "Keychains")
    os.makedirs(kc_dir, exist_ok=True)
    os.makedirs(os.path.join(home_dir, "Library", "Preferences"), exist_ok=True)
    kc_path = os.path.join(kc_dir, "login.keychain-db")
    kc_env = {**os.environ, "HOME": home_dir}
    # 空密码钥匙串；set-keychain-settings 无 -t → 不自动锁（撑过整个浏览器授权流程）
    cmds = (
        ["security", "create-keychain", "-p", "", kc_path],
        ["security", "set-keychain-settings", kc_path],
        ["security", "unlock-keychain", "-p", "", kc_path],
        ["security", "list-keychains", "-d", "user", "-s", kc_path],
        ["security", "default-keychain", "-d", "user", "-s", kc_path],
    )
    for cmd in cmds:
        try:
            subprocess.run(cmd, env=kc_env, capture_output=True, timeout=10)
        except Exception as e:
            logger.debug(f"隔离钥匙串 {cmd[1]} 失败（忽略）: {e}")


def _prepare_isolated_kiro_home() -> tuple[str, str]:
    """为一次并发登录准备独立的 kiro-cli $HOME，返回 (home_dir, sqlite_path)。

    kiro-cli 把凭据写死在 `$HOME/Library/Application Support/kiro-cli/data.sqlite3`
    的 auth_kv 表 + macOS 钥匙串（svce=kirocli:odic:token 等）。多账号并发共用会互相
    logout/覆盖、读到别人的 token → 串号。经真机验证 kiro-cli 尊重 $HOME：换 HOME 后
    sqlite 和钥匙串都落到隔离目录，主库/主钥匙串不受影响。

    这里给每个任务开一个临时 HOME：跟账号无关的共享运行时（bun 等）软链回主目录，
    data.sqlite3 走独立库，再建一个全新空钥匙串设为该 HOME 默认。调用方负责 finally
    里删掉 home_dir（连带清掉隔离钥匙串文件）。
    """
    home_dir = tempfile.mkdtemp(prefix="kiro_home_")
    kiro_data = os.path.join(home_dir, "Library", "Application Support", "kiro-cli")
    os.makedirs(kiro_data, exist_ok=True)
    main_data = os.path.dirname(KIRO_SQLITE_PATH)
    for name in _KIRO_SHARED_RUNTIME:
        src = os.path.join(main_data, name)
        if os.path.exists(src):
            try:
                os.symlink(src, os.path.join(kiro_data, name))
            except OSError as e:
                logger.debug(f"软链共享运行时 {name} 失败（忽略）: {e}")
    # 每账号独立空钥匙串：避免「找不到钥匙串」弹窗 & 残留 token 导致的「Already logged in」
    _init_isolated_keychain(home_dir)
    return home_dir, os.path.join(kiro_data, "data.sqlite3")


def _build_browser_intercept_env(home_dir: str = "") -> tuple[dict, str]:
    """构造一个屏蔽 `open` / `xdg-open` 调用的 env，让 kiro-cli 调用打开默认浏览器时
    被静默劫胡。返回 (env, intercept_dir)；调用方 finally 里清理 intercept_dir。

    home_dir 非空时覆盖子进程 $HOME（并发隔离用，见 _prepare_isolated_kiro_home）。

    工作机制：
      - 临时目录里放 fake `open` 和 `xdg-open` 脚本（仅 exit 0）
      - PATH 头部插入该目录 → kiro-cli 调 `open <url>` 时先命中我们的 fake
      - 唯一拦不到的场景：kiro-cli 内部 hardcode `/usr/bin/open` 绝对路径（不走 PATH）
        —— 此时主浏览器仍会弹，但我们 URL 已从 Code 拼出，业务上无损

    为什么要拦：kiro-cli device flow 会调系统 `open <verification_uri>` 把 URL 抛给
    默认浏览器，但本流程下游用 Camoufox/Firefox 接管，那个主浏览器标签是无用副作用 ——
    给用户视觉干扰，跑完还得 close_kiro_signin_tabs_in_main_chrome 清理。
    """
    intercept_dir = tempfile.mkdtemp(prefix="kiro_open_intercept_")
    fake_script = "#!/bin/sh\n# silently swallow browser-open call from kiro-cli\nexit 0\n"
    for name in ("open", "xdg-open", "sensible-browser", "x-www-browser"):
        path = os.path.join(intercept_dir, name)
        with open(path, "w") as f:
            f.write(fake_script)
        os.chmod(path, 0o755)

    env = os.environ.copy()
    env["PATH"] = f"{intercept_dir}:{env.get('PATH', '')}"
    # 顺便清掉 BROWSER —— 部分 CLI 看这个 env 决定打开方式
    env.pop("BROWSER", None)
    if home_dir:
        # 隔离 HOME：kiro-cli 的数据目录随之落到独立库，token 不与其他并发任务串号
        env["HOME"] = home_dir
    return env, intercept_dir


async def _spawn_kiro_cli_pexpect(argv: list, identity_label: str, start_url: str,
                                  home_dir: str = ""):
    """用 pexpect 拉 kiro-cli 子进程，返回 (child, enter_task, code_future, intercept_dir)。

    职责：
      - 跨 Start URL / Region prompt 的盲发回车（按表 [2, 4.5, 7, 10, 14]s）
      - 静默 spinner 帧防日志爆炸
      - 维持子进程、监听 EOF
      - 抓 Code 后按 `{start_url}/#/device?user_code={code}` 模板拼 verify URL
      - 通过 PATH 劫持 fake `open` 阻止 kiro-cli 弹主浏览器标签

    回车策略：kiro-cli 2.2.1 实测即使传 --identity-provider / --region 命令行参数仍
    prompt `? Enter Start URL ›` / `? Enter Region › us-east-1` 让用户回车确认。
    盲发跨过，多发的 kiro-cli 会忽略。
    """
    env, intercept_dir = _build_browser_intercept_env(home_dir)
    child = pexpect.spawn(
        argv[0],
        argv[1:],
        encoding="utf-8",
        codec_errors="replace",
        timeout=None,  # 由调用方控制超时，pexpect 本身不限时
        dimensions=(40, 200),  # 避免 80 列折行把 Code/URL 拦腰断开
        env=env,  # PATH 头部 fake open，阻止主浏览器弹窗
    )

    loop = asyncio.get_event_loop()
    code_future: asyncio.Future = loop.create_future()
    stop_event = asyncio.Event()
    child.logfile_read = _PexpectLogger(identity_label, start_url, code_future, loop)

    # Code 抓到 = 两次回车 gate (Start URL / Region) 都已跨过，kiro-cli 进入 device
    # polling 阶段，不再读 stdin。盲发回车协程立即停手，避免日志干扰 + 无意义系统调用。
    code_future.add_done_callback(lambda _: stop_event.set())

    # 读取泵：专用阻塞线程持续 drain 子进程 pty 输出。
    #
    # 为什么必须是线程而不是 `child.expect(async_=True)`：
    #   kiro-cli 用 dialoguer/console 读交互 prompt，读键前会 `tcsetattr(fd, TCSADRAIN)`
    #   把 tty 切 raw 模式；TCSADRAIN 会**阻塞到已写出的输出被 master 端读干净**才返回。
    #   若 master 端没人持续读，drain 不掉 → kiro-cli 卡死在 tcsetattr、连第一个 prompt
    #   （? Enter Start URL）都发不出来（实测批量第 3 个账号必现、stdout 全静默 60s）。
    #   asyncio 在 macOS 上对 pty(字符设备)用 kqueue add_reader 泵输出不可靠，且
    #   expect_async 完成后残留的 reader 会在下次 spawn 复用同一 fd 号时互抢事件 ——
    #   正是「每成功一个就泄漏一个、攒到第 3 个新泵收不到读事件」的根因。
    #   一个一直在 blocking read 的独立线程能保证 master 端始终排空，tcsetattr 永不阻塞。
    def _drain_child_output():
        try:
            while True:
                try:
                    # read_nonblocking 内部会把读到的字节喂给 logfile_read(_PexpectLogger)，
                    # 顺带完成 drain。timeout 只是让循环能周期性检查存活，不是真超时退出。
                    child.read_nonblocking(size=4096, timeout=1)
                except pexpect.TIMEOUT:
                    if not child.isalive():
                        break
                    continue
                except (pexpect.EOF, OSError, ValueError):
                    break
        finally:
            # 子进程退出/EOF：通知盲发协程停手，并在还没抓到 Code 时让等待方失败收场。
            loop.call_soon_threadsafe(stop_event.set)

            def _fail_if_pending():
                if not code_future.done():
                    code_future.set_exception(
                        RuntimeError(
                            f"kiro-cli 提前退出（exit={child.exitstatus} "
                            f"signal={child.signalstatus}）未输出 Code"
                        )
                    )
            loop.call_soon_threadsafe(_fail_if_pending)

    reader_thread = threading.Thread(
        target=_drain_child_output,
        name=f"kiro-cli-drain-{identity_label[:24]}",
        daemon=True,
    )
    reader_thread.start()

    enter_task = asyncio.create_task(_periodic_send_enter(child, stop_event))
    return child, enter_task, code_future, intercept_dir


def _kill_kiro_cli_group(child) -> None:
    """整组杀掉 kiro-cli 进程树（child + 它可能 spawn 的 bun 运行时等子进程）。

    child.terminate()/close() 只对 child.pid 发信号；kiro-cli 若另起后台子进程，
    terminate 收不到、会 orphan 常驻。pexpect.spawn 在子进程里 os.setsid() →
    child.pid 即会话/进程组组长，组内就是本次登录整棵树。os.killpg 只杀这一组，不碰
    兄弟登录（每次登录各自独立组），故并发安全 —— 对齐 social 路径「pkill 完整终止
    kiro-cli」的意图，但避免 pkill 按名字误杀并发中的其它 kiro-cli。

    注：批量第 3 个账号卡死的真正根因是 pty 输出没被 drain、kiro-cli 阻塞在
    tcsetattr（见 _spawn_kiro_cli_pexpect 的读取线程说明），已由专用读取线程根治；
    整组回收在此作为进程清理兜底保留，防止任何后台子进程泄漏。
    """
    try:
        pgid = os.getpgid(child.pid)
    except Exception:
        return
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(pgid, sig)
        except ProcessLookupError:
            return  # 组已空，收工
        except Exception as e:
            logger.debug(f"killpg({pgid}, {sig}) 异常: {e}")
            return
        time.sleep(0.3)  # 给 SIGTERM 一点优雅退出时间，仍在就 SIGKILL


async def _cleanup_kiro_cli_pexpect(child, enter_task, intercept_dir: str = "") -> None:
    """终止 pexpect 子进程 + 取消盲发协程 + 删 PATH 劫持临时目录，吞所有异常。"""
    try:
        if child.isalive():
            try:
                child.terminate(force=True)  # SIGHUP → SIGCONT → SIGINT → SIGKILL
            except Exception:
                pass
        # 关键补刀：terminate 只覆盖 child.pid（launcher shim），真正的 kiro-cli 二进制
        # + bun 运行时是它 spawn 的组内子进程，必须整组 killpg 收干净，否则 orphan 累积
        # 会把后续账号的 kiro-cli 卡死在启动阶段。
        _kill_kiro_cli_group(child)
    except Exception as e:
        logger.debug(f"清理 kiro-cli pexpect 子进程异常: {e}")
    try:
        enter_task.cancel()
        await asyncio.wait_for(enter_task, timeout=1)
    except Exception:
        pass
    try:
        child.close(force=True)
    except Exception:
        pass
    if intercept_dir:
        try:
            import shutil
            shutil.rmtree(intercept_dir, ignore_errors=True)
        except Exception:
            pass


def _fmt_kiro_expires(val):
    """把 kiro-cli token 的 expiresAt 转成 kiro.json 用的本地时间串；解析失败原样返回。
    支持 epoch 秒 / RFC3339（含 'Z' 或带偏移）。
    """
    if val in (None, ""):
        return None
    if isinstance(val, (int, float)):
        try:
            return datetime.fromtimestamp(val).strftime("%Y/%m/%d %H:%M:%S")
        except Exception:
            return None
    s = str(val).strip()
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
        if dt.tzinfo:
            dt = dt.astimezone()  # 转本地时区
        return dt.strftime("%Y/%m/%d %H:%M:%S")
    except Exception:
        return s


def _kiro_idc_token_ready() -> bool:
    """kiro-cli 是否已把本次 IdC token 写进 auth_kv —— 登录成功的即时信号。

    register_kiro_idc 开头已 run_kiro_logout() 清空 token key，所以一旦
    kirocli:odic:token 里出现 accessToken，就一定是本次设备授权成功后 kiro-cli
    回写的。审批序列 / token 轮询用它提前收尾，不必死等 45s 空转 + 180s 上限。
    sqlite 读极廉价且 read_kiro_auth_kv 已吞异常，轮询里高频调用安全。
    """
    try:
        tok = read_kiro_auth_kv("kirocli:odic:token")
        return bool(tok.get("accessToken") or tok.get("access_token"))
    except Exception:
        return False


def _kiro_sqlite_in_home(home_dir: str) -> str:
    """隔离 HOME 下 kiro-cli 的 data.sqlite3 路径。"""
    return os.path.join(home_dir, "Library", "Application Support",
                        "kiro-cli", "data.sqlite3")


async def register_kiro_idc(parsed: tuple, output_file: str = KIRO_OUTPUT_FILE,
                            iso_home: str = "") -> dict:
    """IdC 模式：走 kiro-cli login（Pro/Identity Center）完成登录，再读 kiro-cli 本地
    凭据写 kiro.json——对齐 social 的 register_kiro，让 kiro-cli 本身处于登录态。

    iso_home 非空 = 并发隔离态：本次 kiro-cli 的 auth_kv 走 iso_home 下的独立库，
    logout/login/读回都不碰主库，避免多账号并发 token 串号。

    流程：
      1) 清理本地 kiro-cli 会话（避免读到上一个账号的 token）
      2) Terminal 起 kiro-cli login --license pro --identity-provider <startUrl>
         --region <region> --use-device-flow；带了 idp+region 会直接进 awsapps 设备授权，
         跳过 kiro.dev 选择/填表；--use-device-flow 适配"独立浏览器驱动、CLI 后台跑"。
      3) AppleScript 抓 kiro-cli 在主 Chrome 打开的设备验证 URL → CloakBrowser 接管
      4) kiro_idc_signin_inline 驱动 AWS 登录（用户名/临时密码/按需改密/Allow）
      5) 等 kiro-cli 后台完成 token 交换（写好 auth_kv）
      6) 读回 kirocli:odic:token + :device-registration → 取 usage → 写 kiro.json
    parsed: ("idc", start_url, username, temp_pwd, new_pwd[, region])
    """
    _, start_url, username, temp_pwd, new_pwd = parsed[:5]
    # 第 6 段（可选）为显式 region（批量 --region）；否则从 start_url 推断（awsapps 默认 us-east-1）。
    region = parsed[5] if len(parsed) > 5 and parsed[5] else _idc_region_from_start_url(start_url)
    identity_label = f"{username}@{start_url}"
    # 入口诊断：parse 后的 temp_pwd 指纹 —— 跟 fill 前的指纹比对，能判断是 parse 解析
    # 错（输入分隔符吃了字符）还是 fill 改坏的；跟原始输入文件里的密码比对，能判断
    # parse 阶段就丢了字符（如 split('----') 在密码含 `----` 时截断）。
    logger.info(
        f"IDC parsed: username={username!r} "
        f"temp_pwd fingerprint={_pwd_fingerprint(temp_pwd)} "
        f"new_pwd fingerprint={_pwd_fingerprint(new_pwd)}"
    )

    # 0) 并发隔离：把本任务的 kiro-cli auth_kv 指向独立库（contextvar 随 asyncio Task
    #    继承，只影响本协程；单条/串行流程 iso_home 为空 → 走主库，行为不变）。
    if iso_home:
        set_kiro_sqlite_path(_kiro_sqlite_in_home(iso_home))
        logger.info(f"IDC: 隔离 kiro-cli 库 → {current_kiro_sqlite_path()}")

    # 1) 清理本地 kiro-cli 会话：清掉旧 auth_kv，登录后读回的才是本账号
    logger.info("清理本地 kiro-cli 会话")
    run_kiro_logout()
    close_kiro_signin_tabs_in_main_chrome()

    # 2) pexpect 拉 kiro-cli login（Pro/Identity Center）子进程。--use-device-flow 让
    #    CLI 走 device code（不依赖本地回调）。
    #    替代历史方案的演进：
    #      旧旧：Terminal.app + osascript do script + System Events keystroke return 盲发回车
    #            → 依赖 Accessibility 权限、抢前台焦点、失败需人工救场
    #      旧：  pty.openpty 手写 reader + prompt 文本匹配触发回车
    #            → kiro-cli prompt 文本因版本/locale 变化时正则不匹配，仍卡死
    #      新：  pexpect.spawn + [URL 正则 expect 主路] + [定时盲发回车兜底]
    #            → 不依赖 prompt 文本识别，多发的回车 kiro-cli 会忽略
    argv = [
        "kiro-cli", "login", "--license", "pro",
        "--identity-provider", start_url,
        "--region", region,
        "--use-device-flow",
    ]
    logger.info(f"启动 kiro-cli（pexpect 子进程）: {' '.join(shlex.quote(a) for a in argv)}")
    child, enter_task, code_future, intercept_dir = await _spawn_kiro_cli_pexpect(
        argv, identity_label, start_url, home_dir=iso_home,
    )

    # 3) URL 来源 —— 从 kiro-cli stdout 抓 Code 后按模板自拼，不再依赖 AppleScript：
    #      `{start_url}/#/device?user_code={code}`
    #    跟 kiro-cli 内部弹主浏览器用的 URL 一致。AppleScript 扫主 Chrome 标签页那条
    #    路径整段废弃 —— 慢、依赖默认浏览器是 Chrome、依赖 Chrome 在跑、需要 Apple
    #    Events 权限。直接从 Code 拼无任何外部依赖。
    #    PATH 劫持 fake `open` 已经在 _spawn_kiro_cli_pexpect 里设好，kiro-cli 走 PATH
    #    打开默认浏览器的调用会被静默吞掉，主 Chrome 不再弹副作用标签页。
    try:
        verify_url = await asyncio.wait_for(code_future, timeout=60)
    except (asyncio.TimeoutError, Exception) as e:
        await _cleanup_kiro_cli_pexpect(child, enter_task, intercept_dir)
        raise RuntimeError(f"未能从 kiro-cli stdout 抓到 device code: {e}")
    logger.info(f"抓到 kiro-cli IdC signin URL: {verify_url[:100]}")
    # 兜底清理：如果 PATH 劫持没拦住（kiro-cli hardcode /usr/bin/open），主 Chrome
    # 可能还是弹了一个标签，跑完顺手清掉。拦住时这个调用是 no-op。
    close_kiro_signin_tabs_in_main_chrome()

    # 4) Camoufox/Firefox 持久化 profile 接管打开 verify_url，驱动 AWS 登录。
    #    awsapps 设备授权/登录页挂着 AWS WAF "Security check" 人机校验，自动跳不过去：
    #    遇到时由 kiro_idc_signin_inline 里的 handle_aws_waf 暂停、等人工手点 Verify
    #    （需 HEADLESS=False）。持久化 profile 会留住过校验后的 aws-waf-token，免疫期内
    #    后续步骤/重跑可少弹。kiro 整路径换 Firefox 内核（CloakBrowser 的 Chromium 会被
    #    Google "This browser may not be secure" 拦），window 在 launch 时定死，无 CDP。
    #    后端由 KIRO_BROWSER_BACKEND 决定（默认 camoufox；可切 cloak）。
    backend = kiro_browser_backend()
    _browser = None
    profile_dir = None
    instance_region_box = {"region": ""}
    ok = False  # 完整跑通标记：成功后用本 profile 的完整 cache2 晋升为共享基准
    try:
        if backend in ("safari", "chrome"):
            # Selenium/WebDriver（safari 或 chrome）过 AWS WAF，走完 IdC 设备授权登录；
            # kiro-cli(device flow) 后台轮询 token，浏览器点完 Allow 即成功。
            from app.kiro.safari_idc import drive_safari_idc_login
            region_found = await asyncio.to_thread(
                drive_safari_idc_login, verify_url, username, temp_pwd, new_pwd,
                _kiro_idc_token_ready, 180, backend)
            instance_region_box["region"] = region_found or ""
            for _ in range(60):
                if _kiro_idc_token_ready() or not child.isalive():
                    break
                await asyncio.sleep(1)
            if not _kiro_idc_token_ready():
                if child.isalive():
                    child.terminate(force=True)
                raise RuntimeError("Safari IdC 登录未拿到 token")
            if child.isalive():
                child.terminate(force=True)
        else:
            context, profile_dir, _browser = await launch_kiro_persistent_context(identity_label)
            try:
                await context.add_init_script(
                    """
                    Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
                    Object.defineProperty(navigator, 'plugins',
                        {get: () => [1, 2, 3, 4, 5]});
                    Object.defineProperty(navigator, 'languages',
                        {get: () => ['en-US', 'en']});
                    """
                )
            except Exception as e:
                logger.debug(f"注入 stealth 脚本异常: {e}")

            pages = context.pages
            page = pages[0] if pages else await context.new_page()
            # 不再调 fit_window_to_screen：Firefox 无 CDP，窗口尺寸由 Camoufox launch 时定死。

            # 捕获 Identity Center 实例 region：OIDC 恒走 us-east-1，但导出记录里的 region
            # 要的是目录所在区。登录流程渲染同意页时会请求区域化门户后端
            # （portal.sso.<region>.amazonaws.com / *.portal.<region>.app.aws），从这些
            # 请求 URL 里解析出实例 region。监听 request + framenavigated，覆盖弹窗页。
            instance_region_box = {"region": ""}

            def _capture_region(url: str) -> None:
                if instance_region_box["region"] or not url:
                    return
                r = _idc_instance_region_from_url(url)
                if r:
                    instance_region_box["region"] = r
                    logger.info(f"IDC: 捕获实例 region={r}（来源 {url[:90]}）")

            def _on_request(req) -> None:
                _capture_region(getattr(req, "url", ""))

            def _on_frame_navigated(frame) -> None:
                _capture_region(getattr(frame, "url", ""))

            def _wire_page(p) -> None:
                try:
                    p.on("request", _on_request)
                    p.on("framenavigated", _on_frame_navigated)
                except Exception:
                    pass

            _wire_page(page)
            context.on("page", _wire_page)  # 审批流程开新 tab/popup 时也挂上

            try:
                await page.goto(verify_url, wait_until="domcontentloaded", timeout=30000)
            except Exception as e:
                logger.warning(f"打开 verify URL 失败（可能已 302）: {e}")
            await human_delay(page, "navigate")

            await kiro_idc_signin_inline(page, context, username, temp_pwd, new_pwd,
                                         is_login_done=_kiro_idc_token_ready)

            # 5) 等 kiro-cli 后台完成 token 交换。
            #    polling 期间每 8 秒扫一次页面：如果发现还有 Allow/Accept 按钮就再点 ——
            #    实测 headless + Firefox + 新账号改密路径，inline 第一次 click 可能命中
            #    了中间页的 "Accept"（不是 device authorize 真正按钮），导致 OIDC 未授权、
            #    polling 永远拿不到 token。第二次扫到真正的 Allow 时再补点。多点的按钮
            #    无副作用（按钮点完就消失，不会重复触发）。
            logger.info("等待 kiro-cli 完成 IdC token 交换...")
            # polling 期间补点：扫所有可能的接续按钮（Allow / Accept / Continue / Confirm 等）
            # 优先级：终极 Allow > 中间 Accept > Continue/Confirm。终极 Allow 命中后由 OIDC
            # 服务器 mark authorized，kiro-cli polling 拿到 token；中间步骤命中只算"推进"。
            _POLL_BUTTON_PRIORITY = [
                ("Allow access", "Allow", "允许访问", "允许"),
                ("Approve", "Accept", "批准", "接受"),
                ("Confirm and continue", "确认并继续", "Continue", "Next", "继续", "下一步", "Confirm", "确认"),
                # 兜底：登录类按钮 —— 实测新版 `us-east-1.signin.aws/platform/.../login` 页可能
                # 卡在密码 submit 未生效状态；polling 期间补点 Sign in/Verify 把流程推进
                ("Sign in", "Verify", "登录", "Authorize"),
            ]

            # polling 补点也要去重：同一 URL 上同名按钮只点一次，避免每 8s 把一个「点了也不
            # 跳转」的按钮反复点（注释里「按钮点完就消失」的假设在卡住场景并不成立 —— 重复点
            # OIDC 同意按钮可能反复重提交、把已授权又打回，正是 polling 拿不到 token 的诱因）。
            poll_last_click_sig = {"v": None}

            async def _try_click_button_during_polling() -> str:
                """polling 期间扫页面：按优先级找按钮就点一下，返回点中的文本。
                同一 (按钮文案, URL) 不重复点；URL 变了或换了按钮才会再点。"""
                for tier in _POLL_BUTTON_PRIORITY:
                    for text in tier:
                        try:
                            btn = page.locator(
                                f'button:has-text("{text}"), a:has-text("{text}"), '
                                f'[role="button"]:has-text("{text}")'
                            ).first
                            if await btn.count() == 0:
                                continue
                            if not await btn.is_visible():
                                continue
                            sig = (text, page.url)
                            if sig == poll_last_click_sig["v"]:
                                continue  # 这个按钮在这一页已经点过，别再连点
                            try:
                                await btn.click(timeout=2000)
                            except Exception:
                                try:
                                    await btn.click(timeout=2000, force=True)
                                except Exception:
                                    continue
                            poll_last_click_sig["v"] = sig
                            return text
                        except Exception:
                            continue
                return ""

            last_recheck = 0
            last_url_log = 0
            token_obtained = False
            for i in range(180):
                if not child.isalive():
                    break
                # token 一落库即视为成功，立刻退出——不必等 child 进程自己收尾，
                # 也不必跑满 180s 上限。失败路径（设备未授权 / code 过期）下 kiro-cli
                # 会自行退出令 child.isalive() 转 False，仍由上面的分支提前 break。
                if _kiro_idc_token_ready():
                    token_obtained = True
                    logger.info(f"IDC: 第 {i}s 检测到 kiro-cli 已写入 token，提前结束轮询")
                    break
                await asyncio.sleep(1)
                # 每 5 秒扫一次按钮（不在 i=0 扫，inline 刚点过 Allow，给 AWS 处理时间）。
                # 改密路径下 device 同意页可能在轮询期才慢加载出来，缩短间隔让 Allow 早点被补点。
                if i > 0 and (i - last_recheck) >= 5:
                    last_recheck = i
                    clicked = await _try_click_button_during_polling()
                    if clicked:
                        logger.info(f"IDC polling 期间补点按钮 '{clicked}'，当前 URL: {page.url[:120]}")
                # 每 30 秒打一次 page.url —— polling 拿不到 token 时这条日志能快速定位
                # 是哪个页面卡住了（已授权页 / 错误页 / 还在 Allow 页等）
                if i > 0 and (i - last_url_log) >= 30:
                    last_url_log = i
                    try:
                        logger.info(f"IDC polling 第 {i}s，当前 URL: {page.url[:150]}")
                    except Exception:
                        pass
            if token_obtained:
                # token 已落库 = 登录成功。kiro-cli 通常会在写完 token 后自行退出，
                # 给它最多 3s 优雅收尾；仍存活就主动 terminate（成功路径，不当失败 raise）。
                for _ in range(6):
                    if not child.isalive():
                        break
                    await asyncio.sleep(0.5)
                if child.isalive():
                    logger.info("IDC: token 已拿到但 kiro-cli 仍在跑，主动结束子进程")
                    child.terminate(force=True)
            elif child.isalive():
                child.terminate(force=True)
                raise RuntimeError("kiro-cli IdC 登录超时未完成")
            # pexpect 的 exitstatus 在进程退出后才有值；signalstatus 非 None 说明被信号杀掉。
            # token_obtained 时跳过退出码校验：token 已确认落库即成功，被我们 terminate 掉
            # 导致的非零 exit/signal 不应误判为失败。
            elif child.exitstatus is None or child.exitstatus != 0:
                raise RuntimeError(
                    f"kiro-cli IdC 登录失败：exit={child.exitstatus} signal={child.signalstatus}"
                )

            # 关页前再扫一遍所有 tab 的 URL，兜底捕获实例 region（监听没逮到时）
            for p in context.pages:
                _capture_region(getattr(p, "url", ""))
            try:
                await page.close()
            except Exception:
                pass

        # 6) 读回 kiro-cli 本地凭据（kiro-cli 已按自己格式写好 auth_kv）
        tok = read_kiro_auth_kv("kirocli:odic:token")
        reg = read_kiro_auth_kv("kirocli:odic:device-registration")
        access_token = tok.get("accessToken") or tok.get("access_token") or ""
        refresh_token = tok.get("refreshToken") or tok.get("refresh_token") or ""
        id_token = tok.get("idToken") or tok.get("id_token")
        expires_at = _fmt_kiro_expires(tok.get("expiresAt") or tok.get("expires_at"))
        client_id = reg.get("clientId") or reg.get("client_id")
        client_secret = reg.get("clientSecret") or reg.get("client_secret")

        # 实例 region：浏览器捕获优先，其次 token/registration 里的 region，最后回落入参 region
        instance_region = (instance_region_box["region"]
                           or tok.get("region") or reg.get("region") or region)

        # profileArn + usage：CodeWhisperer 端点必须用 SSO 实例所在区，否则 IdC token 跨区
        # 会被判 invalid bearer（403）。先试实例区，再回落 us-east-1（兼容老的 us-east 实例）。
        # ListAvailableProfiles / GetUsageLimits 用同一 region，保证 ARN 与端点区一致。
        # 候选区：实例区优先，再依次回落常见 IdC 目录区。门户 URL 里的
        # `.portal.<region>.app.aws` 只反映门户前端区（常为 us-east-1），不一定等于
        # Q Developer subscription 实际所在区（可能是 eu-central-1 等），因此单靠
        # instance_region + us-east-1 会漏掉真实区、GetUsageLimits 全部 403。
        cw_regions = []
        for r in [instance_region, "us-east-1", "eu-central-1"]:
            if r and r not in cw_regions:
                cw_regions.append(r)
        profile_arn = KIRO_PROFILE_ARN_DEFAULT
        usage = {}
        usage_region = instance_region  # 命中的 CodeWhisperer 区（仅用于本地 usage/日志，CW 区已存 profileArn）
        for cw_region in cw_regions:
            arn = kiro_list_first_profile_arn(access_token, region=cw_region)
            u = kiro_get_usage_limits(access_token, arn or KIRO_PROFILE_ARN_DEFAULT,
                                      region=cw_region)
            if isinstance(u, dict) and u.get("userInfo"):
                profile_arn = arn or KIRO_PROFILE_ARN_DEFAULT
                usage = u
                usage_region = cw_region
                logger.info(f"IDC: CodeWhisperer 命中 region={cw_region}")
                break
            logger.warning(f"IDC: CodeWhisperer region={cw_region} 取 usage 失败，尝试下一区")
        user_id = None
        user_email = None
        if isinstance(usage, dict):
            user_info = usage.get("userInfo") or {}
            user_id = user_info.get("userId")
            user_email = user_info.get("email")
        # userId 取不到 = GetUsageLimits 全区失败（如 403 FEATURE_NOT_SUPPORTED），
        # 说明该 IdC token 在 CodeWhisperer 端不可用，本质是登录失败：不落盘、不标记成功。
        if not user_id:
            raise RuntimeError(
                f"Kiro IdC 登录失败：{identity_label} 取不到 userId"
                f"（GetUsageLimits 全区失败，region={instance_region}），不写入 kiro.json"
            )
        # email：优先用账号真实邮箱（usageData.userInfo.email），但 GetUsageLimits 常
        # 只回 userId 不带 email；缺失时用 用户名@配置域名 补全（登录名多为不含域的 kiro-xxx）
        if user_email:
            account_email = user_email
        elif "@" in username:
            account_email = username
        else:
            account_email = f"{username}@{AWS_IDC_EMAIL_DOMAIN}"

        # 6) 写 kiro.json（Kiro 原生 Enterprise/IdC 格式）
        record = {
            "id": str(uuid.uuid4()),
            "email": account_email,
            "password": None,
            "label": "Kiro Enterprise 账号",
            "status": "active",
            "addedAt": datetime.now().strftime("%Y/%m/%d %H:%M:%S"),
            "accessToken": access_token,
            "refreshToken": refresh_token,
            "expiresAt": expires_at,
            "provider": "Enterprise",
            "userId": user_id,
            "authMethod": "IdC",
            "clientId": client_id,
            "clientSecret": client_secret,
            # region = SSO/OIDC 登录区（clientId/secret/refreshToken 的签发区）；
            # CodeWhisperer 命中区(usage_region) 已完整存于 profileArn，不覆盖此字段
            "region": region,
            "clientIdHash": None,
            "ssoSessionId": None,
            "idToken": id_token,
            "startUrl": start_url,
            "profileArn": profile_arn,
            "usageData": usage or None,
            "groupId": None,
            "tagLinks": [],
            "machineId": str(uuid.uuid4()),
            "availableModelsCache": None,
            "failureCount": 0,
            "lastFailureAt": None,
            "disabledReason": None,
            "successCount": 0,
            "enabled": True,
        }
        async with _kiro_json_write_lock:  # 并发批量下串行化 kiro.json 的读-改-写
            append_kiro_record(record, output_file=output_file)
        # 注：kiro-cli 自己已写好 auth_kv（本身就是登录态），无需再手写。
        logger.info(
            f"Kiro Enterprise(IdC) {identity_label} 登录完成（kiro-cli 已登录），"
            f"userId={user_id} sso_region={region} cw_region={usage_region}"
        )
        ok = True
        return record
    finally:
        await close_kiro_persistent_context(_browser)
        if ok and _browser is not None and _browser.backend == "camoufox":
            _promote_kiro_asset_cache(profile_dir)
        # pexpect 子进程：terminate + 取消盲发回车协程。pexpect 路径下没有 Terminal
        # 窗口，不再需要 close_terminal_window_by_id。
        await _cleanup_kiro_cli_pexpect(child, enter_task)


async def register_kiro(parsed: tuple, output_file: str = KIRO_OUTPUT_FILE,
                        iso_home: str = "") -> dict:
    """kiro-cli 登录 + 自动化 OAuth（Builder ID/Google、GitHub 或 IDC），返回完整账号记录。

    iso_home 非空 = 并发隔离态，仅 IDC 路径支持（走 pexpect + 独立 $HOME）。
    Builder ID/GitHub 走 Terminal.app + `pkill -f` 共享路径，天然无法并发（pkill 会误杀
    兄弟登录进程），批量层对这类只能串行；iso_home 在该分支被忽略。
    parsed 来自 parse_kiro_input，格式：
      ("builderid", email, password, totp_secret)
      ("github", username, password, totp_secret)
      ("idc", start_url, username, temp_pwd, new_pwd)

    IDC 走 register_kiro_idc 的直连 OIDC device flow（更快，省掉 kiro-cli + kiro.dev
    gateway 那一长串），不在本函数里。Builder ID 与 GitHub 都走 kiro-cli login
    --license free + 浏览器 OAuth，仅 provider 选择按钮和 inline 填表函数不同。
    """
    mode = parsed[0]
    if mode == "idc":
        return await register_kiro_idc(parsed, output_file=output_file, iso_home=iso_home)
    if mode == "builderid":
        _, email, password, totp_secret = parsed
        identity_label = email
        provider_url_match = ("accounts.google.com",)
        provider_buttons = ("Continue with Google", "Google")
        provider_oauth_inline = kiro_google_oauth_inline
    elif mode == "github":
        _, username, password, totp_secret = parsed
        # 用 username 占用 email 槽位（profile dir / screenshot / record 里复用）
        email = username
        identity_label = f"github:{username}"
        provider_url_match = ("github.com",)
        provider_buttons = (
            "Continue with GitHub", "Sign in with GitHub",
            "Log in with GitHub", "GitHub",
        )
        provider_oauth_inline = kiro_github_oauth_inline
    else:
        raise ValueError(f"register_kiro: 未知 mode={mode}")

    # provider_url_match 统一成元组，判断"是否已到 provider 域"用子串任一命中
    def _on_provider(u: str) -> bool:
        return any(m in u for m in provider_url_match)

    # === 1. 清理 ===
    logger.info("清理本地 kiro-cli 会话（保留 server 端 token）")
    run_kiro_logout()
    close_kiro_signin_tabs_in_main_chrome()
    leftover = _list_kiro_signin_urls_in_main_chrome()
    if leftover:
        logger.warning(f"清理后主 Chrome 仍有 {len(leftover)} 个 kiro URL，可能干扰抓取")

    # === 2. 启动 kiro-cli（Terminal.app）===
    shell_cmd = "kiro-cli login --license free"
    logger.info(f"启动 {shell_cmd}（via Terminal.app）")
    as_script = f'''
    tell application "Terminal"
        activate
        do script {json.dumps(shell_cmd)}
        delay 0.3
        return id of front window
    end tell
    '''
    try:
        res = subprocess.run(["osascript", "-e", as_script],
                             check=True, capture_output=True, text=True, timeout=10)
        kiro_terminal_window_id = (res.stdout or "").strip()
    except Exception:
        kiro_terminal_window_id = ""
    logger.debug(f"Terminal window id: {kiro_terminal_window_id}")

    # kiro-cli 完成状态：用 pgrep + sqlite token 联合判断
    _proc_pattern = shell_cmd
    class _KiroProc:
        returncode = None
        def poll(self):
            if self.returncode is not None:
                return self.returncode
            pgrep = subprocess.run(["pgrep", "-f", _proc_pattern],
                                   capture_output=True, text=True)
            if not pgrep.stdout.strip():
                try:
                    tok = read_kiro_social_token()
                    self.returncode = 0 if tok.get("access_token") else 1
                except Exception:
                    self.returncode = 1
                return self.returncode
            return None
        def kill(self):
            subprocess.run(["pkill", "-TERM", "-f", _proc_pattern],
                           capture_output=True)
            self.returncode = -1
    proc = _KiroProc()

    # === 3. AppleScript 抓主 Chrome 里 kiro 的 URL（此时尚未启动 Playwright Chrome）===
    logger.info("等待 kiro-cli 打开登录 URL（AppleScript 抓主 Chrome）...")
    try:
        verify_url = capture_new_kiro_signin_url(timeout_s=90)
    except BaseException:
        close_terminal_window_by_id(kiro_terminal_window_id)
        raise

    if not verify_url:
        if proc.poll() is None:
            proc.kill()
        close_terminal_window_by_id(kiro_terminal_window_id)
        raise RuntimeError("未能从主 Chrome 抓到 kiro signin URL")

    logger.info(f"抓到 kiro signin URL: {verify_url}")
    close_kiro_signin_tabs_in_main_chrome()

    # === 4. 此时再启动 CloakBrowser stealth Chromium（独立 user-data-dir，不复用主 Chrome）===
    # CloakBrowser 自带源码级指纹补丁，用来绕过 Google "This browser may not be secure" 拦截；
    # 独立 user-data-dir 意味着和主 Chrome 不共享进程/登录态，关 URL tab 阶段已完成，此处安全
    # === 4. 启动 Camoufox stealth Firefox（独立 user-data-dir，不复用主 Chrome）===
    # Firefox 内核 + 源码级反指纹补丁，专门用来绕过 Google "This browser may not be secure"
    # 拦截 —— CloakBrowser 的 Chromium 在这一步会触发风控。geoip=True 让 timezone/locale
    # 跟出口 IP 自动同步，避免指纹矛盾；持久化 profile 让第二次起步直接进登录态。
    context, profile_dir, _browser = await launch_kiro_persistent_context(email)
    ok = False  # 完整跑通标记：成功后用本 profile 的完整 cache2 晋升为共享基准

    # 用 try/finally 保证 Firefox / Terminal 窗口都被清理
    try:
        # 注入 stealth：盖掉 navigator.webdriver 等（Camoufox 内核已 patch，这里冗余兜底）
        try:
            await context.add_init_script(
                """
                Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
                Object.defineProperty(navigator, 'plugins',
                    {get: () => [1, 2, 3, 4, 5]});
                Object.defineProperty(navigator, 'languages',
                    {get: () => ['en-US', 'en']});
                """
            )
        except Exception as e:
            logger.debug(f"注入 stealth 脚本异常: {e}")

        # === 5. Playwright 打开 URL 完成 OAuth ===
        # 持久化 context 首次可能已有一个默认 about:blank 页，复用它
        pages = context.pages
        page = pages[0] if pages else await context.new_page()
        # 不再调 fit_window_to_screen：Firefox 无 CDP，窗口尺寸由 Camoufox launch 时定死。
        try:
            await page.goto(verify_url, wait_until="domcontentloaded", timeout=30000)
        except Exception as e:
            logger.warning(f"打开 verify URL 失败（可能已 302 重定向）: {e}")
        await human_delay(page, "navigate")

        # 在 app.kiro.dev/signin 上点对应 provider 入口 → 跳到 provider 登录页
        for _ in range(30):
            if _on_provider(page.url):
                break
            clicked = False
            for text in ("Confirm and continue", "Confirm", "Continue",
                         "Next", "Allow access", "Allow", "Approve",
                         "确认并继续", "确认", "继续", "下一步",
                         "允许访问", "允许", "批准"):
                btn = page.locator(
                    f'button:has-text("{text}"), a:has-text("{text}"), '
                    f'[role="button"]:has-text("{text}"), input[type="submit"][value="{text}"]'
                )
                if await btn.count() > 0 and await btn.first.is_visible():
                    try:
                        await btn.first.click()
                        logger.info(f"点击按钮: {text}")
                        await human_delay(page, "click")
                        clicked = True
                        break
                    except Exception:
                        pass
            if not clicked:
                for ptext in provider_buttons:
                    # 与 idc 选 Your organization 共用同一套点击+校验逻辑
                    if await _kiro_click_signin_option(page, ptext):
                        clicked = True
                        # 点完 provider 按钮主动等导航到 provider 域，避免 30 轮跑完跳转还没到
                        try:
                            await page.wait_for_url(_on_provider, timeout=20000)
                        except Exception:
                            pass
                        break
            if _on_provider(page.url):
                break
            if not clicked:
                await page.wait_for_timeout(1000)

        # 兜底：循环结束但 URL 还没到 provider 域，再多等一会
        if not _on_provider(page.url):
            try:
                await page.wait_for_url(_on_provider, timeout=20000)
            except Exception:
                pass

        if _on_provider(page.url):
            await provider_oauth_inline(page, context, email, password, totp_secret)

        logger.info("等待并点击最终 Allow/Confirm 授权按钮")
        last_url = ""
        diag_dumped = False
        extracted_code = None
        extracted_state = None
        for i in range(60):
            if proc.poll() is not None:
                break
            try:
                cur = page.url
                if cur != last_url:
                    logger.info(f"[{i}s] Playwright 当前 URL: {cur[:200]}")
                    last_url = cur

                # 到达 kiro.dev auth success 页：方案 D 接管最后一跳
                if "auth_status=success" in cur and not extracted_code:
                    # 给页面点时间让 JS 存 code
                    await page.wait_for_timeout(1500)
                    # 首次进入时 dump 诊断数据，方便后续优化抽取逻辑
                    if not diag_dumped:
                        diag_dumped = True
                        try:
                            diag = await page.evaluate("""() => ({
                                url: location.href,
                                title: document.title,
                                bodyText: (document.body && document.body.innerText || '').slice(0, 2000),
                                localStorage: Object.fromEntries(
                                    Object.keys(localStorage).map(k => [k, localStorage.getItem(k)])
                                ),
                                sessionStorage: Object.fromEntries(
                                    Object.keys(sessionStorage).map(k => [k, sessionStorage.getItem(k)])
                                ),
                                cookies: document.cookie,
                                hash: location.hash,
                                search: location.search,
                            })""")
                            diag_path = f"/tmp/kiro_success_diag_{email.replace('@','_')}.json"
                            with open(diag_path, "w") as f:
                                json.dump(diag, f, ensure_ascii=False, indent=2)
                            logger.info(f"success 页诊断 dump 到: {diag_path}")
                        except Exception as e:
                            logger.warning(f"dump 诊断失败: {e}")
                    # 尝试多种方式抽取 code+state
                    try:
                        extracted = await page.evaluate("""() => {
                            // 1) URL search/hash 里直接带
                            const sp = new URLSearchParams(location.search);
                            const hp = new URLSearchParams(location.hash.replace(/^#/,''));
                            const pick = (k) => sp.get(k) || hp.get(k);
                            let code = pick('code');
                            let state = pick('state');
                            // 2) storage 里找
                            const all = {...localStorage, ...sessionStorage};
                            for (const [k, v] of Object.entries(all)) {
                                if (!v) continue;
                                if (!code && /code/i.test(k)) code = v;
                                if (!state && /state/i.test(k)) state = v;
                                // 也可能是 JSON 里嵌套
                                try {
                                    const j = JSON.parse(v);
                                    if (j && typeof j === 'object') {
                                        code = code || j.code || j.authorizationCode;
                                        state = state || j.state;
                                    }
                                } catch {}
                            }
                            return {code, state};
                        }""")
                        extracted_code = (extracted or {}).get("code")
                        extracted_state = (extracted or {}).get("state")
                        if extracted_code:
                            logger.info(f"从 kiro.dev 页面抽到 code={extracted_code[:20]}... state={extracted_state}")
                    except Exception as e:
                        logger.debug(f"抽取 code 异常: {e}")

                    # 抽到了就手动打 localhost:3128，触发 kiro-cli token 交换
                    if extracted_code:
                        from urllib.parse import urlencode
                        cb_url = "http://localhost:3128/?" + urlencode({
                            k: v for k, v in {"code": extracted_code, "state": extracted_state}.items() if v
                        })
                        logger.info(f"手动 navigate 到 kiro-cli 回调: {cb_url[:80]}...")
                        try:
                            await page.goto(cb_url, wait_until="domcontentloaded", timeout=15000)
                        except Exception as e:
                            logger.warning(f"navigate localhost:3128 异常: {e}")

                # 常规按钮匹配（兜底，有些页面依然走点击流）
                for text in ("Allow access", "Allow", "Approve",
                             "Confirm and continue", "Confirm", "Continue",
                             "Launch", "Open CLI", "Return",
                             "允许访问", "允许", "批准",
                             "确认并继续", "确认", "继续", "启动", "返回"):
                    btn = page.locator(
                        f'button:has-text("{text}"), a:has-text("{text}"), '
                        f'[role="button"]:has-text("{text}"), input[type="submit"][value="{text}"]'
                    )
                    if await btn.count() > 0 and await btn.first.is_visible():
                        await btn.first.click()
                        logger.info(f"点击最终按钮: {text}")
                        await human_delay(page, "click")
                        break
            except Exception:
                pass
            await page.wait_for_timeout(1000)

        logger.info("等待 kiro-cli 完成 token 交换...")
        for _ in range(120):
            if proc.poll() is not None:
                break
            await asyncio.sleep(1)

        if proc.poll() is None:
            proc.kill()
            raise RuntimeError("kiro-cli 登录超时未完成")

        if proc.returncode != 0:
            raise RuntimeError(f"kiro-cli 退出码 {proc.returncode}")

        try:
            await page.close()
        except Exception:
            pass

        # === 6. 读取 token + 写 kiro.json ===
        token = read_kiro_social_token()
        access_token = token.get("access_token") or ""
        refresh_token = token.get("refresh_token") or ""
        provider_lower = (token.get("provider") or "google").lower()
        profile_arn = token.get("profile_arn") or KIRO_PROFILE_ARN_DEFAULT

        usage = kiro_get_usage_limits(access_token, profile_arn)
        user_id = None
        if isinstance(usage, dict):
            user_id = usage.get("userInfo", {}).get("userId")
        # userId 取不到 = GetUsageLimits 失败，token 不可用，本质登录失败：不落盘、不标记成功。
        if not user_id:
            raise RuntimeError(
                f"Kiro 登录失败：{identity_label} 取不到 userId"
                f"（GetUsageLimits 失败），不写入 kiro.json"
            )

        if mode == "github" and provider_lower in ("google", ""):
            # kiro-cli 偶尔不区分 provider，按当前 mode 校正
            provider_lower = "github"
        if provider_lower == "google":
            provider_display = "Google"
        elif provider_lower == "github":
            provider_display = "GitHub"
        else:
            provider_display = provider_lower.capitalize()

        record = {
            "id": str(uuid.uuid4()),
            "email": email,
            "password": None,
            "label": f"Kiro {provider_display} 账号",
            "status": "active",
            "addedAt": datetime.now().strftime("%Y/%m/%d %H:%M:%S"),
            "accessToken": access_token,
            "refreshToken": refresh_token,
            "expiresAt": None,
            "provider": provider_display,
            "userId": user_id,
            "authMethod": "social",
            "clientId": None,
            "clientSecret": None,
            "region": None,
            "clientIdHash": None,
            "ssoSessionId": None,
            "idToken": None,
            "startUrl": None,
            "profileArn": profile_arn,
            "usageData": usage or None,
            "groupId": None,
            "tagLinks": [],
            "machineId": str(uuid.uuid4()),
        }

        append_kiro_record(record, output_file=output_file)
        logger.info(f"Kiro 账号 {identity_label} 登录完成，userId={user_id}")
        ok = True
        return record
    finally:
        # === 7. 清理 Camoufox Firefox + Terminal 窗口 ===
        await close_kiro_persistent_context(_browser)
        if ok and _browser is not None and _browser.backend == "camoufox":
            _promote_kiro_asset_cache(profile_dir)
        close_terminal_window_by_id(kiro_terminal_window_id)


# ==========================================================================
# 企业号(IDC) 网页登录 → /settings/api-keys 生成 API Key（ksk_）
# --------------------------------------------------------------------------
# 与 register_kiro_idc 的区别：不走 kiro-cli 设备流，而是直接在 app.kiro.dev 网页里
# 用 "Your organization"(IAM Identity Center) 完成网页登录，拿到网页会话后进
# /settings/api-keys 页填 Key name、点 Create key，抓创建瞬间只显示一次的完整 ksk_ key。
# 登录那一段完全复用现成的 IDC signin 三件套：
#   kiro_select_idc_on_kiro_dev / kiro_idc_enter_start_url_on_kiro_dev / kiro_idc_signin_inline
# ==========================================================================

KIRO_APIKEY_OUTPUT_FILE = "kiro_api_keys.txt"


def _on_aws_signin_url(u: str) -> bool:
    """判断 URL 是否已到 AWS IDC / 门户登录域（web OAuth 途中，用于切到 AWS 登录 tab）。"""
    if not u:
        return False
    return any(s in u for s in (
        "signin.aws", "awsapps.com", ".app.aws", "portal.sso",
        ".amazoncognito.", "oidc.", "signin.aws.amazon.com",
    ))


def _kiro_dev_logged_in(u: str) -> bool:
    """URL 在 app.kiro.dev 且不在 signin 页 = 已登录态（仅凭 URL 的粗判，可能误判：
    会话失效时 SPA 会在 /settings/api-keys 这个 URL 上直接渲染 signin 选择页，URL 不变。
    真正判断"是否可用"要再叠加 _kiro_page_is_signin_chooser 的内容判定）。"""
    u = u or ""
    return "app.kiro.dev" in u and "/signin" not in u


async def _kiro_page_is_signin_chooser(page: Page) -> bool:
    """内容判定当前页是否为 app.kiro.dev 的 signin 选择页（"Choose a way to sign in/sign
    up" + Google / GitHub / Builder ID / Your organization 四个入口）。

    为什么必须按内容判：会话失效/被登出时，kiro 的 SPA 常常【不改 URL】就地把
    /settings/api-keys 渲染成这张选择页。只看 URL（_kiro_dev_logged_in）会误判成已登录，
    于是去 api-keys 页空等 20s "Key name" 输入框、最后报一个误导的"页面结构变化"（本 bug）。
    这里用「Your organization 入口按钮」或选择页专属文案判定，可靠得多。
    """
    try:
        if await page.locator(
            'button:has-text("Your organization"), a:has-text("Your organization")'
        ).count() > 0:
            return True
    except Exception:
        pass
    try:
        body = (await page.inner_text("body", timeout=1500)).lower()
    except Exception:
        body = ""
    return ("choose a way to sign" in body
            or ("builder id" in body and "your organization" in body))


async def _kiro_page_failed_to_load(page: Page) -> bool:
    """判断当前页是否是 kiro 的 "Kiro failed to load" 资源加载失败页（assets.app.kiro.dev
    被墙/加载失败时出现，带一个 Retry 按钮，原表单/页面内容整个消失）。这是 kiro.dev 自身
    的偶发抽风，不是我们填表的问题——命中后应点 Retry / 重新导航恢复，而不是当成永久失败。"""
    try:
        body = (await page.inner_text("body", timeout=1500)).lower()
    except Exception:
        return False
    return "kiro failed to load" in body or "assets.app.kiro.dev" in body


async def _kiro_recover_failed_to_load(page: Page, tries: int = 2) -> bool:
    """命中 "Kiro failed to load" 就尝试恢复：优先点页面自带的 Retry 按钮，其次整页 reload。
    每次恢复后等网络空闲再复查。返回 True=已不在失败页（恢复成功或本就正常）。"""
    for _ in range(tries):
        if not await _kiro_page_failed_to_load(page):
            return True
        logger.warning("[apikey] 命中 'Kiro failed to load' 资源加载失败页，尝试 Retry/reload 恢复")
        clicked = False
        for text in ("Retry", "重试", "Try again", "Reload"):
            try:
                btn = page.locator(
                    f'button:has-text("{text}"), a:has-text("{text}"), '
                    f'[role="button"]:has-text("{text}")'
                ).first
                if await btn.count() > 0 and await btn.is_visible():
                    await btn.click(timeout=3000)
                    clicked = True
                    break
            except Exception:
                continue
        if not clicked:
            try:
                await page.reload(wait_until="domcontentloaded", timeout=30000)
            except Exception:
                pass
        await _apikey_settle(page)
    return not await _kiro_page_failed_to_load(page)


async def _apikey_settle(page: Page, timeout_ms: int = 4000) -> None:
    """api-keys / signin 都是自家已登录后台页，不需要反爬用的拟人延迟（human_delay 的
    navigate 要 3~6s）。这里只等网络空闲，页面早渲染好就立刻返回，超时也直接走。"""
    try:
        await page.wait_for_load_state("networkidle", timeout=timeout_ms)
    except Exception:
        pass


async def _kiro_apikey_wait_logged_in(context: BrowserContext, signin_page: Page,
                                      timeout_s: int = 150) -> "Page | None":
    """AWS 登录完成后，等待任一 tab 回到 app.kiro.dev 登录态；期间补点最终同意/继续按钮
    （web OAuth 收尾可能有一页 Allow/Continue）。返回登录态的 page，超时返回 None。

    只补点同意类按钮（Allow/Approve/Accept/Authorize/Confirm/Continue），不点
    "Sign in"/"Next" —— 避免在 kiro landing 上误触发再次登录形成回环。同一
    (page, 文案, url) 只点一次。
    """
    consent_texts = (
        "Allow access", "Allow", "Approve", "Accept", "Authorize",
        "Confirm and continue", "Confirm", "Continue",
        "允许访问", "允许", "批准", "接受", "确认并继续", "确认", "继续",
    )
    last_click = {"v": None}
    for _i in range(timeout_s):
        for p in list(context.pages):
            try:
                if _kiro_dev_logged_in(p.url):
                    try:
                        await p.bring_to_front()
                    except Exception:
                        pass
                    logger.info(f"[apikey] 已回到 app.kiro.dev 登录态: {p.url[:90]}")
                    return p
            except Exception:
                continue
        for p in list(context.pages):
            for text in consent_texts:
                try:
                    btn = p.locator(
                        f'button:has-text("{text}"), a:has-text("{text}"), '
                        f'[role="button"]:has-text("{text}")'
                    ).first
                    if await btn.count() == 0 or not await btn.is_visible():
                        continue
                    sig = (id(p), text, p.url)
                    if sig == last_click["v"]:
                        continue
                    try:
                        await btn.click(timeout=2000)
                    except Exception:
                        continue
                    last_click["v"] = sig
                    logger.info(f"[apikey] 收尾补点 '{text}'（{p.url[:80]}）")
                    break
                except Exception:
                    continue
        try:
            await signin_page.wait_for_timeout(1000)
        except Exception:
            await asyncio.sleep(1)
    return None


async def _kiro_apikey_extract_new_key(page: Page) -> str:
    """从当前页面抓创建后弹出的完整 ksk_ key。

    要点：
      - key 前缀是 `ksk_`；列表里只显示掩码 `ksk_S12rEEN1...`（含省略号、是 <td> 纯文本），
        完整 key 只在创建瞬间的弹窗/只读框里出现，无省略号。
      - 优先 input/textarea 的 value、code/pre 文本（完整 key 常在只读框/代码块）；
        整页文本兜底。紧跟 `.`/`…` 的一律当掩码丢弃。
      - 完整 key 远长于掩码前缀（掩码约 12 字符），设 len>=20 下限，取最长。
    """
    cands = await page.evaluate(
        r"""
        () => {
          const re = /ksk_[A-Za-z0-9_\-]{6,}/g;
          const out = [];
          const push = (s, src) => {
            if (!s) return;
            let m; re.lastIndex = 0;
            while ((m = re.exec(s)) !== null) {
              const tok = m[0];
              const after = s.slice(m.index + tok.length, m.index + tok.length + 3);
              const truncated = after.indexOf('.') === 0 || after.indexOf('…') === 0;
              out.push({tok, src, truncated, len: tok.length});
            }
          };
          document.querySelectorAll('input, textarea').forEach(el => push(el.value || '', 'input'));
          document.querySelectorAll('code, pre').forEach(el => push(el.innerText || el.textContent || '', 'code'));
          push(document.body ? document.body.innerText : '', 'body');
          return out;
        }
        """
    )
    best = ""
    for c in cands or []:
        tok = c.get("tok") or ""
        if c.get("truncated"):
            continue
        if len(tok) < 20:
            continue
        if len(tok) > len(best):
            best = tok
    return best


async def _kiro_apikey_dump_labels(page: Page, tag: str) -> None:
    """建 key 卡住时把页面所有 button/a 文字 dump 到日志，便于定位真实按钮文案。"""
    try:
        labels = await page.evaluate("""() => {
            const seen = new Set(); const out = [];
            document.querySelectorAll('button, a, [role="button"]').forEach(el => {
                const t = (el.innerText || el.textContent || '').trim().replace(/\\s+/g, ' ');
                if (t && t.length < 60 && !seen.has(t)) { seen.add(t); out.push(t); }
            });
            return out;
        }""")
        logger.warning(f"[apikey] {tag}：页面候选按钮 labels={labels[:40]}")
    except Exception as e:
        logger.debug(f"[apikey] dump labels 异常: {e}")


async def _kiro_apikey_create_via_spa(page: Page, key_name: str,
                                      identity_label: str = "") -> str:
    """在 app.kiro.dev/settings/api-keys 页面用【网页 SPA 交互】建一个 API Key（ksk_），
    抓创建弹窗里只显示一次的完整 key。不嗅探 Bearer、不调 management.kiro.dev CreateApiKey。

    步骤：点 "Create API key" 入口 → 填 Key name → 点弹窗内确认 Create → 抓 ksk_。
    每一步找不到目标就 dump 页面按钮文字到日志。返回完整 ksk_ key（失败返回空串）。
    """
    # 1) 点开"建 key"入口（列表页顶部按钮）。这些文案是入口，不含裸 "Create"——避免页面上
    #    恰好有别的 Create 按钮时误点；入口点开后靠下面等 Key name 框判定是否真开了弹窗。
    entry_texts = (
        "Create API key", "Create API Key", "Create new API key",
        "Create new key", "New API key", "Add API key", "Generate API key",
        "创建 API 密钥", "创建 API Key", "新建 API 密钥", "生成 API 密钥",
    )
    opened = False
    for text in entry_texts:
        try:
            btn = page.locator(
                f'button:has-text("{text}"), a:has-text("{text}"), '
                f'[role="button"]:has-text("{text}")'
            ).first
            if await btn.count() > 0 and await btn.is_visible():
                await btn.click(timeout=4000)
                logger.info(f"[apikey] 点开建 key 入口 '{text}'")
                opened = True
                break
        except Exception:
            continue
    if not opened:
        # 入口文案可能只是 "Create"/"New"：退一步用更宽松的候选再试一次
        for text in ("Create key", "Create", "New key", "New", "创建密钥", "新建", "创建"):
            try:
                btn = page.locator(
                    f'button:has-text("{text}"), [role="button"]:has-text("{text}")'
                ).first
                if await btn.count() > 0 and await btn.is_visible():
                    await btn.click(timeout=4000)
                    logger.info(f"[apikey] 点开建 key 入口（宽松匹配）'{text}'")
                    opened = True
                    break
            except Exception:
                continue
    if not opened:
        await _kiro_apikey_dump_labels(page, "未找到建 key 入口按钮")

    # 2) 等 Key name 输入框出现并填入（有的 UI 无命名步，等不到就跳过直接确认）
    name_inp = page.locator(
        'input[name="name"], input[id*="name" i], input[placeholder*="name" i], '
        'input[aria-label*="name" i], input[placeholder*="名称" i], '
        '[role="dialog"] input[type="text"], input[type="text"]'
    ).first
    try:
        await name_inp.wait_for(state="visible", timeout=8000)
        if not await _react_safe_fill_input(name_inp, key_name):
            logger.warning("[apikey] Key name React-safe 填值未确认")
        else:
            logger.info(f"[apikey] 已填 Key name={key_name}")
        await human_delay(page, "type")
    except Exception:
        logger.info("[apikey] 未见 Key name 输入框（该 UI 可能不需要命名，直接确认建 key）")

    # 3) 点弹窗内的确认 Create。优先在 [role=dialog] 内找，避免又点回列表页入口按钮。
    confirm_texts = ("Create key", "Create API key", "Create", "Generate",
                     "Confirm", "Save", "Add", "确认创建", "创建", "生成", "确定", "保存")
    confirmed = False
    for scope in ('[role="dialog"] ', '[role="alertdialog"] ', ''):
        for text in confirm_texts:
            try:
                btn = page.locator(
                    f'{scope}button:has-text("{text}"), '
                    f'{scope}[role="button"]:has-text("{text}")'
                ).first
                if await btn.count() > 0 and await btn.is_visible():
                    await btn.click(timeout=4000)
                    logger.info(f"[apikey] 点确认建 key '{text}'（scope={scope or 'page'}）")
                    confirmed = True
                    break
            except Exception:
                continue
        if confirmed:
            break
    if not confirmed:
        await _kiro_apikey_dump_labels(page, "未找到确认 Create 按钮")

    # 4) 抓弹窗里只显示一次的完整 ksk_（最多 ~12s 轮询，key 生成有网络延迟）
    api_key = ""
    for _ in range(24):
        api_key = await _kiro_apikey_extract_new_key(page)
        if api_key:
            break
        await page.wait_for_timeout(500)
    if api_key:
        logger.info(f"[apikey] 网页建 key 成功 ksk_…（len={len(api_key)}），{identity_label}")
    return api_key


async def register_kiro_apikey(parsed: tuple, output_file: str = KIRO_APIKEY_OUTPUT_FILE,
                               iso_home: str = "", key_name: str = "") -> dict:
    """企业号(IDC) 网页登录 app.kiro.dev → /settings/api-keys 创建 API Key（ksk_）。

    仅支持 idc（"Your organization"）。parsed 格式与 register_kiro_idc 相同：
      ("idc", start_url, username, temp_pwd, new_pwd[, region])
    返回含 apiKey 的记录 dict（由上层写入 kiro_api_keys.json）。

    流程：
      1) 持久化 Firefox profile 直接进 /settings/api-keys；已登录则复用会话直达。
      2) 未登录 → app.kiro.dev/signin 选 "Your organization" → 填 Start URL/Region
         → 驱动 AWS IDC 登录（用户名/临时密码/按需改密/Allow）→ 等回到 kiro 登录态。
      3) 填 Key name（key_name，空则自动 kiro-<时间戳>-<随机>）、点 Create key。
      4) 抓弹窗里只显示一次的完整 ksk_ key。
    """
    if not parsed or parsed[0] != "idc":
        raise ValueError("kiro-apikey 仅支持 IDC（Your organization）企业号账号")
    _, start_url, username, temp_pwd, new_pwd = parsed[:5]
    region = parsed[5] if len(parsed) > 5 and parsed[5] else _idc_region_from_start_url(start_url)
    identity_label = f"{username}@{start_url}"
    if not key_name:
        key_name = "kiro-" + datetime.now().strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:4]
    logger.info(f"[apikey] 开始：{identity_label} region={region} key_name={key_name}")

    _wd_backend = kiro_browser_backend()
    if _wd_backend in ("safari", "chrome"):
        # Selenium/WebDriver（safari 或 chrome）过 AWS WAF，走完 kiro.dev 网页登录 + 建 key。
        from app.kiro.safari_idc import drive_safari_apikey
        result = await asyncio.to_thread(
            drive_safari_apikey, start_url, username, temp_pwd, new_pwd, region,
            key_name, 300, _wd_backend)
        api_key = result.get("apiKey") or ""
        if not api_key:
            raise RuntimeError("[apikey] safari 网页建 key 未拿到 ksk_")
        account_email = username if "@" in username else f"{username}@{AWS_IDC_EMAIL_DOMAIN}"
        record = {
            "email": account_email,
            "username": username,
            "startUrl": start_url,
            "region": result.get("region") or region,
            "keyName": key_name,
            "apiKey": api_key,
            "profileArn": None,
            "createdAt": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        logger.info(f"[apikey] safari 建 key 成功：{identity_label} ksk_…(len={len(api_key)})")
        return record

    # 后端由 KIRO_BROWSER_BACKEND 决定（默认 camoufox；可切 cloak）。
    context, profile_dir, _browser = await launch_kiro_persistent_context(identity_label)
    ok = False  # 完整跑通标记：成功后用本 profile 的完整 cache2 晋升为共享基准

    # 建 key 走【纯网页 SPA 交互】（登录 + 点 Create key + 抓弹窗），不嗅 Bearer、不调
    # management.kiro.dev CreateApiKey。下面这个嗅探器仅【被动】记录 SPA 自己发的
    # profileArn，写进结果 record 作参考信息用；抓不到也不影响建 key，绝不用它去调控制面。
    _sniff = {"bearer": "", "profile_arn": ""}

    # codewhisperer profile ARN 形态：arn:aws:codewhisperer:<region>:<acct>:profile/<id>
    _PROFILE_ARN_RE = re.compile(
        r"arn:aws[a-z-]*:codewhisperer:[a-z0-9-]+:\d+:profile/[A-Za-z0-9]+")

    async def _sniff_mgmt(response):
        try:
            url = response.url
            if ".kiro.dev/" not in url or "management." not in url:
                return
            req = response.request
            auth = req.headers.get("authorization") or ""
            if not auth.lower().startswith("bearer "):
                return
            _sniff["bearer"] = auth.split(" ", 1)[1].strip()  # 会话 bearer，跨区一致
            # profileArn 来源（都是真实 ARN，region 后面从 ARN 自身解析，不看命中哪个探测端点）：
            #   1) 请求体（GetProfile/ListApiKeys/CreateApiKey 带 profileArn）
            #   2) 响应体（ListAvailableProfiles 列出账号真实 profile，可能在 eu-central-1）
            # 不同 d-* 目录的 profile 落区不定，靠响应体兜住"真实区在 eu-central-1"的账号。
            if not _sniff["profile_arn"]:
                body = req.post_data
                if body:
                    try:
                        arn = json.loads(body).get("profileArn")
                        if arn:
                            _sniff["profile_arn"] = arn
                    except Exception:
                        pass
            if not _sniff["profile_arn"]:
                try:
                    text = await response.text()
                    m = _PROFILE_ARN_RE.search(text or "")
                    if m:
                        _sniff["profile_arn"] = m.group(0)
                except Exception:
                    pass
        except Exception as e:
            logger.debug(f"[apikey] 嗅探 management bearer 异常: {e}")

    context.on("response", _sniff_mgmt)

    # 【策略：不复用 / 不落盘任何跨账号产物】不再嗅探 signin fingerprint、也不按目录缓存回读。
    # 每个账号都走正常 Camoufox 启动、由浏览器现场生成各自独立的真实 fingerprint，避免
    # 「同目录多号共用一份指纹」被 Kiro 风控关联成批量注册。
    # 全量抓包仅为调试保留：只有显式置 KIRO_CAPTURE 环境变量时开启，写 scratchpad jsonl，
    # 正常跑零额外 IO、无任何 fingerprint 缓存副作用。
    _cap_path = os.environ.get("KIRO_CAPTURE") or ""

    def _cap_write(kind: str, url: str, payload):
        if not _cap_path:
            return
        try:
            with open(_cap_path, "a", encoding="utf-8") as f:
                f.write(json.dumps({"kind": kind, "url": url, "data": payload},
                                   ensure_ascii=False)[:20000] + "\n")
        except Exception:
            pass

    async def _sniff_capture_req(request):
        if not _cap_path:
            return
        try:
            u = request.url
            if "/api/execute" in u:
                _cap_write("api_execute_req", u, request.post_data)
            elif "/GetToken" in u or "/ExchangeToken" in u:
                _cap_write("kiro_rpc_req", u, {"headers": dict(request.headers)})
        except Exception:
            pass

    async def _sniff_capture_resp(response):
        if not _cap_path:
            return
        try:
            u = response.url
            if "/api/execute" in u:
                _cap_write("api_execute_resp", u, await response.text())
            elif "/GetToken" in u or "/ExchangeToken" in u:
                _cap_write("kiro_rpc_resp", u,
                           {"status": response.status,
                            "headers": dict(response.headers)})
        except Exception:
            pass

    if _cap_path:
        context.on("request", _sniff_capture_req)
        context.on("response", _sniff_capture_resp)
    try:
        try:
            await context.add_init_script(
                """
                Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
                Object.defineProperty(navigator, 'plugins',
                    {get: () => [1, 2, 3, 4, 5]});
                Object.defineProperty(navigator, 'languages',
                    {get: () => ['en-US', 'en']});
                """
            )
        except Exception as e:
            logger.debug(f"[apikey] 注入 stealth 脚本异常: {e}")

        pages = context.pages
        page = pages[0] if pages else await context.new_page()

        # 1) 进 api-keys 并确保处于「已登录」态：会话失效时 kiro 会【不改 URL】就地把
        #    /settings/api-keys 渲染成 signin 选择页，所以既看 URL 也看页面内容。未登录就
        #    走 IDC 网页登录；最多 2 轮，第 2 轮仍落回选择页 = 账号会话真没建立，准确报错。
        # 最多 3 轮：每轮进 api-keys → 若命中 "Kiro failed to load" 先 Retry/reload 恢复 →
        # 判是否已登录；已登录就建 key，未登录就走一轮 IDC 网页登录再回到顶部复检。登录途中
        # 的暂时性抽风（Kiro failed to load / Continue 没跳）不再当场致命 raise，而是截图后
        # continue 换新一轮全新导航重试——实测这类失败后账号往往其实已登录，下一轮直接进。
        for _login_round in range(3):
            try:
                await page.goto("https://app.kiro.dev/settings/api-keys",
                                wait_until="domcontentloaded", timeout=30000)
            except Exception as e:
                logger.warning(f"[apikey] 打开 api-keys 失败（可能已重定向登录）: {e}")
            await _apikey_settle(page)
            # kiro 资源加载失败页（assets.app.kiro.dev）先尝试恢复，别误判成需登录/结构变化
            await _kiro_recover_failed_to_load(page)
            await _kshot(page, "apikey_landing", identity_label)

            # URL 粗判 + 内容判定（会话失效时 URL 不变但就地渲染 signin 选择页）
            need_login = (not _kiro_dev_logged_in(page.url)
                          or "/settings/api-keys" not in page.url
                          or await _kiro_page_is_signin_chooser(page))
            if not need_login:
                logger.info(f"[apikey] 已登录态，直达 api-keys（第 {_login_round + 1} 轮）")
                break

            logger.info("[apikey] 未登录（或会话失效落回 signin 选择页），走 IDC 网页登录")
            if "app.kiro.dev/signin" not in page.url:
                try:
                    await page.goto("https://app.kiro.dev/signin",
                                    wait_until="domcontentloaded", timeout=30000)
                except Exception as e:
                    logger.warning(f"[apikey] 打开 signin 失败: {e}")
                await _apikey_settle(page)
            # a) 选 "Your organization"（IDC 入口）
            if not await kiro_select_idc_on_kiro_dev(page):
                logger.warning("[apikey] 未能点到 'Your organization' 入口（继续尝试填表）")
            # b) 填 Start URL + Region + Continue
            await kiro_idc_enter_start_url_on_kiro_dev(page, start_url, region)
            # c) AWS 登录页可能在当前 tab 直接跳转，或新开 tab/popup
            signin_page = await _idc_resolve_signin_page(
                context, page, _on_aws_signin_url, timeout_s=25)
            # c') 护栏：25s 后仍不在 AWS 域（还停在 app.kiro.dev/signin）= 上游 Continue 没把
            #     浏览器带进 AWS 登录页（Start URL/Region 提交未生效）。此时进 signin_inline 只会
            #     在 kiro 页上空等一串 8s 密码框超时刷屏。这里 dump 表单实况 + 截图后快速失败，
            #     把 Continue 为什么没跳的根因直接暴露在日志里，不再空转。
            if not _on_aws_signin_url(signin_page.url):
                try:
                    diag = await signin_page.evaluate(
                        """() => {
                          const q = (s) => document.querySelector(s);
                          const url = q('input[name="startUrl"],input[id="startUrl"],'
                            + 'input[name="issuerUrl"],input[id="issuerUrl"],input[type="url"],'
                            + 'input[placeholder*="start" i],input[placeholder*="https" i]');
                          const reg = q('input[name*="region" i],input[id*="region" i],'
                            + 'input[aria-label*="region" i],input[placeholder*="region" i],'
                            + 'input[placeholder*="us-east-1" i]');
                          const btn = [...document.querySelectorAll('button')].find(b =>
                            b.type === 'submit'
                            || /continue|next|sign in|继续|下一步|登录/i.test(b.textContent || ''));
                          const errs = [...document.querySelectorAll(
                              '[role="alert"],[class*="error" i],[class*="Error"]')]
                            .map(e => (e.textContent || '').trim()).filter(Boolean).slice(0, 3);
                          const body = (document.body.innerText || '').replace(/\\s+/g, ' ').slice(0, 200);
                          return {
                            startUrl: url ? (url.value || '<empty>') : '<no-input>',
                            region: reg ? (reg.value || '<empty>') : '<no-input>',
                            continueBtn: btn ? ((btn.textContent || '').trim().slice(0, 20)
                              + (btn.disabled ? ' [disabled]' : ' [enabled]')
                              + (btn.getAttribute('aria-disabled') === 'true' ? ' aria-disabled' : ''))
                              : '<no-btn>',
                            errors: errs,
                            onChooser: /choose a way to sign|your organization/i.test(body),
                            bodyHead: body,
                          };
                        }""")
                    logger.warning(f"[apikey] Continue 未进 AWS 登录页，kiro 表单实况: {diag}")
                except Exception as e:
                    logger.warning(f"[apikey] Continue 未进 AWS 登录页，dump 表单实况失败: {e}")
                await _kshot(page, "idc_continue_no_aws", identity_label)
                logger.warning(
                    f"[apikey] 本轮 Continue 未进 AWS 登录页（停在 {signin_page.url[:90]}），"
                    "换新一轮全新导航重试")
                continue
            # d) 驱动 AWS IDC 登录（用户名/临时密码/按需改密/Allow）。
            #    关键：传 is_login_done —— 网页登录没有设备流的 "Allow access to CLI" 同意步，
            #    登录完成会直接 302 回 app.kiro.dev。一旦任何 tab 到了 app.kiro.dev 登录态就
            #    让 signin_inline 的审批序列循环立刻收尾，否则它会空等到 45s/240s 超时，还可能
            #    把 username 误填进 api-keys 页的 "Key name" 文本框。
            def _apikey_login_done() -> bool:
                return any(_kiro_dev_logged_in(getattr(p, "url", "")) for p in context.pages)
            await kiro_idc_signin_inline(signin_page, context, username, temp_pwd, new_pwd,
                                         is_login_done=_apikey_login_done)
            # e) 等回到 app.kiro.dev 登录态（期间补点最终同意按钮）
            main_page = await _kiro_apikey_wait_logged_in(context, signin_page, timeout_s=150)
            if main_page is None:
                await _kshot(page, "apikey_login_timeout", identity_label)
                logger.warning("[apikey] 本轮登录后未回到 app.kiro.dev 登录态（超时），换新一轮重试")
                continue
            page = main_page
            # 登录拿到 main_page 后立刻进 api-keys 并【内容确认】已登录，是就直接建 key，
            # 别再回顶部重来一轮——刚登录完 re-goto 偶发闪 signin/home 页会让 need_login 误判，
            # 白跑一整轮（还可能撞上 Kiro failed to load）。只有确实没就绪才 continue 复核。
            try:
                await page.goto("https://app.kiro.dev/settings/api-keys",
                                wait_until="domcontentloaded", timeout=30000)
            except Exception as e:
                logger.warning(f"[apikey] 登录后打开 api-keys 失败: {e}")
            await _apikey_settle(page)
            await _kiro_recover_failed_to_load(page)
            if (_kiro_dev_logged_in(page.url)
                    and "/settings/api-keys" in page.url
                    and not await _kiro_page_is_signin_chooser(page)):
                logger.info("[apikey] 登录完成并确认已登录 api-keys 页，去建 key")
                break
            logger.info("[apikey] 登录后 api-keys 未即时就绪，换新一轮复核")
        else:
            # 3 轮都没 break（始终没进已登录 api-keys 页）→ 彻底失败，截图留证
            await _kshot(page, "apikey_login_failed", identity_label)
            raise RuntimeError(
                "[apikey] 多轮登录后仍未进入已登录 api-keys 页"
                "（Kiro failed to load 持续 / 账号凭据失效 / 会话未建立）")

        await _kshot(page, "apikey_page", identity_label)

        # 2) 【网页操作建 key】不嗅探 Bearer、不调 management.kiro.dev CreateApiKey。
        #    直接在 api-keys 页驱动 SPA：点 Create key → 填 Key name → 确认 → 抓一次性弹窗
        #    里的完整 ksk_。profileArn 若从会话里顺带嗅到就记进结果，没有也不影响建 key。
        api_key = await _kiro_apikey_create_via_spa(page, key_name, identity_label)
        if not api_key:
            await _kshot(page, "apikey_create_failed", identity_label)
            raise RuntimeError(
                "[apikey] 网页建 key 失败：未在创建弹窗抓到完整 ksk_"
                "（入口/确认按钮文案变化，或该账号无可用 Kiro profile 无法建 key）——"
                "详见日志里 dump 的页面候选按钮 labels 与 apikey_create_failed 截图")
        await _kshot(page, "apikey_created", identity_label)

        account_email = username if "@" in username else f"{username}@{AWS_IDC_EMAIL_DOMAIN}"
        record = {
            "email": account_email,
            "username": username,
            "startUrl": start_url,
            "region": region,
            "keyName": key_name,
            "apiKey": api_key,
            "profileArn": _sniff.get("profile_arn") or None,
            "createdAt": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
        ok = True
        return record
    finally:
        await close_kiro_persistent_context(_browser)
        # context 关掉后 cache2 已落盘：完整跑通的账号才拿它晋升基准（含点 Continue 之后
        # 那个懒加载 chunk），残缺/失败账号不会晋升（内部按缓存大小 + 新鲜度把关）。
        if ok and _browser is not None and _browser.backend == "camoufox":
            _promote_kiro_asset_cache(profile_dir)


