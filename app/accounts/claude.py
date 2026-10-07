"""Claude 账号：注册、console magic link、session/cookie 登录检测、邮箱封禁检查（由 main.py 拆分而来）"""

from email.header import decode_header
import asyncio
import email as email_pkg
import imaplib
import json
import logging
import random
import re
import time
import urllib.error
import urllib.parse
import urllib.request

from playwright.async_api import Page, BrowserContext

from app.settings import (
    CLAUDE_CONSOLE_EMAIL,
    CLAUDE_CONSOLE_IMAP_HOST,
    CLAUDE_CONSOLE_IMAP_PASS,
    CLAUDE_CONSOLE_IMAP_PORT,
    CLAUDE_CONSOLE_IMAP_USER,
)
from app.core.browser import human_delay, screenshot_path
from app.core.parsing import parse_session_input
from app.accounts.google_auth import google_login, handle_oauth_popup

logger = logging.getLogger(__name__)


MAIL_CHECK_URL = "https://sz1881.xyz/user/mail/messages"


def check_mail_suspended(email: str, password: str, timeout: int = 30) -> tuple[str, str]:
    """调用邮箱检查接口，判断账号是否被封
    返回: (status, raw_text)
      status: "已封禁" / "正常" / "异常: <msg>"
    """
    payload = json.dumps({
        "mode": "imap",
        "email": email,
        "password": password,
        "token_line": "",
        "folder": "inbox",
        "limit": 10,
        "subject_keyword": "",
        "since": "",
    }).encode("utf-8")

    req = urllib.request.Request(
        MAIL_CHECK_URL,
        data=payload,
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            text = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        text = e.read().decode("utf-8", errors="replace") if e.fp else str(e)
    except Exception as e:
        return f"异常: {e}", ""

    if "Your account has been suspended" in text:
        return "已封禁", text
    return "正常", text


async def _claude_try_one_tap(page: Page, email: str) -> bool:
    """检测并点击主页右上角的 Google One Tap "Continue as <X>" 按钮。
    成功返回 True（无需后续 OAuth 弹窗）；找不到返回 False。
    One Tap 内容在 iframe 中（src 含 accounts.google.com/gsi）；
    Chrome 翻译会改文本内容，所以用 iframe 选择器锁范围，再点其中的主操作按钮。
    """
    try:
        iframe_loc = page.locator('iframe[src*="accounts.google.com/gsi"]')
        cnt = await iframe_loc.count()
        if cnt == 0:
            return False
        for i in range(cnt):
            frame = page.frame_locator('iframe[src*="accounts.google.com/gsi"]').nth(i)
            # 优先匹配带 email/Continue as 的主操作按钮（多语言）
            target = frame.locator(
                f'div[role="button"]:has-text("{email}"), '
                'div[role="button"]:has-text("Continue as"), '
                'div[role="button"]:has-text("Tiếp tục với"), '
                'div[role="button"]:has-text("身份继续"), '
                'div[role="button"]:has-text("的身份继续"), '
                'button:has-text("Continue as"), '
                'button:has-text("身份继续")'
            )
            if await target.count() == 0:
                # 兜底：iframe 内任何 role=button（One Tap 主操作通常是最大那一个）
                target = frame.locator('div[role="button"]')
            if await target.count() > 0:
                try:
                    await target.first.click(timeout=3000)
                    logger.info(f"One Tap: 点击 'Continue as' 成功 (iframe[{i}])")
                    await page.screenshot(path=screenshot_path("claude_one_tap_click", email))
                    return True
                except Exception as e:
                    logger.debug(f"One Tap 点击失败 iframe[{i}]: {e}")
    except Exception as e:
        logger.debug(f"One Tap 检测异常: {e}")
    return False


def _claude_name_from_email(email: str) -> str:
    """从 email 派生用户名：去尾部数字/分隔符 + 首字母大写。
    'drillingconcretehehe0487@gmail.com' → 'Drillingconcretehehe'
    '123@gmail.com' → 'User'（无字母兜底）
    """
    local = email.split("@")[0] if "@" in email else email
    stripped = re.sub(r"[\d_\-.]+$", "", local)
    if not stripped or not any(c.isalpha() for c in stripped):
        return "User"
    return stripped[:30].capitalize()


async def _claude_terms_is_checked(page: Page) -> bool:
    """检查 terms checkbox 是否已勾上（aria-checked / is_checked / 错误提示消失任一为真）。"""
    try:
        cb = page.get_by_role("checkbox").first
        if await cb.count() > 0:
            aria = await cb.get_attribute("aria-checked")
            if aria == "true":
                return True
            try:
                if await cb.is_checked():
                    return True
            except Exception:
                pass
    except Exception:
        pass
    # 兜底：错误提示已消失说明同意了
    try:
        err = page.locator('text="Agree to the terms to continue"')
        return await err.count() == 0
    except Exception:
        return False


async def _claude_check_terms_checkbox(page: Page) -> bool:
    """多策略勾选 'Let's create your account' 页的第一个 checkbox（terms）。
    返回是否成功。
    """
    # 已勾上直接返回
    if await _claude_terms_is_checked(page):
        return True

    strategies = [
        # 1. ARIA role-based 精确匹配 terms 文本
        lambda: page.get_by_role("checkbox", name=re.compile(r"agree.*Anthropic|Consumer Terms|18 years", re.I)),
        # 2. 任意 role=checkbox 取第一个（顺序：terms 在前）
        lambda: page.get_by_role("checkbox").first,
        # 3. 点击包含 "I agree" 文本的 label（label 点击会触发关联 input toggle）
        lambda: page.locator('label').filter(has_text=re.compile(r"I agree|Consumer Terms", re.I)).first,
        # 4. 原生 input
        lambda: page.locator('input[type="checkbox"]').first,
    ]

    for idx, get_target in enumerate(strategies):
        try:
            target = get_target()
            if await target.count() == 0:
                continue
            try:
                await target.click(force=True, timeout=3000)
            except Exception as e:
                logger.debug(f"terms 策略 {idx} click 失败: {e}")
                continue
            await page.wait_for_timeout(400)
            if await _claude_terms_is_checked(page):
                logger.info(f"terms checkbox 已勾选（策略 {idx}）")
                return True
        except Exception as e:
            logger.debug(f"terms 策略 {idx} 异常: {e}")

    # 最后兜底：JavaScript 直接触发 click 事件
    try:
        await page.evaluate(
            """() => {
                const cb = document.querySelector('[role="checkbox"]')
                       || document.querySelector('input[type="checkbox"]');
                if (cb) cb.click();
            }"""
        )
        await page.wait_for_timeout(400)
        if await _claude_terms_is_checked(page):
            logger.info("terms checkbox 已勾选（JS evaluate）")
            return True
    except Exception as e:
        logger.debug(f"JS evaluate 勾选失败: {e}")

    return False


async def _claude_advance_onboarding(page: Page, email: str) -> str:
    """识别并推进 claude.ai 的注册/onboarding 页面。
    成功点击一步时返回步骤名（用于日志），未识别返回 ""。
    页面包括：
      - "Let's create your account"：勾选同意 + Create account
      - "Plans that grow with you"：Use Claude for free
      - "Get the most out of Claude on your desktop"：Skip
      - "What kind of work do you do?"：I have my own topic
      - "What are you interested in?"：随机选一个兴趣 + Continue
    """
    # 1. 条款同意页：勾第一个 checkbox（terms，必选） + Create account
    #    第二个 checkbox 是 promo 订阅（可选），跳过
    create_btn = page.locator('button:has-text("Create account")')
    try:
        if await create_btn.count() > 0 and await create_btn.first.is_visible():
            checked = await _claude_check_terms_checkbox(page)
            if not checked:
                logger.warning("terms checkbox 全部策略失败，仍尝试点 Create account")
            await page.screenshot(path=screenshot_path("claude_onboard_terms", email))
            await create_btn.first.click()
            await human_delay(page, "click")
            return "terms" if checked else "terms_unchecked"
    except Exception as e:
        logger.debug(f"onboarding terms 失败: {e}")

    # 2. 价格页：选 Free 方案
    free_btn = page.locator('button:has-text("Use Claude for free")')
    try:
        if await free_btn.count() > 0 and await free_btn.first.is_visible():
            await page.screenshot(path=screenshot_path("claude_onboard_plan_free", email))
            await free_btn.first.click()
            await human_delay(page, "click")
            return "plan_free"
    except Exception as e:
        logger.debug(f"onboarding plan_free 失败: {e}")

    # 3. 角色页（旧版）：跳过（点 "I have my own topic"）
    own_topic_btn = page.locator('button:has-text("I have my own topic")')
    try:
        if await own_topic_btn.count() > 0 and await own_topic_btn.first.is_visible():
            await page.screenshot(path=screenshot_path("claude_onboard_role_skip", email))
            await own_topic_btn.first.click()
            await human_delay(page, "click")
            return "role_skip"
    except Exception as e:
        logger.debug(f"onboarding role_skip 失败: {e}")

    # 3b. 角色页（新版）："What kind of work do you do?" 下拉选角色 + Continue
    #     下拉未选时 Continue 是 disabled，需要先打开下拉选一个选项。
    #     页面特征：标题含 "What kind of work"，下拉文本含 "Search for your role"。
    role_heading = page.locator('text="What kind of work do you do?"')
    try:
        if await role_heading.count() > 0 and await role_heading.first.is_visible():
            # 多策略展开下拉
            dropdown_opened = False
            strategies = [
                ("role=combobox", lambda: page.get_by_role("combobox").first),
                ("role=button near role text", lambda: page.locator('button:has-text("Search for your role")')),
                ("aria-haspopup", lambda: page.locator('[aria-haspopup="listbox"], [aria-haspopup="true"]')),
                ("input placeholder", lambda: page.locator('input[placeholder*="role" i]')),
            ]
            for name, get_loc in strategies:
                try:
                    loc = get_loc()
                    if await loc.count() > 0 and await loc.first.is_visible():
                        await loc.first.click(timeout=3000)
                        await page.wait_for_timeout(800)
                        # 判断下拉是否展开（出现 option 或 listbox）
                        has_opts = await page.locator('[role="option"], [role="listbox"]').count()
                        if has_opts > 0:
                            dropdown_opened = True
                            logger.info(f"角色下拉：策略 '{name}' 展开成功")
                            break
                        logger.debug(f"角色下拉：策略 '{name}' 点击后未出现选项，继续")
                except Exception as e:
                    logger.debug(f"角色下拉：策略 '{name}' 失败: {e}")

            # 兜底：用 Tab 键聚焦到下拉框再按 Space/Enter 展开
            if not dropdown_opened:
                logger.info("角色下拉：尝试键盘 Tab + Space 展开")
                for _ in range(5):
                    await page.keyboard.press("Tab")
                    await page.wait_for_timeout(300)
                await page.keyboard.press("Space")
                await page.wait_for_timeout(800)
                if await page.locator('[role="option"], [role="listbox"]').count() > 0:
                    dropdown_opened = True
                    logger.info("角色下拉：键盘展开成功")

            # 最终兜底：键盘按 Enter
            if not dropdown_opened:
                await page.keyboard.press("Enter")
                await page.wait_for_timeout(800)
                if await page.locator('[role="option"], [role="listbox"]').count() > 0:
                    dropdown_opened = True

            await page.screenshot(path=screenshot_path("claude_onboard_role_dropdown", email))

            # 选择下拉中出现的第一个选项
            if dropdown_opened:
                option = page.locator('[role="option"]')
                if await option.count() == 0:
                    option = page.locator('text="Engineering"')
                if await option.count() == 0:
                    option = page.locator('text="Product management"')
                if await option.count() > 0:
                    await option.first.click()
                    await page.wait_for_timeout(500)
                    logger.info("角色下拉：已选择选项")
                else:
                    # 键盘选择：按 ArrowDown 选中第一项再 Enter
                    await page.keyboard.press("ArrowDown")
                    await page.wait_for_timeout(300)
                    await page.keyboard.press("Enter")
                    logger.info("角色下拉：键盘选择第一项")

            await page.screenshot(path=screenshot_path("claude_onboard_role_select", email))
            cont_btn = page.locator('button:has-text("Continue")')
            if await cont_btn.count() > 0:
                # 等 Continue 按钮变为 enabled
                for _ in range(10):
                    if await cont_btn.first.is_enabled():
                        break
                    await page.wait_for_timeout(500)
                await cont_btn.first.click()
                await human_delay(page, "click")
            return "role_select"
    except Exception as e:
        logger.debug(f"onboarding role_select 失败: {e}")

    # 4. /onboarding "What's your name?" 页：填名字 + Continue
    name_input = page.locator(
        'input[placeholder*="your name" i], '
        'input[placeholder*="Enter your name" i]'
    ).first
    try:
        if await name_input.count() > 0 and await name_input.is_visible():
            derived = _claude_name_from_email(email)
            await name_input.fill(derived)
            await page.wait_for_timeout(300)
            await page.screenshot(path=screenshot_path("claude_onboard_name", email))
            cont_btn = page.locator('button:has-text("Continue")')
            if await cont_btn.count() > 0 and await cont_btn.first.is_visible():
                await cont_btn.first.click()
                await human_delay(page, "click")
            return f"onboarding_name:{derived}"
    except Exception as e:
        logger.debug(f"onboarding name 失败: {e}")

    # 4b. "What are you interested in?" 兴趣页：随机选一个兴趣 + Continue
    #     Continue 在未选任何兴趣前是 disabled，必须先点一个兴趣按钮。
    interest_heading = page.locator('text="What are you interested in?"')
    try:
        if await interest_heading.count() > 0 and await interest_heading.first.is_visible():
            interests = [
                "Coding & developing", "Learning & studying", "Writing & content creation",
                "Business & strategy", "Design & creativity", "Career chat",
            ]
            # 只在页面上实际存在的兴趣里随机选，避免文案变动时点空
            available = []
            for label in interests:
                btn = page.locator(f'button:has-text("{label}")')
                if await btn.count() > 0 and await btn.first.is_visible():
                    available.append(label)
            chosen = random.choice(available) if available else None
            if chosen:
                await page.locator(f'button:has-text("{chosen}")').first.click()
                await page.wait_for_timeout(400)
                logger.info(f"兴趣页：随机选择 '{chosen}'")
            else:
                logger.warning("兴趣页：未找到可点的兴趣按钮，仍尝试 Continue")
            await page.screenshot(path=screenshot_path("claude_onboard_interest", email))
            cont_btn = page.locator('button:has-text("Continue")')
            if await cont_btn.count() > 0:
                # 等 Continue 变 enabled（选中兴趣后才可点）
                for _ in range(10):
                    if await cont_btn.first.is_enabled():
                        break
                    await page.wait_for_timeout(500)
                await cont_btn.first.click()
                await human_delay(page, "click")
            return f"onboarding_interest:{chosen or 'none'}"
    except Exception as e:
        logger.debug(f"onboarding interest 失败: {e}")

    # 5. /onboarding "Before your first chat" 页：只点 Continue
    #    (Help Claude improve 开关保持默认开启 — 改成关需要在这里点 toggle)
    if "/onboarding" in page.url:
        continue_btn = page.locator('button:has-text("Continue")')
        try:
            if await continue_btn.count() > 0 and await continue_btn.first.is_visible():
                await page.screenshot(path=screenshot_path("claude_onboard_continue", email))
                await continue_btn.first.click()
                await human_delay(page, "click")
                return "onboarding_continue"
        except Exception as e:
            logger.debug(f"onboarding continue 失败: {e}")

    # 6. 桌面 App / 其他可 Skip 的引导页
    skip_btn = page.locator('button:has-text("Skip"), button:has-text("跳过")')
    try:
        if await skip_btn.count() > 0 and await skip_btn.first.is_visible():
            await page.screenshot(path=screenshot_path("claude_onboard_skip", email))
            await skip_btn.first.click()
            await human_delay(page, "click")
            return "skip"
    except Exception as e:
        logger.debug(f"onboarding skip 失败: {e}")

    return ""


async def register_claude(context: BrowserContext, email: str, password: str, totp_secret: str):
    """先登录 Google，再打开 claude.ai，等待自动登录并获取 sessionKey"""

    # 步骤1: 先登录 Google
    page = await google_login(context, email, password, totp_secret)
    return await claude_login_after_google(context, page, email, password, totp_secret)


async def claude_login_after_google(
    context: BrowserContext, page: Page, email: str, password: str, totp_secret: str
):
    """在已登录 Google 的 page 上打开 claude.ai，自动推进注册并获取 sessionKey。

    与 register_claude 的区别：不重复登录 Google，复用调用方传入的已登录 page。
    """

    # 步骤2: 打开 claude.ai
    logger.info("正在打开 claude.ai...")
    await page.goto("https://claude.ai", wait_until="domcontentloaded")
    await human_delay(page, "navigate")

    await page.screenshot(path=screenshot_path("claude_step_1_landing", email))
    logger.info(f"claude.ai 落地页 URL: {page.url}")

    # 步骤3a: 优先 Google One Tap（右上角 "Continue as X"）- 路径短，避开多语言弹窗
    await page.wait_for_timeout(3000)  # 给 One Tap iframe 加载时间
    one_tap_clicked = await _claude_try_one_tap(page, email)
    if one_tap_clicked:
        logger.info("One Tap 路径生效，跳过 OAuth 弹窗，直接进步骤4")
        await human_delay(page, "navigate")

    # 步骤3b: 没有 One Tap 时走 "Continue with Google" + OAuth 弹窗
    current_url = page.url
    if not one_tap_clicked and ("login" in current_url or "oauth" in current_url or "claude.ai" == current_url.rstrip("/")):
        logger.info("查找 Google 登录按钮...")
        google_btn = page.locator('button:has-text("Continue with Google")')
        if await google_btn.count() == 0:
            google_btn = page.locator('a:has-text("Continue with Google")')

        if await google_btn.count() > 0:
            # 已登录 Google，点击后应自动跳过密码步骤
            async with context.expect_page(timeout=15000) as popup_info:
                await google_btn.first.click()
                logger.info("已点击 Google 登录按钮，等待 OAuth 弹窗...")

            popup = await popup_info.value
            await popup.wait_for_load_state("domcontentloaded")
            await human_delay(popup, "load")
            logger.info(f"OAuth 弹窗 URL: {popup.url}")

            # Google 已登录，弹窗应该直接显示账号选择或授权页面
            await handle_oauth_popup(popup, context, email, password, totp_secret)

            # 等待主页面完成跳转
            logger.info("OAuth 完成，等待 Claude 页面加载...")
            await human_delay(page, "navigate")
            await human_delay(page, "load")

    # 步骤4: 等待页面稳定 + 自动推进注册引导
    manual_warned = False
    last_url = ""
    unrecognized_streak = 0
    for i in range(120):  # 最多等待 6 分钟
        await page.wait_for_timeout(3000)
        current_url = page.url
        if current_url != last_url:
            logger.info(f"等待登录完成... ({(i+1)*3}s) URL: {current_url}")
            last_url = current_url

        # 已进入对话页面
        if "claude.ai/new" in current_url or "claude.ai/chat" in current_url:
            logger.info("已进入 Claude 对话页面！")
            break

        # 主动推进注册引导（terms / plan / role / skip）
        try:
            action = await _claude_advance_onboarding(page, email)
        except Exception as e:
            logger.debug(f"onboarding 推进异常: {e}")
            action = ""
        if action:
            logger.info(f"自动通过注册引导: {action}")
            unrecognized_streak = 0
            continue

        # 兜底：其他位置可能弹出的条款 Accept/Agree
        terms_btn = page.locator('button:has-text("Accept"), button:has-text("Agree"), button:has-text("接受"), button:has-text("同意")')
        if await terms_btn.count() > 0 and await terms_btn.first.is_visible():
            logger.info("同意服务条款...")
            await terms_btn.first.click()
            await human_delay(page, "click")
            unrecognized_streak = 0
            continue

        # 仍停留在 signup/onboarding 但识别不出来 → 截图警告（每个账号只提示一次）
        if "signup" in current_url or "register" in current_url or "onboarding" in current_url:
            unrecognized_streak += 1
            if unrecognized_streak == 3 and not manual_warned:
                logger.warning(f"⚠️  检测到未识别的注册/验证页面 URL={current_url}，已截图，继续等待")
                await page.screenshot(path=screenshot_path("claude_needs_manual", email))
                manual_warned = True

    # 步骤5: 提取 sessionKey
    final_url = page.url
    logger.info(f"最终页面: {final_url}")
    await page.screenshot(path=screenshot_path("claude_step_3_final", email))

    cookies = await context.cookies("https://claude.ai")
    session_key = None
    for cookie in cookies:
        if cookie["name"] == "sessionKey":
            session_key = cookie["value"]
            break

    if session_key:
        logger.info(f"获取到 sessionKey: {session_key[:20]}...")
    else:
        logger.warning("未找到 sessionKey cookie")

    return session_key


def _decode_header_str(raw) -> str:
    """imaplib 返回值经常是 (bytes, charset) 元组，统一解码成 str"""
    if raw is None:
        return ""
    if isinstance(raw, bytes):
        try:
            return raw.decode("utf-8", errors="replace")
        except Exception:
            return raw.decode("latin-1", errors="replace")
    if isinstance(raw, str):
        decoded = decode_header(raw)
        parts = []
        for text, enc in decoded:
            if isinstance(text, bytes):
                parts.append(text.decode(enc or "utf-8", errors="replace"))
            else:
                parts.append(text)
        return "".join(parts)
    return str(raw)


def _extract_email_body(msg) -> str:
    """从 email.message.Message 里提取正文（优先 text/html，其次 text/plain）"""
    if msg.is_multipart():
        html = ""
        text = ""
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype not in ("text/plain", "text/html"):
                continue
            try:
                payload = part.get_payload(decode=True) or b""
                charset = part.get_content_charset() or "utf-8"
                body = payload.decode(charset, errors="replace")
            except Exception:
                continue
            if ctype == "text/html" and not html:
                html = body
            elif ctype == "text/plain" and not text:
                text = body
        return html or text
    payload = msg.get_payload(decode=True) or b""
    charset = msg.get_content_charset() or "utf-8"
    try:
        return payload.decode(charset, errors="replace")
    except Exception:
        return payload.decode("utf-8", errors="replace")


def fetch_anthropic_magic_link(host: str, port: int, user: str, password: str,
                                timeout_s: int = 180, poll_interval_s: int = 6) -> str:
    """轮询 IMAP 收件箱，从最新的 Anthropic 邮件里提取登录 magic link。
    返回完整 URL；超时返回空串。
    """
    url_pattern = re.compile(
        r"https://(?:[a-zA-Z0-9_-]+\.)?(?:anthropic\.com|claude\.com|claude\.ai)/[^\s\"'<>]+",
        re.IGNORECASE,
    )
    static_suffix = re.compile(r"\.(png|jpe?g|gif|svg|webp|ico|css|js)(\?|$)", re.IGNORECASE)
    tracker_host = re.compile(r"^https://[^/]*mail\.anthropic\.com/", re.IGNORECASE)
    preferred_kw = re.compile(
        r"(partner-onboarding|sign[-_]?in|magic|verify|auth|login|token|invite|onboard)",
        re.IGNORECASE,
    )
    logger.info(f"开始通过 IMAP {host}:{port} 抓取 Anthropic 邮件（{user}）...")
    end = time.time() + timeout_s

    while time.time() < end:
        try:
            with imaplib.IMAP4_SSL(host, port, timeout=30) as imap:
                imap.login(user, password)
                imap.select("INBOX")
                # 搜索来自 Anthropic 域的邮件；找不到再退回全量取最新
                typ, data = imap.search(None, '(FROM "anthropic")')
                ids = data[0].split() if data and data[0] else []
                if not ids:
                    typ, data = imap.search(None, "ALL")
                    ids = data[0].split() if data and data[0] else []
                # 倒序遍历最近若干封
                for mid in reversed(ids[-10:]):
                    typ, msg_data = imap.fetch(mid, "(RFC822)")
                    if typ != "OK" or not msg_data or not msg_data[0]:
                        continue
                    raw = msg_data[0][1]
                    msg = email_pkg.message_from_bytes(raw)
                    subject = _decode_header_str(msg.get("Subject", ""))
                    from_addr = _decode_header_str(msg.get("From", ""))
                    body = _extract_email_body(msg)
                    matches = url_pattern.findall(body)
                    if not matches:
                        continue
                    # 过滤掉静态资源 + 邮件跟踪域
                    candidates = [
                        u for u in matches
                        if not static_suffix.search(u) and not tracker_host.match(u)
                    ]
                    if not candidates:
                        continue
                    # 优先关键字命中
                    preferred = [u for u in candidates if preferred_kw.search(u)]
                    link = preferred[0] if preferred else candidates[0]
                    logger.info(f"命中邮件: subject={subject[:60]!r} from={from_addr[:50]!r}")
                    logger.info(f"提取到 magic link: {link[:120]}...")
                    return link
        except Exception as e:
            logger.debug(f"IMAP 轮询异常: {e}")
        time.sleep(poll_interval_s)

    logger.warning("IMAP 轮询超时，未抓到 Anthropic 邮件")
    return ""


async def _claude_console_fill_owner_email(page: Page, owner_email: str, label: str) -> bool:
    """在 console.anthropic.com 的 "Build on the Claude Platform" 页面填入 owner 邮箱并点 Get started"""
    try:
        await page.wait_for_load_state("networkidle", timeout=15000)
    except Exception:
        pass

    email_input = page.locator('input[type="email"], input[placeholder*="@"], input[name="email"]')
    try:
        await email_input.first.wait_for(state="visible", timeout=15000)
    except Exception:
        logger.warning("Claude Console 邮箱输入框未出现，跳过")
        return False

    logger.info(f"在 Claude Console 填入 owner 邮箱: {owner_email}")
    await email_input.first.fill(owner_email)
    await human_delay(page, "type")

    get_started_btn = page.locator(
        'button:has-text("Get started"), button:has-text("Get Started"), button:has-text("开始使用")'
    )
    if await get_started_btn.count() == 0:
        # 按 Enter 兜底
        await page.keyboard.press("Enter")
    else:
        await get_started_btn.first.click()
    await human_delay(page, "navigate")
    await page.screenshot(path=screenshot_path("claude_console_get_started", label))
    return True


async def claude_console_via_magic_link(page: Page, label: str) -> str:
    """登入 console.anthropic.com 全流程：填邮箱 → Get started → IMAP 抓 magic link → 浏览器打开"""
    if not CLAUDE_CONSOLE_EMAIL or not CLAUDE_CONSOLE_IMAP_HOST:
        logger.info("未配置 CLAUDE_CONSOLE_* 凭据，跳过 Claude Console magic-link 流程")
        return ""

    filled = await _claude_console_fill_owner_email(page, CLAUDE_CONSOLE_EMAIL, label)
    if not filled:
        return ""

    # 异步线程跑 IMAP 阻塞调用
    link = await asyncio.to_thread(
        fetch_anthropic_magic_link,
        CLAUDE_CONSOLE_IMAP_HOST,
        CLAUDE_CONSOLE_IMAP_PORT,
        CLAUDE_CONSOLE_IMAP_USER,
        CLAUDE_CONSOLE_IMAP_PASS,
    )
    if not link:
        logger.warning("未抓到 magic link，可能邮件未到或解析失败")
        await page.screenshot(path=screenshot_path("claude_console_no_link", label))
        return ""

    logger.info("打开 magic link 完成登录...")
    await page.goto(link, wait_until="domcontentloaded")
    await human_delay(page, "navigate")
    await human_delay(page, "load")
    await page.screenshot(path=screenshot_path("claude_console_after_magic", label))
    logger.info(f"Claude Console 登录后页面: {page.url}")

    try:
        await _claude_console_fill_org_details(page, label)
    except Exception as e:
        logger.warning(f"organization details 表单处理失败: {e}")
        await page.screenshot(path=screenshot_path("claude_console_org_form_error", label))

    return page.url


async def _click_first_visible(loc, timeout_ms: int = 5000) -> bool:
    """从 locator 集合里找第一个可见+可点击的元素并点击"""
    try:
        n = await loc.count()
    except Exception:
        return False
    for i in range(n):
        cand = loc.nth(i)
        try:
            if await cand.is_visible():
                await cand.scroll_into_view_if_needed()
                await cand.click(timeout=timeout_ms)
                return True
        except Exception:
            continue
    return False


async def _claude_select_combobox(page: Page, label_substr: str, option_text: str) -> bool:
    """点开 label_substr 对应的下拉；若是带搜索框的（如 country picker）先 fill，再点 option_text"""
    label = page.get_by_text(label_substr, exact=False).first
    try:
        await label.wait_for(state="visible", timeout=5000)
    except Exception:
        logger.warning(f"找不到 label: {label_substr!r}")
        return False

    # 触发器：先找 label 同级容器内的 button/combobox；再退到 following 轴
    container = label.locator('xpath=ancestor::*[self::div or self::section][1]')
    trigger_candidates = [
        container.get_by_role("combobox"),
        container.locator('button:has-text("Select")'),
        container.locator('[role="combobox"]'),
        container.locator('button').last,
        label.locator('xpath=following::*[@role="combobox"][1]'),
        label.locator('xpath=following::button[1]'),
    ]
    opened = False
    for cand in trigger_candidates:
        if await _click_first_visible(cand):
            opened = True
            break
    if not opened:
        logger.warning(f"无法打开下拉: {label_substr!r}")
        return False

    await page.wait_for_timeout(600)

    # 国家这类下拉是搜索式的，长列表不输入不渲染。检测搜索框存在则先 fill
    search_input = page.locator(
        'input[placeholder*="Search"], input[placeholder*="search"], '
        'input[type="search"], input[role="searchbox"], input[role="combobox"]'
    )
    n_search = await search_input.count()
    for i in range(n_search):
        cand = search_input.nth(i)
        try:
            if await cand.is_visible():
                await cand.fill(option_text)
                await page.wait_for_timeout(500)
                break
        except Exception:
            continue

    # 选项：role / exact text 多策略
    option_candidates = [
        page.get_by_role("option", name=option_text, exact=True),
        page.get_by_role("radio", name=option_text, exact=True),
        page.get_by_role("menuitem", name=option_text, exact=True),
        page.get_by_text(option_text, exact=True),
        page.locator(f'li:has-text("{option_text}")'),
        page.locator(f'div[role="menuitem"]:has-text("{option_text}")'),
    ]
    for cand in option_candidates:
        if await _click_first_visible(cand):
            await page.wait_for_timeout(400)
            return True

    logger.warning(f"找不到选项 {option_text!r} for {label_substr!r}")
    try:
        await page.keyboard.press("Escape")
    except Exception:
        pass
    return False


async def _claude_click_yes_no(page: Page, question_substr: str, value: str,
                                wait_appear_s: int = 10) -> bool:
    """在含问题文本的行里点 Yes / No。

    这些问题中有些是"条件渲染"的（比如选完 country 后才会出现 'outside of this location'），
    所以加 wait_appear_s 秒轮询等待。
    """
    end = time.time() + wait_appear_s
    while time.time() < end:
        question = page.get_by_text(question_substr, exact=False).first
        if await question.count() > 0 and await question.is_visible():
            break
        await page.wait_for_timeout(500)
    else:
        logger.warning(f"问题未渲染: {question_substr!r}")
        return False

    # 策略 1: 含 <button>Yes</button>/<button>No</button> 的最近祖先
    for axis in [
        'xpath=ancestor::*[descendant::button[normalize-space()="Yes"] and descendant::button[normalize-space()="No"]][1]',
        'xpath=ancestor::*[descendant::*[@role="button" and normalize-space()="Yes"] and descendant::*[@role="button" and normalize-space()="No"]][1]',
        'xpath=ancestor::*[descendant::*[@role="radio" and normalize-space()="Yes"] and descendant::*[@role="radio" and normalize-space()="No"]][1]',
        'xpath=ancestor::*[descendant::*[normalize-space()="Yes"] and descendant::*[normalize-space()="No"]][1]',
    ]:
        ancestor = question.locator(axis)
        if await ancestor.count() == 0:
            continue
        # 在祖先内找 value 元素
        target_candidates = [
            ancestor.locator(f'xpath=.//button[normalize-space()="{value}"]'),
            ancestor.locator(f'xpath=.//*[@role="button" and normalize-space()="{value}"]'),
            ancestor.locator(f'xpath=.//*[@role="radio" and normalize-space()="{value}"]'),
            ancestor.locator(f'xpath=.//*[normalize-space()="{value}"]'),
        ]
        for cand in target_candidates:
            if await _click_first_visible(cand):
                await page.wait_for_timeout(300)
                return True
    logger.warning(f"找不到 Yes/No 容器或按钮: {question_substr!r} / {value!r}")
    return False


async def _claude_console_fill_org_details(page: Page, label: str) -> bool:
    """填写 "Let's get your organization details" 表单 → Complete setup"""
    try:
        await page.wait_for_selector(
            'h1:has-text("organization details"), h2:has-text("organization details"), :text("Let\'s get your organization details")',
            timeout=30000,
        )
    except Exception:
        logger.info('未检测到 "organization details" 表单，可能已配置过，跳过')
        return False

    logger.info('开始填写 "organization details" 表单...')
    await page.screenshot(path=screenshot_path("claude_console_org_form", label))

    # 1) Entity type
    await _claude_select_combobox(page, "What type of entity", "Small or medium business")
    # 2) Country
    await _claude_select_combobox(page, "Where is your organization", "United States")
    # 3) 是否在该地区以外使用 → No
    await _claude_click_yes_no(page, "outside of this location", "No")
    # 4) Building for → Internal
    await _claude_select_combobox(page, "internal customers, external customers", "Internal")
    # 5) 用途文本框 → Coding
    use_case = page.locator('textarea').first
    if await use_case.count() == 0:
        use_case = page.locator('input[placeholder*="Document summarization"], textarea[placeholder*="Document summarization"]').first
    if await use_case.count() > 0:
        await use_case.fill("Coding")
        await human_delay(page, "type")
    # 6) legal/medical/financial advice → No
    await _claude_click_yes_no(page, "legal, medical", "No")
    # 7) under age 18 → No
    await _claude_click_yes_no(page, "under age 18", "No")

    await page.screenshot(path=screenshot_path("claude_console_org_form_filled", label))

    # Complete setup
    complete_btn = page.locator('button:has-text("Complete setup")')
    await complete_btn.first.wait_for(state="visible", timeout=10000)
    await complete_btn.first.click()
    await human_delay(page, "navigate")
    try:
        await page.wait_for_load_state("networkidle", timeout=30000)
    except Exception:
        pass
    await page.screenshot(path=screenshot_path("claude_console_setup_done", label))
    logger.info(f"完成 organization 设置，当前 URL: {page.url}")
    return True


async def check_kyc_status(context: BrowserContext, org_id: str) -> str:
    """请求 claude.ai KYC 接口，返回 status 字段（失败返回空字符串）"""
    url = f"https://claude.ai/api/organizations/{org_id}/kyc_status"
    try:
        resp = await context.request.get(url)
    except Exception as e:
        logger.warning(f"KYC 请求异常: {e}")
        return ""

    if not resp.ok:
        logger.warning(f"KYC 请求失败: HTTP {resp.status}")
        return ""

    try:
        data = await resp.json()
    except Exception as e:
        logger.warning(f"KYC 响应解析失败: {e}")
        return ""

    return data.get("status", "") if isinstance(data, dict) else ""


async def login_claude_by_session(context: BrowserContext, session_key: str) -> str:
    """通过 sessionKey cookie 登录 Claude"""
    logger.info("正在通过 sessionKey 登录 claude.ai...")

    # 设置 sessionKey cookie
    await context.add_cookies([{
        "name": "sessionKey",
        "value": session_key,
        "domain": ".claude.ai",
        "path": "/",
        "httpOnly": True,
        "secure": True,
        "sameSite": "Lax",
    }])

    return await _claude_check_login_status(context)


async def login_claude_by_cookies(context: BrowserContext, cookies: list) -> str:
    """通过整份浏览器 cookie 导出（.crash/.json）登录 Claude：先注入全部 cookie 再检查登录状态。"""
    logger.info(f"正在通过 cookie 文件登录 claude.ai（注入 {len(cookies)} 条 cookie）...")
    if cookies:
        await context.add_cookies(cookies)
    return await _claude_check_login_status(context)


async def _claude_check_login_status(context: BrowserContext) -> str:
    """cookie 注入完成后，打开 claude.ai 判断登录状态，返回中文结果（可用/不可用/待定）。"""
    page = await context.new_page()

    # 监听网络请求，从 /api/organizations/{uuid}/sync/gcal/auth 中提取 organization id
    org_id_holder = {"id": None}
    gcal_pattern = re.compile(r"/api/organizations/([0-9a-f-]{36})/sync/gcal/auth")
    fallback_pattern = re.compile(r"/api/organizations/([0-9a-f-]{36})(?:/|$|\?)")

    def on_request(req):
        if org_id_holder["id"]:
            return
        m = gcal_pattern.search(req.url)
        if m:
            org_id_holder["id"] = m.group(1)
            logger.info(f"从 gcal/auth 捕获 organization id: {org_id_holder['id']}")
            return
        # 兜底：匹配任意 /api/organizations/{uuid}/* 请求，避免 gcal/auth 未触发
        if "/kyc_status" in req.url:
            return
        m = fallback_pattern.search(req.url)
        if m:
            org_id_holder["id"] = m.group(1)
            logger.info(f"兜底捕获 organization id: {org_id_holder['id']}")

    page.on("request", on_request)

    # 访问主页
    logger.info("访问 claude.ai 主页...")
    try:
        await page.goto("https://claude.ai", wait_until="domcontentloaded", timeout=15000)
    except Exception:
        pass

    # 等待页面重定向完成
    await page.wait_for_timeout(5000)

    current_url = page.url
    logger.info(f"当前页面: {current_url}")

    # 登录成功：重定向到 /new
    if "claude.ai/new" in current_url:
        logger.info("Claude sessionKey 登录成功！")

        # 再等一会，确保前端完成 organization 相关请求
        for _ in range(10):
            if org_id_holder["id"]:
                break
            await page.wait_for_timeout(500)

        org_id = org_id_holder["id"]
        if not org_id:
            logger.warning("未捕获到 organization id，跳过 KYC 检查")
            return "可用"

        kyc = await check_kyc_status(context, org_id)
        logger.info(f"KYC status: {kyc or '未知'}")
        if kyc == "not_required":
            logger.info("不需要身份校验")
            return "可用-不需要身份校验"
        if kyc:
            return f"可用-KYC:{kyc}"
        return "可用"

    # 被重定向到登录页 — sessionKey 失效
    if "login" in current_url or "oauth" in current_url:
        logger.warning("sessionKey 已失效，需要重新登录")
        return "不可用"

    # challenge 未通过
    if "challenge" in current_url:
        logger.warning(f"Cloudflare challenge 未通过，URL: {current_url}")
        return "待定"

    logger.warning(f"登录状态不确定，当前 URL: {current_url}")
    return "待定"


async def batch_check_sessions(browser, lines: list[str]) -> list[dict]:
    """批量检查 sessionKey 是否可用，每个账号用独立 context"""
    results = []
    total = len(lines)

    for idx, line in enumerate(lines, 1):
        line = line.strip()
        if not line:
            continue

        try:
            email, password, session_key = parse_session_input(line)
        except ValueError as e:
            logger.warning(f"[{idx}/{total}] 解析失败: {e}")
            results.append({"email": line[:30], "status": "解析失败"})
            continue

        logger.info(f"[{idx}/{total}] 检查账号: {email}")

        context = await browser.new_context()

        try:
            status = await login_claude_by_session(context, session_key)
            results.append({"email": email, "password": password, "session_key": session_key, "status": status})
            logger.info(f"[{idx}/{total}] {email}: {status}")
        except Exception as e:
            results.append({"email": email, "password": password, "session_key": session_key, "status": f"异常: {e}"})
            logger.warning(f"[{idx}/{total}] {email}: 异常 - {e}")
        finally:
            await context.close()

    return results


async def batch_check_cookie_jars(browser, jars: list[tuple]) -> list[dict]:
    """批量检查 cookie 导出文件（.crash/.json）能否登录，每个文件用独立 context。
    jars: [(label, session_key, cookies), ...]"""
    results = []
    total = len(jars)

    for idx, (label, session_key, cookies) in enumerate(jars, 1):
        logger.info(f"[{idx}/{total}] 检查 cookie 文件: {label}")
        context = await browser.new_context()
        try:
            status = await login_claude_by_cookies(context, cookies)
            results.append({"email": label, "password": "", "session_key": session_key, "status": status})
            logger.info(f"[{idx}/{total}] {label}: {status}")
        except Exception as e:
            results.append({"email": label, "password": "", "session_key": session_key, "status": f"异常: {e}"})
            logger.warning(f"[{idx}/{total}] {label}: 异常 - {e}")
        finally:
            await context.close()

    return results


def print_batch_results(results: list[dict]):
    """打印批量检查结果汇总"""
    print("\n" + "=" * 60)
    print("批量检查结果汇总")
    print("=" * 60)

    available = [r for r in results if str(r["status"]).startswith("可用")]
    pending = [r for r in results if r["status"] == "待定"]
    unavailable = [r for r in results if not str(r["status"]).startswith("可用") and r["status"] != "待定"]

    print(f"\n总计: {len(results)}  可用: {len(available)}  待定: {len(pending)}  不可用: {len(unavailable)}")

    if available:
        print(f"\n--- 可用账号 ({len(available)}) ---")
        for r in available:
            suffix = f"  ({r['status']})" if r["status"] != "可用" else ""
            print(f"  {r['email']}{suffix}")

    if pending:
        print(f"\n--- 待定账号 ({len(pending)}) ---")
        for r in pending:
            print(f"  {r['email']}  ({r['status']})")

    if unavailable:
        print(f"\n--- 不可用账号 ({len(unavailable)}) ---")
        for r in unavailable:
            print(f"  {r['email']}  ({r['status']})")

    # 将可用和待定账号写入文件
    to_save = available + pending
    if to_save:
        with open("available.txt", "w") as f:
            for r in to_save:
                if "session_key" in r:
                    f.write(f"{r['email']}----{r['password']}----{r['session_key']}\n")
        print(f"\n可用+待定账号已保存到 available.txt ({len(available)}可用, {len(pending)}待定)")

    print("=" * 60)


