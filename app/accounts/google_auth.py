"""Google 账号：登录、改密码、OAuth 弹窗处理（由 main.py 拆分而来）"""

import logging

from playwright.async_api import Page, BrowserContext

from app.settings import GOOGLE_NEW_PASSWORD
from app.core.browser import get_totp_code, human_click, human_delay, screenshot_path

logger = logging.getLogger(__name__)


async def google_login(context: BrowserContext, email: str, password: str, totp_secret: str) -> Page:
    """登录 Google 账号。

    若 context 复用了已保存的 storage_state（登录态仍有效），先探测 myaccount：
    已登录则直接返回，跳过邮箱/密码/2FA，避免在登录页空等邮箱框而超时。
    """
    page = await context.new_page()

    # 快速探测已有登录态（复用 storage_state 的场景）：直接开 myaccount，
    # 未登录会被重定向到 signin/ServiceLogin —— 那时判定失败，走正常登录。
    logger.info("检测已有 Google 登录态...")
    try:
        await page.goto("https://myaccount.google.com/", wait_until="domcontentloaded")
        await page.wait_for_load_state("networkidle")
        url = page.url
        if "myaccount.google.com" in url and "signin" not in url and "ServiceLogin" not in url:
            logger.info("已存在有效 Google 登录态，跳过登录步骤")
            return page
    except Exception as e:
        logger.debug(f"登录态探测异常（忽略，走正常登录）: {e}")

    logger.info("正在打开 Google 登录页面...")
    await page.goto("https://accounts.google.com/signin")
    await page.wait_for_load_state("networkidle")

    # 步骤1: 输入邮箱（逐字输入，模拟真人）
    logger.info("输入邮箱...")
    email_input = page.locator('input[type="email"], input#identifierId, input[name="identifier"]').first
    try:
        await email_input.wait_for(state="visible", timeout=15000)
    except Exception:
        logger.error(f"未在登录页找到邮箱输入框，当前 URL: {page.url}")
        await page.screenshot(path=screenshot_path("google_signin_no_email", email))
        raise
    await email_input.fill(email)
    await human_delay(page, "type")
    await human_click(page, "#identifierNext")
    await human_delay(page, "navigate")

    # 步骤2: 输入密码（逐字输入）
    logger.info("输入密码（传入密码）...")
    password_input = page.locator('input[type="password"]')
    await password_input.wait_for(state="visible", timeout=10000)
    await page.locator('input[type="password"]').fill(password)
    await human_delay(page, "type")
    await human_click(page, "#passwordNext")
    await human_delay(page, "navigate")

    # 检查密码是否错误，尝试修改后的密码
    error_msg = page.locator('span:has-text("Wrong password"), span:has-text("密码错误")')
    if await error_msg.count() > 0:
        logger.info("传入密码错误，尝试使用修改后的密码...")
        password_input = page.locator('input[type="password"]')
        await password_input.fill("")
        await page.locator('input[type="password"]').fill(GOOGLE_NEW_PASSWORD)
        await human_delay(page, "type")
        await human_click(page, "#passwordNext")
        await human_delay(page, "navigate")

    # 步骤3: 处理 2FA 验证
    logger.info("检测是否需要 2FA 验证...")
    await human_delay(page, "load")

    current_url = page.url
    if "challenge" in current_url or "signin/v2" in current_url:
        logger.info("需要 2FA 验证，正在获取验证码...")

        # 如果有多种验证方式，尝试选择 TOTP 方式
        try:
            totp_option = page.locator('div[data-challengeid="6"]')
            if await totp_option.count() > 0:
                await totp_option.click()
                await human_delay(page, "click")
        except Exception:
            pass

        # 本地按 RFC 6238 生成 TOTP 验证码（不依赖任何外部服务）
        totp_code = await get_totp_code(secret=totp_secret)

        # 输入验证码
        logger.info("输入 2FA 验证码...")
        otp_input = page.locator('input[type="tel"]')
        if await otp_input.count() == 0:
            otp_input = page.locator("#totpPin")
        if await otp_input.count() == 0:
            otp_input = page.locator('input[name="totpPin"]')

        await otp_input.wait_for(state="visible", timeout=10000)
        await otp_input.fill(totp_code)

        next_button = page.locator("#totpNext")
        if await next_button.count() > 0:
            await next_button.click()
        else:
            await page.keyboard.press("Enter")

        await human_delay(page, "navigate")

    current_url = page.url
    logger.info(f"当前页面: {current_url}")
    if "myaccount.google.com" in current_url or "google.com" in current_url:
        logger.info("Google 登录成功！")
    else:
        logger.warning(f"登录状态不确定，当前 URL: {current_url}")

    return page


async def change_password(context: BrowserContext, page: Page, current_password: str, new_password: str, totp_secret: str):
    """修改 Google 账号密码"""
    logger.info("正在导航到密码修改页面...")
    await page.goto("https://myaccount.google.com/signinoptions/password")
    await page.wait_for_load_state("networkidle")
    await human_delay(page, "navigate")

    # Google 可能要求再次验证身份
    current_url = page.url
    if "challenge" in current_url or "signin" in current_url:
        logger.info("需要重新验证身份...")

        # 检查是否要求 TOTP 验证码（Google Authenticator）
        totp_input = page.locator('input[type="tel"]')
        password_input = page.locator('input[type="password"]')

        if await totp_input.count() > 0 and await totp_input.is_visible():
            logger.info("需要输入 TOTP 验证码...")
            totp_code = await get_totp_code(secret=totp_secret)

            await totp_input.fill(totp_code)
            next_btn = page.locator('button:has-text("Next"), button:has-text("下一步")')
            if await next_btn.count() > 0:
                await next_btn.click()
            else:
                await page.keyboard.press("Enter")
            await human_delay(page, "navigate")

        elif await password_input.count() > 0 and await password_input.is_visible():
            logger.info("需要输入当前密码...")
            await password_input.fill(current_password)
            await human_delay(page, "type")
            await page.keyboard.press("Enter")
            await human_delay(page, "navigate")

    # 输入新密码
    logger.info("输入新密码...")
    new_password_input = page.locator('input[type="password"][name="password"]')
    if await new_password_input.count() == 0:
        new_password_input = page.locator('input[type="password"]').first

    await new_password_input.wait_for(state="visible", timeout=10000)
    await new_password_input.fill(new_password)

    # 输入确认密码
    confirm_input = page.locator('input[type="password"]').nth(1)
    if await confirm_input.count() > 0:
        await confirm_input.fill(new_password)

    await human_delay(page, "type")

    # 提交
    change_btn = page.locator('button:has-text("更改密码"), button:has-text("Change password")')
    if await change_btn.count() > 0:
        await change_btn.click()
    else:
        submit_btn = page.locator('button[type="submit"], div[role="button"]').last
        await submit_btn.click()

    await human_delay(page, "navigate")
    logger.info("密码修改请求已提交！")
    logger.info(f"当前页面: {page.url}")


async def handle_oauth_popup(popup: Page, context: BrowserContext, email: str, password: str, totp_secret: str):
    """处理 Google OAuth 弹窗的完整认证流程，循环检测每一步"""
    password_tried_new = False  # 是否已尝试过 GOOGLE_NEW_PASSWORD
    max_steps = 10
    for step in range(max_steps):
        if popup.is_closed():
            logger.info("OAuth 弹窗已关闭，认证完成")
            return

        try:
            await human_delay(popup, "load")
            await popup.screenshot(path=screenshot_path(f"oauth_step_{step}", email))
            current_url = popup.url
            logger.info(f"OAuth 步骤 {step}, URL: {current_url}")

            # 账号选择页面 — 按 URL 检测，语言无关
            # ("Choose an account" / "选择帐号" / "Chọn tài khoản" / 其他语言)
            is_chooser = "accountchooser" in current_url.lower()
            if is_chooser:
                # Gmail 忽略本地部分中的点 — 两个变体都试
                candidates = [email]
                norm = _gmail_normalize(email)
                if norm != email:
                    candidates.append(norm)
                logger.info(f"在账号选择页面，匹配 {candidates}...")
                clicked = False
                # 1) data-email / data-identifier 属性匹配
                for cand in candidates:
                    for sel in (f'[data-email="{cand}"]', f'[data-identifier="{cand}"]'):
                        loc = popup.locator(sel)
                        if await loc.count() > 0:
                            try:
                                await loc.first.click()
                                clicked = True
                                break
                            except Exception as e:
                                logger.debug(f"账号选择 {sel} 点击失败: {e}")
                    if clicked:
                        break
                # 2) email 文本匹配（语言无关）
                if not clicked:
                    for cand in candidates:
                        text_locator = popup.locator(
                            f'div[role="link"]:has-text("{cand}"), '
                            f'li:has-text("{cand}"), '
                            f'a:has-text("{cand}"), '
                            f'button:has-text("{cand}")'
                        )
                        if await text_locator.count() > 0:
                            try:
                                await text_locator.first.click()
                                clicked = True
                                break
                            except Exception as e:
                                logger.debug(f"按 email 文本点击失败 ({cand}): {e}")
                # 3) 直接点击 email 文本节点
                if not clicked:
                    for cand in candidates:
                        try:
                            await popup.get_by_text(cand, exact=False).first.click(timeout=3000)
                            clicked = True
                            break
                        except Exception as e:
                            logger.debug(f"get_by_text({cand}) 点击失败: {e}")
                # 4) 最后兜底：页面只列一个账号时，点第一个含 @ 的账号选项
                #    （避开 "Use another account" / "Sử dụng một tài khoản khác" 等）
                if not clicked:
                    any_account = popup.locator(
                        'li:has-text("@"), '
                        'div[role="link"]:has-text("@"), '
                        'a:has-text("@")'
                    )
                    try:
                        cnt = await any_account.count()
                        if cnt > 0:
                            await any_account.first.click()
                            logger.info(f"账号选择：精确匹配失败，点击第一个含 @ 的账号选项（共 {cnt} 个）")
                            clicked = True
                    except Exception as e:
                        logger.debug(f"兜底点击第一个账号失败: {e}")

                if clicked:
                    await human_delay(popup, "click")
                    continue
                logger.warning(f"账号选择页：找不到目标账号 {email}（已尝试 {candidates}）")

            if popup.is_closed():
                logger.info("OAuth 弹窗已关闭，认证完成")
                return

            # 授权同意 / 登录确认页 — 按 URL 检测（语言无关）
            # 包含 /signin/oauth/id (登录确认) 或 /signin/oauth/consent (授权同意) 或 /signin/oauth/legacy
            # 也兜底 text=will allow（英文页面提示）
            is_consent = (
                "/signin/oauth/id" in current_url
                or "/signin/oauth/consent" in current_url
                or "/signin/oauth/legacy" in current_url
                or await popup.locator('text=will allow').count() > 0
            )
            if is_consent:
                logger.info("在授权同意/登录确认页，滚动并点击主操作按钮...")
                await popup.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                await human_delay(popup, "click")
                # 多语言主操作按钮（避开 Cancel/取消/Huỷ 等）
                consent_btn = popup.locator(
                    'button:has-text("Continue"), '
                    'button:has-text("Allow"), '
                    'button:has-text("Next"), '
                    'button:has-text("继续"), '
                    'button:has-text("允许"), '
                    'button:has-text("下一步"), '
                    'button:has-text("Tiếp tục"), '
                    'button:has-text("Cho phép"), '
                    'button:has-text("Tiếp theo"), '
                    'button:has-text("Continuer"), '
                    'button:has-text("Autoriser"), '
                    'button:has-text("Continuar"), '
                    'button:has-text("Permitir"), '
                    'button:has-text("Weiter"), '
                    'button:has-text("Zulassen")'
                )
                if await consent_btn.count() > 0 and await consent_btn.first.is_visible():
                    await consent_btn.first.click()
                    await human_delay(popup, "click")
                    continue
                # 兜底：取所有按钮中最后一个（Google 习惯主操作在右/末尾）
                all_btns = popup.locator('button:visible')
                bcount = await all_btns.count()
                if bcount > 0:
                    try:
                        await all_btns.nth(bcount - 1).click()
                        logger.info(f"OAuth 确认页：未匹配文本，点击末尾按钮 (共 {bcount} 个)")
                        await human_delay(popup, "click")
                        continue
                    except Exception as e:
                        logger.debug(f"末尾按钮点击失败: {e}")

            # 密码输入
            password_input = popup.locator('input[type="password"]')
            if await password_input.count() > 0 and await password_input.is_visible():
                # 检查是否有密码错误提示，如果有则尝试 GOOGLE_NEW_PASSWORD
                error_msg = popup.locator('span:has-text("Wrong password"), span:has-text("密码错误")')
                if await error_msg.count() > 0 and not password_tried_new:
                    logger.info("OAuth: 旧密码错误，尝试使用修改后的密码...")
                    await password_input.fill(GOOGLE_NEW_PASSWORD)
                    password_tried_new = True
                else:
                    current_pw = GOOGLE_NEW_PASSWORD if password_tried_new else password
                    logger.info(f"OAuth: 输入密码... ({'修改后密码' if password_tried_new else '传入密码'})")
                    await password_input.fill(current_pw)

                next_btn = popup.locator('#passwordNext')
                if await next_btn.count() > 0:
                    await next_btn.click()
                else:
                    await popup.keyboard.press("Enter")
                await human_delay(popup, "click")
                continue

            # 邮箱输入
            email_input = popup.locator('input[type="email"]')
            if await email_input.count() > 0 and await email_input.is_visible():
                logger.info("OAuth: 输入邮箱...")
                await email_input.fill(email)
                next_btn = popup.locator('#identifierNext')
                if await next_btn.count() > 0:
                    await next_btn.click()
                else:
                    await popup.keyboard.press("Enter")
                await human_delay(popup, "click")
                continue

            # TOTP 验证码
            totp_input = popup.locator('input[type="tel"]')
            if await totp_input.count() > 0 and await totp_input.is_visible():
                logger.info("OAuth: 需要 TOTP 验证码...")
                totp_code = await get_totp_code(secret=totp_secret)
                await totp_input.fill(totp_code)
                next_btn = popup.locator('#totpNext')
                if await next_btn.count() > 0:
                    await next_btn.click()
                else:
                    await popup.keyboard.press("Enter")
                await human_delay(popup, "click")
                continue

            # "Continue as xxx" / 多语言继续按钮
            continue_btn = popup.locator(
                'button:has-text("Continue as"), '
                'button:has-text("Continue"), '
                'button:has-text("Next"), '
                'button:has-text("继续"), '
                'button:has-text("下一步"), '
                'button:has-text("Tiếp tục"), '
                'button:has-text("Tiếp theo"), '
                'button:has-text("Continuer"), '
                'button:has-text("Continuar"), '
                'button:has-text("Weiter")'
            )
            if await continue_btn.count() > 0 and await continue_btn.first.is_visible():
                logger.info("OAuth: 点击 Continue 按钮...")
                await continue_btn.first.click()
                await human_delay(popup, "click")
                continue

            # Allow / 多语言允许按钮
            allow_btn = popup.locator(
                'button:has-text("Allow"), '
                'button:has-text("允许"), '
                'button:has-text("Cho phép"), '
                'button:has-text("Autoriser"), '
                'button:has-text("Permitir"), '
                'button:has-text("Zulassen")'
            )
            if await allow_btn.count() > 0 and await allow_btn.first.is_visible():
                logger.info("OAuth: 点击允许按钮...")
                await allow_btn.first.click()
                await human_delay(popup, "click")
                continue

            logger.info(f"OAuth 步骤 {step}: 未匹配到已知元素，等待中...")

        except Exception as e:
            if popup.is_closed():
                logger.info("OAuth 弹窗已关闭，认证完成")
                return
            logger.warning(f"OAuth 步骤 {step} 异常: {e}")


def _gmail_normalize(email: str) -> str:
    """Gmail 忽略本地部分中的点 — 'a.b.c@gmail.com' 与 'abc@gmail.com' 是同一账号。
    Google 登录页通常展示去点形式，所以匹配时两个变体都试。
    """
    if "@" not in email:
        return email
    local, domain = email.rsplit("@", 1)
    if domain.lower() in ("gmail.com", "googlemail.com"):
        local = local.replace(".", "")
    return f"{local}@{domain}"


