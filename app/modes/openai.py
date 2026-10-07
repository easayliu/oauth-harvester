"""openai mode：ChatGPT（OpenAI）OAuth 登录 → 组装导入格式 → 可选推送 admin。

输入自动识别：
  - email----password----totp  卡密      → 浏览器跑 Codex PKCE 流登录（HEADLESS=False 时可人工接管）
  - rt.xxx / 一行一个 refresh_token       → 直接用 refresh_token 换 token（不开浏览器）
  - {...credentials...} / 完整导入记录 JSON → 直接重排成导入格式（解 JWT 反推字段）
  - 文件：JSON 数组 / 每行一条，逐条处理
默认只产出导入格式（写文件 + 打印）；加 --push 才推送到 admin API。
"""

import json
import logging
import os
import sys

from app.accounts.openai import (
    build_authorize_url,
    build_openai_oauth_record,
    generate_pkce,
    generate_state,
    openai_exchange_code,
    openai_refresh_tokens,
    register_openai_oauth_account,
)
from app.core.browser import cloak_browser_session, new_window_sized_context, screenshot_path
from app.core.parsing import parse_input
from app.settings import OPENAI_OAUTH_CLIENT_ID, OPENAI_OUTPUT_FILE

logger = logging.getLogger(__name__)


# ---- 浏览器登录：Codex PKCE 流 ---------------------------------------------

async def openai_browser_login(email: str, password: str, totp_secret: str = "",
                               client_id: str = "", tag: str = "",
                               wait_timeout_s: int = 300) -> dict:
    """打开 ChatGPT 授权链接，登录后从 localhost:1455 回调里截获 code，换成 token 响应。

    best-effort 自动填邮箱/密码；HEADLESS=False 时浏览器可见，可由人工完成登录（含 SSO/2FA），
    回调拦截照常工作。成功返回 token 响应字典，失败返回 None。
    """
    client_id = client_id or OPENAI_OAUTH_CLIENT_ID
    verifier, challenge = generate_pkce()
    state = generate_state()
    auth_url = build_authorize_url(challenge, state, client_id)

    captured = {"code": None, "state": None}

    async with cloak_browser_session(maximized=True) as browser:
        # 裸 new_context() 的默认 1280x720 viewport 会让 Playwright 在开页时把窗口
        # 缩回小尺寸，maximized=True 形同虚设；改走统一的铺满可用区流程
        context = await new_window_sized_context(browser)

        async def _route(route):
            # 拦截对 localhost:1455 的回调跳转：取出 code/state，回个成功页面（避免连接失败错误页）
            try:
                url = route.request.url
                from urllib.parse import urlparse, parse_qs
                q = parse_qs(urlparse(url).query)
                if q.get("code"):
                    captured["code"] = q["code"][0]
                    captured["state"] = (q.get("state") or [None])[0]
                    logger.info(f"已截获授权 code ({len(captured['code'])} 字符)")
                await route.fulfill(
                    status=200, content_type="text/html",
                    body="<html><body><h2>登录完成，可关闭此窗口</h2></body></html>",
                )
            except Exception:
                try:
                    await route.abort()
                except Exception:
                    pass

        await context.route("http://localhost:1455/**", _route)

        try:
            page = await context.new_page()
            logger.info("打开 ChatGPT 授权链接...")
            try:
                await page.goto(auth_url, wait_until="domcontentloaded", timeout=30000)
            except Exception as e:
                logger.warning(f"授权页加载异常（可能正常）: {e}")

            await _try_autofill_login(page, email, password, totp_secret, tag)

            # 轮询等待回调 code（人工接管时给足时间）
            waited = 0
            step = 2000
            while captured["code"] is None and waited < wait_timeout_s * 1000:
                await page.wait_for_timeout(step)
                waited += step
                if waited % 20000 == 0:
                    logger.info(f"等待登录完成... ({waited // 1000}s/{wait_timeout_s}s)")

            if captured["code"] is None:
                logger.warning("未截获到授权 code（登录未完成或回调未触发）")
                try:
                    await page.screenshot(path=screenshot_path("openai_no_code", tag or email))
                except Exception:
                    pass
                return None

            if captured["state"] and captured["state"] != state:
                logger.warning("state 不匹配，疑似回调被串改，放弃")
                return None
        finally:
            try:
                await context.close()
            except Exception:
                pass

    return openai_exchange_code(captured["code"], verifier, client_id)


async def _try_autofill_login(page, email, password, totp_secret, tag):
    """best-effort 自动填邮箱→继续→密码→继续；失败不抛，留给人工接管。"""
    try:
        await page.wait_for_timeout(2500)
        email_sel = 'input[name="email"], input[type="email"], input[autocomplete="username"]'
        el = page.locator(email_sel)
        if await el.count() > 0 and await el.first.is_visible():
            await el.first.fill(email)
            await page.wait_for_timeout(500)
            await _click_continue(page)
            await page.wait_for_timeout(2500)

        pwd_sel = 'input[name="password"], input[type="password"]'
        el = page.locator(pwd_sel)
        if await el.count() > 0 and await el.first.is_visible():
            await el.first.fill(password)
            await page.wait_for_timeout(500)
            await _click_continue(page)
            await page.wait_for_timeout(2500)

        if totp_secret:
            from app.core.browser import generate_totp
            otp_sel = 'input[autocomplete="one-time-code"], input[name="code"], input[inputmode="numeric"]'
            el = page.locator(otp_sel)
            if await el.count() > 0 and await el.first.is_visible():
                await el.first.fill(generate_totp(totp_secret))
                await page.wait_for_timeout(500)
                await _click_continue(page)

        try:
            await page.screenshot(path=screenshot_path("openai_after_login", tag or email))
        except Exception:
            pass
    except Exception as e:
        logger.info(f"自动填充未完成（交由人工接管）: {e}")


async def _click_continue(page):
    for sel in ['button[type="submit"]', 'button:has-text("Continue")',
                'button:has-text("继续")', 'button:has-text("Log in")',
                'button:has-text("Sign in")', 'button:has-text("Next")']:
        try:
            btn = page.locator(sel)
            if await btn.count() > 0 and await btn.first.is_visible():
                await btn.first.click()
                return True
        except Exception:
            continue
    try:
        await page.keyboard.press("Enter")
    except Exception:
        pass
    return False


# ---- 输出落盘 --------------------------------------------------------------

def _write_records(records: list, out_path: str) -> int:
    """把记录按 refresh_token / email 去重后并入 out_path（JSON 数组），返回新增条数。"""
    existing = []
    if os.path.isfile(out_path):
        try:
            with open(out_path, "r", encoding="utf-8") as f:
                existing = json.load(f)
            if not isinstance(existing, list):
                existing = []
        except Exception as e:
            logger.warning(f"读取已有 {out_path} 失败，按新文件创建: {e}")
            existing = []

    def _key(r):
        cred = r.get("credentials", {}) if isinstance(r, dict) else {}
        return cred.get("refresh_token") or cred.get("email") or r.get("name")

    seen = {_key(r) for r in existing if isinstance(r, dict)}
    added = 0
    for r in records:
        k = _key(r)
        if k and k in seen:
            continue
        existing.append(r)
        seen.add(k)
        added += 1

    if added:
        tmp = f"{out_path}.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(existing, f, ensure_ascii=False, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, out_path)
    return added


# ---- 输入归集 --------------------------------------------------------------

def _token_data_from_obj(obj: dict) -> dict:
    """从一个 JSON 对象里取出 token 响应：完整导入记录取 credentials，否则对象本身需含 access_token。"""
    if not isinstance(obj, dict):
        return None
    if isinstance(obj.get("credentials"), dict) and obj["credentials"].get("access_token"):
        return obj["credentials"]
    if obj.get("access_token"):
        return obj
    return None


def _collect_targets(raw_input: str, is_file: bool, force_refresh: bool) -> list:
    """归集待处理任务，每项为 (kind, value)：
       kind ∈ {"login": parse_input 卡密三元组, "refresh": refresh_token, "token": token_data 字典}。
    """
    targets = []
    content = raw_input
    if is_file:
        with open(raw_input, "r", encoding="utf-8") as f:
            content = f.read()
    cstrip = content.strip()

    # 整体是 JSON（数组/对象）：当成 token 响应 / 导入记录处理
    if cstrip[:1] in ("[", "{"):
        try:
            data = json.loads(cstrip)
        except ValueError:
            data = None
        if data is not None:
            items = data if isinstance(data, list) else [data]
            for it in items:
                td = _token_data_from_obj(it)
                if td:
                    targets.append(("token", td))
                elif isinstance(it, dict) and (it.get("refresh_token") or it.get("refreshToken")):
                    targets.append(("refresh", it.get("refresh_token") or it.get("refreshToken")))
            return targets

    # 文本：逐行
    lines = cstrip.splitlines() if is_file else [cstrip]
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if force_refresh or line.startswith("rt.") or (("----" not in line) and ("@" not in line)):
            targets.append(("refresh", line))
        else:
            try:
                email, password, totp = parse_input(line)
                targets.append(("login", (email, password, totp)))
            except ValueError as e:
                logger.warning(f"无法识别的输入，跳过: {line[:40]} ({e})")
    return targets


# ---- mode 入口 -------------------------------------------------------------

async def run_openai(mode: str, raw_input: str, is_file: bool):
    extra = sys.argv[3:]

    def _opt(flag, default=None):
        if flag in extra:
            i = extra.index(flag)
            if i + 1 < len(extra):
                return extra[i + 1]
        return default

    do_push = "--push" in extra
    force_refresh = "--refresh" in extra
    out_path = _opt("--out", OPENAI_OUTPUT_FILE)
    name_override = _opt("--name", "")
    client_id = _opt("--client-id", "") or OPENAI_OAUTH_CLIENT_ID
    concurrency = int(_opt("--concurrency", "-1"))
    priority = int(_opt("--priority", "-1"))

    targets = _collect_targets(raw_input, is_file, force_refresh)
    if not targets:
        print("无可处理的输入（需要 卡密 / refresh_token / token JSON）")
        exit(1)

    logger.info(f"openai 模式：准备处理 {len(targets)} 条...")
    records = []
    results = []
    for idx, (kind, value) in enumerate(targets, 1):
        label = ""
        try:
            if kind == "login":
                email, password, totp = value
                label = email
                logger.info(f"[{idx}/{len(targets)}] {email} 浏览器登录 ChatGPT...")
                token_data = await openai_browser_login(
                    email, password, totp, client_id=client_id, tag=f"openai_{idx}")
            elif kind == "refresh":
                label = value[:16] + "..."
                logger.info(f"[{idx}/{len(targets)}] 用 refresh_token 换 token...")
                token_data = openai_refresh_tokens(value, client_id=client_id)
            else:  # token
                label = value.get("email", "token")
                token_data = value

            if not token_data:
                results.append({"label": label, "status": "获取 token 失败"})
                continue

            this_name = name_override if (name_override and len(targets) == 1) else ""
            record = build_openai_oauth_record(
                token_data, name=this_name, concurrency=concurrency, priority=priority)
            records.append(record)
            label = record["name"]

            status = "成功"
            if do_push:
                ok = register_openai_oauth_account(record)
                status = "成功(已推送)" if ok else "成功(推送失败)"
            results.append({"label": label, "status": status})
        except Exception as e:
            logger.error(f"[{idx}/{len(targets)}] {label or kind} 出错: {e}")
            results.append({"label": label or kind, "status": f"异常: {e}"})

    added = _write_records(records, out_path) if records else 0

    print("\n" + "=" * 60)
    print("openai (ChatGPT) 导入格式结果")
    print("=" * 60)
    if records:
        print(json.dumps(records, ensure_ascii=False, indent=2))
    success = [r for r in results if r["status"].startswith("成功")]
    failed = [r for r in results if not r["status"].startswith("成功")]
    print(f"\n总计: {len(results)}  成功: {len(success)}  失败: {len(failed)}")
    print(f"新增写入 {added} 条到 {out_path}（去重后）")
    if failed:
        print(f"\n--- 失败 ({len(failed)}) ---")
        for r in failed:
            print(f"  {r['label']}  ({r['status']})")
    print("=" * 60)
    return
