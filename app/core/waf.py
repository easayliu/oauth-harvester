"""AWS WAF "Security check" 人机校验处理。

AWS access portal / signin.aws 登录页受 AWS WAF 保护，自动化浏览器常被弹出
"Security check → Please click verify to start your security challenge" 的 CAPTCHA，
不过它就报 "验证码无效" 卡死。本模块提供两种处理：

  1) 配了 CAPSOLVER_API_KEY → 调 CapSolver 的 AntiAwsWafTaskProxyLess 拿 aws-waf-token，
     注入 cookie 后刷新页面，自动过校验。
  2) 没配 key → 暂停等人工在可见浏览器里手点 Verify（轮询到校验消失再继续），需 HEADLESS=False。

CapSolver 文档: https://docs.capsolver.com/en/guide/captcha/awsWaf/
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
import urllib.request
from datetime import datetime
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from app.settings import CAPSOLVER_API_KEY

logger = logging.getLogger(__name__)

_CAPSOLVER_CREATE = "https://api.capsolver.com/createTask"
_CAPSOLVER_RESULT = "https://api.capsolver.com/getTaskResult"


async def detect_aws_waf_challenge(page) -> bool:
    """页面当前是否处于 AWS WAF "Security check" 人机校验。"""
    try:
        # 文案信号："Security check" / "security challenge" / "验证码无效"
        for pat in (r"Security check", r"security challenge",
                    r"start your security", r"验证码无效", r"人机"):
            if await page.locator(f'text=/{pat}/i').count() > 0:
                return True
        # 资源信号：awswaf 的 challenge.js / token / captcha 容器 / iframe
        sel = ('script[src*="awswaf"], iframe[src*="awswaf"], '
               'script[src*="captcha.awswaf"], [id*="awswaf" i], '
               '#captcha-container, #captcha-box')
        if await page.locator(sel).count() > 0:
            return True
    except Exception as e:
        logger.debug(f"WAF 检测异常: {e}")
    return False


def _capsolver_post(url: str, payload: dict, timeout: int = 30) -> dict:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8", errors="replace"))


def _capsolver_solve_token(website_url: str, api_key: str,
                           extra: dict | None = None,
                           timeout_s: int = 120) -> str:
    """同步调 CapSolver 拿 aws-waf-token（solution.cookie）。失败返回 ""。

    extra 可携带从实时页面抓到的 awsKey/awsIv/awsContext/awsChallengeJS。
    signin.aws 这类"按会话指纹"才弹出的 CAPTCHA，只给 websiteURL 时 CapSolver
    后端自己 GET 拿到的是无校验的 200 页面（ERROR_INVALID_TASK_DATA），必须把这四个
    参数从浏览器里捞出来一起传。
    """
    task = {
        "type": "AntiAwsWafTaskProxyLess",
        "websiteURL": website_url,
    }
    if extra:
        # 只透传有值的，CapSolver 要求的键名：awsKey/awsIv/awsContext/awsChallengeJS
        for k in ("awsKey", "awsIv", "awsContext", "awsChallengeJS"):
            if extra.get(k):
                task[k] = extra[k]
    try:
        created = _capsolver_post(_CAPSOLVER_CREATE, {
            "clientKey": api_key,
            "task": task,
        })
    except Exception as e:
        logger.warning(f"CapSolver createTask 异常: {e}")
        return ""
    if created.get("errorId"):
        logger.warning(
            f"CapSolver createTask 失败: {created.get('errorCode')} "
            f"{created.get('errorDescription')}"
        )
        return ""
    task_id = created.get("taskId")
    if not task_id:
        logger.warning(f"CapSolver createTask 无 taskId: {created}")
        return ""

    deadline = time.time() + timeout_s
    while time.time() < deadline:
        time.sleep(3)
        try:
            res = _capsolver_post(_CAPSOLVER_RESULT, {
                "clientKey": api_key, "taskId": task_id,
            })
        except Exception as e:
            logger.debug(f"CapSolver getTaskResult 异常: {e}")
            continue
        if res.get("errorId"):
            logger.warning(
                f"CapSolver getTaskResult 失败: {res.get('errorCode')} "
                f"{res.get('errorDescription')}"
            )
            return ""
        if res.get("status") == "ready":
            cookie = (res.get("solution") or {}).get("cookie") or ""
            if cookie:
                logger.info("CapSolver: 已拿到 aws-waf-token")
            return cookie
        # status == "processing" → 继续轮询
    logger.warning("CapSolver: 轮询超时未拿到 token")
    return ""


# 从实时页面（含跨域 awswaf 子 iframe）抓 CAPTCHA 渲染参数
_WAF_PARAMS_JS = """
() => {
  const out = {};
  try {
    const gp = window.gokuProps
      || (window.AwsWafIntegration && window.AwsWafIntegration.gokuProps);
    if (gp) { out.awsKey = gp.key; out.awsIv = gp.iv; out.awsContext = gp.context; }
  } catch (e) {}
  try {
    for (const s of document.querySelectorAll('script[src]')) {
      if (s.src && s.src.indexOf('challenge.js') !== -1) {
        out.awsChallengeJS = s.src;
        break;
      }
    }
  } catch (e) {}
  return out;
}
"""


async def _extract_waf_params_once(page) -> dict:
    """遍历主框架与所有子 iframe（CAPTCHA 多在跨域的 *.awswaf.com iframe 里），
    捞出 awsKey/awsIv/awsContext/awsChallengeJS。Playwright 的 frame.evaluate 跑在该
    frame 的隔离世界里，可读跨域 iframe 的 window，原生 JS 做不到。"""
    best: dict = {}
    for fr in page.frames:
        try:
            r = await fr.evaluate(_WAF_PARAMS_JS)
        except Exception as e:
            logger.debug(f"抓 WAF 参数异常（frame={getattr(fr, 'url', '?')}）: {e}")
            continue
        if not r:
            continue
        for k, v in r.items():
            if v and not best.get(k):
                best[k] = v
    return best


# 抓不到参数时的诊断：dump 各 frame 上 goku/waf/captcha 相关全局名、script、iframe
_WAF_DIAG_JS = """
() => {
  const info = {url: location.href, globals: [], scripts: [], iframes: []};
  try {
    for (const k in window) {
      if (/goku|waf|captcha|challenge|aws/i.test(k)) info.globals.push(k);
    }
  } catch (e) {}
  try {
    for (const s of document.querySelectorAll('script[src]')) info.scripts.push(s.src);
  } catch (e) {}
  try {
    for (const f of document.querySelectorAll('iframe')) info.iframes.push(f.src);
  } catch (e) {}
  return info;
}
"""


async def _dump_waf_diag(page) -> None:
    """抓不到 awsKey 时，把每个 frame 的全局名/script/iframe 打到日志，方便定位真实结构。"""
    for fr in page.frames:
        try:
            info = await fr.evaluate(_WAF_DIAG_JS)
        except Exception as e:
            logger.info(f"WAF 诊断 frame={getattr(fr, 'url', '?')} evaluate 失败: {e}")
            continue
        logger.info(
            f"WAF 诊断 frame={info.get('url')} "
            f"globals={info.get('globals')} "
            f"iframes={info.get('iframes')} "
            f"scripts={info.get('scripts')}"
        )


async def _click_waf_verify(page) -> bool:
    """点掉 'Security check' 框里的 Verify，触发真正的 captcha challenge 渲染。
    截图里的框是 CAPTCHA 入口态，点 Verify 后才加载 puzzle、生成 gokuProps。"""
    sel = ('button:has-text("Verify"), [role="button"]:has-text("Verify"), '
           'input[type="submit"][value="Verify" i], '
           'button:has-text("验证"), [role="button"]:has-text("验证")')
    for fr in page.frames:
        try:
            btn = fr.locator(sel)
            if await btn.count() > 0 and await btn.first.is_visible():
                await btn.first.click()
                logger.info("CapSolver: 已点击 Verify，等待 captcha 渲染")
                await page.wait_for_timeout(1500)
                return True
        except Exception as e:
            logger.debug(f"点 Verify 异常（frame={getattr(fr, 'url', '?')}）: {e}")
            continue
    logger.info("CapSolver: 未找到 Verify 按钮（可能已是 puzzle 态）")
    return False


async def _extract_waf_params(page, timeout_s: int = 20) -> dict:
    """轮询等验证码渲染出参数。gokuProps / challenge.js 在校验脚本跑完后才生成，
    抓太早会拿到空，所以每 1s 试一次，直到拿到 awsKey（必需项）或超时。"""
    deadline = time.time() + timeout_s
    best: dict = {}
    while time.time() < deadline:
        cur = await _extract_waf_params_once(page)
        for k, v in cur.items():
            if v and not best.get(k):
                best[k] = v
        if best.get("awsKey"):
            break
        await page.wait_for_timeout(1000)
    have = [k for k in ("awsKey", "awsIv", "awsContext", "awsChallengeJS")
            if best.get(k)]
    logger.info(f"CapSolver: 抓到 WAF 参数 {have or '无'}")
    return best


async def _solve_with_capsolver(page, context, api_key: str) -> bool:
    """用 CapSolver 拿 token 注入 cookie 后刷新页面。返回是否过了校验。"""
    website_url = page.url
    host = urlparse(website_url).hostname or ""
    logger.info(f"CapSolver: 开始打码 AWS WAF（{host}）...")
    # 先点 Verify，把 CAPTCHA 从"入口态"推进到 puzzle 态，gokuProps 才会生成
    await _click_waf_verify(page)
    extra = await _extract_waf_params(page)
    if not extra.get("awsKey"):
        # 抓不到必需参数：dump 页面真实结构，方便定位（key 名/iframe 层级可能跟预期不同）
        await _dump_waf_diag(page)
    # 同步阻塞调用放到线程里，避免卡事件循环
    token = await asyncio.to_thread(
        _capsolver_solve_token, website_url, api_key, extra
    )
    if not token:
        return False
    # aws-waf-token 注入到当前域（含父域，覆盖子域跳转）
    cookies = [{"name": "aws-waf-token", "value": token,
                "domain": host, "path": "/"}]
    # 同时按可注册父域再写一份（host 形如 us-east-1.signin.aws → .signin.aws）
    parts = host.split(".")
    if len(parts) >= 2:
        parent = "." + ".".join(parts[-2:])
        cookies.append({"name": "aws-waf-token", "value": token,
                        "domain": parent, "path": "/"})
    try:
        await context.add_cookies(cookies)
    except Exception as e:
        logger.warning(f"注入 aws-waf-token cookie 异常: {e}")
        return False
    try:
        await page.reload(wait_until="domcontentloaded", timeout=30000)
    except Exception as e:
        logger.warning(f"注入 token 后刷新异常: {e}")
    await page.wait_for_timeout(1500)
    still = await detect_aws_waf_challenge(page)
    if still:
        logger.warning("CapSolver: 注入 token 后仍检测到 WAF 校验")
    else:
        logger.info("CapSolver: WAF 校验已通过")
    return not still


async def _wait_human_solve(page, timeout_s: int = 240) -> bool:
    """人工兜底：等用户在可见浏览器里手点 Verify 完成校验。轮询到校验消失返回 True。"""
    logger.warning(
        "检测到 AWS WAF 人机校验，且未配 CAPSOLVER_API_KEY。"
        "请在弹出的浏览器窗口里手动点 'Verify' 完成校验（需 HEADLESS=False）..."
    )
    deadline = time.time() + timeout_s
    last_tick = 0
    start = time.time()
    while time.time() < deadline:
        if not await detect_aws_waf_challenge(page):
            logger.info("WAF 校验已消失（人工已完成），继续流程")
            return True
        elapsed = int(time.time() - start)
        if elapsed >= last_tick + 15:
            last_tick = elapsed
            logger.info(f"[{elapsed}s] 仍在等待人工完成 WAF 校验...")
        await page.wait_for_timeout(2000)
    logger.warning(f"WAF 校验人工等待超时（{timeout_s}s）")
    return False


_WAF_SNAPSHOT_JS = r"""
() => {
  const PATTERNS = /security check|security challenge|start your security|验证码无效|人机/i;
  const out = {url: location.href, matches: [], iframes: [], buttons: []};
  try {
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    let n;
    while ((n = walker.nextNode())) {
      const t = (n.nodeValue || '').trim();
      if (t && PATTERNS.test(t)) {
        const el = n.parentElement;
        out.matches.push({
          text: t.slice(0, 200),
          tag: el ? el.tagName : '',
          html: el ? (el.outerHTML || '').slice(0, 400) : '',
        });
        if (out.matches.length >= 10) break;
      }
    }
  } catch (e) {}
  try {
    for (const f of document.querySelectorAll('iframe')) {
      out.iframes.push({src: f.src || '', visible: !!(f.offsetWidth || f.offsetHeight)});
    }
  } catch (e) {}
  try {
    for (const b of document.querySelectorAll('button, [role="button"], input[type=submit]')) {
      const visible = !!(b.offsetWidth || b.offsetHeight);
      if (!visible) continue;
      const label = (b.innerText || b.value || '').trim().slice(0, 80);
      if (label) out.buttons.push(label);
      if (out.buttons.length >= 30) break;
    }
  } catch (e) {}
  return out;
}
"""


async def _snapshot_waf_state(page) -> None:
    """触发 WAF 处理时，把页面真实状态 dump 到日志 + screenshots/，用于事后判断是真挑战还是误判。

    重点产物：
      - 截图 + HTML：直观看页面长啥样
      - 每个 frame 匹配到"Security check"等文案的元素 outerHTML：确认文案来源
      - 所有 iframe src（含 threat-mitigation 的 use_vr 参数）：use_vr=false 通常意味着没真挑战
      - 所有可见按钮文案：判断 _click_waf_verify 可能点到了谁
    """
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = Path("screenshots")
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        logger.debug(f"WAF snapshot mkdir 失败: {e}")
    png_path = out_dir / f"waf_{ts}.png"
    html_path = out_dir / f"waf_{ts}.html"
    try:
        await page.screenshot(path=str(png_path), full_page=True)
        logger.info(f"WAF snapshot: 截图已保存 {png_path}")
    except Exception as e:
        logger.info(f"WAF snapshot: 截图失败 {e}")
    try:
        html = await page.content()
        html_path.write_text(html, encoding="utf-8")
        logger.info(f"WAF snapshot: HTML 已保存 {html_path}")
    except Exception as e:
        logger.info(f"WAF snapshot: HTML 抓取失败 {e}")

    for fr in page.frames:
        fr_url = getattr(fr, "url", "?")
        try:
            info = await fr.evaluate(_WAF_SNAPSHOT_JS)
        except Exception as e:
            logger.info(f"WAF snapshot frame={fr_url} evaluate 失败: {e}")
            continue
        matches = info.get("matches") or []
        iframes = info.get("iframes") or []
        buttons = info.get("buttons") or []
        logger.info(
            f"WAF snapshot frame={info.get('url')} "
            f"matches={len(matches)} iframes={len(iframes)} buttons={len(buttons)}"
        )
        for m in matches:
            logger.info(
                f"  match tag={m.get('tag')} text={m.get('text')!r} "
                f"html={m.get('html')!r}"
            )
        for ifr in iframes:
            src = ifr.get("src") or ""
            extra = ""
            try:
                qs = parse_qs(urlparse(src).query)
                if "use_vr" in qs:
                    extra = f" use_vr={qs['use_vr'][0]}"
            except Exception:
                pass
            logger.info(f"  iframe visible={ifr.get('visible')} src={src}{extra}")
        if buttons:
            logger.info(f"  visible_buttons={buttons}")


async def handle_aws_waf(page, context) -> bool:
    """检测并处理 AWS WAF 校验。未触发 → True；触发后处理成功 → True；失败 → False。

    配了 CAPSOLVER_API_KEY 走自动打码；否则暂停等人工。自动打码失败再退回人工兜底。
    """
    if not await detect_aws_waf_challenge(page):
        return True
    logger.info("检测到 AWS WAF 'Security check' 人机校验，开始处理")
    await _snapshot_waf_state(page)
    if CAPSOLVER_API_KEY:
        if await _solve_with_capsolver(page, context, CAPSOLVER_API_KEY):
            return True
        logger.warning("CapSolver 自动打码失败，退回人工兜底")
    return await _wait_human_solve(page)
