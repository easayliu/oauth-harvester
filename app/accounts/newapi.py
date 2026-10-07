"""New API (newapi.ai / new-api) 渠道管理接口。

把已抓到的 AWS AK/SK 注册成 New API 后台的「AWS Bedrock」渠道（channel type=33）。
文档: https://www.newapi.ai/zh/docs/api/management/channel-management/channel-post

要点（对照 new-api 源码 model/channel.go + relay/channel/aws/relay-aws.go）:
  - 建渠道: POST {base_url}/api/channel/  body {"mode":"single","channel":{...}}
  - 鉴权: 头 `Authorization: Bearer <系统访问令牌>` + `New-Api-User: <令牌所属用户 id>`
  - AWS 渠道: type=33，key 固定格式 `ak|sk|region`（三段用竖线分隔）
  - models: 逗号分隔的对外模型名；model_mapping: JSON 串「请求模型名 -> Bedrock 模型 id」
  - 注意 new-api 校验失败仍回 HTTP 200，靠 body 里的 success=false 判定，必须解析 body。
"""

import json
import logging
import urllib.error
import urllib.request

from app.accounts.subus import aws_region_to_geo
from app.settings import (
    NEWAPI_ADMIN_TOKEN,
    NEWAPI_BASE_URL,
    NEWAPI_DEFAULT_GROUP,
    NEWAPI_DEFAULT_PRIORITY,
    NEWAPI_MODEL_MAPPING_BY_GEO,
    NEWAPI_USER_ID,
)

logger = logging.getLogger(__name__)

# new-api 里 AWS Bedrock 渠道的 type 值（constant/channel.go: ChannelTypeAws = 33）
CHANNEL_TYPE_AWS = 33


def newapi_model_mapping_for_geo(geo: str, mapping_by_geo: dict = None) -> dict:
    """按 geo 名（us/eu/au/global/...）取模型映射表。找不到返回空 dict。"""
    mapping_by_geo = mapping_by_geo if mapping_by_geo is not None else NEWAPI_MODEL_MAPPING_BY_GEO
    return dict(mapping_by_geo.get(geo) or {})


def newapi_model_mapping_for_region(region: str, mapping_by_geo: dict = None) -> dict:
    """按 region 的 geo（us/eu/au/...）选出该渠道的模型映射表。找不到返回空 dict。
    注意 global 前缀不由 region 推出（aws_region_to_geo 不返回 global），需显式走 geo 表。"""
    return newapi_model_mapping_for_geo(aws_region_to_geo(region), mapping_by_geo)


def register_newapi_channel(ak: str, sk: str, region: str, name: str,
                            base_url: str = "", token: str = "", user_id: str = "",
                            group: str = "", priority: int = None,
                            model_mapping: dict = None, models: list = None,
                            timeout: int = 30) -> bool:
    """把一对 AWS AK/SK 注册成 New API 的 AWS Bedrock 渠道（一个 region 一条）。

    model_mapping 为 None 时按 region 的 geo 自动选表；models 为 None 时取映射表的 key。
    映射表为空（该 geo 无配置）时跳过并告警，避免建出跑不通的渠道。
    """
    base_url = (base_url or NEWAPI_BASE_URL).rstrip("/")
    token = token or NEWAPI_ADMIN_TOKEN
    user_id = str(user_id or NEWAPI_USER_ID)
    group = group or NEWAPI_DEFAULT_GROUP
    priority = NEWAPI_DEFAULT_PRIORITY if priority is None else priority

    if not base_url or not token:
        logger.warning("NEWAPI_BASE_URL / NEWAPI_ADMIN_TOKEN 未配置，跳过 New API 建渠道")
        return False
    if not ak or not sk or not region or not name:
        logger.warning(f"参数缺失 (ak={bool(ak)}, sk={bool(sk)}, region={region!r}, name={name!r})，跳过")
        return False

    if model_mapping is None:
        model_mapping = newapi_model_mapping_for_region(region)
    if not model_mapping:
        logger.warning(f"{name} @ {region}: 该 geo 无模型映射（geo={aws_region_to_geo(region)}），跳过建渠道")
        return False
    if models is None:
        models = list(model_mapping.keys())

    channel = {
        "type": CHANNEL_TYPE_AWS,
        "name": name,
        # new-api AWS 渠道 key 固定格式：ak|sk|region
        "key": f"{ak}|{sk}|{region}",
        "models": ",".join(models),
        "group": group,
        "model_mapping": json.dumps(model_mapping, ensure_ascii=False),
        "groups": [g.strip() for g in group.split(",") if g.strip()],
        "priority": priority,
        "status": 1,
    }
    payload = {"mode": "single", "channel": channel}

    url = f"{base_url}/api/channel/"
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "Authorization": f"Bearer {token}",
            "New-Api-User": user_id,
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
            text = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        status = e.code
        text = e.read().decode("utf-8", errors="replace") if e.fp else str(e)
    except Exception as e:
        logger.warning(f"New API 建渠道请求异常 ({name} @ {region}): {e}")
        return False

    # new-api 校验失败也回 HTTP 200，success=false 在 body 里，必须解析
    ok = False
    try:
        parsed = json.loads(text)
        ok = bool(parsed.get("success"))
    except ValueError:
        ok = 200 <= status < 300

    if ok:
        logger.info(f"New API 建渠道成功 [{status}] {name} @ {region}: {text[:160]}")
        return True
    logger.warning(f"New API 建渠道失败 [{status}] {name} @ {region}: {text[:300]}")
    return False
