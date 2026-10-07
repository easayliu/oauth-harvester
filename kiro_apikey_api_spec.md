# Kiro apikey（ksk_）纯 API 规格

实测抓包确认（2026-07-17，账号 marcelpotaru3@d-906676fe77）：`ksk_` API Key 的**创建/列出/删除全是纯 JSON HTTP 请求**，无需浏览器、无需 cookie、无需 csrf-token。

## 端点

- URL：`POST https://management.us-east-1.kiro.dev/`
- 服务前缀：`KiroControlPlaneBearerService`
- Content-Type：`application/x-amz-json-1.0`（AWS awsJson-1.0 协议）
- 认证：`Authorization: Bearer <IDC accessToken>`（`aoa...` 前缀，就是 AWS SSO/IDC 的 accessToken）
- **必需头只有 3 个**：`Authorization` / `Content-Type` / `X-Amz-Target`。
  实测 `x-csrf-token`、`x-kiro-userid`、`x-kiro-visitorid`、Cookie **全部可省**。

## 操作（X-Amz-Target）

| Target | 请求 body | 响应 |
|---|---|---|
| `KiroControlPlaneBearerService.GetProfile` | `{"profileArn":"..."}` | `{"profile":{"arn","optInFeatures":{"apiKeys":{"toggle":"ON"}},...}}` |
| `KiroControlPlaneBearerService.ListApiKeys` | `{"profileArn":"..."}` | `{"keys":[{"keyId":"kskid_...","keyPrefix":"ksk_xxxx","label":"...","createdAt":...}]}` |
| `KiroControlPlaneBearerService.CreateApiKey` | `{"profileArn":"...","label":"<key名>"}` | `{"keyId":"kskid_...","keyPrefix":"ksk_...","rawKey":"ksk_完整key","createdAt":...}` |
| `KiroControlPlaneBearerService.DeleteApiKey` | `{"profileArn":"...","keyId":"kskid_..."}` | `{}` |

- **完整 key 在 `CreateApiKey` 响应的 `rawKey` 字段**（网页里那个"只显示一次"的弹窗，就是读这个字段）。列表接口只回 `keyPrefix`（掩码）。
- `profileArn` 形如 `arn:aws:codewhisperer:us-east-1:495199591619:profile/3CVECDVDWXPH`（495199591619 是 Kiro 服务账号，profile 名 `KiroProfile-us-east-1`）。
- 建 key 前提：profile 的 `optInFeatures.apiKeys.toggle == "ON"`（GetProfile 可查）。

## profileArn 从哪来

代码里已有 `app/kiro/api.py: kiro_list_first_profile_arn(access_token, region)`（调 CodeWhisperer `ListAvailableProfiles`），传同一个 accessToken 就能拿到 profileArn。无需网页。

## Bearer token 从哪来（登录那一半）

`aoa...` 就是 IDC accessToken。当前 `register_kiro_apikey` 走浏览器网页 OAuth：
IDC 网页登录 → `app.kiro.dev` 下发 httpOnly cookie（`AccessToken`/`SessionToken`）→
SPA 调 `app.kiro.dev/service/KiroWebPortalService/operation/GetToken`（cookie 认证）换出这个 `aoa` Bearer →
再打 `management.us-east-1.kiro.dev`。

要纯 API 化这一半，两条路：
1. **复用现有 OIDC device flow**（`app/kiro/api.py` 的 `idc_register_client`/`idc_start_device_authorization`/`idc_create_token`）产出的 accessToken —— 待验证它是否被 `management.kiro.dev` 接受（大概率可以，同为 IDC accessToken）。device 授权的 "Allow" 目前仍走浏览器。
2. 完全无浏览器则需把 IDC 门户的 用户名+临时密码+按需改密+OTP 流程用 HTTP 复刻（SAML/OIDC authorize），工作量更大，尚未做。

## 最小可用改造

把 `register_kiro_apikey` 里"网页进 /settings/api-keys → 填名 → 点 Create → 正则抓弹窗"整段，替换为：
拿到 accessToken 后 → `kiro_list_first_profile_arn` 取 profileArn → 一发 `CreateApiKey` 读 `rawKey`。
浏览器（若仍需要）只用于登录换 accessToken，不再驱动 SPA、不再截屏抓 key。

## 已验证证据

- 纯 urllib（最小 3 头，无 cookie/csrf）建出 `ksk_hqmOejyMESnMsElqeUe2XPLKkFWJgJOK`，随后 `DeleteApiKey` 删除成功。
- 抓包原始数据：`kiro_createkey_capture.jsonl`（含 GetProfile/ListApiKeys/CreateApiKey/DeleteApiKey 完整请求响应）。
