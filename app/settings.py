"""配置加载：从 config.py 导入,缺失项用默认值兜底（由 main.py 拆分而来）"""




try:
    from config import GOOGLE_NEW_PASSWORD, HEADLESS, PROXY
except ImportError:
    print("请复制 config.example.py 为 config.py 并填写配置信息")
    exit(1)

try:
    from config import KIRO_IDC_NEW_PASSWORD
except ImportError:
    KIRO_IDC_NEW_PASSWORD = "Kiro-Idc-New-2026!"

# 测代理出口 IP 的地址（纯文本返回 IP）。老 config.py 没有这项时兜底，避免退出。
try:
    from config import PROXY_TEST_URL
except ImportError:
    PROXY_TEST_URL = "https://api.ipify.org"

# kiro 登录浏览器后端：'camoufox'(默认,stealth Firefox) 或 'cloak'(CloakBrowser
# stealth Chromium)。Firefox 内核过 Google 'This browser may not be secure' 更稳,
# 是默认;想用 Chromium 指纹/复用 chrome profile 时切 'cloak'。也可用环境变量
# KIRO_BROWSER_BACKEND 临时覆盖(环境变量优先),便于不改 config 直接 A/B。
# 浏览器指纹/地区配置（所有浏览器模式通用；命令行 --tz/--locale/--os/--geoip 覆盖）
try:
    from config import BROWSER_LOCALE
except ImportError:
    BROWSER_LOCALE = "en-US"
try:
    from config import BROWSER_TIMEZONE
except ImportError:
    BROWSER_TIMEZONE = ""
try:
    from config import BROWSER_OS
except ImportError:
    BROWSER_OS = "windows"
try:
    from config import BROWSER_GEOIP
except ImportError:
    BROWSER_GEOIP = True

try:
    from config import KIRO_BROWSER_BACKEND
except ImportError:
    KIRO_BROWSER_BACKEND = "camoufox"

# BotBrowser（patched Chromium，源码级指纹伪装）后端所需的两个外部资产：
#   BOTBROWSER_EXEC_PATH    : 内核可执行文件（GitHub Releases 下载解压，
#                             macOS 形如 /Applications/Chromium.app/Contents/MacOS/Chromium）
#   BOTBROWSER_PROFILE_PATH : .enc 指纹 profile（订阅获取；留空则退化为普通 Chromium）
try:
    from config import BOTBROWSER_EXEC_PATH, BOTBROWSER_PROFILE_PATH
except ImportError:
    BOTBROWSER_EXEC_PATH = ""
    BOTBROWSER_PROFILE_PATH = ""

try:
    from config import CAPSOLVER_API_KEY
except ImportError:
    CAPSOLVER_API_KEY = ""

# kiro 浏览器 profile 磁盘上限：~/.kiro-profiles 与 ~/.kiro-firefox-profiles 每个账号
# 一份 profile（firefox 约 100–260MB）且从不复用，长期堆积会打满磁盘。创建新 profile
# 前按 LRU（最旧优先）清理，直到「每个 root 的 profile 数 ≤ 上限」且「磁盘可用 ≥ 阈值」。
# 置 0 关闭对应判据；近 KIRO_PROFILE_ACTIVE_TTL_S 秒内活跃的 profile 视为可能在跑，不删。
try:
    from config import KIRO_PROFILE_MAX_COUNT
except ImportError:
    KIRO_PROFILE_MAX_COUNT = 0  # 0=不按数量删，仅靠下面的磁盘可用阈值自调节
try:
    from config import KIRO_PROFILE_MIN_FREE_GB
except ImportError:
    KIRO_PROFILE_MIN_FREE_GB = 15.0
try:
    from config import KIRO_PROFILE_ACTIVE_TTL_S
except ImportError:
    KIRO_PROFILE_ACTIVE_TTL_S = 3600

# aws-kiro 模式：登录 AWS 后在 IAM Identity Center 自动建用户
# AWS_IDC_INSTANCE_ID 留空则脚本进 SSO 控制台后从 URL 自动探测当前账号的实例 ID
try:
    from config import (
        AWS_IDC_INSTANCE_ID,
        AWS_IDC_REGION,
        AWS_IDC_EMAIL_DOMAIN,
        AWS_IDC_USERNAME_PREFIX,
        AWS_IDC_KIRO_OUTPUT_FILE,
    )
except ImportError:
    AWS_IDC_INSTANCE_ID = "7223caf889bdb02d"
    AWS_IDC_REGION = "us-east-1"
    AWS_IDC_EMAIL_DOMAIN = "pannebakercorolis887.space"
    AWS_IDC_USERNAME_PREFIX = "kiro"
    AWS_IDC_KIRO_OUTPUT_FILE = "kiro_idc_users.txt"

# aws-kiro 模式：建好 IDC 用户后加入的群组名（留空则不加群组）
try:
    from config import AWS_IDC_GROUP
except ImportError:
    AWS_IDC_GROUP = ""

# aws-kiro 模式：完全自定义用户名（原样使用，不拼序号）。
# 字符串（多个用逗号分隔）或列表；留空则回退「基名+序号」命名。命令行 --username 优先。
try:
    from config import AWS_IDC_USERNAME
except ImportError:
    AWS_IDC_USERNAME = ""

try:
    from config import (
        CLAUDE_CONSOLE_EMAIL,
        CLAUDE_CONSOLE_IMAP_HOST,
        CLAUDE_CONSOLE_IMAP_PORT,
        CLAUDE_CONSOLE_IMAP_USER,
        CLAUDE_CONSOLE_IMAP_PASS,
    )
except ImportError:
    CLAUDE_CONSOLE_EMAIL = ""
    CLAUDE_CONSOLE_IMAP_HOST = ""
    CLAUDE_CONSOLE_IMAP_PORT = 993
    CLAUDE_CONSOLE_IMAP_USER = ""
    CLAUDE_CONSOLE_IMAP_PASS = ""

try:
    from config import (
        SUBUS_API_BASE_URL,
        SUBUS_API_ADMIN_TOKEN,
        SUBUS_API_DEFAULT_GROUP_IDS,
        SUBUS_API_DEFAULT_AWS_REGION,
    )
except ImportError:
    SUBUS_API_BASE_URL = "https://subus.milus.one"
    SUBUS_API_ADMIN_TOKEN = ""
    SUBUS_API_DEFAULT_GROUP_IDS = [21]
    SUBUS_API_DEFAULT_AWS_REGION = "us-east-1"

try:
    from config import SUBUS_API_DEFAULT_CONCURRENCY, SUBUS_API_DEFAULT_PRIORITY
except ImportError:
    SUBUS_API_DEFAULT_CONCURRENCY = 10
    SUBUS_API_DEFAULT_PRIORITY = 1

try:
    from config import (
        SUBUS_API_DEFAULT_NOTES,
        SUBUS_API_DEFAULT_PROXY_ID,
        SUBUS_API_DEFAULT_LOAD_FACTOR,
        SUBUS_API_DEFAULT_RATE_MULTIPLIER,
        SUBUS_API_DEFAULT_STATUS,
        SUBUS_API_DEFAULT_EXPIRES_AT,
        SUBUS_API_DEFAULT_AUTO_PAUSE_ON_EXPIRED,
    )
except ImportError:
    SUBUS_API_DEFAULT_NOTES = ""
    SUBUS_API_DEFAULT_PROXY_ID = 0
    SUBUS_API_DEFAULT_LOAD_FACTOR = 0
    SUBUS_API_DEFAULT_RATE_MULTIPLIER = 1
    SUBUS_API_DEFAULT_STATUS = "active"
    SUBUS_API_DEFAULT_EXPIRES_AT = 0
    SUBUS_API_DEFAULT_AUTO_PAUSE_ON_EXPIRED = True

try:
    from config import (
        SUBUS_API_DEFAULT_BASE_RPM,
        SUBUS_API_DEFAULT_RPM_STRATEGY,
        SUBUS_API_DEFAULT_RPM_STICKY_BUFFER,
    )
except ImportError:
    SUBUS_API_DEFAULT_BASE_RPM = 15
    SUBUS_API_DEFAULT_RPM_STRATEGY = "tiered"
    SUBUS_API_DEFAULT_RPM_STICKY_BUFFER = 5

try:
    from config import SUBUS_API_DEFAULT_TEMP_UNSCHEDULABLE_RULES
except ImportError:
    SUBUS_API_DEFAULT_TEMP_UNSCHEDULABLE_RULES = [
        {
            "error_code": 429,
            "keywords": ["would exceed your organization", "tokens per minute"],
            "duration_minutes": 2,
            "description": "",
        },
    ]

try:
    from config import SUBUS_API_DEFAULT_TEMP_UNSCHEDULABLE_ENABLED
except ImportError:
    SUBUS_API_DEFAULT_TEMP_UNSCHEDULABLE_ENABLED = True

# subus oauth 模式（通过 sessionKey 登录 claude.ai 授权，拿 OAuth token 推到 subus）默认值
try:
    from config import (
        SUBUS_OAUTH_DEFAULT_GROUP_IDS,
        SUBUS_OAUTH_CONCURRENCY,
        SUBUS_OAUTH_PRIORITY,
        SUBUS_OAUTH_RATE_MULTIPLIER,
        SUBUS_OAUTH_MAX_DEVICES,
        SUBUS_OAUTH_DEVICE_IDLE_TIMEOUT_MINUTES,
        SUBUS_OAUTH_BASE_RPM,
        SUBUS_OAUTH_RPM_STRATEGY,
        SUBUS_OAUTH_USER_MSG_QUEUE_MODE,
        SUBUS_OAUTH_ENABLE_TLS_FINGERPRINT,
        SUBUS_OAUTH_TLS_FINGERPRINT_PROFILE_ID,
    )
except ImportError:
    SUBUS_OAUTH_DEFAULT_GROUP_IDS = [20]
    SUBUS_OAUTH_CONCURRENCY = 10
    SUBUS_OAUTH_PRIORITY = 1
    SUBUS_OAUTH_RATE_MULTIPLIER = 1
    SUBUS_OAUTH_MAX_DEVICES = 3
    SUBUS_OAUTH_DEVICE_IDLE_TIMEOUT_MINUTES = 5
    SUBUS_OAUTH_BASE_RPM = 10
    SUBUS_OAUTH_RPM_STRATEGY = "tiered"
    SUBUS_OAUTH_USER_MSG_QUEUE_MODE = "serialize"
    SUBUS_OAUTH_ENABLE_TLS_FINGERPRINT = True
    SUBUS_OAUTH_TLS_FINGERPRINT_PROFILE_ID = 7

# OpenAI / ChatGPT OAuth（openai 模式）配置
try:
    from config import (
        OPENAI_OAUTH_CLIENT_ID,
        OPENAI_OAUTH_CONCURRENCY,
        OPENAI_OAUTH_PRIORITY,
        OPENAI_OUTPUT_FILE,
    )
except ImportError:
    OPENAI_OAUTH_CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann"
    OPENAI_OAUTH_CONCURRENCY = 10
    OPENAI_OAUTH_PRIORITY = 1
    OPENAI_OUTPUT_FILE = "openai_accounts.json"

# openai 推送 admin API（可选；留空则只产出导入格式不推送）
try:
    from config import (
        OPENAI_API_BASE_URL,
        OPENAI_API_ADMIN_TOKEN,
        OPENAI_API_DEFAULT_GROUP_IDS,
    )
except ImportError:
    OPENAI_API_BASE_URL = ""
    OPENAI_API_ADMIN_TOKEN = ""
    OPENAI_API_DEFAULT_GROUP_IDS = []

# gptus.milus.one (Bedrock API Key) 配置（可选，bedrock 模式使用）
try:
    from config import (
        BEDROCK_API_BASE_URL,
        BEDROCK_API_ADMIN_TOKEN,
        BEDROCK_API_DEFAULT_GROUP_IDS,
        BEDROCK_API_REGIONS,
        BEDROCK_API_DEFAULT_CONCURRENCY,
        BEDROCK_API_DEFAULT_PRIORITY,
        BEDROCK_API_NAME_PREFIX,
    )
except ImportError:
    BEDROCK_API_BASE_URL = "https://gptus.milus.one"
    BEDROCK_API_ADMIN_TOKEN = ""
    BEDROCK_API_DEFAULT_GROUP_IDS = []
    BEDROCK_API_REGIONS = [
        "us-east-1", "us-east-2", "us-west-2",
        "ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
        "ap-south-1", "ap-southeast-1", "ap-southeast-2",
        "ca-central-1",
        "eu-central-1", "eu-north-1", "eu-south-1",
        "eu-west-1", "eu-west-2", "eu-west-3",
        "sa-east-1",
    ]
    BEDROCK_API_DEFAULT_CONCURRENCY = 10
    BEDROCK_API_DEFAULT_PRIORITY = 1
    BEDROCK_API_NAME_PREFIX = "aws"

# 跑完 17 个区域后追加的"强制 global"条目的 source region。
# 必须是 AWS Bedrock global. 前缀支持的 source region 之一：
# us-east-1, us-east-2, us-west-2, eu-west-1, ap-northeast-1 (Sonnet 4)；
# Sonnet 4.5/Haiku 4.5 还放开了更多 source。
try:
    from config import BEDROCK_API_GLOBAL_SOURCE_REGION
except ImportError:
    BEDROCK_API_GLOBAL_SOURCE_REGION = "eu-west-1"

_BEDROCK_DEFAULT_MODEL_MAPPING = {
    "claude-sonnet-4-5-20250929": "claude-sonnet-4-5-20250929",
    "claude-haiku-4-5-20251001":  "claude-haiku-4-5-20251001",
    "claude-opus-4-5-20251101":   "claude-opus-4-5-20251101",
    "claude-opus-4-6":            "claude-opus-4-6",
    "claude-sonnet-4-6":          "claude-sonnet-4-6",
}
try:
    from config import BEDROCK_MODEL_MAPPING
except ImportError:
    BEDROCK_MODEL_MAPPING = _BEDROCK_DEFAULT_MODEL_MAPPING

# New API (newapi.ai / new-api) 渠道管理（可选，aws-newapi 模式使用）
_NEWAPI_DEFAULT_MODEL_MAPPING_BY_GEO = {
    "us": {
        "claude-haiku-4-5":  "us.anthropic.claude-haiku-4-5-20251001-v1:0",
        "claude-opus-4-5":   "us.anthropic.claude-opus-4-5-20251101-v1:0",
        "claude-opus-4-6":   "us.anthropic.claude-opus-4-6-v1",
        "claude-sonnet-4-5": "us.anthropic.claude-sonnet-4-5-20250929-v1:0",
        "claude-sonnet-4-6": "us.anthropic.claude-sonnet-4-6",
    },
    "eu": {
        "claude-haiku-4-5":  "eu.anthropic.claude-haiku-4-5-20251001-v1:0",
        "claude-opus-4-5":   "eu.anthropic.claude-opus-4-5-20251101-v1:0",
        "claude-opus-4-6":   "eu.anthropic.claude-opus-4-6-v1",
        "claude-sonnet-4-5": "eu.anthropic.claude-sonnet-4-5-20250929-v1:0",
        "claude-sonnet-4-6": "eu.anthropic.claude-sonnet-4-6",
        "claude-opus-4-7":   "eu.anthropic.claude-opus-4-7-v1",
        "claude-opus-4-8":   "eu.anthropic.claude-opus-4-8-v1",
        "claude-fable-5":    "anthropic.claude-fable-5",
    },
    # au：Sonnet4.5 / Sonnet4.6 / Haiku4.5 / Opus4.6（比 jp 多 Opus4.6）
    "au": {
        "claude-haiku-4-5":  "au.anthropic.claude-haiku-4-5-20251001-v1:0",
        "claude-sonnet-4-5": "au.anthropic.claude-sonnet-4-5-20250929-v1:0",
        "claude-sonnet-4-6": "au.anthropic.claude-sonnet-4-6",
        "claude-opus-4-6":   "au.anthropic.claude-opus-4-6-v1",
    },
    # jp：Sonnet4.5 / Sonnet4.6 / Haiku4.5（无 Opus）
    "jp": {
        "claude-haiku-4-5":  "jp.anthropic.claude-haiku-4-5-20251001-v1:0",
        "claude-sonnet-4-5": "jp.anthropic.claude-sonnet-4-5-20250929-v1:0",
        "claude-sonnet-4-6": "jp.anthropic.claude-sonnet-4-6",
    },
    # global：AWS 文档确认 Opus4.6 / Sonnet4.6 / Sonnet4.5 / Haiku4.5
    "global": {
        "claude-haiku-4-5":  "global.anthropic.claude-haiku-4-5-20251001-v1:0",
        "claude-sonnet-4-5": "global.anthropic.claude-sonnet-4-5-20250929-v1:0",
        "claude-sonnet-4-6": "global.anthropic.claude-sonnet-4-6",
        "claude-opus-4-6":   "global.anthropic.claude-opus-4-6-v1",
    },
}
try:
    from config import (
        NEWAPI_BASE_URL,
        NEWAPI_ADMIN_TOKEN,
        NEWAPI_USER_ID,
        NEWAPI_REGIONS,
        NEWAPI_DEFAULT_GROUP,
        NEWAPI_NAME_PREFIX,
        NEWAPI_DEFAULT_PRIORITY,
    )
except ImportError:
    NEWAPI_BASE_URL = ""
    NEWAPI_ADMIN_TOKEN = ""
    NEWAPI_USER_ID = "1"
    NEWAPI_REGIONS = ["us-east-1"]
    NEWAPI_DEFAULT_GROUP = "default"
    NEWAPI_NAME_PREFIX = "aws"
    NEWAPI_DEFAULT_PRIORITY = 0

try:
    from config import NEWAPI_GLOBAL_SOURCE_REGION
except ImportError:
    NEWAPI_GLOBAL_SOURCE_REGION = "us-east-1"

try:
    from config import NEWAPI_MODEL_MAPPING_BY_GEO
except ImportError:
    NEWAPI_MODEL_MAPPING_BY_GEO = _NEWAPI_DEFAULT_MODEL_MAPPING_BY_GEO

# SSH 远程配置（可选，remote 模式使用）
try:
    from config import (
        SSH_USER, SSH_SERVERS, SSH_KEY, REMOTE_SCRIPT_PATH,
        REMOTE_PROMPT, REMOTE_INTERVAL, REMOTE_LOOP_COUNT, REMOTE_CONCURRENCY,
        REMOTE_CLAUDE_CONFIG_DIR,
    )
except ImportError:
    SSH_USER = "root"
    SSH_SERVERS = []
    SSH_KEY = "~/.ssh/id_rsa"
    REMOTE_SCRIPT_PATH = "~/repeat_claude.sh"
    REMOTE_PROMPT = "你好"
    REMOTE_INTERVAL = 300
    REMOTE_LOOP_COUNT = 0
    REMOTE_CONCURRENCY = 1
    REMOTE_CLAUDE_CONFIG_DIR = ""

try:
    from config import (
        MXROUTE_API_BASE_URL,
        MXROUTE_SERVER,
        MXROUTE_USERNAME,
        MXROUTE_API_KEY,
        MXROUTE_DEFAULT_DOMAIN,
        MXROUTE_DEFAULT_QUOTA,
        MXROUTE_DEFAULT_LIMIT,
    )
except ImportError:
    MXROUTE_API_BASE_URL = "https://api.mxroute.com"
    MXROUTE_SERVER = ""
    MXROUTE_USERNAME = ""
    MXROUTE_API_KEY = ""
    MXROUTE_DEFAULT_DOMAIN = ""
    MXROUTE_DEFAULT_QUOTA = 1024
    MXROUTE_DEFAULT_LIMIT = 9600

try:
    from config import OAUTH_ADMIN_API_BASE_URL
except ImportError:
    OAUTH_ADMIN_API_BASE_URL = "http://47.89.254.216:38080"
try:
    from config import OAUTH_ADMIN_API_TOKEN
except ImportError:
    OAUTH_ADMIN_API_TOKEN = ""
try:
    from config import OAUTH_ADMIN_API_REFRESH_TOKEN
except ImportError:
    OAUTH_ADMIN_API_REFRESH_TOKEN = ""

# claude-bind（登录后把账号加到 oauth-accounts 后台）exchange 接口的默认入参。
# 均可在 config.py 覆盖；group_ids / policy_template_id 与后台环境强相关，务必按实际填。
try:
    from config import OAUTH_BIND_INFERENCE_BACKEND
except ImportError:
    OAUTH_BIND_INFERENCE_BACKEND = "native"
try:
    from config import OAUTH_BIND_OUTBOUND_PROXY_MODE
except ImportError:
    OAUTH_BIND_OUTBOUND_PROXY_MODE = "auto"
try:
    from config import OAUTH_BIND_OUTBOUND_PROXY_ID
except ImportError:
    OAUTH_BIND_OUTBOUND_PROXY_ID = None
try:
    from config import OAUTH_BIND_MAX_RPM
except ImportError:
    OAUTH_BIND_MAX_RPM = 100
try:
    from config import OAUTH_BIND_MAX_TPM
except ImportError:
    OAUTH_BIND_MAX_TPM = 8000000
try:
    from config import OAUTH_BIND_MAX_CONCURRENT
except ImportError:
    OAUTH_BIND_MAX_CONCURRENT = 50
try:
    from config import OAUTH_BIND_MAX_SESSIONS
except ImportError:
    OAUTH_BIND_MAX_SESSIONS = 100
try:
    from config import OAUTH_BIND_GROUP_IDS
except ImportError:
    OAUTH_BIND_GROUP_IDS = ["fb637398-f209-41a5-8e64-bdbe569ac391"]
try:
    from config import OAUTH_BIND_POLICY_TEMPLATE_ID
except ImportError:
    OAUTH_BIND_POLICY_TEMPLATE_ID = "ae11cd2c-7df1-4355-b166-2db1afc21095"
