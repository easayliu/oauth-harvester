# ═══════════════════════════════════════════════════════════════════
# 基础配置
# ═══════════════════════════════════════════════════════════════════

HEADLESS = True                  # True=无头模式  False=可视化调试
PROXY = ""                       # 代理，如 "socks5://host:port" 或 "http://user:pass@host:port"
PROXY_TEST_URL = "https://api.ipify.org"                                      # 测代理出口 IP 的地址（纯文本返回 IP）
CAPSOLVER_API_KEY = ""           # CapSolver 打码（过 AWS WAF）；留空=手工点 Verify
USE_SYSTEM_CHROME = True         # True=系统 Chrome（反检测最佳）  False=Playwright 自带 Chromium

# ═══════════════════════════════════════════════════════════════════
# 浏览器指纹 / 地区 / 后端
# ─────────────────────────────────────────────────────────────────
# 所有浏览器模式（claude-mail/claude-email/chrome/kiro/aws 等）通用。
# 命令行可逐次覆盖：--tz=Asia/Tokyo --locale=ja --os=macos --geoip=false --proxy=socks5://...
# ═══════════════════════════════════════════════════════════════════

BROWSER_LOCALE   = "en-US"       # 语言/地区（en-US / ja / zh-CN / de-DE …）
BROWSER_TIMEZONE = ""            # 时区（Asia/Tokyo / America/New_York …）；留空=系统/geoip 自动
BROWSER_OS       = "windows"     # Camoufox OS 指纹（windows / macos / linux）
BROWSER_GEOIP    = True          # 按出口 IP 自动同步 timezone/locale/WebRTC（Camoufox 专用）

# 后端选择（环境变量 KIRO_BROWSER_BACKEND 可临时覆盖）
# camoufox : stealth Firefox（默认，过 Google "browser may not be secure" 最稳）
# cloak    : CloakBrowser stealth Chromium
# webkit   : Playwright WebKit（Safari 引擎）
# safari   : 真 Safari via safaridriver
# botbrowser: BotBrowser（patched Chromium，源码级指纹伪装）
KIRO_BROWSER_BACKEND = "camoufox"

# BotBrowser 后端所需外部资产（仅 backend=botbrowser 时生效）
BOTBROWSER_EXEC_PATH    = ""     # 内核路径，如 "/Applications/Chromium.app/Contents/MacOS/Chromium"
BOTBROWSER_PROFILE_PATH = ""     # .enc 指纹 profile；留空退化为普通 Chromium

# Profile 磁盘管理（创建新 profile 前按 LRU 清理最旧的）
KIRO_PROFILE_MIN_FREE_GB  = 15.0   # 磁盘可用低于此值就删最旧 profile
KIRO_PROFILE_MAX_COUNT    = 0      # 每个 root 最多保留几个 profile；0=不限
KIRO_PROFILE_ACTIVE_TTL_S = 3600   # 近 N 秒活跃的 profile 不删

# ═══════════════════════════════════════════════════════════════════
# Google 账号
# ═══════════════════════════════════════════════════════════════════

GOOGLE_NEW_PASSWORD = "your-new-password"

# ═══════════════════════════════════════════════════════════════════
# AWS IAM Identity Center（aws-kiro 模式）
# ─────────────────────────────────────────────────────────────────
# 登录 AWS 后在 IAM Identity Center 自动建用户、Amazon Q 授予 Kiro 订阅
# ═══════════════════════════════════════════════════════════════════

KIRO_IDC_NEW_PASSWORD     = "Kiro-Idc-New-2026!"    # IDC 首次强制改密（≥8 位、大小写/数字/符号）
AWS_IDC_INSTANCE_ID       = ""                       # 留空=从 SSO 控制台 URL 自动探测
AWS_IDC_REGION            = "us-east-1"
AWS_IDC_EMAIL_DOMAIN      = "example.com"            # 自动生成的用户邮箱域名
AWS_IDC_USERNAME_PREFIX   = "kiro"                   # 用户名前缀：<prefix>-<随机>
AWS_IDC_KIRO_OUTPUT_FILE  = "kiro_idc_users.txt"     # 产出 idc:: 行的文件
AWS_IDC_GROUP             = ""                       # 建好用户后加入的群组名（留空=不加）
AWS_IDC_USERNAME          = ""                       # 完全自定义用户名（逗号分隔）；--username 优先

# ═══════════════════════════════════════════════════════════════════
# Claude Console IMAP
# ─────────────────────────────────────────────────────────────────
# AWS → Claude Platform 激活后，从邮件里抓 console.anthropic.com 的 magic link
# ═══════════════════════════════════════════════════════════════════

CLAUDE_CONSOLE_EMAIL     = ""
CLAUDE_CONSOLE_IMAP_HOST = ""
CLAUDE_CONSOLE_IMAP_PORT = 993
CLAUDE_CONSOLE_IMAP_USER = ""
CLAUDE_CONSOLE_IMAP_PASS = ""

# ═══════════════════════════════════════════════════════════════════
# Subus Admin API（aws 模式推送 api_key + workspace_id）
# ═══════════════════════════════════════════════════════════════════

SUBUS_API_BASE_URL              = "https://subus.milus.one"
SUBUS_API_ADMIN_TOKEN           = ""           # 留空=跳过推送
SUBUS_API_DEFAULT_GROUP_IDS     = [21]
SUBUS_API_DEFAULT_AWS_REGION    = "us-east-1"
SUBUS_API_DEFAULT_CONCURRENCY   = 10
SUBUS_API_DEFAULT_PRIORITY      = 1
SUBUS_API_DEFAULT_BASE_RPM      = 15
SUBUS_API_DEFAULT_RPM_STRATEGY  = "tiered"
SUBUS_API_DEFAULT_RPM_STICKY_BUFFER = 10
SUBUS_API_DEFAULT_NOTES         = ""
SUBUS_API_DEFAULT_PROXY_ID      = 0
SUBUS_API_DEFAULT_LOAD_FACTOR   = 0
SUBUS_API_DEFAULT_RATE_MULTIPLIER = 1
SUBUS_API_DEFAULT_STATUS        = "active"
SUBUS_API_DEFAULT_EXPIRES_AT    = 0
SUBUS_API_DEFAULT_AUTO_PAUSE_ON_EXPIRED = True
SUBUS_API_DEFAULT_TEMP_UNSCHEDULABLE_ENABLED = True
SUBUS_API_DEFAULT_TEMP_UNSCHEDULABLE_RULES = [
    {"error_code": 429, "keywords": ["would exceed your organization", "tokens per minute"],
     "duration_minutes": 2, "description": ""},
]

# --- Subus OAuth 模式（python main.py oauth）--- type=oauth 账号
SUBUS_OAUTH_DEFAULT_GROUP_IDS          = [20]
SUBUS_OAUTH_CONCURRENCY               = 10
SUBUS_OAUTH_PRIORITY                   = 1
SUBUS_OAUTH_RATE_MULTIPLIER            = 1
SUBUS_OAUTH_MAX_DEVICES                = 3
SUBUS_OAUTH_DEVICE_IDLE_TIMEOUT_MINUTES = 5
SUBUS_OAUTH_BASE_RPM                   = 10
SUBUS_OAUTH_RPM_STRATEGY               = "tiered"
SUBUS_OAUTH_USER_MSG_QUEUE_MODE         = "serialize"
SUBUS_OAUTH_ENABLE_TLS_FINGERPRINT      = True
SUBUS_OAUTH_TLS_FINGERPRINT_PROFILE_ID  = 7

# ═══════════════════════════════════════════════════════════════════
# OpenAI / ChatGPT OAuth（python main.py openai）
# ═══════════════════════════════════════════════════════════════════

OPENAI_OAUTH_CLIENT_ID      = "app_EMoamEEZ73f0CkXaXp7hrann"   # Codex CLI client_id
OPENAI_OAUTH_CONCURRENCY    = 10
OPENAI_OAUTH_PRIORITY       = 1
OPENAI_OUTPUT_FILE          = "openai_accounts.json"
# 可选推送（加 --push 时生效）；留空=只产出不推送
OPENAI_API_BASE_URL         = ""
OPENAI_API_ADMIN_TOKEN      = ""
OPENAI_API_DEFAULT_GROUP_IDS = []

# ═══════════════════════════════════════════════════════════════════
# Bedrock API Key（python main.py bedrock → gptus.milus.one）
# ═══════════════════════════════════════════════════════════════════

BEDROCK_API_BASE_URL           = "https://gptus.milus.one"
BEDROCK_API_ADMIN_TOKEN        = ""
BEDROCK_API_DEFAULT_GROUP_IDS  = []
BEDROCK_API_DEFAULT_CONCURRENCY = 10
BEDROCK_API_DEFAULT_PRIORITY   = 1
BEDROCK_API_NAME_PREFIX        = "aws"
BEDROCK_API_GLOBAL_SOURCE_REGION = "eu-west-1"   # global. 前缀的 source region
BEDROCK_API_REGIONS = [
    "us-east-1", "us-east-2", "us-west-1", "us-west-2", "ca-central-1",       # US
    "eu-central-1", "eu-central-2", "eu-north-1",                              # EU
    "eu-south-1", "eu-south-2", "eu-west-1", "eu-west-2", "eu-west-3",
    "ap-southeast-2",                                                           # AU
]

# ═══════════════════════════════════════════════════════════════════
# New API 渠道管理（python main.py aws-newapi）
# ─────────────────────────────────────────────────────────────────
# 把 AWS AK/SK 注册成 New API 的 Bedrock 渠道（type=33, key=ak|sk|region）
# ═══════════════════════════════════════════════════════════════════

NEWAPI_BASE_URL          = "https://your-newapi.example.com"
NEWAPI_ADMIN_TOKEN       = ""        # 系统访问令牌（管理员「个人设置→安全设置」生成）
NEWAPI_USER_ID           = "1"       # 令牌所属用户 id
NEWAPI_DEFAULT_GROUP     = "default"
NEWAPI_NAME_PREFIX       = "aws"
NEWAPI_DEFAULT_PRIORITY  = 0
NEWAPI_GLOBAL_SOURCE_REGION = "us-east-1"
NEWAPI_REGIONS = ["us-east-1"]
NEWAPI_MODEL_MAPPING_BY_GEO = {
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
    "au": {
        "claude-haiku-4-5":  "au.anthropic.claude-haiku-4-5-20251001-v1:0",
        "claude-sonnet-4-5": "au.anthropic.claude-sonnet-4-5-20250929-v1:0",
        "claude-sonnet-4-6": "au.anthropic.claude-sonnet-4-6",
        "claude-opus-4-6":   "au.anthropic.claude-opus-4-6-v1",
    },
    "jp": {
        "claude-haiku-4-5":  "jp.anthropic.claude-haiku-4-5-20251001-v1:0",
        "claude-sonnet-4-5": "jp.anthropic.claude-sonnet-4-5-20250929-v1:0",
        "claude-sonnet-4-6": "jp.anthropic.claude-sonnet-4-6",
    },
    "global": {
        "claude-haiku-4-5":  "global.anthropic.claude-haiku-4-5-20251001-v1:0",
        "claude-sonnet-4-5": "global.anthropic.claude-sonnet-4-5-20250929-v1:0",
        "claude-sonnet-4-6": "global.anthropic.claude-sonnet-4-6",
        "claude-opus-4-6":   "global.anthropic.claude-opus-4-6-v1",
    },
}

# ═══════════════════════════════════════════════════════════════════
# OAuth Admin API（disabled 模式：获取已停用的 oauth 账号）
# ═══════════════════════════════════════════════════════════════════

OAUTH_ADMIN_API_BASE_URL      = "http://47.89.254.216:38080"
OAUTH_ADMIN_API_TOKEN         = ""    # access_token（15min 有效），留空自动用 refresh_token 刷新
OAUTH_ADMIN_API_REFRESH_TOKEN = ""    # 从浏览器 Cookie 复制（7 天有效）

# claude-bind 模式：claude-email 登录成功后，自动走 OAuth 授权并把账号加到后台（exchange 接口默认入参）
# base_url / token / refresh_token 复用上面的 OAUTH_ADMIN_API_*；group_ids、policy_template_id 必须按后台实际填
OAUTH_BIND_INFERENCE_BACKEND   = "native"
OAUTH_BIND_OUTBOUND_PROXY_MODE = "auto"
OAUTH_BIND_OUTBOUND_PROXY_ID   = None
OAUTH_BIND_MAX_RPM             = 100
OAUTH_BIND_MAX_TPM             = 8000000
OAUTH_BIND_MAX_CONCURRENT      = 50
OAUTH_BIND_MAX_SESSIONS        = 100
OAUTH_BIND_GROUP_IDS           = ["fb637398-f209-41a5-8e64-bdbe569ac391"]
OAUTH_BIND_POLICY_TEMPLATE_ID  = "ae11cd2c-7df1-4355-b166-2db1afc21095"

# ═══════════════════════════════════════════════════════════════════
# MXroute 邮箱 API（python main.py email）
# ═══════════════════════════════════════════════════════════════════

MXROUTE_API_BASE_URL    = "https://api.mxroute.com"
MXROUTE_SERVER          = ""         # 邮件服务器，如 eagle.mxlogin.com
MXROUTE_USERNAME        = ""         # DirectAdmin 用户名
MXROUTE_API_KEY         = ""         # https://panel.mxroute.com/api-keys.php 创建
MXROUTE_DEFAULT_DOMAIN  = ""         # 默认域名（add/del/list 未指定 --domain 时使用）
MXROUTE_DEFAULT_QUOTA   = 1024       # 新邮箱配额 MB（0=不限）
MXROUTE_DEFAULT_LIMIT   = 9600       # 每日发送上限（最大 9600）

# ═══════════════════════════════════════════════════════════════════
# SSH 远程（python main.py remote）
# ═══════════════════════════════════════════════════════════════════

SSH_USER    = "root"
SSH_SERVERS = []                     # IP / user@host / user@host:port
SSH_KEY     = "~/.ssh/id_rsa"
REMOTE_SCRIPT_PATH       = "~/repeat_claude.sh"
REMOTE_PROMPT            = "你好"
REMOTE_INTERVAL          = 300
REMOTE_LOOP_COUNT        = 0
REMOTE_CONCURRENCY       = 1
REMOTE_CLAUDE_CONFIG_DIR = ""        # 留空不传，如 ~/.claude1
