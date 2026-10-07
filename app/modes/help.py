"""命令行帮助文本"""


def print_help():
    h = """用法: python main.py <mode> '<参数>' [选项]

═══ Google 账号 ═══

  password        登录 Google 改密码
                  python main.py password 'email----password----x----totp'
                  python main.py password accounts.txt

  claude          Google OAuth 登录 Claude，提取 sessionKey → session.txt
                  python main.py claude 'email----password----x----totp'

  password-claude 先改密再登录 Claude（仅批量），结果 → session.txt
                  python main.py password-claude gmail.txt

═══ AWS 账号 ═══

  aws             登录 AWS console（有密码走 Root+TOTP，只有 AK/SK 走联邦）
                  python main.py aws 'email----pwd----totp----AKID----SAK'
                  python main.py aws 'email AKID SAK'

  aws-claude      登录 AWS → 开通 Claude Platform → 抓 api_key → aws_api_keys.txt
                  python main.py aws-claude 'email----pwd----totp----AKID----SAK'

  aws-diag        AK/SK 诊断：权限不足 vs 账号被限（纯 API，不开浏览器）
                  python main.py aws-diag 'AKID----SAK----email'

  aws-quota       AK/SK 查配额（纯 SigV4，不依赖 boto3）
                  python main.py aws-quota 'AKID----SAK----email'
                  --full 查全部  --region <code>

  aws-extract     从杂乱文本抽出 AK/SK 对 → <文件>.aksk.txt
                  python main.py aws-extract aws/kiro-aws.md

  aws-kiro        IAM Identity Center 建用户 → idc:: 行（默认 --ak 纯 API）
                  python main.py aws-kiro 'email AKID SAK' --ak
                  python main.py aws-kiro admins.txt --count 5
                  --browser 走网页  --group <组名>  --username <名>

  aws-kiro-bind   批量绑定 Kiro 订阅（纯 API）
                  python main.py aws-kiro-bind 'AKID SAK'
                  --power 开付费订阅  --group <组名>  --dry-run

  aws-newapi      AK/SK → New API Bedrock 渠道（纯 HTTP）
                  python main.py aws-newapi 'email AKID SAK'
                  --regions ...  --no-global  --dry-run

═══ Claude 登录 ═══

  session         用 sessionKey 登录 Claude（支持 cookie 文件 .crash/.json）
                  python main.py session 'sk-ant-sid02-xxx'
                  python main.py session claude/export.crash

  batch           批量检查 sessionKey 是否可用 → available.txt
                  python main.py batch session.txt

  claude-mail     真 Chrome(零自动化) 打开 claude.ai + IMAP 自动抓 magic link
                  python main.py claude-mail 'email----app_password'
                  两行格式: $'imap.nifty.com:993\\nuser@nifty.com:password'
                  --keep 保留邮件

  claude-email    Camoufox 自动化登录 Claude（自动填邮箱、抓链接、推引导、提取 sessionKey）
                  python main.py claude-email 'email----app_password'
                  批量：传文件路径即逐个处理 → python main.py claude-email accounts.txt

  claude-bind     同 claude-email，登录成功后再自动走 OAuth 授权，把账号加入 oauth-accounts 后台
                  python main.py claude-bind 'email----app_password'
                  批量：python main.py claude-bind accounts.txt
                  （或 python main.py claude-email ... --bind）
                  后台地址/鉴权复用 OAUTH_ADMIN_API_*，exchange 入参见 OAUTH_BIND_*（config.py）
                  可临时用 --admin-token=<access_token> 覆盖后台 token
                  批量文件两种布局：
                    A) 首行 IMAP 服务器，其后每行 email:password（同邮箱域共享服务器，推荐）
                         glacier.mxrouting.net:993
                         a@gonaoa.com:pwd1
                         b@gonaoa.com:pwd2
                    B) 每行一个 email----app_password（按域名推断服务器）

  chatgpt-mail    同 claude-mail，打开 ChatGPT 登录页，抓验证码 → 剪贴板
                  python main.py chatgpt-mail 'email----app_password'

═══ Kiro ═══

  kiro            kiro-cli 设备流登录 → kiro.json
                  python main.py kiro 'email----password----totp'
                  --overage [enable|disable]  --out <path>

  kiro-apikey     IDC 企业号网页登录 → 创建 API Key（ksk_）
                  python main.py kiro-apikey 'idc::https://d-xxx.awsapps.com/start----user----pwd'
                  --idc-url <url>  --key-name <名>  -c <并发>

  overage         切换 Kiro 账号超额计费开关
                  python main.py overage kiro.json [enable|disable]

  refresh         refreshToken → [{refreshToken, provider}] JSON
                  python main.py refresh tokens.txt --out refresh_tokens.json

  export-kiro     kiro.json → [{refreshToken, provider}]
                  python main.py export-kiro kiro.json --append

  import-kiro     [{refreshToken, provider}] → 完整 kiro.json 条目
                  python main.py import-kiro tokens.json --overage enable

═══ API 推送 ═══

  subus           推送 (email, api_key, workspace_id) → subus admin API
                  python main.py subus aws_api_keys.txt

  oauth           sessionKey → OAuth 授权 → subus type=oauth 账号
                  python main.py oauth 'sk-ant-sid02-xxx'
                  python main.py oauth claude/  （扫描目录）

  openai          ChatGPT OAuth 登录/刷新，产出导入格式
                  python main.py openai 'email----password----totp'
                  python main.py openai 'rt.1.AAC...'  （refresh_token 刷新）
                  --push 推送到 admin API

  bedrock         Bedrock API Key 按区域推送 → gptus admin API
                  python main.py bedrock keys.txt
                  --regions ...  --no-global

═══ 浏览器 / 邮箱 ═══

  chrome          启动真 Chrome（独立 profile，零自动化，供手动操作）
                  python main.py chrome 'a@b.com'
                  --url https://kiro.dev

  yahoo           Yahoo IMAP 读最新 Anthropic/OpenAI 邮件，提取登录链接
                  python main.py yahoo 'email----app_password'

  email           MXroute 邮箱管理（add/del/list/inbox）
                  python main.py email add user@domain.com Password123
                  python main.py email add --random 10 --domain domain.com
                  python main.py email del accounts.txt
                  python main.py email list domain.com
                  python main.py email inbox 'user@domain.com----Password123'

═══ 文件处理 ═══

  format          规范化账号文件 → email----password----totp_secret
                  python main.py format accounts.txt --write

  diff            对比账号文件与 sub2api JSON，找缺失账号 → missing.txt
                  python main.py diff normal.txt sub2api-account.json

  common          对比两个文件，找共同/差异邮箱（支持纯文本、CSV 等任意格式）
                  python main.py common a.txt b.csv
                  --only-a  --only-b  --out result.txt

  suspend         批量检查邮箱是否被封禁 → suspended.txt / normal.txt
                  python main.py suspend accounts.txt

  extract         从 session.txt 提取 sessionKey → sessionkey.txt
                  python main.py extract session.txt

  tokens          从任意格式提取 sk-ant key → tokens.txt
                  python main.py tokens raw.txt

  emails          从任意格式提取纯邮箱列表
                  python main.py emails accounts.txt --unique --out emails.txt

  disabled        从 OAuth admin API 拉取已停用账号 → disabled_emails.txt
                  python main.py disabled

═══ SSH 远程 ═══

  remote          SSH 到远程服务器执行 repeat_claude.sh
                  python main.py remote 1.2.3.4 -d ~/.claude1 auth sk-ant-xxx
                  python main.py remote 1.2.3.4 -d ~/.claude1 start '你好' 300 0
                  python main.py remote 1.2.3.4 -d ~/.claude1 stop/status/log
                  python main.py remote servers.txt -d ~/.claude1 start

═══════════════════════════════════════════════════════════════════

通用浏览器参数（claude-mail / claude-email / chatgpt-mail / chrome 等）:
  --tz=Asia/Tokyo        时区
  --locale=ja            语言/地区
  --os=macos             OS 指纹伪装（仅 Camoufox）
  --geoip=false          关闭 IP 自动同步 tz/locale（仅 Camoufox）
  --proxy=socks5://h:p   代理（覆盖 config PROXY，支持 socks5/socks5h/http）
  也可在 config.py 全局配置: BROWSER_LOCALE / BROWSER_TIMEZONE / BROWSER_OS / BROWSER_GEOIP

说明:
  - 不传 mode 时默认 password 模式
  - 密码错误会自动尝试 config.py 的 GOOGLE_NEW_PASSWORD"""

    print(h)
