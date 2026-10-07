#!/usr/bin/env python3
"""
ChatGPT Team 去除个人空间流程自动化
流程: 邀请用户 → 用户接受邀请 → 用户去除个人空间 → 踢出用户
PRO20X账号加入空间后会自动退款
作者：久雾vov(fake)

使用方法:
  # 交互模式
  python3 pro20x.py

  # 文件模式 (推荐，避免终端粘贴问题)
  python3 pro20x.py --admin-at admin_token.txt --user-at user_token.txt

  # 也可以直接传 token 字符串
  python3 pro20x.py --admin-at "eyJ..." --user-at "eyJ..."

  # 用户已在团队中，跳过邀请和接受邀请（步骤1、2）
  python3 pro20x.py --admin-at admin_token.txt --user-at user_token.txt --skip-invite
"""

import requests
import json
import base64
import time
import sys
import argparse
import os

# ============ 通用配置 ============

BASE_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "*/*",
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/26.5 Safari/605.1.15",
    "Origin": "https://chatgpt.com",
    "Referer": "https://chatgpt.com/",
    "oai-language": "zh-CN",
}

BASE_URL = "https://chatgpt.com/backend-api"

# ============ 工具函数 ============

def decode_jwt(token: str) -> dict:
    """解码 JWT payload（不验证签名）"""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("无效的 JWT 格式")
    
    payload = parts[1]
    padding = 4 - len(payload) % 4
    if padding != 4:
        payload += "=" * padding
    
    decoded = base64.urlsafe_b64decode(payload)
    return json.loads(decoded)


def get_user_info(at: str) -> dict:
    """从 AT 中提取用户信息"""
    payload = decode_jwt(at)
    
    auth_info = payload.get("https://api.openai.com/auth", {})
    profile = payload.get("https://api.openai.com/profile", {})
    
    return {
        "user_id": auth_info.get("chatgpt_user_id"),
        "email": profile.get("email"),
        "name": profile.get("name"),
        "account_id": auth_info.get("chatgpt_account_id"),
        "plan_type": auth_info.get("chatgpt_plan_type"),
    }


def make_headers(at: str, account_id: str = None) -> dict:
    """构造请求头"""
    headers = BASE_HEADERS.copy()
    headers["Authorization"] = f"Bearer {at}"
    if account_id:
        headers["chatgpt-account-id"] = account_id
    return headers


# ============ 步骤函数 ============

def step1_invite(admin_at: str, team_account_id: str, email: str) -> dict:
    """步骤1: 母号邀请用户"""
    print(f"\n[步骤1] 邀请 {email} 加入团队...")
    
    url = f"{BASE_URL}/accounts/{team_account_id}/invites"
    headers = make_headers(admin_at, team_account_id)
    
    payload = {
        "email_addresses": [email],
        "role": "standard-user",
        "seat_type": "default"
    }
    
    resp = requests.post(url, headers=headers, json=payload)
    print(f"  状态: {resp.status_code}")
    
    if resp.status_code == 200:
        data = resp.json()
        print(f"  响应: {json.dumps(data, ensure_ascii=False, indent=2)}")
        return data
    else:
        print(f"  错误: {resp.text}")
        return None


def step2_accept_invite(user_at: str, team_account_id: str, user_id: str) -> dict:
    """步骤2: 用户接受邀请"""
    print(f"\n[步骤2] 用户接受邀请...")
    
    url = f"{BASE_URL}/accounts/{team_account_id}/invites/accept"
    headers = make_headers(user_at)
    
    payload = {
        "accepted_tos_version": "2024-12-17"
    }

    resp = requests.post(url, headers=headers, json=payload)
    print(f"  状态: {resp.status_code}")
    print(f"  响应: {resp.text}")
    return resp.json() if resp.status_code == 200 else None


def step3_remove_personal_space(user_at: str, team_account_id: str) -> dict:
    """步骤3: 去除个人空间（账户转移）"""
    print(f"\n[步骤3] 去除个人空间...")
    
    url = f"{BASE_URL}/accounts/transfer"
    headers = make_headers(user_at, team_account_id)
    
    # 服务器要求 body 里必须有 workspace_id（422 报错得知）
    payload = {
        "workspace_id": team_account_id
    }
    
    resp = requests.post(url, headers=headers, json=payload)
    print(f"  状态: {resp.status_code}")
    print(f"  响应: {resp.text}")
    return resp.json() if resp.status_code == 200 else None


def check_user_in_team(admin_at: str, team_account_id: str, user_id: str) -> bool:
    """查询团队成员列表，确认目标用户是否已在团队中"""
    print(f"\n[检查] 查询团队成员，确认 {user_id} 是否已在团队...")

    url = f"{BASE_URL}/accounts/{team_account_id}/users"
    headers = make_headers(admin_at, team_account_id)

    resp = requests.get(url, headers=headers)
    print(f"  状态: {resp.status_code}")

    if resp.status_code != 200:
        print(f"  错误: {resp.text}")
        return False

    try:
        data = resp.json()
    except Exception:
        print(f"  无法解析响应: {resp.text}")
        return False

    # 兼容不同返回结构
    items = data.get("items") or data.get("users") or data.get("account_users") or []
    if isinstance(data, list):
        items = data

    for u in items:
        uid = (
            u.get("user_id")
            or u.get("id")
            or (u.get("user") or {}).get("id")
            or (u.get("user") or {}).get("user_id")
        )
        if uid == user_id:
            print(f"  ✓ 用户已在团队中")
            return True

    print(f"  ✗ 用户不在团队成员列表中 (共 {len(items)} 人)")
    return False


def step4_kick_user(admin_at: str, team_account_id: str, user_id: str) -> dict:
    """步骤4: 踢出用户"""
    print(f"\n[步骤4] 踢出用户 {user_id}...")
    
    url = f"{BASE_URL}/accounts/{team_account_id}/users/{user_id}"
    headers = make_headers(admin_at, team_account_id)
    
    resp = requests.delete(url, headers=headers)
    print(f"  状态: {resp.status_code}")
    print(f"  响应: {resp.text}")
    return resp.json() if resp.status_code == 200 else None


# ============ 主流程 ============

def read_token(value: str) -> str:
    """读取 token：支持 JSON 文件(.json 读 accessToken 字段)、纯文本文件、或直接传 token 字符串"""
    if os.path.isfile(value):
        with open(value, "r") as f:
            content = f.read().strip()
        if value.endswith(".json"):
            data = json.loads(content)
            if "accessToken" not in data:
                print(f"错误: JSON 文件 {value} 中没有 accessToken 字段")
                sys.exit(1)
            return data["accessToken"]
        return content
    return value.strip()


def main():
    parser = argparse.ArgumentParser(description="ChatGPT 去除个人空间自动化")
    parser.add_argument("--admin-at", help="母号 AT (token 字符串或文件路径)")
    parser.add_argument("--user-at", help="用户 AT (token 字符串或文件路径)")
    parser.add_argument("-y", "--yes", action="store_true", help="跳过确认直接执行")
    parser.add_argument("--skip-invite", action="store_true", help="跳过邀请和接受邀请（步骤1、2），仅当用户已在团队中")
    args = parser.parse_args()

    print("=" * 50)
    print("ChatGPT 去除个人空间自动化")
    print("=" * 50)

    # 获取母号 AT
    if args.admin_at:
        admin_at = read_token(args.admin_at)
    else:
        admin_at = input("\n请输入母号 (管理员) AT: ").strip()
    if not admin_at:
        print("错误: 母号 AT 不能为空")
        sys.exit(1)

    # 解析母号信息
    try:
        admin_info = get_user_info(admin_at)
    except Exception as e:
        print(f"解析母号 AT 失败: {e}")
        sys.exit(1)

    team_account_id = admin_info["account_id"]
    print(f"  母号: {admin_info['name']} ({admin_info['email']})")
    print(f"  团队ID: {team_account_id}")
    print(f"  计划: {admin_info['plan_type']}")

    # 获取用户 AT
    if args.user_at:
        user_at = read_token(args.user_at)
    else:
        user_at = input("\n请输入用户 AT: ").strip()
    if not user_at:
        print("错误: 用户 AT 不能为空")
        sys.exit(1)

    # 解析用户信息
    try:
        user_info = get_user_info(user_at)
    except Exception as e:
        print(f"解析用户 AT 失败: {e}")
        sys.exit(1)
    
    print(f"  用户: {user_info['name']} ({user_info['email']})")
    print(f"  用户ID: {user_info['user_id']}")
    print(f"  当前计划: {user_info['plan_type']}")
    
    print("\n" + "=" * 50)
    print("即将执行:")
    if args.skip_invite:
        print(f"  1. [跳过] 邀请 {user_info['email']} 加入团队")
        print(f"  2. [跳过] 用户接受邀请")
    else:
        print(f"  1. 邀请 {user_info['email']} 加入团队")
        print(f"  2. 用户接受邀请")
    print(f"  3. 用户去除个人空间")
    print(f"  4. 踢出用户")
    print("=" * 50)
    
    if not args.yes:
        confirm = input("\n确认执行? (yes/no): ").strip().lower()
        if confirm != "yes":
            print("已取消")
            sys.exit(0)
    
    # 执行流程
    if args.skip_invite:
        print("\n[步骤1、2] 已跳过邀请与接受邀请")
        if not check_user_in_team(admin_at, team_account_id, user_info["user_id"]):
            print("\n❌ 用户不在团队中，无法跳过邀请。请去掉 --skip-invite 重新运行")
            sys.exit(1)
    else:
        # 步骤1
        result = step1_invite(admin_at, team_account_id, user_info["email"])
        if not result:
            print("\n❌ 邀请失败，终止")
            sys.exit(1)

        print("\n⏳ 等待3秒...")
        time.sleep(3)

        # 步骤2
        result = step2_accept_invite(user_at, team_account_id, user_info["user_id"])
        if not result:
            print("\n❌ 接受邀请失败，终止")
            sys.exit(1)

        print("\n⏳ 等待2秒...")
        time.sleep(2)
    
    # 步骤3
    result = step3_remove_personal_space(user_at, team_account_id)
    if not result:
        print("\n❌ 去除个人空间失败，终止")
        sys.exit(1)
    
    print("\n⏳ 等待5秒...")
    time.sleep(5)
    
    # 步骤4
    result = step4_kick_user(admin_at, team_account_id, user_info["user_id"])
    if not result:
        print("\n❌ 踢出失败，终止")
        sys.exit(1)
    
    print("\n" + "=" * 50)
    print("✅ 全部完成")
    print(f"  用户 {user_info['email']} 已被去除个人空间并踢出团队")
    print("=" * 50)


if __name__ == "__main__":
    main()
