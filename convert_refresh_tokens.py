#!/usr/bin/env python3.12
"""
将 {"refreshToken": "...", "provider": "Google"} 列表转换为 kiro.json 格式条目。

用法:
    python3 convert_refresh_tokens.py input.json [-o output.json] [--append kiro.json]

输入格式 (input.json):
    每行一个 JSON 对象, 或一个 JSON 数组:
    [{"refreshToken": "aor...", "provider": "Google"}, ...]

输出: 默认打印到 stdout; --append 会把新条目追加进已有 kiro.json 数组。
"""

import argparse
import json
import sys
import uuid
from datetime import datetime
from pathlib import Path


def build_entry(refresh_token: str, provider: str = "Google") -> dict:
    now = datetime.now().strftime("%Y/%m/%d %H:%M:%S")
    return {
        "id": str(uuid.uuid4()),
        "email": "",
        "password": None,
        "label": f"Kiro {provider} 账号",
        "status": "active",
        "addedAt": now,
        "accessToken": "",
        "refreshToken": refresh_token,
        "expiresAt": None,
        "provider": provider,
        "userId": None,
        "authMethod": "social",
        "clientId": None,
        "clientSecret": None,
        "region": None,
        "clientIdHash": None,
        "ssoSessionId": None,
        "idToken": None,
        "startUrl": None,
        "profileArn": None,
        "usageData": None,
        "groupId": None,
        "tagLinks": [],
        "machineId": str(uuid.uuid4()),
    }


def load_input(path: Path) -> list[dict]:
    text = path.read_text(encoding="utf-8").strip()
    if text.startswith("["):
        return json.loads(text)
    items = []
    for line in text.splitlines():
        line = line.strip().rstrip(",")
        if not line:
            continue
        items.append(json.loads(line))
    return items


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("input", type=Path, help="输入文件 (JSON 数组或每行一个对象)")
    parser.add_argument("-o", "--output", type=Path, help="输出文件 (默认 stdout)")
    parser.add_argument("--append", type=Path, help="追加到已有 kiro.json 文件")
    args = parser.parse_args()

    raw = load_input(args.input)
    new_entries = [build_entry(item["refreshToken"], item.get("provider", "Google")) for item in raw]

    if args.append:
        existing = json.loads(args.append.read_text(encoding="utf-8"))
        if not isinstance(existing, list):
            print("--append 目标不是 JSON 数组", file=sys.stderr)
            return 1
        existing.extend(new_entries)
        args.append.write_text(json.dumps(existing, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"已追加 {len(new_entries)} 条到 {args.append} (现共 {len(existing)} 条)", file=sys.stderr)
        return 0

    out = json.dumps(new_entries, ensure_ascii=False, indent=2)
    if args.output:
        args.output.write_text(out, encoding="utf-8")
        print(f"已写入 {len(new_entries)} 条到 {args.output}", file=sys.stderr)
    else:
        print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
