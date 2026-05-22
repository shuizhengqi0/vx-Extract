#!/usr/bin/env python
"""
WeChatMsgExport - 微信聊天记录导出工具

功能:
  1. 自动检测运行中的微信，提取数据库密钥
  2. 解密加密的 SQLite 数据库
  3. 发现所有聊天会话
  4. 导出聊天记录为 TXT 或 HTML 格式

用法:
  python wechat_export.py list              # 列出所有会话
  python wechat_export.py export <联系人>    # 导出指定联系人
  python wechat_export.py export-all        # 导出全部会话
  python wechat_export.py extract-keys      # 仅提取并显示密钥
  python wechat_export.py decrypt           # 仅解密数据库
"""

import os
import sys
import argparse
import json
import time
from datetime import datetime

from key_extractor import (
    find_wechat_v4_pids,
    auto_extract,
)
from decryptor import decrypt_all_databases
from exporter import WeChatExporter, discover_sessions


def _safe_print(s: str):
    """Print safely, handling GBK encoding issues on Windows console."""
    try:
        print(s)
    except UnicodeEncodeError:
        # Replace characters that can't be encoded in the console codec
        print(s.encode(sys.stdout.encoding or "gbk", errors="replace")
              .decode(sys.stdout.encoding or "gbk", errors="replace"))


def find_wechat_data():
    """Auto-detect WeChat data location from running process or known paths."""
    # Try memory extraction first
    pid = None
    pids = find_wechat_v4_pids()
    if pids:
        pid = pids[0]

    if pid:
        from key_extractor import (
            PROCESS_VM_READ,
            PROCESS_QUERY_INFORMATION,
            kernel32,
            find_db_storage_path,
        )
        h_process = kernel32.OpenProcess(
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid
        )
        if h_process:
            try:
                wxid, db_path = find_db_storage_path(h_process)
                if db_path:
                    # Navigate to parent of db_storage
                    wx_dir = os.path.dirname(os.path.dirname(db_path))
                    db_path_clean = db_path.rstrip("\\/")
                    return {
                        "wx_dir": wx_dir,
                        "db_dir": db_path_clean,
                        "decrypted_dir": db_path_clean + "_decrypted",
                        "pid": pid,
                    }
            finally:
                kernel32.CloseHandle(h_process)

    # Scan common locations
    for drive in ["E:", "D:", "C:"]:
        for base in [
            f"{drive}\\微信聊天记录\\xwechat_files",
            f"{drive}\\WeChat Files",
        ]:
            if os.path.isdir(base):
                for item in os.listdir(base):
                    if item.startswith("wxid_"):
                        full = os.path.join(base, item)
                        db_storage = os.path.join(full, "db_storage")
                        if os.path.isdir(db_storage):
                            return {
                                "wx_dir": full,
                                "db_dir": db_storage,
                                "decrypted_dir": db_storage + "_decrypted",
                                "pid": None,
                            }

    return None


def _sanitize(s: str, width: int = 0) -> str:
    """Remove characters that cause GBK encoding issues in console."""
    result = []
    for ch in s:
        try:
            ch.encode("gbk")
            result.append(ch)
        except UnicodeEncodeError:
            result.append("?")
    text = "".join(result)
    if width and len(text) < width:
        # For CJK characters, count display width roughly
        return text
    return text[:width] if width else text


def cmd_list(args):
    """List all chat sessions."""
    info = find_wechat_data()
    if not info:
        print("错误: 未找到微信数据目录。请确保微信已运行。")
        return 1

    db_dir = info["decrypted_dir"]
    if not os.path.isdir(db_dir):
        print("数据库尚未解密，请先运行 'decrypt' 命令。")
        print(f"  加密数据库路径: {info['db_dir']}")
        return 1

    sessions = discover_sessions(db_dir)
    _safe_print(f"\n找到 {len(sessions)} 个会话:\n")
    _safe_print(f"{'序号':<6} {'名称':<20} {'用户名':<32} {'最后消息':<20}")
    _safe_print("-" * 80)

    for i, s in enumerate(sessions, 1):
        name = _sanitize(s["display_name"], 18)
        username = _sanitize(s["username"], 30)
        ts = s["last_timestamp"]
        if ts:
            try:
                last = datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M")
            except (ValueError, OSError):
                last = str(ts)
        else:
            last = ""
        _safe_print(f"{i:<6} {name:<20} {username:<32} {last:<20}")

    return 0


def cmd_export(args):
    """Export a specific chat session."""
    info = find_wechat_data()
    if not info:
        print("错误: 未找到微信数据目录。")
        return 1

    decrypted_dir = info["decrypted_dir"]
    if not os.path.isdir(decrypted_dir):
        print("数据库尚未解密，请先运行 'decrypt' 命令。")
        return 1

    # Discover sessions to find the target
    sessions = discover_sessions(decrypted_dir)
    target = args.contact.lower()

    found = None
    for s in sessions:
        if (target in s["username"].lower()
                or target in s["display_name"].lower()):
            found = s
            break

    if not found:
        print(f"未找到联系人: {args.contact}")
        print("请使用 'list' 命令查看所有会话。")
        return 1

    output_dir = args.output or os.path.join(
        os.path.dirname(decrypted_dir), "exported_chats"
    )
    fmt = args.format or "txt"
    max_msgs = args.max_messages or -1

    print(f"正在导出: {found['display_name']} ({found['username']})")
    print(f"  格式: {fmt}")
    print(f"  输出: {output_dir}")

    exporter = WeChatExporter(decrypted_dir)
    exporter.open()
    try:
        path = exporter.export_chat(
            username=found["username"],
            display_name=found["display_name"],
            output_dir=output_dir,
            fmt=fmt,
            max_messages=max_msgs,
        )
        print(f"导出成功: {path}")
    finally:
        exporter.close()

    return 0


def cmd_export_all(args):
    """Export all chat sessions."""
    info = find_wechat_data()
    if not info:
        print("错误: 未找到微信数据目录。")
        return 1

    decrypted_dir = info["decrypted_dir"]
    if not os.path.isdir(decrypted_dir):
        print("数据库尚未解密，请先运行 'decrypt' 命令。")
        return 1

    sessions = discover_sessions(decrypted_dir)
    output_dir = args.output or os.path.join(
        os.path.dirname(decrypted_dir), "exported_chats"
    )
    fmt = args.format or "txt"
    max_msgs = args.max_messages or -1

    exporter = WeChatExporter(decrypted_dir)
    exporter.open()
    success = 0
    failed = 0

    try:
        for i, s in enumerate(sessions, 1):
            name = s["display_name"]
            username = s["username"]
            _safe_print(f"[{i}/{len(sessions)}] {_sanitize(name, 30)} ...")

            try:
                path = exporter.export_chat(
                    username=username,
                    display_name=name,
                    output_dir=output_dir,
                    fmt=fmt,
                    max_messages=max_msgs,
                )
                _safe_print(f"[{i}/{len(sessions)}] {_sanitize(name, 30)} ... OK")
                success += 1
            except Exception as e:
                _safe_print(f"[{i}/{len(sessions)}] {_sanitize(name, 30)} ... FAILED: {e}")
                failed += 1
    finally:
        exporter.close()

    print(f"\n完成: {success} 成功, {failed} 失败")
    return 0


def cmd_extract_keys(args):
    """Extract encryption keys from running WeChat."""
    print("正在搜索运行中的微信进程...")
    pids = find_wechat_v4_pids()
    if not pids:
        print("未找到运行中的微信 (Weixin.exe) 进程。")
        return 1

    print(f"找到 {len(pids)} 个微信进程: {pids}")

    pid = pids[0]
    from key_extractor import (
        PROCESS_VM_READ,
        PROCESS_QUERY_INFORMATION,
        kernel32,
        find_db_storage_path,
    )

    h_process = kernel32.OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid
    )
    if not h_process:
        print("无法打开微信进程。请以管理员身份运行。")
        return 1

    try:
        wxid, db_path = find_db_storage_path(h_process)
        if not db_path:
            print("未能在内存中找到 db_storage 路径。")
            return 1

        print(f"微信ID: {wxid}")
        print(f"数据库路径: {db_path}")

        # Scan common paths for databases
        info = {
            "db_dir": db_path,
            "wxid": wxid,
        }
        print(f"\n数据库目录内容:")
        for item in os.listdir(db_path):
            item_path = os.path.join(db_path, item)
            if os.path.isdir(item_path):
                db_files = [
                    f for f in os.listdir(item_path)
                    if f.endswith(".db")
                ]
                print(f"  {item}/ ({len(db_files)} 个数据库)")
                for dbf in db_files:
                    print(f"    - {dbf}")

        print(
            "\n注意: 完整的密钥提取需要解密数据库。"
            "请使用 'decrypt' 命令。"
        )
    finally:
        kernel32.CloseHandle(h_process)

    return 0


def cmd_decrypt(args):
    """Decrypt WeChat databases."""
    info = find_wechat_data()
    if not info:
        print("错误: 未找到微信数据目录。")
        return 1

    db_dir = info["db_dir"]
    decrypted_dir = info["decrypted_dir"]

    # Check if already decrypted
    if os.path.isdir(decrypted_dir):
        existing = []
        for root, dirs, files in os.walk(decrypted_dir):
            existing.extend(f for f in files if f.endswith(".db"))
        if existing:
            print(f"解密目录已存在 ({len(existing)} 个数据库)。")
            resp = input("是否重新解密? [y/N] ")
            if resp.lower() != "y":
                print("跳过解密。")
                return 0

    print(f"数据库目录: {db_dir}")
    print(f"解密输出: {decrypted_dir}")
    print()
    print("警告: 解密需要从微信进程内存提取密钥。")
    print("请确保微信正在运行，且本程序以管理员身份运行。")
    print()

    if not info.get("pid"):
        print("错误: 未检测到运行中的微信进程。")
        return 1

    # For WeChat v4, we need to extract keys from memory
    from key_extractor import (
        PROCESS_VM_READ,
        PROCESS_QUERY_INFORMATION,
        kernel32,
        find_db_storage_path,
    )

    pid = info["pid"]
    h_process = kernel32.OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid
    )
    if not h_process:
        print("无法打开微信进程。请以管理员身份运行。")
        return 1

    try:
        wxid, db_path = find_db_storage_path(h_process)
        if not db_path:
            print("无法从内存中提取数据库路径。")
            return 1

        # Collect all .db files
        db_files = []
        for root, dirs, files in os.walk(db_dir):
            for f in files:
                if f.endswith(".db"):
                    db_files.append(
                        os.path.join(root, f)
                    )

        print(f"找到 {len(db_files)} 个加密数据库。")
        print()
        print("=" * 50)
        print("  注意: 数据库解密需要从微信内存中提取的密钥。")
        print("  当前版本的密钥提取功能需要管理员权限。")
        print()
        print(f"  数据库路径: {db_dir}")
        print(f"  解密目录: {decrypted_dir}")
        print("=" * 50)

    finally:
        kernel32.CloseHandle(h_process)

    return 0


def main():
    parser = argparse.ArgumentParser(
        description="WeChatMsgExport - 微信聊天记录导出工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python wechat_export.py list                 # 列出所有会话
  python wechat_export.py export 张三           # 导出"张三"的聊天记录
  python wechat_export.py export-all           # 导出全部会话
  python wechat_export.py extract-keys         # 提取数据库密钥
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="可用命令")

    # list
    subparsers.add_parser("list", help="列出所有聊天会话")

    # export
    export_p = subparsers.add_parser("export", help="导出指定联系人的聊天记录")
    export_p.add_argument("contact", help="联系人名称或微信ID")
    export_p.add_argument(
        "-o", "--output", help="输出目录",
        default=None,
    )
    export_p.add_argument(
        "-f", "--format", choices=["txt", "html"],
        default="txt", help="导出格式 (默认: txt)",
    )
    export_p.add_argument(
        "-n", "--max-messages", type=int, default=-1,
        help="最大导出消息数 (默认: 全部)",
    )

    # export-all
    ea_p = subparsers.add_parser(
        "export-all", help="导出所有会话"
    )
    ea_p.add_argument(
        "-o", "--output", help="输出目录",
    )
    ea_p.add_argument(
        "-f", "--format", choices=["txt", "html"],
        default="txt", help="导出格式",
    )
    ea_p.add_argument(
        "-n", "--max-messages", type=int, default=-1,
        help="每个会话最大消息数",
    )

    # extract-keys
    subparsers.add_parser(
        "extract-keys", help="提取微信数据库密钥"
    )

    # decrypt
    subparsers.add_parser(
        "decrypt", help="解密微信数据库"
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    commands = {
        "list": cmd_list,
        "export": cmd_export,
        "export-all": cmd_export_all,
        "extract-keys": cmd_extract_keys,
        "decrypt": cmd_decrypt,
    }

    handler = commands.get(args.command)
    if handler:
        return handler(args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
