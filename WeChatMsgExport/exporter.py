"""WeChat chat export: session discovery and TXT export."""

import os
import re
import sqlite3
import json
from datetime import datetime
from collections import defaultdict

# Message types
MSG_TYPE_TEXT = 1
MSG_TYPE_IMAGE = 3
MSG_TYPE_VOICE = 34
MSG_TYPE_VIDEO = 43
MSG_TYPE_EMOJI = 47
MSG_TYPE_LOCATION = 48
MSG_TYPE_LINK = 49
MSG_TYPE_FILE = 10000
MSG_TYPE_SYSTEM = 10002

MSG_TYPE_NAMES = {
    1: "文本",
    3: "图片",
    34: "语音",
    43: "视频",
    47: "表情包",
    48: "位置",
    49: "链接",
    10000: "文件",
    10002: "系统消息",
}


def discover_sessions(db_dir: str) -> list:
    """
    Discover all chat sessions from decrypted databases.

    Returns list of dicts:
        {username, display_name, type, message_count, last_timestamp}
    """
    sessions = []
    session_path = os.path.join(db_dir, "session", "session.db")

    if not os.path.exists(session_path):
        return sessions

    conn = sqlite3.connect(session_path)
    conn.row_factory = sqlite3.Row

    try:
        rows = conn.execute(
            "SELECT username, type, summary, last_timestamp, "
            "last_sender_display_name, unread_count "
            "FROM SessionTable ORDER BY sort_timestamp DESC"
        ).fetchall()

        contact_conn = sqlite3.connect(
            os.path.join(db_dir, "contact", "contact.db")
        )
        contact_conn.row_factory = sqlite3.Row

        for row in rows:
            username = row["username"]
            display_name = _resolve_display_name(
                contact_conn, username
            )
            sessions.append(
                {
                    "username": username,
                    "display_name": display_name,
                    "type": row["type"],
                    "summary": row["summary"] or "",
                    "last_timestamp": row["last_timestamp"] or 0,
                    "last_sender": row["last_sender_display_name"] or "",
                }
            )

        contact_conn.close()
    finally:
        conn.close()

    return sessions


def _resolve_display_name(contact_conn, username: str) -> str:
    """Resolve a username to the best display name."""
    try:
        row = contact_conn.execute(
            "SELECT remark, nick_name, alias FROM contact "
            "WHERE username = ?",
            (username,),
        ).fetchone()
        if row:
            return row["remark"] or row["nick_name"] or row["alias"] or username

        row = contact_conn.execute(
            "SELECT remark, nick_name, alias FROM stranger "
            "WHERE username = ?",
            (username,),
        ).fetchone()
        if row:
            return row["remark"] or row["nick_name"] or row["alias"] or username
    except Exception:
        pass
    return username


def _get_msg_table_name(conn, username: str) -> str:
    """Get the per-session message table name (Msg_<md5>)."""
    # MD5 hash of username determines the table name
    import hashlib
    table_suffix = hashlib.md5(username.encode()).hexdigest()
    table_name = f"Msg_{table_suffix}"

    # Verify the table exists
    try:
        conn.execute(
            f"SELECT COUNT(*) FROM \"{table_name}\""
        ).fetchone()
        return table_name
    except Exception:
        return None


def _format_message(row, my_wxid: str = "") -> str:
    """Format a single message row into a text line."""
    create_time = row.get("create_time", 0)
    if create_time:
        try:
            dt = datetime.fromtimestamp(create_time)
            time_str = dt.strftime("%Y-%m-%d %H:%M:%S")
        except (ValueError, OSError):
            time_str = str(create_time)
    else:
        time_str = "unknown"

    sender_id = row.get("real_sender_id", "")
    content = row.get("message_content", "") or ""
    msg_type = row.get("local_type", 1)

    # Resolve sender name
    if isinstance(sender_id, int) and sender_id != 0:
        sender_name = f"user_{sender_id}"
    else:
        sender_name = "unknown"

    if msg_type == MSG_TYPE_TEXT:
        # Clean content - it may be XML/HTML in some cases
        # Strip XML tags for plain text
        text = _extract_text_content(content)
        return f"{time_str} {sender_name}\n{text}\n"
    elif msg_type == MSG_TYPE_IMAGE:
        return f"{time_str} {sender_name}\n【图片】\n"
    elif msg_type == MSG_TYPE_VOICE:
        return f"{time_str} {sender_name}\n【语音】\n"
    elif msg_type == MSG_TYPE_VIDEO:
        return f"{time_str} {sender_name}\n【视频】\n"
    elif msg_type == MSG_TYPE_EMOJI:
        return f"{time_str} {sender_name}\n【表情包】\n"
    elif msg_type == MSG_TYPE_LINK:
        title = _extract_link_title(content)
        return f"{time_str} {sender_name}\n【链接】{title}\n"
    elif msg_type == MSG_TYPE_FILE:
        return f"{time_str} {sender_name}\n【文件】\n"
    elif msg_type == MSG_TYPE_LOCATION:
        return f"{time_str} {sender_name}\n【位置】\n"
    else:
        text = _extract_text_content(content)
        if text:
            return f"{time_str} {sender_name}\n{text}\n"
        return f"{time_str} {sender_name}\n【消息 type={msg_type}】\n"


def _extract_text_content(content) -> str:
    """Extract readable text from message content (may be XML or bytes)."""
    if not content:
        return ""

    # Handle bytes content
    if isinstance(content, bytes):
        try:
            content = content.decode("utf-8")
        except UnicodeDecodeError:
            try:
                content = content.decode("gbk", errors="replace")
            except Exception:
                return str(content)

    if not isinstance(content, str):
        content = str(content)

    # Try to parse as XML and extract text
    # WeChat content is often stored as XML: <msg><text>...</text></msg>
    text_match = re.search(r"<text>(.*?)</text>", content, re.DOTALL)
    if text_match:
        return text_match.group(1).strip()

    # Remove common XML tags
    content = re.sub(r"<[^>]+>", "", content)
    # Decode HTML entities
    content = content.replace("&amp;", "&").replace("&lt;", "<").replace(
        "&gt;", ">"
    ).replace("&quot;", '"').replace("&#39;", "'")
    return content.strip()


def _extract_link_title(content) -> str:
    """Extract link title from content XML."""
    if isinstance(content, bytes):
        try:
            content = content.decode("utf-8")
        except UnicodeDecodeError:
            content = content.decode("gbk", errors="replace")
    if not isinstance(content, str):
        content = str(content)
    title_match = re.search(r"<title>(.*?)</title>", content, re.DOTALL)
    if title_match:
        return title_match.group(1)
    desc_match = re.search(r"<des>(.*?)</des>", content, re.DOTALL)
    if desc_match:
        return desc_match.group(1)
    return ""


def _build_sender_mapping(msg_conns: list, contact_conn) -> dict:
    """
    Build a global sender ID -> display name mapping.

    In WeChat v4, real_sender_id is an internal integer. We resolve it by:
    1. Looking up the contact table by rowid
    2. Using heuristics for the "me" sender (appears across all chats)
    3. Falling back to the sender_id itself
    """
    mapping = {}

    # Collect all unique sender IDs across all chats
    all_senders = set()
    for conn in msg_conns:
        try:
            tables = [
                r[0] for r in conn.execute(
                    "SELECT name FROM sqlite_master "
                    "WHERE type='table' AND name LIKE 'Msg_%'"
                ).fetchall()
            ]
            for table in tables:
                rows = conn.execute(
                    f'SELECT DISTINCT real_sender_id FROM "{table}"'
                ).fetchall()
                for r in rows:
                    sid = r[0]
                    if sid is not None and sid != 0:
                        all_senders.add(sid)
        except Exception:
            pass

    # Try contact lookup for each sender
    if contact_conn:
        for sid in all_senders:
            try:
                row = contact_conn.execute(
                    "SELECT remark, nick_name, username FROM contact "
                    "WHERE rowid = ?",
                    (sid,),
                ).fetchone()
                if row:
                    name = (
                        row["remark"]
                        or row["nick_name"]
                        or row["username"]
                    )
                    if name and name not in (
                        "weixin", "notifymessage", "medianote",
                        "floatbottle", "qmessage",
                    ):
                        mapping[sid] = name
            except Exception:
                pass

    return mapping


def _resolve_sender_for_chat(
    sender_id,
    chat_username: str,
    contact_conn,
    global_mapping: dict,
    my_wxid_candidates: set,
) -> str:
    """
    Resolve a sender ID within a specific chat.

    For 1-on-1 chats, we distinguish:
    - The sender matching the chat's wxid = the other person
    - The remaining sender = me
    """
    if sender_id == 0:
        return "我"

    # Check global mapping first
    if sender_id in global_mapping:
        name = global_mapping[sender_id]
        # Check if this name's wxid matches the chat
        if contact_conn:
            row = contact_conn.execute(
                "SELECT username FROM contact WHERE remark = ? OR nick_name = ?",
                (name, name),
            ).fetchone()
            if row and row["username"] == chat_username:
                return name
        return name

    # Try looking up by contact rowid
    if contact_conn:
        try:
            row = contact_conn.execute(
                "SELECT username, remark, nick_name FROM contact "
                "WHERE rowid = ?",
                (sender_id,),
            ).fetchone()
            if row:
                name = row["remark"] or row["nick_name"] or row["username"]
                # Filter out system contacts
                if row["username"] not in (
                    "weixin", "notifymessage", "medianote",
                    "floatbottle", "qmessage",
                ):
                    return name
        except Exception:
            pass

    return str(sender_id)


class WeChatExporter:
    """Main export engine for WeChat chat records."""

    def __init__(self, db_dir: str):
        """
        Initialize with path to decrypted db_storage directory.

        Args:
            db_dir: Path to decrypted db_storage_decrypted
        """
        self.db_dir = db_dir
        self.contact_conn = None
        self.msg_conns = []

    def open(self):
        """Open all database connections."""
        contact_path = os.path.join(self.db_dir, "contact", "contact.db")
        if os.path.exists(contact_path):
            self.contact_conn = sqlite3.connect(contact_path)
            self.contact_conn.row_factory = sqlite3.Row

        # Open all message databases
        msg_dir = os.path.join(self.db_dir, "message")
        if os.path.isdir(msg_dir):
            for f in sorted(os.listdir(msg_dir)):
                if re.match(r"message_\d+\.db", f):
                    path = os.path.join(msg_dir, f)
                    conn = sqlite3.connect(path)
                    conn.row_factory = sqlite3.Row
                    self.msg_conns.append(conn)

    def close(self):
        """Close all database connections."""
        if self.contact_conn:
            self.contact_conn.close()
        for conn in self.msg_conns:
            conn.close()

    def discover(self) -> list:
        """Discover all chat sessions."""
        return discover_sessions(self.db_dir)

    def export_chat(
        self,
        username: str,
        display_name: str,
        output_dir: str,
        fmt: str = "txt",
        max_messages: int = -1,
        time_start: int = None,
        time_end: int = None,
    ) -> str:
        """
        Export a single chat session.

        Args:
            username: WeChat username (wxid_...)
            display_name: Display name for the contact
            output_dir: Directory to write output
            fmt: Output format ("txt" or "html")
            max_messages: Max messages to export (-1 = all)
            time_start: Start timestamp filter
            time_end: End timestamp filter

        Returns:
            Path to exported file
        """
        import hashlib

        # Get the per-chat message table
        table_suffix = hashlib.md5(username.encode()).hexdigest()
        table_name = f"Msg_{table_suffix}"

        messages = []
        for conn in self.msg_conns:
            try:
                cursor = conn.execute(
                    f"SELECT * FROM \"{table_name}\" "
                    f"ORDER BY create_time ASC"
                )
                for row in cursor:
                    create_time = row["create_time"]
                    if time_start and create_time < time_start:
                        continue
                    if time_end and create_time > time_end:
                        continue
                    messages.append(dict(row))
            except Exception:
                continue

        if max_messages > 0 and len(messages) > max_messages:
            messages = messages[-max_messages:]

        # Create output directory
        safe_name = _safe_filename(display_name)
        chat_dir = os.path.join(
            output_dir, f"{safe_name}({_safe_filename(username)})"
        )
        os.makedirs(chat_dir, exist_ok=True)

        # Build sender ID -> name mapping
        # In WeChat v4, real_sender_id uses LOCAL per-chat integers
        # Resolution strategy:
        #   1. sender_id == 0 → "我"
        #   2. Try contact.rowid lookup for a non-system name
        #   3. For 1-on-1 chats: the sender NOT matching the chat partner's
        #      contact is "me"
        sender_names = {}
        unique_senders = set()
        for msg in messages:
            sid = msg.get("real_sender_id", 0)
            unique_senders.add(sid)

        # Get session type to determine if this is a 1-on-1 chat
        is_group = False
        session_path = os.path.join(self.db_dir, "session", "session.db")
        if os.path.exists(session_path):
            sconn = sqlite3.connect(session_path)
            sconn.row_factory = sqlite3.Row
            srow = sconn.execute(
                "SELECT type FROM SessionTable WHERE username=?",
                (username,),
            ).fetchone()
            if srow and srow["type"] != 0:
                is_group = True
            sconn.close()

        # Resolve each sender
        non_system_senders = {}
        for sid in unique_senders:
            if sid == 0 or sid == "":
                sender_names[sid] = "我"
                continue
            try:
                row = self.contact_conn.execute(
                    "SELECT username, remark, nick_name FROM contact "
                    "WHERE rowid=?",
                    (int(sid) if isinstance(sid, int) or (
                        isinstance(sid, str) and sid.isdigit()
                    ) else -1,),
                ).fetchone()
                if row and row["username"] not in (
                    "weixin", "notifymessage", "medianote",
                    "floatbottle", "qmessage",
                ):
                    name = row["remark"] or row["nick_name"] or row["username"]
                    sender_names[sid] = name
                    non_system_senders[sid] = name
                    continue
            except Exception:
                pass

        # For remaining unresolved senders:
        # In 1-on-1 chats, assign display_name to one, "我" to the other
        unresolved = [s for s in unique_senders if s not in sender_names]
        if not is_group and len(unresolved) > 0:
            partner_assigned = len(non_system_senders) > 0
            for sid in sorted(unresolved):
                if sid == 0 or sid == "":
                    sender_names[sid] = "我"
                elif not partner_assigned:
                    sender_names[sid] = display_name
                    partner_assigned = True
                else:
                    # Remaining senders = me
                    sender_names[sid] = "我"
        else:
            for sid in unresolved:
                sender_names[sid] = str(sid)

        if fmt == "txt":
            output_path = os.path.join(chat_dir, f"{safe_name}.txt")
            self._export_txt(
                messages, sender_names, username, display_name, output_path
            )
        elif fmt == "html":
            output_path = os.path.join(chat_dir, f"{safe_name}.html")
            self._export_html(
                messages, sender_names, username, display_name, output_path
            )
        else:
            raise ValueError(f"Unsupported format: {fmt}")

        return output_path

    def _export_txt(
        self,
        messages: list,
        sender_names: dict,
        username: str,
        display_name: str,
        output_path: str,
    ):
        """Write messages to TXT file."""
        with open(output_path, "w", encoding="utf-8") as f:
            for msg in messages:
                create_time = msg.get("create_time", 0)
                if create_time:
                    try:
                        dt = datetime.fromtimestamp(create_time)
                        time_str = dt.strftime("%Y-%m-%d %H:%M:%S")
                    except (ValueError, OSError):
                        time_str = str(create_time)
                else:
                    time_str = "unknown"

                sender_id = msg.get("real_sender_id", "")
                if sender_id == 0 or sender_id == "" or sender_id == "0":
                    sender_name = "我"
                else:
                    sender_name = sender_names.get(sender_id, str(sender_id))

                content = msg.get("message_content", "") or ""
                compress = msg.get("compress_content", "") or ""
                msg_type = msg.get("local_type", 1)

                # WeChat v4 uses composite type encoding for some messages:
                # real_type = msg_type & 0xFF when msg_type > 0xFFFF
                if msg_type > 0xFFFF:
                    real_type = msg_type & 0xFF
                else:
                    real_type = msg_type

                # Non-text types: don't decode binary content
                TEXT_TYPES = {MSG_TYPE_TEXT, MSG_TYPE_LINK,
                              MSG_TYPE_LOCATION, MSG_TYPE_SYSTEM}
                if real_type not in TEXT_TYPES:
                    label = MSG_TYPE_NAMES.get(real_type, f"消息({real_type})")
                    if real_type == MSG_TYPE_IMAGE:
                        label = "图片"
                    elif real_type == MSG_TYPE_VOICE:
                        label = "语音"
                    elif real_type == MSG_TYPE_VIDEO:
                        label = "视频"
                    elif real_type == MSG_TYPE_EMOJI:
                        label = "表情包"
                    elif real_type == MSG_TYPE_FILE:
                        label = "文件"
                    f.write(f"{time_str} {sender_name}\n【{label}】\n\n")
                    continue

                # Normalize bytes to str for text-based types
                if isinstance(content, bytes):
                    try:
                        content = content.decode("utf-8")
                    except UnicodeDecodeError:
                        content = content.decode("gbk", errors="replace")
                if isinstance(compress, bytes):
                    try:
                        compress = compress.decode("utf-8")
                    except UnicodeDecodeError:
                        compress = compress.decode("gbk", errors="replace")

                if real_type == MSG_TYPE_TEXT:
                    text = _extract_text_content(content)
                    if not text and compress:
                        text = _extract_text_content(compress)
                    f.write(f"{time_str} {sender_name}\n")
                    f.write(f"{text}\n\n")
                elif real_type == MSG_TYPE_IMAGE:
                    f.write(f"{time_str} {sender_name}\n【图片】\n\n")
                elif real_type == MSG_TYPE_VOICE:
                    f.write(f"{time_str} {sender_name}\n【语音】\n\n")
                elif real_type == MSG_TYPE_VIDEO:
                    f.write(f"{time_str} {sender_name}\n【视频】\n\n")
                elif real_type == MSG_TYPE_EMOJI:
                    f.write(f"{time_str} {sender_name}\n【表情包】\n\n")
                elif real_type == MSG_TYPE_LINK:
                    title = _extract_link_title(content)
                    f.write(f"{time_str} {sender_name}\n【链接】{title}\n\n")
                elif real_type == MSG_TYPE_LOCATION:
                    f.write(f"{time_str} {sender_name}\n【位置】\n\n")
                elif real_type == MSG_TYPE_FILE:
                    f.write(f"{time_str} {sender_name}\n【文件】\n\n")
                elif real_type == MSG_TYPE_SYSTEM:
                    f.write(f"{time_str} 【系统消息】\n{content}\n\n")
                else:
                    text = _extract_text_content(content)
                    if text:
                        f.write(f"{time_str} {sender_name}\n{text}\n\n")
                    else:
                        f.write(
                            f"{time_str} {sender_name}\n"
                            f"【消息 type={msg_type}】\n\n"
                        )

    def _export_html(
        self,
        messages: list,
        sender_names: dict,
        username: str,
        display_name: str,
        output_path: str,
    ):
        """Write messages to HTML file."""
        html_parts = [
            "<!DOCTYPE html><html><head><meta charset='UTF-8'>",
            f"<title>{display_name} - 聊天记录</title>",
            "<style>",
            "body{font-family:'Microsoft YaHei',sans-serif;max-width:800px;"
            "margin:0 auto;padding:20px;background:#f5f5f5}",
            ".msg{margin:10px 0;padding:10px;border-radius:8px;"
            "background:#fff;box-shadow:0 1px 3px rgba(0,0,0,.1)}",
            ".time{color:#999;font-size:12px}",
            ".sender{font-weight:700;color:#333}",
            ".content{margin-top:5px;color:#555;white-space:pre-wrap}",
            "</style></head><body>",
            f"<h2>{display_name} ({username})</h2>",
            f"<p>共 {len(messages)} 条消息</p><hr>",
        ]

        for msg in messages:
            create_time = msg.get("create_time", 0)
            if create_time:
                try:
                    dt = datetime.fromtimestamp(create_time)
                    time_str = dt.strftime("%Y-%m-%d %H:%M:%S")
                except (ValueError, OSError):
                    time_str = str(create_time)
            else:
                time_str = "unknown"

            sender_id = msg.get("real_sender_id", "")
            if sender_id == 0 or sender_id == "" or sender_id == "0":
                sender_name = "我"
            else:
                sender_name = sender_names.get(sender_id, str(sender_id))

            content = msg.get("message_content", "") or ""
            if isinstance(content, bytes):
                try:
                    content = content.decode("utf-8")
                except UnicodeDecodeError:
                    content = content.decode("gbk", errors="replace")
            msg_type = msg.get("local_type", 1)
            text = _extract_text_content(content)

            type_label = MSG_TYPE_NAMES.get(msg_type, f"消息({msg_type})")
            if msg_type == MSG_TYPE_TEXT:
                display = text
            elif msg_type in (MSG_TYPE_IMAGE, MSG_TYPE_VOICE,
                              MSG_TYPE_VIDEO, MSG_TYPE_EMOJI):
                display = f"[{type_label}]"
            else:
                display = text if text else f"[{type_label}]"

            html_parts.append(
                f"<div class='msg'><span class='time'>{time_str}</span> "
                f"<span class='sender'>{sender_name}</span>"
                f"<div class='content'>{display}</div></div>"
            )

        html_parts.append("</body></html>")

        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(html_parts))


def _safe_filename(name: str) -> str:
    """Convert a name to a safe filename."""
    unsafe = r'[<>:"/\\|?*\x00-\x1f]'
    safe = re.sub(unsafe, "_", name)
    return safe.strip()[:100]
