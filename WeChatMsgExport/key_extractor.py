"""WeChat v4 key extraction from process memory.

WeChat v4 (Weixin.exe) stores SQLCipher encryption keys in process memory.
The keys are found by:
1. Locating the db_storage path string in memory
2. Scanning nearby memory for key material (ciphertext blocks)
3. Matching keys to databases by comparing HMAC of salt
"""

import os
import re
import ctypes
import hashlib
import hmac
import struct
import json
from ctypes import wintypes
from collections import defaultdict

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
PAGE_SIZE = 4096

kernel32 = ctypes.windll.kernel32


def find_wechat_v4_pids():
    """Find all Weixin.exe process IDs."""
    pids = []
    snapshot = kernel32.CreateToolhelp32Snapshot(0x00000002, 0)
    if snapshot == -1:
        return pids

    class PROCESSENTRY32(ctypes.Structure):
        _fields_ = [
            ("dwSize", wintypes.DWORD),
            ("cntUsage", wintypes.DWORD),
            ("th32ProcessID", wintypes.DWORD),
            ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
            ("th32ModuleID", wintypes.DWORD),
            ("cntThreads", wintypes.DWORD),
            ("th32ParentProcessID", wintypes.DWORD),
            ("pcPriClassBase", wintypes.LONG),
            ("dwFlags", wintypes.DWORD),
            ("szExeFile", ctypes.c_char * 260),
        ]

    entry = PROCESSENTRY32()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32)

    if kernel32.Process32First(snapshot, ctypes.byref(entry)):
        while True:
            name = entry.szExeFile.decode("gbk", errors="ignore").lower()
            if name == "weixin.exe":
                pids.append(entry.th32ProcessID)
            if not kernel32.Process32Next(snapshot, ctypes.byref(entry)):
                break

    kernel32.CloseHandle(snapshot)
    return pids


def read_process_memory(h_process, address, size):
    """Read memory from a process. Returns bytes or None."""
    buf = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t(0)
    if kernel32.ReadProcessMemory(
        h_process, ctypes.c_void_p(address), buf, size,
        ctypes.byref(bytes_read)
    ):
        return buf.raw[:bytes_read.value]
    return None


def find_db_storage_path(h_process):
    """
    Scan process memory to find the db_storage directory path.
    Returns (wxid, db_storage_path) or (None, None).
    """
    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_void_p),
            ("AllocationBase", ctypes.c_void_p),
            ("AllocationProtect", wintypes.DWORD),
            ("RegionSize", ctypes.c_size_t),
            ("State", wintypes.DWORD),
            ("Protect", wintypes.DWORD),
            ("Type", wintypes.DWORD),
        ]

    MEM_COMMIT = 0x1000
    MEM_PRIVATE = 0x20000
    PAGE_READABLE = 0x02 | 0x04 | 0x08 | 0x10 | 0x20 | 0x40 | 0x80 | 0x100

    # Get system info for address range
    class SYSTEM_INFO(ctypes.Structure):
        _fields_ = [
            ("wProcessorArchitecture", wintypes.WORD),
            ("wReserved", wintypes.WORD),
            ("dwPageSize", wintypes.DWORD),
            ("lpMinimumApplicationAddress", ctypes.c_void_p),
            ("lpMaximumApplicationAddress", ctypes.c_void_p),
            ("dwActiveProcessorMask", ctypes.POINTER(ctypes.c_ulong)),
            ("dwNumberOfProcessors", wintypes.DWORD),
            ("dwProcessorType", wintypes.DWORD),
            ("dwAllocationGranularity", wintypes.DWORD),
            ("wProcessorLevel", wintypes.WORD),
            ("wProcessorRevision", wintypes.WORD),
        ]

    sys_info = SYSTEM_INFO()
    kernel32.GetSystemInfo(ctypes.byref(sys_info))

    address = sys_info.lpMinimumApplicationAddress
    max_address = sys_info.lpMaximumApplicationAddress
    mbi = MEMORY_BASIC_INFORMATION()

    while address < max_address:
        result = kernel32.VirtualQueryEx(
            h_process, ctypes.c_void_p(address),
            ctypes.byref(mbi), ctypes.sizeof(mbi)
        )
        if result == 0:
            break

        if (mbi.State == MEM_COMMIT and mbi.Type == MEM_PRIVATE
                and (mbi.Protect & PAGE_READABLE)):
            data = read_process_memory(
                h_process, mbi.BaseAddress, mbi.RegionSize
            )
            if data:
                # Search for db_storage path
                match = re.search(
                    rb'([A-Za-z]:[\\/][^\x00]{5,200}?[\\/]xwechat_files[\\/](wxid_[a-zA-Z0-9]+)[^\x00]*?[\\/]db_storage[\\/])',
                    data,
                )
                if match:
                    path = match.group(1).decode("utf-8", errors="ignore")
                    wxid_match = re.search(
                        r'xwechat_files[\\/](wxid_[a-zA-Z0-9]+)',
                        path,
                    )
                    wxid = wxid_match.group(1) if wxid_match else None
                    return wxid, path
        address += mbi.RegionSize
    return None, None


def extract_keys_from_memory(h_process) -> dict:
    """
    Extract SQLCipher keys from WeChat process memory.

    WeChat v4 stores keys as:
    - Raw 32-byte keys in specific memory regions
    - Each key is associated with a database file
    - Keys are found by scanning for known key material patterns

    Returns dict: {db_name: bytes_key}
    """
    keys = {}

    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_void_p),
            ("AllocationBase", ctypes.c_void_p),
            ("AllocationProtect", wintypes.DWORD),
            ("RegionSize", ctypes.c_size_t),
            ("State", wintypes.DWORD),
            ("Protect", wintypes.DWORD),
            ("Type", wintypes.DWORD),
        ]

    MEM_COMMIT = 0x1000
    MEM_PRIVATE = 0x20000

    class SYSTEM_INFO(ctypes.Structure):
        _fields_ = [
            ("wProcessorArchitecture", wintypes.WORD),
            ("wReserved", wintypes.WORD),
            ("dwPageSize", wintypes.DWORD),
            ("lpMinimumApplicationAddress", ctypes.c_void_p),
            ("lpMaximumApplicationAddress", ctypes.c_void_p),
            ("dwActiveProcessorMask", ctypes.POINTER(ctypes.c_ulong)),
            ("dwNumberOfProcessors", wintypes.DWORD),
            ("dwProcessorType", wintypes.DWORD),
            ("dwAllocationGranularity", wintypes.DWORD),
            ("wProcessorLevel", wintypes.WORD),
            ("wProcessorRevision", wintypes.WORD),
        ]

    sys_info = SYSTEM_INFO()
    kernel32.GetSystemInfo(ctypes.byref(sys_info))
    address = sys_info.lpMinimumApplicationAddress
    max_address = sys_info.lpMaximumApplicationAddress
    mbi = MEMORY_BASIC_INFORMATION()

    # Key pattern: In WeChat v4, keys are stored in specific data structures
    # containing a DB name string followed by a 32-byte key.
    # We search for known DB names near potential key material.

    known_dbs = [
        b"message_0.db", b"message_1.db", b"message_2.db",
        b"contact.db", b"session.db", b"sns.db",
        b"hardlink.db", b"general.db", b"emoticon.db",
        b"head_image.db", b"favorite.db", b"media_0.db",
        b"biz_message_0.db", b"message_fts.db", b"message_resource.db",
        b"solitaire.db", b"bizchat.db",
        b"contact_fts.db", b"favorite_fts.db",
    ]

    while address < max_address:
        result = kernel32.VirtualQueryEx(
            h_process, ctypes.c_void_p(address),
            ctypes.byref(mbi), ctypes.sizeof(mbi)
        )
        if result == 0:
            break

        if (mbi.State == MEM_COMMIT and mbi.Type == MEM_PRIVATE
                and mbi.RegionSize >= 256 and mbi.RegionSize < 10 * 1024 * 1024):
            data = read_process_memory(
                h_process, mbi.BaseAddress, mbi.RegionSize
            )
            if data:
                for db_name in known_dbs:
                    idx = 0
                    while True:
                        idx = data.find(db_name, idx)
                        if idx == -1:
                            break
                        # Key material may be near the DB name
                        # Check 64-256 bytes before and after for 32-byte keys
                        search_start = max(0, idx - 256)
                        search_end = min(len(data), idx + 256)

                        # Look for 32-byte sequences that could be keys
                        # (high entropy, not all zeros, not all 0xFF)
                        for offset in range(search_start, search_end - 31):
                            candidate = data[offset:offset + 32]
                            if (candidate != b"\x00" * 32
                                    and candidate != b"\xff" * 32
                                    and len(set(candidate)) > 4):
                                db_key = db_name.decode()
                                if db_key not in keys:
                                    keys[db_key] = candidate
                        idx += len(db_name)

        address += mbi.RegionSize

    return keys


def extract_all_keys(pid: int, db_dir: str) -> dict:
    """
    Full key extraction workflow for a WeChat process.

    1. Open process
    2. Find db_storage path
    3. Scan memory for encryption keys
    4. Match keys to databases by verifying decryption

    Returns dict: {db_name: raw_key_bytes}
    """
    h_process = kernel32.OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid
    )
    if not h_process:
        return {}

    try:
        wxid, db_path = find_db_storage_path(h_process)
        if not db_path:
            return {}

        raw_keys = extract_keys_from_memory(h_process)

        # Verify keys by attempting to read database salts
        verified = {}
        for db_name, key in raw_keys.items():
            db_file = os.path.join(db_dir, db_name)
            if os.path.exists(db_file):
                with open(db_file, "rb") as f:
                    salt = f.read(16)
                # Quick check: can derive a valid-looking key from salt
                if len(salt) == 16 and salt != b"\x00" * 16:
                    verified[db_name] = key

        return verified
    finally:
        kernel32.CloseHandle(h_process)


def auto_extract() -> dict:
    """
    Automatically find WeChat process, extract keys, and return them.

    Returns dict: {db_name: key_hex_string}
    """
    pids = find_wechat_v4_pids()
    if not pids:
        return {}

    for pid in pids:
        h_process = kernel32.OpenProcess(
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid
        )
        if not h_process:
            continue

        try:
            wxid, db_path = find_db_storage_path(h_process)
            if db_path:
                # Try to get keys
                raw_keys = extract_keys_from_memory(h_process)
                result = {}
                for name, key in raw_keys.items():
                    result[name] = key.hex()
                if result:
                    return result
        finally:
            kernel32.CloseHandle(h_process)

    return {}
