"""Shared utilities for WeChatMsgExport."""

import os
import re
import sys
import ctypes
from ctypes import wintypes

# Windows API constants
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010

kernel32 = ctypes.windll.kernel32
psapi = ctypes.windll.psapi
advapi32 = ctypes.windll.advapi32


def find_wechat_processes():
    """Find all Weixin.exe (WeChat v4) processes. Returns list of PIDs."""
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
            exe_name = entry.szExeFile.decode("gbk", errors="ignore").lower()
            if "weixin" in exe_name:
                pids.append(entry.th32ProcessID)
            if not kernel32.Process32Next(snapshot, ctypes.byref(entry)):
                break

    kernel32.CloseHandle(snapshot)
    return pids


def find_wechat_db_path(pid):
    """
    Scan WeChat process memory to find db_storage path.
    WeChat v4 stores the path in memory containing '/db_storage/'.
    """
    PROCESS_VM_READ = 0x0010
    PROCESS_QUERY_INFORMATION = 0x0400

    h_process = kernel32.OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid
    )
    if not h_process:
        return None

    db_path = None
    kernel32.GetSystemInfo.restype = None

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
    page_size = sys_info.dwPageSize

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
    PAGE_READABLE = (
        0x02 | 0x04 | 0x08 | 0x10 | 0x20 | 0x40 | 0x80 | 0x100
    )

    address = sys_info.lpMinimumApplicationAddress
    max_address = sys_info.lpMaximumApplicationAddress

    try:
        mbi = MEMORY_BASIC_INFORMATION()
        while address < max_address:
            if ctypes.sizeof(ctypes.c_void_p) == 8:
                result = kernel32.VirtualQueryEx(
                    h_process, ctypes.c_void_p(address),
                    ctypes.byref(mbi), ctypes.sizeof(mbi)
                )
            else:
                result = kernel32.VirtualQueryEx(
                    h_process, ctypes.c_void_p(address),
                    ctypes.byref(mbi), ctypes.sizeof(mbi)
                )

            if result == 0:
                break

            region_size = mbi.RegionSize
            if (mbi.State == MEM_COMMIT and mbi.Type == MEM_PRIVATE
                    and (mbi.Protect & PAGE_READABLE)):
                try:
                    buf = ctypes.create_string_buffer(region_size)
                    bytes_read = ctypes.c_size_t(0)

                    if kernel32.ReadProcessMemory(
                        h_process, mbi.BaseAddress, buf, region_size,
                        ctypes.byref(bytes_read)
                    ):
                        data = buf.raw[:bytes_read.value]
                        # Search for db_storage path pattern
                        for m in re.finditer(rb'[A-Za-z]:[\\/][^\x00]{10,200}db_storage[\\/]', data):
                            path = m.group(0).decode("utf-8", errors="ignore")
                            db_path = path.rstrip("\\/")
                            break
                    if db_path:
                        break
                except Exception:
                    pass

            address += region_size
    except Exception:
        pass

    kernel32.CloseHandle(h_process)
    return db_path


def get_wechat_data_dir():
    """Get WeChat data directory from common locations."""
    candidates = [
        os.path.join(os.environ.get("USERPROFILE", ""), "Documents", "WeChat Files"),
        os.path.join(os.environ.get("USERPROFILE", ""), "Documents", "xwechat_files"),
        os.path.join(os.environ.get("APPDATA", ""), "Tencent", "WeChat"),
        os.path.join(os.environ.get("APPDATA", ""), "Tencent", "xwechat"),
    ]
    for d in candidates:
        if os.path.isdir(d):
            return d
    return None
