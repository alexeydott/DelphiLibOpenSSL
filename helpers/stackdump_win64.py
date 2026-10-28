"""Suspend each owned thread and walk its AMD64 stack with DbgHelp.

Usage: python helpers/stackdump_win64.py PID
Run from a 64-bit Python process. Threads are resumed even if walking fails.
"""
import ctypes as c
from ctypes import wintypes as w
import struct
import sys


def bind(dll, name, result, *args):
    fn = getattr(dll, name)
    fn.restype, fn.argtypes = result, list(args)
    return fn


def main(pid):
    if c.sizeof(c.c_void_p) != 8:
        raise RuntimeError('64-bit Python required')
    k = c.WinDLL('kernel32', use_last_error=True)
    d = c.WinDLL('dbghelp', use_last_error=True)
    ptr, u64 = c.c_void_p, c.c_uint64
    close = bind(k, 'CloseHandle', w.BOOL, ptr)
    process = bind(k, 'OpenProcess', ptr, w.DWORD, w.BOOL, w.DWORD)(0x410, False, pid)
    if not process:
        raise c.WinError(c.get_last_error())
    suspend = bind(k, 'SuspendThread', w.DWORD, ptr)
    resume = bind(k, 'ResumeThread', w.DWORD, ptr)
    context = bind(k, 'GetThreadContext', w.BOOL, ptr, ptr)
    open_thread = bind(k, 'OpenThread', ptr, w.DWORD, w.BOOL, w.DWORD)
    snapshot = bind(k, 'CreateToolhelp32Snapshot', ptr, w.DWORD, w.DWORD)

    class ThreadEntry(c.Structure):
        _fields_ = [('size', w.DWORD), ('usage', w.DWORD), ('tid', w.DWORD),
                    ('pid', w.DWORD), ('base', w.LONG), ('delta', w.LONG), ('flags', w.DWORD)]

    first = bind(k, 'Thread32First', w.BOOL, ptr, c.POINTER(ThreadEntry))
    next_thread = bind(k, 'Thread32Next', w.BOOL, ptr, c.POINTER(ThreadEntry))
    initialize = bind(d, 'SymInitializeW', w.BOOL, ptr, w.LPCWSTR, w.BOOL)
    cleanup = bind(d, 'SymCleanup', w.BOOL, ptr)
    symbol = bind(d, 'SymFromAddr', w.BOOL, ptr, u64, c.POINTER(u64), ptr)
    walk = bind(d, 'StackWalk64', w.BOOL, w.DWORD, ptr, ptr, ptr, ptr, ptr, ptr, ptr, ptr)
    function_table = c.cast(d.SymFunctionTableAccess64, ptr)
    module_base = c.cast(d.SymGetModuleBase64, ptr)
    get_module = bind(d, 'SymGetModuleBase64', u64, ptr, u64)

    def describe(address):
        info = c.create_string_buffer(88 + 1024)
        struct.pack_into('<I', info, 0, 88)  # sizeof(SYMBOL_INFO)
        struct.pack_into('<I', info, 80, 1024)
        displacement = u64()
        if symbol(process, address, c.byref(displacement), info):
            return c.string_at(c.addressof(info) + 84).decode(errors='replace') + f'+0x{displacement.value:x}'
        base = get_module(process, address)
        return f'module=0x{base:x}+0x{address-base:x}'

    snap = None
    initialized = False
    try:
        initialized = bool(initialize(process, None, True))
        if not initialized:
            raise c.WinError(c.get_last_error())
        snap = snapshot(4, 0)  # TH32CS_SNAPTHREAD
        if snap == c.c_void_p(-1).value:
            raise c.WinError(c.get_last_error())
        entry = ThreadEntry()
        entry.size = c.sizeof(entry)
        ok = first(snap, c.byref(entry))
        while ok:
            if entry.pid == pid:
                thread = open_thread(0x4A, False, entry.tid)
                if not thread:
                    raise c.WinError(c.get_last_error())
                suspended = False
                try:
                    if suspend(thread) == 0xFFFFFFFF:
                        raise c.WinError(c.get_last_error())
                    suspended = True
                    storage = c.create_string_buffer(1232 + 16)
                    ctx = (c.addressof(storage) + 15) & ~15
                    c.c_uint32.from_address(ctx + 48).value = 0x10000B
                    if not context(thread, ctx):
                        raise c.WinError(c.get_last_error())
                    rip = c.c_uint64.from_address(ctx + 248).value
                    rsp = c.c_uint64.from_address(ctx + 152).value
                    rbp = c.c_uint64.from_address(ctx + 160).value
                    frame = c.create_string_buffer(512)  # STACKFRAME64 + SDK extensions
                    for offset, address in ((0, rip), (32, rbp), (48, rsp)):
                        struct.pack_into('<Q', frame, offset, address)
                        struct.pack_into('<I', frame, offset + 12, 3)  # AddrModeFlat
                    print(f'PID={pid} TID={entry.tid} RIP=0x{rip:x} RSP=0x{rsp:x}')
                    print(f'  0x{rip:016x} {describe(rip)}')
                    previous = (rip, rsp)
                    for depth in range(64):
                        if not walk(0x8664, process, thread, frame, ctx, None,
                                    function_table, module_base, None):
                            break
                        address = struct.unpack_from('<Q', frame, 0)[0]
                        stack = struct.unpack_from('<Q', frame, 48)[0]
                        if depth == 0 and (address, stack) == previous:
                            continue
                        if not address or (address, stack) == previous:
                            break
                        previous = (address, stack)
                        print(f'  0x{address:016x} {describe(address)}')
                finally:
                    if suspended:
                        resume(thread)
                    close(thread)
            ok = next_thread(snap, c.byref(entry))
    finally:
        if snap and snap != c.c_void_p(-1).value:
            close(snap)
        if initialized:
            cleanup(process)
        close(process)


if __name__ == '__main__':
    main(int(sys.argv[1]))
