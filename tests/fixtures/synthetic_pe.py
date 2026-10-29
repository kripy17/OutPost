"""Generator for synthetic PE test fixtures (Process Injection capabilities and section permissions)."""

import struct


def make_injection_pe(is_rwx: bool = True) -> bytes:
    """Build a minimal valid PE32+ executable importing injection APIs from KERNEL32.dll.

    When is_rwx=True, contains an anomalous .evil section with RWX permissions (0xE0000040).
    When is_rwx=False, contains a standard .text section with RX permissions (0x60000020).
    """
    mz = bytearray(b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x80) + b"\x00" * 64)
    pe_sig = b"PE\x00\x00"
    coff = struct.pack("<HHIIIHH", 0x8664, 2, 0x67100000, 0, 0, 240, 0x0022)
    std = struct.pack("<HBBIIIII", 0x020B, 14, 0, 0x200, 0x200, 0, 0x1000, 0x1000)
    win = struct.pack(
        "<QIIHHHHHHIIIIHHQQQQII",
        0x140000000,
        0x1000,
        0x200,
        6,
        0,
        0,
        0,
        6,
        0,
        0,
        0x3000,
        0x400,
        0,
        3,
        0x8160,
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,
        16,
    )
    dirs = bytearray(128)
    struct.pack_into("<II", dirs, 1 * 8, 0x2000, 40)  # Import Directory

    sec1_name = b".evil\x00\x00\x00" if is_rwx else b".text\x00\x00\x00"
    sec1_flags = 0xE0000040 if is_rwx else 0x60000020
    sec1 = struct.pack("<8sIIIIIIHHI", sec1_name, 0x1000, 0x1000, 0x200, 0x200, 0, 0, 0, 0, sec1_flags)
    sec2 = struct.pack("<8sIIIIIIHHI", b".idata\x00\x00", 0x1000, 0x2000, 0x400, 0x400, 0, 0, 0, 0, 0x40000040)

    hdrs = bytearray(mz + pe_sig + coff + std + win + dirs + sec1 + sec2)
    hdrs.extend(b"\x00" * (0x200 - len(hdrs)))

    sec1_data = bytearray(b"\xc3" + b"\x00" * 511)

    # .idata section at file offset 0x400, RVA 0x2000
    idata = bytearray(0x400)
    # Import Directory: entry 1
    # OriginalFirstThunk=0x2030, Name=0x2060 (KERNEL32.dll), FirstThunk=0x2030
    struct.pack_into("<IIIII", idata, 0, 0x2030, 0, 0, 0x2060, 0x2030)
    # entry 2 (all 0)

    # Thunk table at 0x2030 (offset 0x30): 3 entries + null
    struct.pack_into("<QQQQ", idata, 0x30, 0x2080, 0x20A0, 0x20C0, 0)
    # Name string at 0x2060 (offset 0x60)
    dll_name = b"KERNEL32.dll\x00"
    idata[0x60 : 0x60 + len(dll_name)] = dll_name
    # Hint/name entries
    h1 = struct.pack("<H", 1) + b"VirtualAllocEx\x00"
    idata[0x80 : 0x80 + len(h1)] = h1
    h2 = struct.pack("<H", 2) + b"WriteProcessMemory\x00"
    idata[0xA0 : 0xA0 + len(h2)] = h2
    h3 = struct.pack("<H", 3) + b"CreateRemoteThread\x00"
    idata[0xC0 : 0xC0 + len(h3)] = h3

    return bytes(hdrs + sec1_data + idata)
