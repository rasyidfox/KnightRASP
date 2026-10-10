#!/usr/bin/env python3
"""Fill the `.krpin` slot of the native library with the FNV-1a digest of its
executable segment (build-time pinning).

Called by CMake as a POST_BUILD step. The runtime computes the same digest from
the mapped segment (skipping the pin bytes, exactly like this tool) and compares
it with the pinned value, so patching the library before it is ever loaded
(Frida gadget/spawn, repackaged .so) is detected.

Pure standard library; supports ELF32 (armeabi-v7a) and ELF64 (arm64/x86_64).
"""

import struct
import sys

FNV_OFFSET_BASIS = 14695981039346656037
FNV_PRIME = 1099511628211
MASK64 = 0xFFFFFFFFFFFFFFFF

PT_LOAD = 1
PF_X = 1
PIN_SIZE = 8


def _unpack(fmt, data, offset):
    return struct.unpack_from(fmt, data, offset)


def _elf_layout(data):
    if data[:4] != b"\x7fELF":
        raise ValueError("not an ELF file")
    is64 = data[4] == 2
    if is64:
        (e_phoff,) = _unpack("<Q", data, 0x20)
        (e_phentsize, e_phnum) = _unpack("<HH", data, 0x36)
        (e_shoff,) = _unpack("<Q", data, 0x28)
        (e_shentsize, e_shnum, e_shstrndx) = _unpack("<HHH", data, 0x3A)
    else:
        (e_phoff,) = _unpack("<I", data, 0x1C)
        (e_phentsize, e_phnum) = _unpack("<HH", data, 0x2A)
        (e_shoff,) = _unpack("<I", data, 0x20)
        (e_shentsize, e_shnum, e_shstrndx) = _unpack("<HHH", data, 0x2E)
    return is64, e_phoff, e_phentsize, e_phnum, e_shoff, e_shentsize, e_shnum, e_shstrndx


def _exec_segment(data, is64, e_phoff, e_phentsize, e_phnum):
    for i in range(e_phnum):
        base = e_phoff + i * e_phentsize
        (p_type,) = _unpack("<I", data, base)
        if p_type != PT_LOAD:
            continue
        if is64:
            (p_flags,) = _unpack("<I", data, base + 4)
            (p_offset,) = _unpack("<Q", data, base + 8)
            (p_filesz,) = _unpack("<Q", data, base + 32)
        else:
            (p_offset,) = _unpack("<I", data, base + 4)
            (p_flags,) = _unpack("<I", data, base + 24)
            (p_filesz,) = _unpack("<I", data, base + 16)
        if p_flags & PF_X:
            return p_offset, p_filesz
    raise ValueError("no executable PT_LOAD segment")


def _section(data, index, is64, e_shoff, e_shentsize):
    base = e_shoff + index * e_shentsize
    if is64:
        (name,) = _unpack("<I", data, base)
        (offset,) = _unpack("<Q", data, base + 24)
        (size,) = _unpack("<Q", data, base + 32)
    else:
        (name,) = _unpack("<I", data, base)
        (offset,) = _unpack("<I", data, base + 16)
        (size,) = _unpack("<I", data, base + 20)
    return name, offset, size


def _find_pin(data, is64, e_shoff, e_shentsize, e_shnum, e_shstrndx):
    _, shstr_off, _ = _section(data, e_shstrndx, is64, e_shoff, e_shentsize)
    for i in range(e_shnum):
        name_off, offset, size = _section(data, i, is64, e_shoff, e_shentsize)
        end = data.index(b"\x00", shstr_off + name_off)
        name = data[shstr_off + name_off : end].decode("ascii", "replace")
        if name == ".krpin":
            if size < PIN_SIZE:
                raise ValueError(".krpin section too small")
            return offset
    raise ValueError(".krpin section not found")


def pin(path):
    with open(path, "rb") as handle:
        data = bytearray(handle.read())

    (is64, e_phoff, e_phentsize, e_phnum, e_shoff, e_shentsize, e_shnum, e_shstrndx) = (
        _elf_layout(data)
    )
    exec_offset, exec_size = _exec_segment(data, is64, e_phoff, e_phentsize, e_phnum)
    pin_offset = _find_pin(data, is64, e_shoff, e_shentsize, e_shnum, e_shstrndx)

    digest = FNV_OFFSET_BASIS
    for index in range(exec_offset, exec_offset + exec_size):
        if pin_offset <= index < pin_offset + PIN_SIZE:
            continue
        digest ^= data[index]
        digest = (digest * FNV_PRIME) & MASK64
    if digest == 0:
        digest = 1

    struct.pack_into("<Q", data, pin_offset, digest)
    with open(path, "wb") as handle:
        handle.write(data)
    print(
        f"pinned {path}: digest=0x{digest:016x} "
        f"(exec segment {exec_size} bytes, pin at 0x{pin_offset:x})"
    )


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: pin_digest.py <path-to-so>")
    pin(sys.argv[1])
