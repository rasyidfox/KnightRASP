// Native probe for KnightRASP: anti-debug, anti-hook, text integrity, kill.
//
// Hardening notes:
// - All sensitive strings (paths, markers, JNI class name) are compile-time
//   XOR-encrypted ("OBF") so they never appear in plaintext in .rodata.
// - Reads of /proc/self/status and /proc/self/maps use raw syscalls on arm64 so
//   they do not go through the easily hooked libc wrappers.
// - The library identifies its own module via dladdr() instead of a file name.
// - JNI methods are bound with RegisterNatives (JNI_OnLoad); no Java_* symbols
//   are exported, which makes symbol-based fingerprinting harder.
// - Fail-open: any failure just yields a negative/unknown result for a check.

#include <jni.h>

#include <dlfcn.h>
#include <elf.h>
#include <fcntl.h>
#include <link.h>
#include <pthread.h>
#include <sys/syscall.h>
#include <sys/system_properties.h>
#include <unistd.h>

#include <array>
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <mutex>
#include <string>

#if defined(__aarch64__)
#define ARCH_ARM64 1
#elif defined(__arm__)
#define ARCH_ARM 1
#endif

// Build-time pinned digest slot. Filled by tools/pin_digest.py (CMake POST_BUILD)
// with the FNV-1a digest of the executable segment. Runtime compares the mapped
// segment against it, so patching the library bytes before it is ever loaded
// (Frida gadget/spawn, repackaged .so) is detected even though the runtime
// baseline would otherwise have been computed from the already-patched code.
extern "C" {
__attribute__((used, section(".krpin"), visibility("hidden")))
volatile uint64_t kr_pin = 0;
}

// ---------------------------------------------------------------------------
// Compile-time string obfuscation
// ---------------------------------------------------------------------------

template <size_t N, unsigned char Key>
class Enc {
public:
    explicit constexpr Enc(const char (&s)[N]) : data_{} {
        for (size_t i = 0; i < N; ++i) {
            data_[i] = static_cast<char>(static_cast<unsigned char>(s[i]) ^ Key);
        }
    }

    std::string str() const {
        std::string out;
        out.reserve(N - 1);
        for (size_t i = 0; i + 1 < N; ++i) {
            out.push_back(static_cast<char>(static_cast<unsigned char>(data_[i]) ^ Key));
        }
        return out;
    }

private:
    char data_[N];
};

// Key varies per literal (derived from its size) to avoid a single constant
// pattern across the binary.
#define ENC(s) \
    (Enc<sizeof(s), static_cast<unsigned char>(sizeof(s) * 31 + 17)>(s).str())

namespace {

long sys6(long number, long a1, long a2, long a3, long a4, long a5, long a6) {
#if defined(ARCH_ARM64)
    register long x8 __asm__("x8") = number;
    register long x0 __asm__("x0") = a1;
    register long x1 __asm__("x1") = a2;
    register long x2 __asm__("x2") = a3;
    register long x3 __asm__("x3") = a4;
    register long x4 __asm__("x4") = a5;
    register long x5 __asm__("x5") = a6;
    __asm__ volatile("svc #0"
                     : "+r"(x0)
                     : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
                     : "memory", "cc");
    return x0;
#elif defined(ARCH_ARM)
    // Thumb mode reserves r7 as the frame pointer, so a raw r7 syscall is not
    // possible; fall back to the libc wrapper on 32-bit ARM.
    return syscall(number, a1, a2, a3, a4, a5, a6);
#else
    return syscall(number, a1, a2, a3, a4, a5, a6);
#endif
}

bool slurp(const char* path, std::string& out, size_t max_bytes) {
#if defined(SYS_openat)
    long fd = sys6(SYS_openat, AT_FDCWD, reinterpret_cast<long>(path),
                           O_RDONLY | O_CLOEXEC, 0, 0, 0);
#else
    long fd = sys6(SYS_open, reinterpret_cast<long>(path), O_RDONLY | O_CLOEXEC, 0, 0, 0);
#endif
    if (fd < 0) {
        return false;
    }

    char buffer[4096];
    bool ok = true;
    while (out.size() < max_bytes) {
        long n = sys6(SYS_read, fd, reinterpret_cast<long>(buffer), sizeof(buffer), 0, 0, 0);
        if (n < 0) {
            ok = false;
            break;
        }
        if (n == 0) {
            break;
        }
        out.append(buffer, static_cast<size_t>(n));
    }
    sys6(SYS_close, fd, 0, 0, 0, 0, 0);
    return ok;
}

bool has_token(const char* data, size_t length, const char* needle) {
    const size_t needle_len = std::strlen(needle);
    if (needle_len == 0 || length < needle_len) {
        return false;
    }
    for (size_t i = 0; i + needle_len <= length; ++i) {
        size_t j = 0;
        for (; j < needle_len; ++j) {
            char a = data[i + j];
            char b = needle[j];
            if (a >= 'A' && a <= 'Z') {
                a = static_cast<char>(a - 'A' + 'a');
            }
            if (b >= 'A' && b <= 'Z') {
                b = static_cast<char>(b - 'A' + 'a');
            }
            if (a != b) {
                break;
            }
        }
        if (j == needle_len) {
            return true;
        }
    }
    return false;
}

bool has_token(const std::string& haystack, const char* needle) {
    return has_token(haystack.data(), haystack.size(), needle);
}

bool scan_status() {
    std::string status;
    if (!slurp(ENC("/proc/self/status").c_str(), status, 64 * 1024)) {
        return false;
    }
    const size_t pos = status.find(ENC("TracerPid:"));
    if (pos == std::string::npos) {
        return false;
    }
    const int pid = std::atoi(status.c_str() + pos + 10);
    return pid > 0;
}

bool scan_trace() {
#if defined(SYS_ptrace)
    // PTRACE_TRACEME = 0. Called once: a second call in the same process always
    // returns -EPERM. Only -EPERM means "already traced". SELinux may deny an
    // untrusted app with -EACCES, which must NOT be treated as evidence.
    static const long result = [] {
        return sys6(SYS_ptrace, 0, 0, 0, 0, 0, 0);
    }();
    return result == -EPERM;
#else
    return false;
#endif
}

// Forward declaration: defined further below with the ELF helpers.
uintptr_t module_base();

bool parse_hex(const char* begin, const char* end, uint64_t& out) {
    out = 0;
    if (begin >= end) {
        return false;
    }
    for (const char* p = begin; p < end; ++p) {
        const char c = *p;
        int value;
        if (c >= '0' && c <= '9') {
            value = c - '0';
        } else if (c >= 'a' && c <= 'f') {
            value = c - 'a' + 10;
        } else if (c >= 'A' && c <= 'F') {
            value = c - 'A' + 10;
        } else {
            return false;
        }
        out = (out << 4) | static_cast<uint64_t>(value);
    }
    return true;
}

// ---------------------------------------------------------------------------
// System-library integrity (mapped memory vs on-disk file)
//
// Frameworks such as LSPosed, SandHook or Epic hook functions inside libart /
// libc, which never touches our own library. Comparing the executable segments
// of those system libraries against the files on disk (kept pristine by
// verified boot) catches the patch without relying on any library name.
//
// Cost is bounded: each call compares a rotating 1 MB window per segment, so a
// large library is fully covered over a few ticks.
// ---------------------------------------------------------------------------

std::mutex g_lib_mutex;
size_t g_lib_rotation = 0;
unsigned char g_lib_buffer[1024 * 1024];

long read_file_range(const char* path, uint64_t offset, unsigned char* buffer, size_t size) {
#if defined(SYS_openat)
    long fd = sys6(SYS_openat, AT_FDCWD, reinterpret_cast<long>(path), O_RDONLY | O_CLOEXEC, 0, 0, 0);
#else
    long fd = sys6(SYS_open, reinterpret_cast<long>(path), O_RDONLY | O_CLOEXEC, 0, 0, 0);
#endif
    if (fd < 0) {
        return -1;
    }
    long total = 0;
    if (sys6(SYS_lseek, fd, static_cast<long>(offset), SEEK_SET, 0, 0, 0) >= 0) {
        while (static_cast<size_t>(total) < size) {
            long n = sys6(SYS_read, fd, reinterpret_cast<long>(buffer + total),
                          size - static_cast<size_t>(total), 0, 0, 0);
            if (n <= 0) {
                break;
            }
            total += n;
        }
    }
    sys6(SYS_close, fd, 0, 0, 0, 0, 0);
    return total;
}

bool system_library_modified() {
    std::lock_guard<std::mutex> lock(g_lib_mutex);

    std::string maps;
    if (!slurp(ENC("/proc/self/maps").c_str(), maps, 8 * 1024 * 1024)) {
        return false;
    }

    static const std::array<std::string, 3> kTokens = {
        ENC("libc.so"),
        ENC("libart.so"),
        ENC("libandroid_runtime.so"),
    };

    const size_t window = sizeof(g_lib_buffer);
    size_t position = 0;
    bool modified = false;

    while (position < maps.size() && !modified) {
        size_t line_end = maps.find('\n', position);
        if (line_end == std::string::npos) {
            line_end = maps.size();
        }
        const char* line = maps.data() + position;
        const size_t length = line_end - position;
        position = line_end + 1;

        size_t spaces[5];
        int space_count = 0;
        for (size_t i = 0; i < length && space_count < 5; ++i) {
            if (line[i] == ' ') {
                spaces[space_count++] = i;
            }
        }
        if (space_count < 5 || length < spaces[0] + 4) {
            continue;
        }
        if (std::memcmp(line + spaces[0] + 1, "r-xp", 4) != 0) {
            continue;
        }
        const char* path = line + spaces[4] + 1;
        const size_t path_length = length - spaces[4] - 1;
        if (path_length == 0 || path[0] != '/') {
            continue;
        }
        bool watched = false;
        for (const auto& token : kTokens) {
            if (has_token(path, path_length, token.c_str())) {
                watched = true;
                break;
            }
        }
        if (!watched) {
            continue;
        }

        uint64_t start = 0;
        uint64_t end = 0;
        uint64_t file_offset = 0;
        if (!parse_hex(line, line + spaces[0], start)) {
            continue;
        }
        const char* dash = static_cast<const char*>(std::memchr(line, '-', spaces[0]));
        if (dash == nullptr || !parse_hex(dash + 1, line + spaces[0], end)) {
            continue;
        }
        if (!parse_hex(line + spaces[1] + 1, line + spaces[2], file_offset)) {
            continue;
        }
        if (end <= start) {
            continue;
        }

        const size_t segment_size = static_cast<size_t>(end - start);
        const size_t offset_in_segment = g_lib_rotation % segment_size;
        size_t compare_size = segment_size - offset_in_segment;
        if (compare_size > window) {
            compare_size = window;
        }
        if (compare_size == 0) {
            continue;
        }

        const std::string path_string(path, path_length);
        const long read_bytes = read_file_range(
            path_string.c_str(),
            file_offset + offset_in_segment,
            g_lib_buffer,
            compare_size
        );
        if (read_bytes < 0 || static_cast<size_t>(read_bytes) != compare_size) {
            // Unreadable file (SELinux, deleted mapping, ...): not evidence.
            continue;
        }
        const auto* memory = reinterpret_cast<const unsigned char*>(start + offset_in_segment);
        if (std::memcmp(memory, g_lib_buffer, compare_size) != 0) {
            modified = true;
        }
    }

    g_lib_rotation += window;
    if (g_lib_rotation > (64 * 1024 * 1024)) {
        g_lib_rotation = 0;
    }
    return modified;
}

// ---------------------------------------------------------------------------
// PLT/GOT integrity
//
// Walks our own relocation table and compares each watched JUMP_SLOT entry with
// the address `dlsym` resolves. A PLT-hooked function (e.g. `__system_property_get`
// rewritten to fake the boot state) shows up as a mismatch.
// ---------------------------------------------------------------------------

#if defined(__aarch64__)
constexpr size_t kJumpSlotType = R_AARCH64_JUMP_SLOT;
#elif defined(__arm__)
constexpr size_t kJumpSlotType = R_ARM_JUMP_SLOT;
#elif defined(__x86_64__)
constexpr size_t kJumpSlotType = R_X86_64_JUMP_SLOT;
#else
constexpr size_t kJumpSlotType = 0;
#endif

bool plt_modified() {
    if (kJumpSlotType == 0) {
        return false;
    }

    struct Finder {
        uintptr_t base;
        const ElfW(Dyn)* dynamic;
    };
    Finder finder{module_base(), nullptr};
    if (finder.base == 0) {
        return false;
    }

    dl_iterate_phdr(
        [](struct dl_phdr_info* info, size_t, void* data) -> int {
            auto* f = static_cast<Finder*>(data);
            if (static_cast<uintptr_t>(info->dlpi_addr) != f->base) {
                return 0;
            }
            for (int i = 0; i < info->dlpi_phnum; ++i) {
                if (info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
                    f->dynamic = reinterpret_cast<const ElfW(Dyn)*>(
                        info->dlpi_addr + info->dlpi_phdr[i].p_vaddr);
                    return 1;
                }
            }
            return 0;
        },
        &finder);
    if (finder.dynamic == nullptr) {
        return false;
    }

    const ElfW(Sym)* symtab = nullptr;
    const char* strtab = nullptr;
    const void* jmprel = nullptr;
    uint64_t symtab_value = 0;
    uint64_t strtab_value = 0;
    uint64_t jmprel_value = 0;
    size_t pltrelsz = 0;
    size_t pltrel_type = 0;
    for (const ElfW(Dyn)* dyn = finder.dynamic; dyn->d_tag != DT_NULL; ++dyn) {
        switch (dyn->d_tag) {
            case DT_SYMTAB:
                symtab_value = dyn->d_un.d_ptr;
                break;
            case DT_STRTAB:
                strtab_value = dyn->d_un.d_ptr;
                break;
            case DT_JMPREL:
                jmprel_value = dyn->d_un.d_ptr;
                break;
            case DT_PLTRELSZ:
                pltrelsz = static_cast<size_t>(dyn->d_un.d_val);
                break;
            case DT_PLTREL:
                pltrel_type = static_cast<size_t>(dyn->d_un.d_val);
                break;
            default:
                break;
        }
    }
    if (symtab_value == 0 || strtab_value == 0 || jmprel_value == 0 || pltrelsz == 0) {
        return false;
    }

    // The dynamic section is read-only: the linker does not relocate its DT_*
    // pointer entries in memory, so the load bias must be added here (values may
    // already be absolute on other loaders — treat anything >= base as absolute).
    auto resolve = [&finder](uint64_t value) -> uintptr_t {
        return value >= finder.base ? static_cast<uintptr_t>(value)
                                    : finder.base + static_cast<uintptr_t>(value);
    };
    symtab = reinterpret_cast<const ElfW(Sym)*>(resolve(symtab_value));
    strtab = reinterpret_cast<const char*>(resolve(strtab_value));
    jmprel = reinterpret_cast<const void*>(resolve(jmprel_value));

    static const std::array<std::string, 9> kWatched = {
        ENC("__system_property_get"),
        ENC("dladdr"),
        ENC("dl_iterate_phdr"),
        ENC("nanosleep"),
        ENC("pthread_create"),
        ENC("dlsym"),
        ENC("atoi"),
        ENC("memset"),
        ENC("memcmp"),
    };
    auto is_watched = [](const char* name) {
        for (const auto& watched : kWatched) {
            if (std::strcmp(name, watched.c_str()) == 0) {
                return true;
            }
        }
        return false;
    };

    if (pltrel_type == DT_REL) {
        const auto* rel = static_cast<const ElfW(Rel)*>(jmprel);
        const size_t count = pltrelsz / sizeof(ElfW(Rel));
        for (size_t i = 0; i < count; ++i) {
            if (ELF32_R_TYPE(rel[i].r_info) != kJumpSlotType) {
                continue;
            }
            const size_t symbol = static_cast<size_t>(ELF32_R_SYM(rel[i].r_info));
            const char* name = strtab + symtab[symbol].st_name;
            if (!is_watched(name)) {
                continue;
            }
            const void* expected = dlsym(RTLD_DEFAULT, name);
            const void* actual = *reinterpret_cast<const void* const*>(finder.base + rel[i].r_offset);
            if (expected != nullptr && actual != expected) {
                return true;
            }
        }
    } else if (pltrel_type == DT_RELA) {
        const auto* rela = static_cast<const ElfW(Rela)*>(jmprel);
        const size_t count = pltrelsz / sizeof(ElfW(Rela));
        for (size_t i = 0; i < count; ++i) {
            if (ELF64_R_TYPE(rela[i].r_info) != kJumpSlotType) {
                continue;
            }
            const size_t symbol = static_cast<size_t>(ELF64_R_SYM(rela[i].r_info));
            const char* name = strtab + symtab[symbol].st_name;
            if (!is_watched(name)) {
                continue;
            }
            const void* expected = dlsym(RTLD_DEFAULT, name);
            const void* actual = *reinterpret_cast<const void* const*>(finder.base + rela[i].r_offset);
            if (expected != nullptr && actual != expected) {
                return true;
            }
        }
    }
    return false;
}

bool scan_regions() {
    std::string maps;
    if (!slurp(ENC("/proc/self/maps").c_str(), maps, 8 * 1024 * 1024)) {
        return false;
    }
    static const std::array<std::string, 15> kMarkers = {
        ENC("frida"),
        ENC("xposed"),
        ENC("substrate"),
        ENC("lsposed"),
        ENC("libgum"),
        ENC("liblspd"),
        ENC("libriru"),
        ENC("zygisk"),
        ENC("sandhook"),
        ENC("libepic"),
        ENC("libdobby"),
        ENC("shadowhook"),
        ENC("libwhale"),
        ENC("yahfa"),
        ENC("libpine"),
    };
    for (const auto& marker : kMarkers) {
        if (has_token(maps, marker.c_str())) {
            return true;
        }
    }
    return false;
}

bool scan_root_mounts() {
    std::string data;
    if (!slurp(ENC("/proc/self/mountinfo").c_str(), data, 4 * 1024 * 1024)) {
        return false;
    }
    static const std::array<std::string, 3> kTokens = {
        ENC("magisk"),
        ENC("kernelsu"),
        ENC("ksud"),
    };
    for (const auto& token : kTokens) {
        if (has_token(data, token.c_str())) {
            return true;
        }
    }
    return false;
}

bool boot_state_modified() {
    char value[PROP_VALUE_MAX] = {0};
    auto prop = [&value](const std::string& key) -> std::string {
        value[0] = '\0';
        __system_property_get(key.c_str(), value);
        return std::string(value);
    };
    const std::string state = prop(ENC("ro.boot.verifiedbootstate"));
    if (state == ENC("orange") || state == ENC("yellow")) {
        return true;
    }
    if (prop(ENC("ro.boot.flash.locked")) == ENC("0")) {
        return true;
    }
    if (prop(ENC("ro.boot.vbmeta.device_state")) == ENC("unlocked")) {
        return true;
    }
    return false;
}

// Memory-map shapes typical of injected agents. File-name-based markers can be
// defeated by renaming; memfd-backed or writable+executable file mappings are
// harder to hide (ART's "jit-cache" memfd is excluded).
bool suspicious_memory() {
    std::string data;
    if (!slurp(ENC("/proc/self/maps").c_str(), data, 8 * 1024 * 1024)) {
        return false;
    }

    const std::string memfd = ENC("memfd:");
    // ART creates memfd mappings of its own (jit caches, profiles, vdex/odex);
    // names containing these tokens are considered benign.
    static const std::array<std::string, 5> kBenign = {
        ENC("jit"),
        ENC("profile"),
        ENC("odex"),
        ENC("vdex"),
        ENC("dex"),
    };
    size_t pos = 0;
    while ((pos = data.find(memfd, pos)) != std::string::npos) {
        const size_t end = data.find('\n', pos);
        const size_t stop = (end == std::string::npos) ? data.size() : end;
        const size_t name_start = pos + memfd.size();
        size_t name_end = data.find_first_of(" \t(", name_start);
        if (name_end == std::string::npos || name_end > stop) {
            name_end = stop;
        }
        const std::string name = data.substr(name_start, name_end - name_start);

        bool benign = false;
        for (const auto& token : kBenign) {
            if (name.find(token) != std::string::npos) {
                benign = true;
                break;
            }
        }
        if (!benign) {
            return true;
        }
        pos = stop;
    }

    const std::string rwxp = ENC("rwxp");
    const std::string so_suffix = ENC(".so");
    pos = 0;
    while ((pos = data.find(rwxp, pos)) != std::string::npos) {
        const size_t end = data.find('\n', pos);
        const size_t stop = (end == std::string::npos) ? data.size() : end;
        const size_t start_raw = data.rfind('\n', pos);
        const size_t start = (start_raw == std::string::npos) ? 0 : start_raw + 1;
        const size_t lib = data.find(so_suffix, start);
        if (lib != std::string::npos && lib < stop) {
            return true;
        }
        pos = stop;
    }
    return false;
}

struct Region {
    uintptr_t base = 0;
    uintptr_t address = 0;
    size_t size = 0;
};

int find_region(struct dl_phdr_info* info, size_t /*size*/, void* data) {
    auto* segment = static_cast<Region*>(data);
    if (static_cast<uintptr_t>(info->dlpi_addr) != segment->base) {
        return 0;
    }
    for (int i = 0; i < info->dlpi_phnum; ++i) {
        const ElfW(Phdr)& phdr = info->dlpi_phdr[i];
        if (phdr.p_type != PT_LOAD || (phdr.p_flags & PF_X) == 0) {
            continue;
        }
        segment->address = info->dlpi_addr + phdr.p_vaddr;
        // p_filesz: bytes that come from the file, so the digest is reproducible
        // against a build-time file hash (memory beyond filesz is zero-filled).
        segment->size = phdr.p_filesz;
        return 1;
    }
    return 0;
}

uintptr_t module_base() {
    Dl_info info{};
    if (dladdr(reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(&find_region)), &info) == 0) {
        return 0;
    }
    return reinterpret_cast<uintptr_t>(info.dli_fbase);
}

uint64_t compute_digest() {
    Region segment;
    segment.base = module_base();
    if (segment.base == 0) {
        return 0;
    }
    if (dl_iterate_phdr(find_region, &segment) == 0 || segment.size == 0) {
        return 0;
    }

    // The pinned slot lives inside the range; both the build-time tool and the
    // runtime hash skip those bytes so patching the pin does not invalidate it.
    const uintptr_t pin_address = reinterpret_cast<uintptr_t>(&kr_pin);
    const bool pin_inside = pin_address >= segment.address &&
                            pin_address - segment.address + sizeof(uint64_t) <= segment.size;
    const size_t pin_offset =
        pin_inside ? static_cast<size_t>(pin_address - segment.address) : SIZE_MAX;

    const auto* bytes = reinterpret_cast<const unsigned char*>(segment.address);
    uint64_t hash = 14695981039346656037ULL;  // FNV-1a 64 offset basis
    for (size_t i = 0; i < segment.size; ++i) {
        if (pin_offset != SIZE_MAX && i >= pin_offset && i < pin_offset + sizeof(uint64_t)) {
            continue;
        }
        hash ^= bytes[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

bool scan_verdict() {
    static uint64_t baseline = 0;
    const uint64_t current = compute_digest();
    if (current == 0) {
        return false;
    }
    if (baseline == 0) {
        baseline = current;
    } else if (current != baseline) {
        // The executable segment changed after load: inline hook / memory patch.
        return true;
    }
    const uint64_t pinned = kr_pin;
    // Pinned at build time: catches patches applied before the first call
    // (pre-load gadget/spawn, repackaged library).
    return pinned != 0 && current != pinned;
}

[[noreturn]] void finish_now() {
#if defined(SYS_exit_group)
    sys6(SYS_exit_group, 0, 0, 0, 0, 0, 0);
#endif
    _exit(0);
}

// ---------------------------------------------------------------------------
// Native watchdog
//
// Runs on its own thread, independent of any Java/Kotlin call path: even if the
// whole Kotlin engine (init, policy, response executor, probe interface) is
// hooked to no-op, this thread keeps re-evaluating the native checks and can
// terminate the process on its own. It also re-checks the executable segment
// every tick, so inline hooks applied after load are detected.
//
// Arming:
// - normal path: Kotlin calls n8() at init with the host configuration;
// - fail-secure path: if n8() never arrives within the grace window (init was
//   hooked or skipped), the watchdog arms itself with killing enabled.
// ---------------------------------------------------------------------------

std::atomic<int> g_kill_mode{-1};  // -1 unconfigured, 0 off, 1 on
std::atomic<int> g_interval_ms{5000};
std::atomic<bool> g_armed{false};
std::atomic<bool> g_risk{false};  // risk latched by the evaluator (signalRisk)

bool watchdog_violation() {
    return g_risk.load() || scan_status() || scan_trace() || scan_regions() ||
           scan_root_mounts() || boot_state_modified() || suspicious_memory() ||
           scan_verdict() || system_library_modified() || plt_modified();
}

void* watchdog_main(void* /*arg*/) {
    // Wait up to 5 s for the Kotlin side to configure us.
    for (int i = 0; i < 50 && !g_armed.load(); ++i) {
        const timespec pause{0, 100 * 1000 * 1000};
        nanosleep(&pause, nullptr);
    }
    if (!g_armed.load()) {
        // Never configured: arming was bypassed, fail secure.
        g_kill_mode.store(1);
        g_armed.store(true);
    }

    for (;;) {
        // Sleep first: an immediate kill right after process start makes the
        // platform relaunch the foreground task (kill-loop). Waiting one tick
        // lets the activity settle, so the termination sticks.
        const long interval = g_interval_ms.load();
        const timespec pause{interval / 1000, (interval % 1000) * 1000 * 1000};
        nanosleep(&pause, nullptr);
        if (g_kill_mode.load() > 0 && watchdog_violation()) {
            finish_now();
        }
    }
    return nullptr;
}

void ensure_watchdog() {
    static const bool started = [] {
        pthread_t thread;
        if (pthread_create(&thread, nullptr, &watchdog_main, nullptr) == 0) {
            pthread_detach(thread);
        }
        return true;
    }();
    (void)started;
}

// ---------------------------------------------------------------------------
// JNI bindings (registered, not exported by name)
// ---------------------------------------------------------------------------

jboolean call_a(JNIEnv* /*env*/, jobject /*thiz*/) {
    return (scan_status() || scan_trace()) ? JNI_TRUE : JNI_FALSE;
}

jboolean call_b(JNIEnv* /*env*/, jobject /*thiz*/) {
    return scan_regions() ? JNI_TRUE : JNI_FALSE;
}

jboolean call_c(JNIEnv* /*env*/, jobject /*thiz*/) {
    return scan_verdict() ? JNI_TRUE : JNI_FALSE;
}

void call_d(JNIEnv* /*env*/, jobject /*thiz*/) {
    finish_now();
}

jboolean call_e(JNIEnv* /*env*/, jobject /*thiz*/) {
    return scan_root_mounts() ? JNI_TRUE : JNI_FALSE;
}

jboolean call_f(JNIEnv* /*env*/, jobject /*thiz*/) {
    return boot_state_modified() ? JNI_TRUE : JNI_FALSE;
}

jboolean call_g(JNIEnv* /*env*/, jobject /*thiz*/) {
    return suspicious_memory() ? JNI_TRUE : JNI_FALSE;
}

void call_h(JNIEnv* /*env*/, jobject /*thiz*/, jboolean enabled, jboolean kill, jint interval_ms) {
    g_armed.store(true);
    if (!enabled) {
        g_kill_mode.store(0);
        return;
    }
    g_kill_mode.store(kill ? 1 : 0);
    if (interval_ms >= 500) {
        g_interval_ms.store(interval_ms);
    }
}

void call_i(JNIEnv* /*env*/, jobject /*thiz*/, jboolean risk) {
    // Only latch: the Kotlin response path performs the termination itself
    // (removing the task first so the platform does not relaunch the activity).
    // The watchdog picks the latch up as a last resort if Kotlin never acts.
    if (risk) {
        g_risk.store(true);
    }
}

jboolean call_j(JNIEnv* /*env*/, jobject /*thiz*/) {
    return system_library_modified() ? JNI_TRUE : JNI_FALSE;
}

jboolean call_k(JNIEnv* /*env*/, jobject /*thiz*/) {
    return plt_modified() ? JNI_TRUE : JNI_FALSE;
}

const JNINativeMethod kMethods[] = {
    {const_cast<char*>("n1"), const_cast<char*>("()Z"),
     reinterpret_cast<void*>(&call_a)},
    {const_cast<char*>("n2"), const_cast<char*>("()Z"),
     reinterpret_cast<void*>(&call_b)},
    {const_cast<char*>("n3"), const_cast<char*>("()Z"),
     reinterpret_cast<void*>(&call_c)},
    {const_cast<char*>("n4"), const_cast<char*>("()V"),
     reinterpret_cast<void*>(&call_d)},
    {const_cast<char*>("n5"), const_cast<char*>("()Z"),
     reinterpret_cast<void*>(&call_e)},
    {const_cast<char*>("n6"), const_cast<char*>("()Z"),
     reinterpret_cast<void*>(&call_f)},
    {const_cast<char*>("n7"), const_cast<char*>("()Z"),
     reinterpret_cast<void*>(&call_g)},
    {const_cast<char*>("n8"), const_cast<char*>("(ZZI)V"),
     reinterpret_cast<void*>(&call_h)},
    {const_cast<char*>("n9"), const_cast<char*>("(Z)V"),
     reinterpret_cast<void*>(&call_i)},
    {const_cast<char*>("n10"), const_cast<char*>("()Z"),
     reinterpret_cast<void*>(&call_j)},
    {const_cast<char*>("n11"), const_cast<char*>("()Z"),
     reinterpret_cast<void*>(&call_k)},
};

}  // namespace

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* /*reserved*/) {
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK || env == nullptr) {
        return JNI_ERR;
    }
    jclass clazz = env->FindClass(ENC("io/knightrasp/nativebridge/JniBridge").c_str());
    if (clazz == nullptr) {
        return JNI_ERR;
    }
    const jint count = static_cast<jint>(sizeof(kMethods) / sizeof(kMethods[0]));
    if (env->RegisterNatives(clazz, kMethods, count) != JNI_OK) {
        return JNI_ERR;
    }
    ensure_watchdog();
    return JNI_VERSION_1_6;
}
