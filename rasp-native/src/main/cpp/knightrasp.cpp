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
#include <fcntl.h>
#include <link.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>

#if defined(__aarch64__)
#define KR_ARCH_ARM64 1
#elif defined(__arm__)
#define KR_ARCH_ARM 1
#endif

// ---------------------------------------------------------------------------
// Compile-time string obfuscation
// ---------------------------------------------------------------------------

template <size_t N, unsigned char Key>
class XorStr {
public:
    explicit constexpr XorStr(const char (&s)[N]) : data_{} {
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
#define OBF(s) \
    (XorStr<sizeof(s), static_cast<unsigned char>(sizeof(s) * 31 + 17)>(s).str())

namespace {

long raw_syscall6(long number, long a1, long a2, long a3, long a4, long a5, long a6) {
#if defined(KR_ARCH_ARM64)
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
#elif defined(KR_ARCH_ARM)
    // Thumb mode reserves r7 as the frame pointer, so a raw r7 syscall is not
    // possible; fall back to the libc wrapper on 32-bit ARM.
    return syscall(number, a1, a2, a3, a4, a5, a6);
#else
    return syscall(number, a1, a2, a3, a4, a5, a6);
#endif
}

bool read_file(const char* path, std::string& out, size_t max_bytes) {
#if defined(SYS_openat)
    long fd = raw_syscall6(SYS_openat, AT_FDCWD, reinterpret_cast<long>(path),
                           O_RDONLY | O_CLOEXEC, 0, 0, 0);
#else
    long fd = raw_syscall6(SYS_open, reinterpret_cast<long>(path), O_RDONLY | O_CLOEXEC, 0, 0, 0);
#endif
    if (fd < 0) {
        return false;
    }

    char buffer[4096];
    bool ok = true;
    while (out.size() < max_bytes) {
        long n = raw_syscall6(SYS_read, fd, reinterpret_cast<long>(buffer), sizeof(buffer), 0, 0, 0);
        if (n < 0) {
            ok = false;
            break;
        }
        if (n == 0) {
            break;
        }
        out.append(buffer, static_cast<size_t>(n));
    }
    raw_syscall6(SYS_close, fd, 0, 0, 0, 0, 0);
    return ok;
}

bool contains_case_insensitive(const std::string& haystack, const char* needle) {
    const size_t needle_len = std::strlen(needle);
    if (needle_len == 0 || haystack.size() < needle_len) {
        return false;
    }
    for (size_t i = 0; i + needle_len <= haystack.size(); ++i) {
        size_t j = 0;
        for (; j < needle_len; ++j) {
            char a = haystack[i + j];
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

bool tracer_pid_detected() {
    std::string status;
    if (!read_file(OBF("/proc/self/status").c_str(), status, 64 * 1024)) {
        return false;
    }
    const size_t pos = status.find(OBF("TracerPid:"));
    if (pos == std::string::npos) {
        return false;
    }
    const int pid = std::atoi(status.c_str() + pos + 10);
    return pid > 0;
}

bool ptrace_self_detected() {
#if defined(SYS_ptrace)
    // PTRACE_TRACEME = 0. Call it only once: the second call always returns EPERM.
    static const bool detected = [] {
        return raw_syscall6(SYS_ptrace, 0, 0, 0, 0, 0, 0) < 0;
    }();
    return detected;
#else
    return false;
#endif
}

bool hook_artifacts_detected() {
    std::string maps;
    if (!read_file(OBF("/proc/self/maps").c_str(), maps, 8 * 1024 * 1024)) {
        return false;
    }
    static const std::array<std::string, 5> kMarkers = {
        OBF("frida"),
        OBF("xposed"),
        OBF("substrate"),
        OBF("lsposed"),
        OBF("libgum"),
    };
    for (const auto& marker : kMarkers) {
        if (contains_case_insensitive(maps, marker.c_str())) {
            return true;
        }
    }
    return false;
}

struct TextSegment {
    uintptr_t base = 0;
    uintptr_t address = 0;
    size_t size = 0;
};

int find_text_segment(struct dl_phdr_info* info, size_t /*size*/, void* data) {
    auto* segment = static_cast<TextSegment*>(data);
    if (static_cast<uintptr_t>(info->dlpi_addr) != segment->base) {
        return 0;
    }
    for (int i = 0; i < info->dlpi_phnum; ++i) {
        const ElfW(Phdr)& phdr = info->dlpi_phdr[i];
        if (phdr.p_type != PT_LOAD || (phdr.p_flags & PF_X) == 0) {
            continue;
        }
        segment->address = info->dlpi_addr + phdr.p_vaddr;
        segment->size = phdr.p_memsz;
        return 1;
    }
    return 0;
}

uintptr_t own_module_base() {
    Dl_info info{};
    if (dladdr(reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(&find_text_segment)), &info) == 0) {
        return 0;
    }
    return reinterpret_cast<uintptr_t>(info.dli_fbase);
}

uint64_t hash_exec_segment() {
    TextSegment segment;
    segment.base = own_module_base();
    if (segment.base == 0) {
        return 0;
    }
    if (dl_iterate_phdr(find_text_segment, &segment) == 0 || segment.size == 0) {
        return 0;
    }
    const auto* bytes = reinterpret_cast<const unsigned char*>(segment.address);
    uint64_t hash = 14695981039346656037ULL;  // FNV-1a 64 offset basis
    for (size_t i = 0; i < segment.size; ++i) {
        hash ^= bytes[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

bool text_modified() {
    static uint64_t baseline = 0;
    const uint64_t current = hash_exec_segment();
    if (current == 0) {
        return false;
    }
    if (baseline == 0) {
        baseline = current;
        return false;
    }
    return current != baseline;
}

[[noreturn]] void kill_process_now() {
#if defined(SYS_exit_group)
    raw_syscall6(SYS_exit_group, 0, 0, 0, 0, 0, 0);
#endif
    _exit(0);
}

// ---------------------------------------------------------------------------
// JNI bindings (registered, not exported by name)
// ---------------------------------------------------------------------------

jboolean anti_debug_jni(JNIEnv* /*env*/, jobject /*thiz*/) {
    return (tracer_pid_detected() || ptrace_self_detected()) ? JNI_TRUE : JNI_FALSE;
}

jboolean anti_hook_jni(JNIEnv* /*env*/, jobject /*thiz*/) {
    return hook_artifacts_detected() ? JNI_TRUE : JNI_FALSE;
}

jboolean text_integrity_jni(JNIEnv* /*env*/, jobject /*thiz*/) {
    return text_modified() ? JNI_TRUE : JNI_FALSE;
}

void kill_process_jni(JNIEnv* /*env*/, jobject /*thiz*/) {
    kill_process_now();
}

const JNINativeMethod kNativeMethods[] = {
    {const_cast<char*>("nativeAntiDebug"), const_cast<char*>("()Z"),
     reinterpret_cast<void*>(&anti_debug_jni)},
    {const_cast<char*>("nativeAntiHook"), const_cast<char*>("()Z"),
     reinterpret_cast<void*>(&anti_hook_jni)},
    {const_cast<char*>("nativeTextIntegrity"), const_cast<char*>("()Z"),
     reinterpret_cast<void*>(&text_integrity_jni)},
    {const_cast<char*>("nativeKillProcess"), const_cast<char*>("()V"),
     reinterpret_cast<void*>(&kill_process_jni)},
};

}  // namespace

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM* vm, void* /*reserved*/) {
    JNIEnv* env = nullptr;
    if (vm->GetEnv(reinterpret_cast<void**>(&env), JNI_VERSION_1_6) != JNI_OK || env == nullptr) {
        return JNI_ERR;
    }
    jclass clazz = env->FindClass(OBF("io/knightrasp/nativebridge/NativeProbeImpl").c_str());
    if (clazz == nullptr) {
        return JNI_ERR;
    }
    const jint count = static_cast<jint>(sizeof(kNativeMethods) / sizeof(kNativeMethods[0]));
    if (env->RegisterNatives(clazz, kNativeMethods, count) != JNI_OK) {
        return JNI_ERR;
    }
    return JNI_VERSION_1_6;
}
