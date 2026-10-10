// Native probe KnightRASP: anti-debug, anti-hook, integritas segmen executable, kill.
//
// Prinsip:
// - Operasi baca kritis (/proc/self/status, /proc/self/maps) memakai syscall langsung
//   pada arm64/arm, sehingga tidak melewati libc yang mudah di-hook.
// - Baseline integritas diambil pada pemanggilan pertama, lalu dibandingkan.
// - Tidak ada alokasi besar; gagal baca = laporan negatif (fail-open di level check).

#include <jni.h>

#include <fcntl.h>
#include <link.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>

#if defined(__aarch64__)
#define FR_ARCH_ARM64 1
#elif defined(__arm__)
#define FR_ARCH_ARM 1
#endif

namespace {

long raw_syscall6(long number, long a1, long a2, long a3, long a4, long a5, long a6) {
#if defined(FR_ARCH_ARM64)
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
#elif defined(FR_ARCH_ARM)
    // Mode Thumb (default NDK) mereservasi r7 sebagai frame pointer sehingga syscall
    // langsung via r7 tidak diizinkan clang; fallback ke wrapper libc untuk armeabi-v7a.
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
    if (!read_file("/proc/self/status", status, 64 * 1024)) {
        return false;
    }
    const size_t pos = status.find("TracerPid:");
    if (pos == std::string::npos) {
        return false;
    }
    const int pid = std::atoi(status.c_str() + pos + 10);
    return pid > 0;
}

bool ptrace_self_detected() {
#if defined(SYS_ptrace)
    // PTRACE_TRACEME = 0. Hanya boleh dipanggil sekali: panggilan kedua selalu EPERM.
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
    if (!read_file("/proc/self/maps", maps, 8 * 1024 * 1024)) {
        return false;
    }
    static const char* const kMarkers[] = {
        "frida",
        "xposed",
        "substrate",
        "lsposed",
        "libgum",
    };
    for (const char* marker : kMarkers) {
        if (contains_case_insensitive(maps, marker)) {
            return true;
        }
    }
    return false;
}

struct TextSegment {
    uintptr_t address = 0;
    size_t size = 0;
};

int find_text_segment(struct dl_phdr_info* info, size_t /*size*/, void* data) {
    if (info->dlpi_name == nullptr ||
        std::strstr(info->dlpi_name, NATIVE_LIB_FILE_NAME) == nullptr) {
        return 0;
    }
    auto* segment = static_cast<TextSegment*>(data);
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

uint64_t hash_text_segment() {
    TextSegment segment;
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
    const uint64_t current = hash_text_segment();
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

}  // namespace

extern "C" {

JNIEXPORT jboolean JNICALL
Java_io_knightrasp_nativebridge_NativeProbeImpl_nativeAntiDebug(JNIEnv* /*env*/, jobject /*thiz*/) {
    return (tracer_pid_detected() || ptrace_self_detected()) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_io_knightrasp_nativebridge_NativeProbeImpl_nativeAntiHook(JNIEnv* /*env*/, jobject /*thiz*/) {
    return hook_artifacts_detected() ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_io_knightrasp_nativebridge_NativeProbeImpl_nativeTextIntegrity(JNIEnv* /*env*/, jobject /*thiz*/) {
    return text_modified() ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT void JNICALL
Java_io_knightrasp_nativebridge_NativeProbeImpl_nativeKillProcess(JNIEnv* /*env*/, jobject /*thiz*/) {
    kill_process_now();
}

}  // extern "C"
