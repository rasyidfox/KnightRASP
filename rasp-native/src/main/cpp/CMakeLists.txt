cmake_minimum_required(VERSION 3.22.1)
project(native_support CXX)

# The output library name is configurable from Gradle (knightrasp.nativeLibName)
# so it does not contain "rasp". The value must match System.loadLibrary() in
# Kotlin (which receives it obfuscated through BuildConfig).
if(NOT DEFINED NATIVE_LIB_NAME)
    set(NATIVE_LIB_NAME "guardcore")
endif()

add_library(${NATIVE_LIB_NAME} SHARED bridge.cpp)

target_compile_features(${NATIVE_LIB_NAME} PRIVATE cxx_std_17)

target_compile_options(
    ${NATIVE_LIB_NAME}
    PRIVATE
    -fvisibility=hidden
    -fstack-protector-strong
    -fno-rtti
    -fno-exceptions
    -Wall
    -Wextra
)

# Hardening: full RELRO + immediate binding, non-executable stack, hide symbols
# from linked static libraries.
target_link_options(
    ${NATIVE_LIB_NAME}
    PRIVATE
    -Wl,-z,relro
    -Wl,-z,now
    -Wl,-z,noexecstack
    -Wl,--exclude-libs,ALL
)

target_link_libraries(${NATIVE_LIB_NAME} PRIVATE log dl)

# Build-time pinning: fills the .krpin slot with the FNV-1a digest of the
# executable segment so pre-load patching is detected at runtime. Requires a
# host Python 3; when missing, pinning is skipped (runtime then relies on the
# load-time baseline only).
# Build-time pinning: the library is stripped here first (llvm-strip from the
# NDK), then the .krpin slot is filled with the FNV-1a digest of the executable
# segment. Stripping before pinning makes later packaging-time stripping a
# no-op, so the pinned bytes stay valid all the way into the APK.
find_package(Python3 COMPONENTS Interpreter QUIET)

file(GLOB KR_STRIP_CANDIDATES "${CMAKE_ANDROID_NDK}/toolchains/llvm/prebuilt/*/bin/llvm-strip*")
list(LENGTH KR_STRIP_CANDIDATES KR_STRIP_COUNT)
if(KR_STRIP_COUNT GREATER 0)
    list(GET KR_STRIP_CANDIDATES 0 KR_STRIP)
endif()

if(Python3_Interpreter_FOUND)
    if(KR_STRIP_COUNT GREATER 0)
        add_custom_command(
            TARGET ${NATIVE_LIB_NAME}
            POST_BUILD
            COMMAND "${KR_STRIP}" --strip-unneeded "$<TARGET_FILE:${NATIVE_LIB_NAME}>"
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/pin_digest.py
                    $<TARGET_FILE:${NATIVE_LIB_NAME}>
            COMMENT "Stripping and pinning native executable-segment digest"
            VERBATIM
        )
    else()
        add_custom_command(
            TARGET ${NATIVE_LIB_NAME}
            POST_BUILD
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/pin_digest.py
                    $<TARGET_FILE:${NATIVE_LIB_NAME}>
            COMMENT "Pinning native executable-segment digest (no strip tool found)"
            VERBATIM
        )
    endif()
else()
    message(STATUS "Python3 not found: native digest pinning disabled")
endif()
