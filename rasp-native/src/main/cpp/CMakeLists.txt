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
