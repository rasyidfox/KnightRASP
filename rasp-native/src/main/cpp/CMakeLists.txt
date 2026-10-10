cmake_minimum_required(VERSION 3.22.1)
project(knightrasp_native CXX)

# Nama output library dapat dikonfigurasi dari Gradle (rasp.nativeLibName) agar tidak
# memuat kata "rasp". Nilai harus sama dengan yang dipakai System.loadLibrary di Kotlin.
if(NOT DEFINED NATIVE_LIB_NAME)
    set(NATIVE_LIB_NAME "guardcore")
endif()

add_library(${NATIVE_LIB_NAME} SHARED knightrasp.cpp)

target_compile_definitions(
    ${NATIVE_LIB_NAME}
    PRIVATE NATIVE_LIB_FILE_NAME="lib${NATIVE_LIB_NAME}.so"
)

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

target_link_libraries(${NATIVE_LIB_NAME} PRIVATE log)
