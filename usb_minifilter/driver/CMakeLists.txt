# CMakeLists.txt — sentry_filter.sys 커널 드라이버 빌드
#
# 사전 조건
#   - Windows Driver Kit (WDK) 10.0.26100 이상
#   - Visual Studio 2022 + WDK 확장
#   - CMake 3.25+
#
# 빌드 방법 (Developer PowerShell for VS 2022):
#   mkdir build && cd build
#   cmake .. -G "Visual Studio 17 2022" -A x64 ^
#       -DCMAKE_SYSTEM_NAME=Windows ^
#       -DCMAKE_SYSTEM_VERSION=10.0 ^
#       -DCMAKE_VS_WINDOWS_TARGET_PLATFORM_VERSION=10.0.26100.0
#   cmake --build . --config Release
#
# 빌드 결과: build\Release\sentry_filter.sys

cmake_minimum_required(VERSION 3.25)

project(sentry_filter LANGUAGES C)

# ── WDK 헬퍼 ──────────────────────────────────────────────────────────────
# WDK CMake 통합은 VS 확장이 제공하는 WDK.cmake를 사용한다.
# 없는 경우 수동으로 include 경로·lib를 지정해야 한다.
find_package(WDK QUIET)

if(NOT WDK_FOUND)
    # WDK.cmake 없을 때 fallback (WDK 직접 설치 경로 기준)
    set(WDK_ROOT "C:/Program Files (x86)/Windows Kits/10")
    set(WDK_VERSION "10.0.26100.0")
    set(WDK_INC "${WDK_ROOT}/Include/${WDK_VERSION}")
    set(WDK_LIB "${WDK_ROOT}/Lib/${WDK_VERSION}")

    add_library(wdk_km INTERFACE)
    target_include_directories(wdk_km INTERFACE
        "${WDK_INC}/km"
        "${WDK_INC}/km/crt"
        "${WDK_INC}/shared"
    )
    target_link_directories(wdk_km INTERFACE
        "${WDK_LIB}/km/x64"
    )
    target_link_libraries(wdk_km INTERFACE
        fltMgr.lib
        ntoskrnl.lib
        BufferOverflowK.lib
    )
endif()

# ── 커널 드라이버 타겟 ─────────────────────────────────────────────────────
if(WDK_FOUND)
    wdk_add_driver(sentry_filter
        sentry_filter.c
    )
    target_include_directories(sentry_filter PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
    )
    set_target_properties(sentry_filter PROPERTIES
        WDK_TARGET_PLATFORM "Desktop"
    )
else()
    # Fallback: 수동 빌드 설정
    add_executable(sentry_filter
        sentry_filter.c
    )
    target_include_directories(sentry_filter PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
    )
    target_link_libraries(sentry_filter PRIVATE wdk_km)

    set_target_properties(sentry_filter PROPERTIES
        SUFFIX ".sys"
        LINK_FLAGS "/DRIVER /NODEFAULTLIB /SUBSYSTEM:NATIVE /ENTRY:GsDriverEntry /LTCG"
    )

    target_compile_options(sentry_filter PRIVATE
        /kernel           # 커널 모드 컴파일
        /GS-              # 스택 쿠키 비활성 (커널에서 자체 처리)
        /W4               # 경고 레벨 4
        /WX               # 경고 = 오류
        /Gz               # __stdcall 기본 호출 규약
        /Zp8              # 8바이트 정렬
        /GF               # 문자열 풀링
        /Gy               # 함수 단위 링크
        /wd4100           # unreferenced formal parameter (콜백에서 불가피)
        /wd4200           # nonstandard extension: zero-sized array
        -D_AMD64_
        -DAMD64
        -DPOOL_NX_OPTIN=1
        -D_KERNEL_MODE
    )
endif()

# ── INF 파일 복사 ──────────────────────────────────────────────────────────
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/sentry_filter.inf
    ${CMAKE_CURRENT_BINARY_DIR}/sentry_filter.inf
    COPYONLY
)
