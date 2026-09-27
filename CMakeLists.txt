cmake_minimum_required(VERSION 3.14)

project(smallest_tcp
    VERSION 0.1.0
    LANGUAGES C
    DESCRIPTION "Portable minimal TCP/IP stack — zero-alloc, application-owned memory"
)

# ── Options ───────────────────────────────────────────────────────────

# The tests and demos are hosted programs: off when cross-compiling
if(PROJECT_IS_TOP_LEVEL AND NOT CMAKE_CROSSCOMPILING)
    set(SMALLEST_TCP_HOSTED ON)
else()
    set(SMALLEST_TCP_HOSTED OFF)
endif()
option(SMALLEST_TCP_BUILD_TESTS   "Build unit tests"           ${SMALLEST_TCP_HOSTED})
option(SMALLEST_TCP_BUILD_DEMO    "Build demo applications"    ${SMALLEST_TCP_HOSTED})
option(SMALLEST_TCP_BUILD_DRIVERS "Build platform MAC drivers" ${PROJECT_IS_TOP_LEVEL})
option(SMALLEST_TCP_IPV4          "IPv4 + ARP + ICMP in the core, and the applications that run only over IPv4" ON)
option(SMALLEST_TCP_IPV6          "IPv6 + ICMPv6 + NDP + MLD in the core (with IPv4: dual stack)" ON)
option(SMALLEST_TCP_UDP           "UDP in the core, and the applications over it" ON)
option(SMALLEST_TCP_TCP           "TCP in the core, and the applications over it" ON)
option(SMALLEST_TCP_TLS           "TLS 1.3 with the Mbed TLS crypto backend (downloads Mbed TLS 3.6)" ${SMALLEST_TCP_HOSTED})
option(SMALLEST_TCP_DEBUG         "NET_LOG debug output to stderr (hosted builds)" OFF)
set(SMALLEST_TCP_CONFIG_FILE "" CACHE FILEPATH
    "Application configuration header, included first by net_config.h")
set(SMALLEST_TCP_BOARD "" CACHE STRING
    "Board port whose firmware to build (boards/<name>), cross-compiling")

if(NOT SMALLEST_TCP_IPV4 AND NOT SMALLEST_TCP_IPV6)
    message(FATAL_ERROR "SMALLEST_TCP_IPV4 and SMALLEST_TCP_IPV6 are both OFF: no network layer")
endif()

# ── Libraries ─────────────────────────────────────────────────────────
#
# smallest_tcp_<name>, also smallest_tcp::<name>.  Consumers get the core
# via FetchContent:
#   target_link_libraries(my_app PRIVATE smallest_tcp::smallest_tcp)

set(SMALLEST_TCP_WARNINGS -Wall -Wextra -Werror -pedantic)

function(smallest_tcp_library name)
    cmake_parse_arguments(LIB "" "" "SOURCES;LINKS" ${ARGN})
    add_library(smallest_tcp_${name} STATIC ${LIB_SOURCES})
    target_include_directories(smallest_tcp_${name} PUBLIC
        $<BUILD_INTERFACE:${smallest_tcp_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>)
    target_compile_features(smallest_tcp_${name} PUBLIC c_std_99)
    target_link_libraries(smallest_tcp_${name} PUBLIC ${LIB_LINKS})
    if(PROJECT_IS_TOP_LEVEL)
        target_compile_options(smallest_tcp_${name} PRIVATE ${SMALLEST_TCP_WARNINGS})
    endif()
    add_library(smallest_tcp::${name} ALIAS smallest_tcp_${name})
endfunction()

# ── Core ──────────────────────────────────────────────────────────────

smallest_tcp_library(core SOURCES
    src/net.c
    src/net_cksum.c
    src/net_text.c
    src/eth.c
)
add_library(smallest_tcp::smallest_tcp ALIAS smallest_tcp_core)

# The configuration changes the layout of net_t, so it is PUBLIC:
# everything linked against the core is compiled the same way.  The
# protocol options set NET_USE_*; a configuration file that sets one too
# is a redefinition error rather than a silent mismatch.
if(SMALLEST_TCP_CONFIG_FILE)
    target_compile_definitions(smallest_tcp_core PUBLIC
        NET_CONFIG_FILE="${SMALLEST_TCP_CONFIG_FILE}")
endif()
if(SMALLEST_TCP_DEBUG)
    target_compile_definitions(smallest_tcp_core PUBLIC NET_DEBUG=1)
endif()
if(SMALLEST_TCP_IPV4)
    target_sources(smallest_tcp_core PRIVATE src/arp.c src/ipv4.c src/icmp.c)
endif()
if(SMALLEST_TCP_IPV6)
    target_sources(smallest_tcp_core PRIVATE
        src/ipv6.c src/icmpv6.c src/ndp.c src/mld.c)
endif()
if(SMALLEST_TCP_UDP)
    target_sources(smallest_tcp_core PRIVATE src/udp.c)
endif()
if(SMALLEST_TCP_TCP)
    target_sources(smallest_tcp_core PRIVATE src/tcp.c src/tcp_buf_saw.c)
endif()
target_compile_definitions(smallest_tcp_core PUBLIC
    NET_USE_IPV4=$<BOOL:${SMALLEST_TCP_IPV4}>
    NET_USE_IPV6=$<BOOL:${SMALLEST_TCP_IPV6}>
    NET_USE_UDP=$<BOOL:${SMALLEST_TCP_UDP}>
    NET_USE_TCP=$<BOOL:${SMALLEST_TCP_TCP}>)

# ── Applications over UDP ─────────────────────────────────────────────

if(SMALLEST_TCP_UDP)
    if(SMALLEST_TCP_IPV4)
        smallest_tcp_library(dhcpv4_client SOURCES src/dhcpv4_client.c LINKS smallest_tcp_core)
        smallest_tcp_library(dhcpv4_server SOURCES src/dhcpv4_server.c LINKS smallest_tcp_core)
        smallest_tcp_library(tftp SOURCES src/tftp.c LINKS smallest_tcp_core)
    endif()
    smallest_tcp_library(mdns
        SOURCES src/dns_wire.c src/mdns.c
        LINKS smallest_tcp_core)
    if(SMALLEST_TCP_IPV4)
        target_sources(smallest_tcp_mdns PRIVATE src/igmp.c)
    endif()
    if(SMALLEST_TCP_IPV6)
        smallest_tcp_library(dhcpv6_client SOURCES src/dhcpv6_client.c LINKS smallest_tcp_core)
    endif()
endif()

# ── TLS 1.3 ───────────────────────────────────────────────────────────
#
# The protocol has no dependencies: the application supplies a crypto
# backend (tls_crypto_t).

smallest_tcp_library(tls SOURCES
    src/tls_common.c
    src/tls.c
    src/tls_keys.c
    src/tls_server.c
    src/tls_client.c
    src/dtls.c
)

# ── Applications over TCP ─────────────────────────────────────────────

if(SMALLEST_TCP_TCP)
    smallest_tcp_library(http SOURCES src/http.c LINKS smallest_tcp_core)
    smallest_tcp_library(tls_tcp SOURCES src/tls_tcp.c
        LINKS smallest_tcp_tls smallest_tcp_core)
    smallest_tcp_library(https SOURCES src/http_tls.c
        LINKS smallest_tcp_http smallest_tcp_tls_tcp)
endif()

# ── TLS crypto backend on Mbed TLS ────────────────────────────────────
#
# Mbed TLS provides the cryptography only (crypto + X.509); the protocol is
# smallest_tcp's own.  Pinned to the 3.6 LTS release tarball.

if(SMALLEST_TCP_TLS)
    include(FetchContent)
    set(ENABLE_PROGRAMS OFF CACHE BOOL "" FORCE)
    set(ENABLE_TESTING OFF CACHE BOOL "" FORCE)
    set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "" FORCE)
    set(MBEDTLS_USER_CONFIG_FILE
        "${CMAKE_CURRENT_SOURCE_DIR}/include/tls_mbedtls_user_config.h"
        CACHE FILEPATH "" FORCE)
    FetchContent_Declare(mbedtls
        URL https://github.com/Mbed-TLS/mbedtls/releases/download/mbedtls-3.6.7/mbedtls-3.6.7.tar.bz2
        URL_HASH SHA256=a7e8bcbec0e6f761b4af24f25677626b35f762f68eef79c08677a363212d11f6
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    )
    FetchContent_MakeAvailable(mbedtls)

    smallest_tcp_library(tls_mbedtls SOURCES src/tls_crypto_mbedtls.c
        LINKS mbedx509 mbedcrypto)
endif()

# ── Platform MAC drivers ──────────────────────────────────────────────

if(SMALLEST_TCP_BUILD_DRIVERS)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        smallest_tcp_library(driver_tap SOURCES src/driver/tap.c LINKS smallest_tcp_core)
        smallest_tcp_library(driver_rawsock SOURCES src/driver/rawsock.c LINKS smallest_tcp_core)
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        smallest_tcp_library(driver_bpf SOURCES src/driver/bpf.c LINKS smallest_tcp_core)
    elseif(CMAKE_SYSTEM_PROCESSOR STREQUAL "arm")
        smallest_tcp_library(driver_stm32f4_eth SOURCES src/driver/stm32f4_eth.c
            LINKS smallest_tcp_core)
    endif()
endif()

# ── Board ports ───────────────────────────────────────────────────────

if(SMALLEST_TCP_BOARD)
    if(NOT CMAKE_CROSSCOMPILING)
        message(FATAL_ERROR "SMALLEST_TCP_BOARD needs a toolchain file, e.g. cmake/arm-none-eabi.cmake")
    endif()
    add_subdirectory(boards/${SMALLEST_TCP_BOARD})
endif()

# ── Unit tests ────────────────────────────────────────────────────────

# The tests and demos exercise the whole stack.
if(NOT (SMALLEST_TCP_UDP AND SMALLEST_TCP_TCP))
    set(SMALLEST_TCP_BUILD_TESTS OFF)
    set(SMALLEST_TCP_BUILD_DEMO OFF)
endif()

if(SMALLEST_TCP_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# ── Demo applications ─────────────────────────────────────────────────

if(SMALLEST_TCP_BUILD_DEMO)
    add_subdirectory(demo)
endif()
