cmake_minimum_required(VERSION 3.14)

project(smallest_tcp
    VERSION 0.1.0
    LANGUAGES C
    DESCRIPTION "Portable minimal TCP/IP stack — zero-alloc, application-owned memory"
)

# ── Options ───────────────────────────────────────────────────────────

option(SMALLEST_TCP_BUILD_TESTS   "Build unit tests"           ${PROJECT_IS_TOP_LEVEL})
option(SMALLEST_TCP_BUILD_DEMO    "Build demo applications"    ${PROJECT_IS_TOP_LEVEL})
option(SMALLEST_TCP_BUILD_DRIVERS "Build platform MAC drivers" ${PROJECT_IS_TOP_LEVEL})
option(SMALLEST_TCP_IPV6          "Dual stack: IPv6 + ICMPv6 + NDP in the core" ON)
option(SMALLEST_TCP_TLS           "TLS 1.3 with the Mbed TLS crypto backend (downloads Mbed TLS 3.6)" ${PROJECT_IS_TOP_LEVEL})

# ── Core library (always built) ───────────────────────────────────────
#
# This is the target consumers get via FetchContent:
#   target_link_libraries(my_app PRIVATE smallest_tcp::smallest_tcp)

add_library(smallest_tcp_core STATIC
    src/net.c
    src/net_cksum.c
    src/eth.c
    src/arp.c
    src/ipv4.c
    src/icmp.c
    src/udp.c
    src/tcp.c
    src/tcp_buf_saw.c
)

target_include_directories(smallest_tcp_core
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_compile_features(smallest_tcp_core PUBLIC c_std_99)

# Strict warnings when building this project directly
if(PROJECT_IS_TOP_LEVEL)
    target_compile_options(smallest_tcp_core PRIVATE
        -Wall -Wextra -Werror -pedantic
    )
endif()

# IPv6 changes the layout of net_t, so the define is PUBLIC: everything
# linked against the core is compiled the same way.
if(SMALLEST_TCP_IPV6)
    target_sources(smallest_tcp_core PRIVATE
        src/ipv6.c
        src/icmpv6.c
        src/ndp.c
        src/mld.c
    )
    target_compile_definitions(smallest_tcp_core PUBLIC NET_USE_IPV6=1)
endif()

# Create a namespaced alias for FetchContent consumers
add_library(smallest_tcp::smallest_tcp ALIAS smallest_tcp_core)

# ── DHCPv4 client (optional — link only what you need) ───────────────

add_library(smallest_tcp_dhcpv4_client STATIC
    src/dhcpv4_client.c
)
target_link_libraries(smallest_tcp_dhcpv4_client PUBLIC smallest_tcp_core)
target_compile_features(smallest_tcp_dhcpv4_client PUBLIC c_std_99)
if(PROJECT_IS_TOP_LEVEL)
    target_compile_options(smallest_tcp_dhcpv4_client PRIVATE
        -Wall -Wextra -Werror -pedantic
    )
endif()
add_library(smallest_tcp::dhcpv4_client ALIAS smallest_tcp_dhcpv4_client)

# ── TFTP client (optional — link only what you need) ─────────────────

add_library(smallest_tcp_tftp STATIC
    src/tftp.c
)
target_link_libraries(smallest_tcp_tftp PUBLIC smallest_tcp_core)
target_compile_features(smallest_tcp_tftp PUBLIC c_std_99)
if(PROJECT_IS_TOP_LEVEL)
    target_compile_options(smallest_tcp_tftp PRIVATE
        -Wall -Wextra -Werror -pedantic
    )
endif()
add_library(smallest_tcp::tftp ALIAS smallest_tcp_tftp)

# ── mDNS + DNS-SD responder (optional) ───────────────────────────────

add_library(smallest_tcp_mdns STATIC
    src/dns_wire.c
    src/igmp.c
    src/mdns.c
)
target_link_libraries(smallest_tcp_mdns PUBLIC smallest_tcp_core)
target_compile_features(smallest_tcp_mdns PUBLIC c_std_99)
if(PROJECT_IS_TOP_LEVEL)
    target_compile_options(smallest_tcp_mdns PRIVATE
        -Wall -Wextra -Werror -pedantic
    )
endif()
add_library(smallest_tcp::mdns ALIAS smallest_tcp_mdns)

# ── HTTP/1.0 server (optional) ───────────────────────────────────────

add_library(smallest_tcp_http STATIC
    src/http.c
)
target_link_libraries(smallest_tcp_http PUBLIC smallest_tcp_core)
target_compile_features(smallest_tcp_http PUBLIC c_std_99)
if(PROJECT_IS_TOP_LEVEL)
    target_compile_options(smallest_tcp_http PRIVATE
        -Wall -Wextra -Werror -pedantic
    )
endif()
add_library(smallest_tcp::http ALIAS smallest_tcp_http)

# ── DHCPv4 server (optional) ─────────────────────────────────────────

add_library(smallest_tcp_dhcpv4_server STATIC
    src/dhcpv4_server.c
)
target_link_libraries(smallest_tcp_dhcpv4_server PUBLIC smallest_tcp_core)
target_compile_features(smallest_tcp_dhcpv4_server PUBLIC c_std_99)
if(PROJECT_IS_TOP_LEVEL)
    target_compile_options(smallest_tcp_dhcpv4_server PRIVATE
        -Wall -Wextra -Werror -pedantic
    )
endif()
add_library(smallest_tcp::dhcpv4_server ALIAS smallest_tcp_dhcpv4_server)

# ── DHCPv6 client (optional, dual stack only) ────────────────────────

if(SMALLEST_TCP_IPV6)
    add_library(smallest_tcp_dhcpv6_client STATIC
        src/dhcpv6_client.c
    )
    target_link_libraries(smallest_tcp_dhcpv6_client PUBLIC smallest_tcp_core)
    target_compile_features(smallest_tcp_dhcpv6_client PUBLIC c_std_99)
    if(PROJECT_IS_TOP_LEVEL)
        target_compile_options(smallest_tcp_dhcpv6_client PRIVATE
            -Wall -Wextra -Werror -pedantic
        )
    endif()
    add_library(smallest_tcp::dhcpv6_client ALIAS smallest_tcp_dhcpv6_client)
endif()

# ── TLS 1.3 protocol (optional) — no dependencies: the application
#    supplies a crypto backend (tls_crypto_t) ────────────────────────────

add_library(smallest_tcp_tls STATIC
    src/tls.c
)
target_include_directories(smallest_tcp_tls PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
)
target_compile_features(smallest_tcp_tls PUBLIC c_std_99)
if(PROJECT_IS_TOP_LEVEL)
    target_compile_options(smallest_tcp_tls PRIVATE
        -Wall -Wextra -Werror -pedantic
    )
endif()
add_library(smallest_tcp::tls ALIAS smallest_tcp_tls)

# ── TLS crypto backend on Mbed TLS (optional) ────────────────────────
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

    add_library(smallest_tcp_tls_mbedtls STATIC
        src/tls_crypto_mbedtls.c
    )
    target_include_directories(smallest_tcp_tls_mbedtls PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    )
    target_link_libraries(smallest_tcp_tls_mbedtls PUBLIC mbedx509 mbedcrypto)
    target_compile_features(smallest_tcp_tls_mbedtls PUBLIC c_std_99)
    if(PROJECT_IS_TOP_LEVEL)
        target_compile_options(smallest_tcp_tls_mbedtls PRIVATE
            -Wall -Wextra -Werror -pedantic
        )
    endif()
    add_library(smallest_tcp::tls_mbedtls ALIAS smallest_tcp_tls_mbedtls)
endif()

# ── Platform MAC drivers (optional) ──────────────────────────────────

if(SMALLEST_TCP_BUILD_DRIVERS)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        add_library(smallest_tcp_driver_tap STATIC
            src/driver/tap.c
        )
        target_link_libraries(smallest_tcp_driver_tap PUBLIC smallest_tcp_core)
        if(PROJECT_IS_TOP_LEVEL)
            target_compile_options(smallest_tcp_driver_tap PRIVATE
                -Wall -Wextra -Werror -pedantic
            )
        endif()
        add_library(smallest_tcp::driver_tap ALIAS smallest_tcp_driver_tap)

        add_library(smallest_tcp_driver_rawsock STATIC
            src/driver/rawsock.c
        )
        target_link_libraries(smallest_tcp_driver_rawsock PUBLIC smallest_tcp_core)
        if(PROJECT_IS_TOP_LEVEL)
            target_compile_options(smallest_tcp_driver_rawsock PRIVATE
                -Wall -Wextra -Werror -pedantic
            )
        endif()
        add_library(smallest_tcp::driver_rawsock ALIAS smallest_tcp_driver_rawsock)

    elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        add_library(smallest_tcp_driver_bpf STATIC
            src/driver/bpf.c
        )
        target_link_libraries(smallest_tcp_driver_bpf PUBLIC smallest_tcp_core)
        if(PROJECT_IS_TOP_LEVEL)
            target_compile_options(smallest_tcp_driver_bpf PRIVATE
                -Wall -Wextra -Werror -pedantic
            )
        endif()
        add_library(smallest_tcp::driver_bpf ALIAS smallest_tcp_driver_bpf)
    endif()
endif()

# ── Unit tests ────────────────────────────────────────────────────────

if(SMALLEST_TCP_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

# ── Demo applications ─────────────────────────────────────────────────

if(SMALLEST_TCP_BUILD_DEMO)
    add_subdirectory(demo)
endif()
