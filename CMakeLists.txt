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
