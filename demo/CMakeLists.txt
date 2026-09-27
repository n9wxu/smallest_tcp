# Demo applications for smallest_tcp

# ── Helper: add a demo that needs a platform MAC driver ──────────────
#
# Linux demos get both the TAP and raw-socket drivers; the interface
# argument picks one at run time (demo/common/demo_mac.h).
# On Linux and Darwin, the platform driver carries PUBLIC smallest_tcp_core,
# so core is pulled in transitively — no explicit core link needed here.
# On other platforms (e.g., bare-metal), link core directly; the demo
# builds but exits at start-up ("Platform not supported").

function(add_demo_with_driver name)
    target_compile_options(${name} PRIVATE -Wall -Wextra -Werror -pedantic)
    target_compile_features(${name} PRIVATE c_std_99)
    target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/common)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        target_link_libraries(${name} PRIVATE
            smallest_tcp_driver_tap smallest_tcp_driver_rawsock)
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        target_link_libraries(${name} PRIVATE smallest_tcp_driver_bpf)
    else()
        target_link_libraries(${name} PRIVATE smallest_tcp_core)
    endif()
endfunction()

# ── frame_dump, echo_server (the smallest demos) ─────────────────────

add_executable(frame_dump frame_dump/main.c)
add_demo_with_driver(frame_dump)

# An IPv6-only build has frame_dump, tcp_echo_demo and tls_echo_demo; the
# other demos use IPv4.

if(SMALLEST_TCP_IPV4)
    add_executable(echo_server echo_server/main.c)
    add_demo_with_driver(echo_server)
endif()

# ── tcp_echo (TCP echo server on port 7) ──────────────────────────────

add_executable(tcp_echo_demo tcp_echo/main.c)
add_demo_with_driver(tcp_echo_demo)
if(SMALLEST_TCP_IPV6)
    target_link_libraries(tcp_echo_demo PRIVATE smallest_tcp_dhcpv6_client)
endif()

# ── tftp_client (TFTP GET demo) ───────────────────────────────────────

if(SMALLEST_TCP_IPV4)
    add_executable(tftp_client_demo tftp_client/main.c)
    add_demo_with_driver(tftp_client_demo)
    target_link_libraries(tftp_client_demo PRIVATE smallest_tcp_tftp)
endif()

# ── dhcp_echo (DHCP client + TCP/UDP echo — blackbox SUT) ────────────

if(SMALLEST_TCP_IPV4)
    add_executable(dhcp_echo_demo dhcp_echo/main.c)
    add_demo_with_driver(dhcp_echo_demo)
    target_link_libraries(dhcp_echo_demo PRIVATE smallest_tcp_dhcpv4_client)
endif()

# ── mdns_demo (mDNS + DNS-SD advertiser — blackbox SUT) ──────────────

if(SMALLEST_TCP_IPV4)
    add_executable(mdns_demo mdns_demo/main.c)
    add_demo_with_driver(mdns_demo)
    target_link_libraries(mdns_demo PRIVATE smallest_tcp_mdns)
endif()

# ── http_demo (HTTP server + mDNS advertising — blackbox SUT) ────────

if(SMALLEST_TCP_IPV4)
    add_executable(http_demo http_demo/main.c)
    add_demo_with_driver(http_demo)
    target_link_libraries(http_demo PRIVATE smallest_tcp_http smallest_tcp_mdns)
endif()

# ── tls_echo, https_demo, tls_client (TLS 1.3 — blackbox SUTs) ────────

if(SMALLEST_TCP_TLS)
    add_executable(tls_echo_demo tls_echo/main.c)
    add_demo_with_driver(tls_echo_demo)
    target_link_libraries(tls_echo_demo PRIVATE
        smallest_tcp_tls_tcp smallest_tcp_tls_mbedtls)
    target_compile_definitions(tls_echo_demo PRIVATE
        TLS_ECHO_DEFAULT_CERT="${PROJECT_SOURCE_DIR}/tests/tls/server.pem"
        TLS_ECHO_DEFAULT_KEY="${PROJECT_SOURCE_DIR}/tests/tls/server.key")

    if(SMALLEST_TCP_IPV4)
        add_executable(https_demo https_demo/main.c)
        add_demo_with_driver(https_demo)
        target_link_libraries(https_demo PRIVATE
            smallest_tcp_https smallest_tcp_tls_mbedtls)
        target_compile_definitions(https_demo PRIVATE
            HTTPS_DEFAULT_CERT="${PROJECT_SOURCE_DIR}/tests/tls/server.pem"
            HTTPS_DEFAULT_KEY="${PROJECT_SOURCE_DIR}/tests/tls/server.key")

        add_executable(tls_client_demo tls_client/main.c)
        add_demo_with_driver(tls_client_demo)
        target_link_libraries(tls_client_demo PRIVATE
            smallest_tcp_tls_tcp smallest_tcp_tls_mbedtls)
        target_compile_definitions(tls_client_demo PRIVATE
            TLS_CLIENT_DEFAULT_CA="${PROJECT_SOURCE_DIR}/tests/tls/ca.pem")
    endif()
endif()
