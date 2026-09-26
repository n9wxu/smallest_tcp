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

# ── frame_dump ────────────────────────────────────────────────────────

add_executable(frame_dump frame_dump/main.c)
add_demo_with_driver(frame_dump)

# ── tcp_echo (TCP echo server on port 7) ──────────────────────────────

add_executable(tcp_echo_demo tcp_echo/main.c)
add_demo_with_driver(tcp_echo_demo)
if(SMALLEST_TCP_IPV6)
    target_link_libraries(tcp_echo_demo PRIVATE smallest_tcp_dhcpv6_client)
endif()

# ── tftp_client (TFTP GET demo) ───────────────────────────────────────

add_executable(tftp_client_demo tftp_client/main.c)
add_demo_with_driver(tftp_client_demo)
target_link_libraries(tftp_client_demo PRIVATE smallest_tcp_tftp)

# ── dhcp_echo (DHCP client + TCP/UDP echo — blackbox SUT) ────────────

add_executable(dhcp_echo_demo dhcp_echo/main.c)
add_demo_with_driver(dhcp_echo_demo)
target_link_libraries(dhcp_echo_demo PRIVATE smallest_tcp_dhcpv4_client)

# ── mdns_demo (mDNS + DNS-SD advertiser — blackbox SUT) ──────────────

add_executable(mdns_demo mdns_demo/main.c)
add_demo_with_driver(mdns_demo)
target_link_libraries(mdns_demo PRIVATE smallest_tcp_mdns)

# ── http_demo (HTTP server + mDNS advertising — blackbox SUT) ────────

add_executable(http_demo http_demo/main.c)
add_demo_with_driver(http_demo)
target_link_libraries(http_demo PRIVATE smallest_tcp_http smallest_tcp_mdns)
