# Unit tests for smallest_tcp
#
# Each test is a standalone executable linked against the library sources
# it needs. CTest runs them all.

# Helper: define a unit test executable
function(add_unit_test name)
    add_executable(${name} unit/${name}.c)
    target_include_directories(${name} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/unit
    )
    target_compile_options(${name} PRIVATE -Wall -Wextra -Werror -pedantic)
    target_compile_features(${name} PRIVATE c_std_99)
    add_test(NAME ${name} COMMAND ${name})
endfunction()

# ── test_endian (header-only, no library link needed) ─────────────────

add_unit_test(test_endian)
target_link_libraries(test_endian PRIVATE smallest_tcp_core)

# ── test_checksum ─────────────────────────────────────────────────────

add_unit_test(test_checksum)
target_link_libraries(test_checksum PRIVATE smallest_tcp_core)

# ── test_eth ──────────────────────────────────────────────────────────

add_unit_test(test_eth)
target_link_libraries(test_eth PRIVATE smallest_tcp_core)

# ── test_net ──────────────────────────────────────────────────────────

add_unit_test(test_net)
target_link_libraries(test_net PRIVATE smallest_tcp_core)

# ── test_tcp_buf ──────────────────────────────────────────────────────

add_unit_test(test_tcp_buf)
target_link_libraries(test_tcp_buf PRIVATE smallest_tcp_core)

add_unit_test(test_dns_wire)
target_link_libraries(test_dns_wire PRIVATE smallest_tcp_mdns)

# ── Over IPv4 ─────────────────────────────────────────────────────────

if(SMALLEST_TCP_IPV4)
    add_unit_test(test_arp)
    target_link_libraries(test_arp PRIVATE smallest_tcp_core)
    add_unit_test(test_ipv4)
    target_link_libraries(test_ipv4 PRIVATE smallest_tcp_core)
    add_unit_test(test_icmp)
    target_link_libraries(test_icmp PRIVATE smallest_tcp_core)
    add_unit_test(test_udp)
    target_link_libraries(test_udp PRIVATE smallest_tcp_core)
    add_unit_test(test_tcp)
    target_link_libraries(test_tcp PRIVATE smallest_tcp_core)
    add_unit_test(test_tftp)
    target_link_libraries(test_tftp PRIVATE smallest_tcp_tftp)
    add_unit_test(test_dhcpv4)
    target_link_libraries(test_dhcpv4 PRIVATE
        smallest_tcp_dhcpv4_client
        smallest_tcp_dhcpv4_server
    )
    add_unit_test(test_mcast)
    target_link_libraries(test_mcast PRIVATE smallest_tcp_mdns)
    add_unit_test(test_mdns)
    target_link_libraries(test_mdns PRIVATE smallest_tcp_mdns)
    add_unit_test(test_http)
    target_link_libraries(test_http PRIVATE smallest_tcp_http)
endif()

# The raw-socket driver's checksum completion is portable; its socket
# tests run on Linux, and the live veth tests only as root.
add_unit_test(test_rawsock)
target_sources(test_rawsock PRIVATE ${PROJECT_SOURCE_DIR}/src/driver/rawsock.c)
target_link_libraries(test_rawsock PRIVATE smallest_tcp_core)

if(SMALLEST_TCP_IPV6)
    add_unit_test(test_ipv6)
    target_link_libraries(test_ipv6 PRIVATE smallest_tcp_core)
    add_unit_test(test_udp6)
    target_link_libraries(test_udp6 PRIVATE smallest_tcp_core)
    add_unit_test(test_tcp6)
    target_link_libraries(test_tcp6 PRIVATE smallest_tcp_core)
    add_unit_test(test_slaac)
    target_link_libraries(test_slaac PRIVATE smallest_tcp_core)
    add_unit_test(test_mld)
    target_link_libraries(test_mld PRIVATE smallest_tcp_core)
    add_unit_test(test_mdns6)
    target_link_libraries(test_mdns6 PRIVATE smallest_tcp_mdns)
    add_unit_test(test_dhcpv6)
    target_link_libraries(test_dhcpv6 PRIVATE smallest_tcp_dhcpv6_client)
endif()

if(SMALLEST_TCP_TLS)
    add_unit_test(test_tls_crypto)
    target_link_libraries(test_tls_crypto PRIVATE smallest_tcp_tls_mbedtls)
    add_unit_test(test_tls_keys)
    target_link_libraries(test_tls_keys PRIVATE
        smallest_tcp_tls smallest_tcp_tls_mbedtls)
    add_unit_test(test_tls_server)
    target_link_libraries(test_tls_server PRIVATE
        smallest_tcp_tls smallest_tcp_tls_mbedtls)
    add_unit_test(test_tls_client)
    target_link_libraries(test_tls_client PRIVATE
        smallest_tcp_tls smallest_tcp_tls_mbedtls)
    if(SMALLEST_TCP_DTLS)
        add_unit_test(test_dtls)
        target_link_libraries(test_dtls PRIVATE
            smallest_tcp_tls smallest_tcp_tls_mbedtls)
    endif()
endif()

# ── Integration tests: the stack driven through its API on a scripted
#    link, traced to the requirements (tests/integration/wire.h) ──────────

function(add_integration_test name)
    add_executable(${name} integration/${name}.c integration/wire.c)
    target_include_directories(${name} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/integration
        ${CMAKE_CURRENT_SOURCE_DIR}/unit
    )
    target_compile_options(${name} PRIVATE -Wall -Wextra -Werror -pedantic)
    target_compile_features(${name} PRIVATE c_std_99)
    target_link_libraries(${name} PRIVATE ${ARGN})
    add_test(NAME ${name} COMMAND ${name})
    set_tests_properties(${name} PROPERTIES LABELS integration)
endfunction()

if(SMALLEST_TCP_IPV4 AND SMALLEST_TCP_UDP)
    add_integration_test(itest_ipv4 smallest_tcp_core)
    add_integration_test(itest_link smallest_tcp_core)
    add_integration_test(itest_udp smallest_tcp_core)
    add_integration_test(itest_mdns smallest_tcp_mdns)
    add_integration_test(itest_igmp smallest_tcp_mdns)
    add_integration_test(itest_dhcpv4
        smallest_tcp_dhcpv4_client smallest_tcp_dhcpv4_server)
    add_integration_test(itest_tftp smallest_tcp_tftp)
endif()
if(SMALLEST_TCP_IPV4 AND SMALLEST_TCP_TCP)
    add_integration_test(itest_tcp smallest_tcp_core)
    if(SMALLEST_TCP_TLS)
        # HTTPS too: slots over TLS, the client the stack's TLS client
        add_integration_test(itest_http
            smallest_tcp_https smallest_tcp_tls_mbedtls)
        target_compile_definitions(itest_http PRIVATE ITEST_HTTPS=1)
    else()
        add_integration_test(itest_http smallest_tcp_http)
    endif()
endif()

# ── Configurations that must not compile ─────────────────────────────
#
# Each test passes when the compiler reports the configuration error.
# Without a group slot mDNS cannot receive its queries: a build error, not
# a responder that silently hears nothing.

function(add_config_rejected_test name source message)
    add_test(NAME ${name} COMMAND ${CMAKE_C_COMPILER} -std=c99 -fsyntax-only
        -I${PROJECT_SOURCE_DIR}/include ${ARGN} ${PROJECT_SOURCE_DIR}/${source})
    set_tests_properties(${name} PROPERTIES PASS_REGULAR_EXPRESSION "${message}")
endfunction()

add_config_rejected_test(mdns_needs_ipv4_group_slot src/mdns.c
    "needs NET_MAX_MCAST_GROUPS >= 1" -DNET_MAX_MCAST_GROUPS=0)
add_config_rejected_test(mdns_needs_ipv6_group_slot src/mdns.c
    "needs NET_MAX_MCAST6_GROUPS >= 1"
    -DNET_USE_IPV6=1 -DNET_MAX_MCAST6_GROUPS=0)

# An IPv6-only build has no IPv4 API: the protocols that run only over
# IPv4 fail to compile, and so does a build with no network layer at all.

add_config_rejected_test(tftp_needs_ipv4 src/tftp.c
    "IPv4 is not compiled in" -DNET_USE_IPV4=0 -DNET_USE_IPV6=1)
add_config_rejected_test(dhcpv4_client_needs_ipv4 src/dhcpv4_client.c
    "IPv4 is not compiled in" -DNET_USE_IPV4=0 -DNET_USE_IPV6=1)
add_config_rejected_test(network_layer_needed src/net.c
    "no network layer" -DNET_USE_IPV4=0 -DNET_USE_IPV6=0)
