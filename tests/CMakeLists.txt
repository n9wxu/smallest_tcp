# Tests of smallest_tcp: unit tests (tests/unit), integration tests that
# drive the stack through its API on a scripted link (tests/integration,
# CTest label "integration"), and checks that configurations which cannot
# work fail to compile.
#
# Each test is a standalone executable linked against the libraries it
# needs.  CTest runs them all.

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

# ── test_endian ───────────────────────────────────────────────────────

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
    add_unit_test(test_mcast)
    target_link_libraries(test_mcast PRIVATE smallest_tcp_mdns)
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
    # The responder without simultaneous-probe tiebreaking (MDNS_TIEBREAK
    # 0, REQ-MDNS-081): its sources compiled into the test with that setting
    add_integration_test(itest_mdns_no_tiebreak smallest_tcp_core)
    target_sources(itest_mdns_no_tiebreak PRIVATE
        ${PROJECT_SOURCE_DIR}/src/mdns.c ${PROJECT_SOURCE_DIR}/src/dns_wire.c
        ${PROJECT_SOURCE_DIR}/src/igmp.c)
    target_compile_definitions(itest_mdns_no_tiebreak PRIVATE MDNS_TIEBREAK=0)
    add_integration_test(itest_igmp smallest_tcp_mdns)
    add_integration_test(itest_dhcpv4
        smallest_tcp_dhcpv4_client smallest_tcp_dhcpv4_server)
    add_integration_test(itest_tftp smallest_tcp_tftp)
endif()
if(SMALLEST_TCP_IPV4 AND SMALLEST_TCP_IPV6 AND SMALLEST_TCP_UDP)
    add_integration_test(itest_mdns6 smallest_tcp_mdns)
    add_integration_test(itest_dhcpv6 smallest_tcp_dhcpv6_client)
    add_integration_test(itest_mld smallest_tcp_core)
    if(SMALLEST_TCP_TCP)
        add_integration_test(itest_ipv6 smallest_tcp_core)
        add_integration_test(itest_ndp smallest_tcp_core)
    endif()
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

# TLS 1.3 and DTLS 1.3: the peer is the tests' own (integration/tls_peer.c,
# on Mbed TLS's primitives)
if(SMALLEST_TCP_TLS AND SMALLEST_TCP_IPV4 AND SMALLEST_TCP_TCP)
    add_integration_test(itest_tls
        smallest_tcp_tls_tcp smallest_tcp_tls_mbedtls)
    target_sources(itest_tls PRIVATE integration/tls_peer.c)
endif()
# DTLS: linked without the stack's core and without the scripted link — the
# test moves the datagrams itself, as an application does (REQ-DTLS-073)
if(SMALLEST_TCP_TLS AND SMALLEST_TCP_DTLS)
    add_executable(itest_dtls integration/itest_dtls.c integration/tls_peer.c)
    target_include_directories(itest_dtls PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/integration
        ${CMAKE_CURRENT_SOURCE_DIR}/unit
    )
    target_compile_options(itest_dtls PRIVATE -Wall -Wextra -Werror -pedantic)
    target_compile_features(itest_dtls PRIVATE c_std_99)
    target_link_libraries(itest_dtls PRIVATE
        smallest_tcp_tls smallest_tcp_tls_mbedtls)
    add_test(NAME itest_dtls COMMAND itest_dtls)
    set_tests_properties(itest_dtls PROPERTIES LABELS integration)
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

# ── Configurations that must compile ─────────────────────────────────
#
# A compiler that does not predefine __BYTE_ORDER__ is told the byte order
# by hand, as net_endian.h's own error message says.

function(add_config_accepted_test name source)
    add_test(NAME ${name} COMMAND ${CMAKE_C_COMPILER} -std=c99 -fsyntax-only
        -I${PROJECT_SOURCE_DIR}/include ${ARGN} ${PROJECT_SOURCE_DIR}/${source})
endfunction()

add_config_accepted_test(byte_order_set_by_hand src/net_cksum.c
    -U__BYTE_ORDER__ -DNET_LITTLE_ENDIAN=1)
add_config_rejected_test(byte_order_set_twice src/net_cksum.c
    "are both defined" -DNET_LITTLE_ENDIAN=1 -DNET_BIG_ENDIAN=1)

# An IPv6 host without UDP or TCP — ICMPv6, Neighbor Discovery and MLD
# alone — compiles without a warning, though icmpv6.c then has no
# transport to hand a received error to.

add_config_accepted_test(icmpv6_without_transports src/icmpv6.c
    -Wall -Wextra -Werror -pedantic
    -DNET_USE_IPV6=1 -DNET_USE_UDP=0 -DNET_USE_TCP=0)

# ── The API under a prefix (NET_API_PREFIX, include/net_rename.h) ─────
#
# A project with a net_init() of its own — or another stack's tcp_write()
# — builds this one under a prefix.  The core compiled with
# NET_API_PREFIX=stcp_ links into a program that defines net_init(),
# net_poll(), tcp_write() and udp_send() itself, and each call reaches its
# own; and net_rename.h lists every external symbol the libraries of this
# configuration define, or names the ones it lacks.

get_target_property(_core_sources smallest_tcp_core SOURCES)
get_target_property(_core_definitions smallest_tcp_core
    INTERFACE_COMPILE_DEFINITIONS)
list(TRANSFORM _core_sources PREPEND ${PROJECT_SOURCE_DIR}/)
add_executable(api_prefix_app config/api_prefix_app.c config/api_prefix_own.c
    config/api_prefix_calls.c ${PROJECT_SOURCE_DIR}/src/driver/stub.c
    ${_core_sources})
target_include_directories(api_prefix_app PRIVATE ${PROJECT_SOURCE_DIR}/include)
target_compile_definitions(api_prefix_app PRIVATE ${_core_definitions})
if(NOT SMALLEST_TCP_API_PREFIX)
    target_compile_definitions(api_prefix_app PRIVATE NET_API_PREFIX=stcp_)
endif()
target_compile_options(api_prefix_app PRIVATE -Wall -Wextra -Werror -pedantic)
target_compile_features(api_prefix_app PRIVATE c_std_99)
add_test(NAME api_prefix_links_beside_own_names COMMAND api_prefix_app)

find_package(Python3 COMPONENTS Interpreter)
if(Python3_FOUND)
    get_property(_libraries GLOBAL PROPERTY SMALLEST_TCP_LIBRARIES)
    set(_library_files "")
    foreach(_library ${_libraries})
        list(APPEND _library_files $<TARGET_FILE:${_library}>)
    endforeach()
    add_test(NAME api_prefix_covers_every_symbol
        COMMAND ${CMAKE_COMMAND} -E env
            NET_API_PREFIX=${SMALLEST_TCP_API_PREFIX}
            ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/scripts/api_rename.py
            --nm ${CMAKE_NM} --check ${_library_files})
endif()
