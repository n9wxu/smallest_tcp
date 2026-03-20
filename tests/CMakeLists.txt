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
