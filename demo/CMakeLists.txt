# Demo applications for smallest_tcp

# ── Helper: add a demo that needs a platform MAC driver ──────────────

function(add_demo_with_driver name)
    target_compile_options(${name} PRIVATE -Wall -Wextra -Werror -pedantic)
    target_compile_features(${name} PRIVATE c_std_99)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        target_link_libraries(${name} PRIVATE smallest_tcp_driver_tap)
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
        target_link_libraries(${name} PRIVATE smallest_tcp_driver_bpf)
    endif()
endfunction()

# ── frame_dump ────────────────────────────────────────────────────────

add_executable(frame_dump frame_dump/main.c)
target_link_libraries(frame_dump PRIVATE smallest_tcp_core)
add_demo_with_driver(frame_dump)

# ── tcp_echo (TCP echo server on port 7) ──────────────────────────────

add_executable(tcp_echo_demo tcp_echo/main.c)
target_link_libraries(tcp_echo_demo PRIVATE smallest_tcp_core)
add_demo_with_driver(tcp_echo_demo)
