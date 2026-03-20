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

# ── Core library (always built) ───────────────────────────────────────
#
# This is the target consumers get via FetchContent:
#   target_link_libraries(my_app PRIVATE smallest_tcp::smallest_tcp)

add_library(smallest_tcp_core STATIC
    src/net.c
    src/net_cksum.c
    src/eth.c
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

# Create a namespaced alias for FetchContent consumers
add_library(smallest_tcp::smallest_tcp ALIAS smallest_tcp_core)

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
