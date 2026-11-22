# SAM4E Xplained Pro firmware: tcp_echo_demo.elf, the hardware fuzz job's SUT.
#   cmake -S . -B build-arm -DCMAKE_TOOLCHAIN_FILE=cmake/arm-none-eabi.cmake \
#         -DSMALLEST_TCP_BOARD=sam4e-xplained-pro
#   cmake --build build-arm --target tcp_echo_demo
#   boards/sam4e-xplained-pro/flash.sh build-arm/tcp_echo_demo.elf
# -DSAM4E_XPLAINED_RAM=ON links it to run from RAM (flash.sh --ram).

if(NOT SMALLEST_TCP_ARM_CPU STREQUAL "cortex-m4")
    message(FATAL_ERROR "sam4e-xplained-pro needs SMALLEST_TCP_ARM_CPU=cortex-m4")
endif()
if(NOT (SMALLEST_TCP_IPV4 AND SMALLEST_TCP_UDP AND SMALLEST_TCP_TCP))
    message(FATAL_ERROR "tcp_echo_demo needs IPv4, UDP and TCP")
endif()

option(SAM4E_XPLAINED_RAM "Link tcp_echo_demo to run from RAM (flash.sh --ram)" OFF)
if(SAM4E_XPLAINED_RAM)
    set(_linker_script ${CMAKE_CURRENT_SOURCE_DIR}/linker-ram.ld)
else()
    set(_linker_script ${CMAKE_CURRENT_SOURCE_DIR}/linker.ld)
endif()

add_executable(tcp_echo_demo main.c board.c startup.c)
target_include_directories(tcp_echo_demo PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(tcp_echo_demo PRIVATE smallest_tcp_driver_sam4e_gmac)
target_compile_options(tcp_echo_demo PRIVATE -Wall -Wextra -Werror)
target_link_options(tcp_echo_demo PRIVATE
    -T${_linker_script} -nostartfiles
    -Wl,--gc-sections -Wl,-Map=${CMAKE_BINARY_DIR}/tcp_echo_demo.map)
set_target_properties(tcp_echo_demo PROPERTIES
    SUFFIX ".elf"
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
    LINK_DEPENDS ${_linker_script})

find_program(SMALLEST_TCP_ARM_SIZE arm-none-eabi-size)
if(SMALLEST_TCP_ARM_SIZE)
    add_custom_command(TARGET tcp_echo_demo POST_BUILD
        COMMAND ${SMALLEST_TCP_ARM_SIZE} $<TARGET_FILE:tcp_echo_demo>)
endif()
