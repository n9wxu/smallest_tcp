# NUCLEO-F429ZI firmware: tcp_echo_demo.elf, the hardware fuzz job's SUT.
#   cmake -S . -B build-arm -DCMAKE_TOOLCHAIN_FILE=cmake/arm-none-eabi.cmake \
#         -DSMALLEST_TCP_BOARD=nucleo-f429zi
#   cmake --build build-arm --target tcp_echo_demo

if(NOT SMALLEST_TCP_ARM_CPU STREQUAL "cortex-m4")
    message(FATAL_ERROR "nucleo-f429zi needs SMALLEST_TCP_ARM_CPU=cortex-m4")
endif()
if(NOT (SMALLEST_TCP_IPV4 AND SMALLEST_TCP_UDP AND SMALLEST_TCP_TCP))
    message(FATAL_ERROR "tcp_echo_demo needs IPv4, UDP and TCP")
endif()

add_executable(tcp_echo_demo main.c board.c startup.c)
target_include_directories(tcp_echo_demo PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(tcp_echo_demo PRIVATE smallest_tcp_driver_stm32f4_eth)
target_compile_options(tcp_echo_demo PRIVATE -Wall -Wextra -Werror)
target_link_options(tcp_echo_demo PRIVATE
    -T${CMAKE_CURRENT_SOURCE_DIR}/linker.ld -nostartfiles
    -Wl,--gc-sections -Wl,-Map=${CMAKE_BINARY_DIR}/tcp_echo_demo.map)
set_target_properties(tcp_echo_demo PROPERTIES
    SUFFIX ".elf"
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
    LINK_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/linker.ld)

find_program(SMALLEST_TCP_ARM_SIZE arm-none-eabi-size)
if(SMALLEST_TCP_ARM_SIZE)
    add_custom_command(TARGET tcp_echo_demo POST_BUILD
        COMMAND ${SMALLEST_TCP_ARM_SIZE} $<TARGET_FILE:tcp_echo_demo>)
endif()
