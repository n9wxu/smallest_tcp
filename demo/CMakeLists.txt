# Demo applications for smallest_tcp

add_executable(frame_dump frame_dump/main.c)
target_link_libraries(frame_dump PRIVATE smallest_tcp_core)
target_compile_options(frame_dump PRIVATE -Wall -Wextra -Werror -pedantic)
target_compile_features(frame_dump PRIVATE c_std_99)

# Link platform-specific driver
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_link_libraries(frame_dump PRIVATE smallest_tcp_driver_tap)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    target_link_libraries(frame_dump PRIVATE smallest_tcp_driver_bpf)
endif()
