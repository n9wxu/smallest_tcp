# Bare-metal ARM Cortex-M with the GNU Arm toolchain:
#   cmake -S . -B build-arm -DCMAKE_TOOLCHAIN_FILE=cmake/arm-none-eabi.cmake
# SMALLEST_TCP_ARM_CPU picks the core: cortex-m4 (the STM32F4 of the
# hardware fuzz job) unless set, e.g. -DSMALLEST_TCP_ARM_CPU=cortex-m0.

set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_PROCESSOR arm)
set(CMAKE_C_COMPILER arm-none-eabi-gcc)

# Test programs cannot link without a board's start-up code
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

set(SMALLEST_TCP_ARM_CPU cortex-m4 CACHE STRING "Cortex-M core (-mcpu)")
set(CMAKE_C_FLAGS_INIT "-mcpu=${SMALLEST_TCP_ARM_CPU} -mthumb")
set(CMAKE_EXE_LINKER_FLAGS_INIT "--specs=nano.specs --specs=nosys.specs")

set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
