###############################################################################
# Example: How to use smallest_tcp via CMake FetchContent
#
# This file is NOT built as part of the smallest_tcp project.
# It serves as documentation/template for downstream consumers.
#
# Usage from your project's CMakeLists.txt:
#
#   include(FetchContent)
#   FetchContent_Declare(
#       smallest_tcp
#       GIT_REPOSITORY https://github.com/n9wxu/smallest_tcp.git
#       GIT_TAG        main   # or a specific tag/commit
#   )
#   FetchContent_MakeAvailable(smallest_tcp)
#
#   target_link_libraries(my_app PRIVATE smallest_tcp::smallest_tcp)
#
###############################################################################

cmake_minimum_required(VERSION 3.14)
project(example_consumer LANGUAGES C)

include(FetchContent)

# In a real project, this would point to the remote repo:
#   GIT_REPOSITORY https://github.com/n9wxu/smallest_tcp.git
#   GIT_TAG        main
#
# For local testing we use a source directory instead:
FetchContent_Declare(
    smallest_tcp
    SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../..
)
FetchContent_MakeAvailable(smallest_tcp)

# ── Example application ──────────────────────────────────────────────

add_executable(example_app main.c)
target_link_libraries(example_app PRIVATE smallest_tcp::smallest_tcp)
