cmake_minimum_required(VERSION 3.10)
project(BelT LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_library(BelT
    src/BelT_core.cpp
    src/BelT_io.cpp
    src/BelT_mode_common.cpp
    src/BelT_ecb.cpp
    src/BelT_cbc.cpp
    src/BelT_ctr.cpp
    src/BelT_mac.cpp
    src/BelT_ccm.cpp
    src/BelT_gcm.cpp
    src/BelT_utils.cpp
)

target_include_directories(BelT PUBLIC include)


enable_testing()
find_package(GTest REQUIRED)

add_executable(belt_tests
    tests/tests.cpp
)
target_link_libraries(belt_tests PRIVATE BelT GTest::gtest_main)
include(GoogleTest)
gtest_discover_tests(belt_tests)
