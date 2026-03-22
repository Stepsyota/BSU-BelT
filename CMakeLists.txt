cmake_minimum_required(VERSION 3.10)
project(BelT LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(BelT
    src/BelT_core.cpp
    src/BelT_io.cpp
    src/BelT_modes.cpp
    src/BelT_utils.cpp
)

target_include_directories(BelT PUBLIC include)

add_executable(belt_app
    app/main.cpp
    app/tests.cpp
)
target_link_libraries(belt_app PRIVATE BelT)