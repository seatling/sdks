cmake_minimum_required(VERSION 3.15)
project(seatling_cpp VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Locate Rust target directory
if(NOT DEFINED RUST_TARGET_DIR)
    set(RUST_TARGET_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../target/release")
endif()

message(STATUS "Looking for Seatling Rust library in: ${RUST_TARGET_DIR}")

add_library(seatling_core STATIC IMPORTED GLOBAL)
if(WIN32)
    set_target_properties(seatling_core PROPERTIES
        IMPORTED_LOCATION "${RUST_TARGET_DIR}/seatling.lib"
    )
elseif(APPLE)
    set_target_properties(seatling_core PROPERTIES
        IMPORTED_LOCATION "${RUST_TARGET_DIR}/libseatling.a"
    )
else()
    set_target_properties(seatling_core PROPERTIES
        IMPORTED_LOCATION "${RUST_TARGET_DIR}/libseatling.a"
    )
endif()

# Header-only interface target wrapping Rust staticlib
add_library(seatling INTERFACE)
target_include_directories(seatling INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(seatling INTERFACE seatling_core)

# Platform-specific link libraries required by Rust staticlib
if(WIN32)
    target_link_libraries(seatling INTERFACE
        ws2_32
        userenv
        bcrypt
        crypt32
        advapi32
        ntdll
    )
elseif(APPLE)
    find_library(IOKIT_LIB IOKit REQUIRED)
    find_library(COREFOUNDATION_LIB CoreFoundation REQUIRED)
    find_library(SECURITY_LIB Security REQUIRED)
    target_link_libraries(seatling INTERFACE
        ${IOKIT_LIB}
        ${COREFOUNDATION_LIB}
        ${SECURITY_LIB}
        pthread
        dl
        m
    )
else()
    target_link_libraries(seatling INTERFACE
        pthread
        dl
        m
    )
endif()

# Enable Testing
enable_testing()

# Unit Test Executable
add_executable(seatling_tests tests/cpp/test_main.cpp)
target_link_libraries(seatling_tests PRIVATE seatling)

if(MSVC)
    target_compile_options(seatling_tests PRIVATE /W4 /WX)
else()
    target_compile_options(seatling_tests PRIVATE -Wall -Wextra -Werror)
endif()

add_test(NAME seatling_unit_tests COMMAND seatling_tests)

# Generic Client Example Executable
add_executable(client_example examples/cpp/client_example.cpp)
target_link_libraries(client_example PRIVATE seatling)

if(MSVC)
    target_compile_options(client_example PRIVATE /W4 /WX)
else()
    target_compile_options(client_example PRIVATE -Wall -Wextra -Werror)
endif()

add_test(NAME seatling_client_example COMMAND client_example)
