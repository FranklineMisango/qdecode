cmake_minimum_required(VERSION 3.16)
project(qdecode VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Production flags: maximum optimization, native arch, LTO. These are the
# prerequisites for sub-10ns per-message decode (inlining + vectorization).
set(CMAKE_CXX_FLAGS_RELEASE "-O3 -march=native -flto")

option(QDECODE_ENABLE_BOUNDS_CHECK "Emit defensive bounds checks (debug)" OFF)
option(QDECODE_BUILD_TESTS "Build the round-trip test suite" ON)
option(QDECODE_BUILD_BENCH "Build the microbenchmark" ON)

# Header-only decoder core (byte_order, buffer_view, message_header, group,
# schema, router, encoder). pcap.cpp is the only translation unit (mmap glue).
add_library(qdecode STATIC src/pcap.cpp)
target_include_directories(qdecode PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_link_libraries(qdecode PUBLIC m)

if(QDECODE_ENABLE_BOUNDS_CHECK)
    target_compile_definitions(qdecode PUBLIC QDECODE_ENABLE_BOUNDS_CHECK=1)
endif()

if(QDECODE_BUILD_TESTS)
    enable_testing()
    add_executable(qdecode_tests tests/test_decoder.cpp src/pcap.cpp)
    target_include_directories(qdecode_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    if(QDECODE_ENABLE_BOUNDS_CHECK)
        target_compile_definitions(qdecode_tests PUBLIC QDECODE_ENABLE_BOUNDS_CHECK=1)
    endif()
    add_test(NAME qdecode_roundtrip COMMAND qdecode_tests)
endif()

if(QDECODE_BUILD_BENCH)
    add_executable(qdecode_bench bench/bench.cpp)
    target_include_directories(qdecode_bench PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
endif()

# Optional command-line tools (built only when QDECODE_BUILD_TOOLS is on).
option(QDECODE_BUILD_TOOLS "Build the decode/bench command-line tools" ON)
if(QDECODE_BUILD_TOOLS)
    add_executable(mdp3_bench tools/mdp3_bench.cpp src/pcap.cpp)
    target_include_directories(mdp3_bench PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_link_libraries(mdp3_bench PRIVATE m)

    # Databento DBN benchmark (requires a zstd-capable linker; optional).
    find_library(ZSTD_LIB zstd)
    if(ZSTD_LIB)
        add_executable(dbn_bench tools/dbn_bench.cpp)
        target_include_directories(dbn_bench PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)
        target_link_libraries(dbn_bench PRIVATE ${ZSTD_LIB})
    endif()
endif()
