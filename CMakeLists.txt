cmake_minimum_required(VERSION 3.15)
project(Ascon_Hash256 C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_EXTENSIONS OFF)

# Warnings
if (CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# Library with core Ascon functionality
add_library(ascon STATIC
        src/ascon_permutation.c
        src/ascon_hash.c
        src/ascon_aead.c
        src/ascon_xof.c
        src/ascon_aead.c
)

target_include_directories(ascon PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

# Main executable (CLI/demo)
add_executable(Ascon_Hash256
        main.c
)

target_link_libraries(Ascon_Hash256 PRIVATE ascon)

# Enable testing
include(CTest)

if (BUILD_TESTING)
    add_executable(test_hash tests/test_hash.c)
    target_link_libraries(test_hash PRIVATE ascon)
    add_test(NAME ascon_hash256_basic COMMAND test_hash)
    set_tests_properties(ascon_hash256_basic PROPERTIES LABELS "non_kat")

    add_executable(test_aead128 tests/test_aead128.c)
    target_link_libraries(test_aead128 PRIVATE ascon)
    add_test(NAME ascon128_roundtrip_and_negative COMMAND test_aead128)
    set_tests_properties(ascon128_roundtrip_and_negative PROPERTIES LABELS "non_kat")

    add_executable(test_xof tests/test_xof.c)
    target_link_libraries(test_xof PRIVATE ascon)
    add_test(NAME ascon_xof_behavior COMMAND test_xof)
    set_tests_properties(ascon_xof_behavior PROPERTIES LABELS "non_kat")

    add_executable(test_aead128a tests/test_aead128a.c)
    target_link_libraries(test_aead128a PRIVATE ascon)
    add_test(NAME ascon128a_roundtrip_and_negative COMMAND test_aead128a)
    set_tests_properties(ascon128a_roundtrip_and_negative PROPERTIES LABELS "non_kat")

    add_executable(test_hash_variants tests/test_hash_variants.c)
    target_link_libraries(test_hash_variants PRIVATE ascon)
    add_test(NAME ascon_hash_variants_behavior COMMAND test_hash_variants)

    add_executable(test_aead80pq tests/test_aead80pq.c)
    target_link_libraries(test_aead80pq PRIVATE ascon)
    add_test(NAME ascon80pq_roundtrip_and_negative COMMAND test_aead80pq)

    # File-based KAT runners (official Ascon v1.2 KATs)
    add_executable(test_kat_aead
            tests/test_kat_aead.c
            tests/kat_parser.c)
    target_include_directories(test_kat_aead PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests)
    target_link_libraries(test_kat_aead PRIVATE ascon)
    add_test(NAME ascon_kat_aead COMMAND test_kat_aead)

    add_executable(test_kat_hash_kat
            tests/test_kat_hash_kat.c
            tests/kat_parser.c)
    target_include_directories(test_kat_hash_kat PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests)
    target_link_libraries(test_kat_hash_kat PRIVATE ascon)
    add_test(NAME ascon_kat_hash256 COMMAND test_kat_hash_kat)

    add_executable(test_kat_xof_kat
            tests/test_kat_xof_kat.c
            tests/kat_parser.c)
    target_include_directories(test_kat_xof_kat PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/tests)
    target_link_libraries(test_kat_xof_kat PRIVATE ascon)
    add_test(NAME ascon_kat_xof COMMAND test_kat_xof_kat)
endif()
