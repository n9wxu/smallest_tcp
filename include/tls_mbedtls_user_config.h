/**
 * @file tls_mbedtls_user_config.h
 * @brief Additions to Mbed TLS's default configuration for smallest_tcp
 *        (MBEDTLS_USER_CONFIG_FILE, set by CMakeLists.txt).
 *
 * The static-arena allocator lets an application keep Mbed TLS off the heap
 * (tls_mbedtls_use_arena()); until an arena is set, mbedtls_calloc() is the
 * C library's calloc().
 */

#ifndef TLS_MBEDTLS_USER_CONFIG_H
#define TLS_MBEDTLS_USER_CONFIG_H

#define MBEDTLS_PLATFORM_MEMORY
#define MBEDTLS_MEMORY_BUFFER_ALLOC_C

#endif /* TLS_MBEDTLS_USER_CONFIG_H */
