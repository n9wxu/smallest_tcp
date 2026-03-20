/* Minimal arch/cc.h for lwIP bare-metal ARM build */
#ifndef LWIP_ARCH_CC_H
#define LWIP_ARCH_CC_H

#include <stdint.h>
#include <stdlib.h>

/* Types */
typedef uint8_t u8_t;
typedef int8_t s8_t;
typedef uint16_t u16_t;
typedef int16_t s16_t;
typedef uint32_t u32_t;
typedef int32_t s32_t;
typedef uintptr_t mem_ptr_t;

/* Compiler hints */
#define LWIP_NO_STDDEF_H 0
#define LWIP_NO_STDINT_H 0
#define LWIP_NO_INTTYPES_H 1

/* Byte order — ARM is little-endian */
#define BYTE_ORDER LITTLE_ENDIAN

/* Platform-specific diagnostic macros */
#define LWIP_PLATFORM_DIAG(x)
#define LWIP_PLATFORM_ASSERT(x)

/* Protection (bare-metal single-threaded: no-op) */
typedef int sys_prot_t;
#define SYS_ARCH_DECL_PROTECT(x) sys_prot_t x
#define SYS_ARCH_PROTECT(x) ((x) = 0)
#define SYS_ARCH_UNPROTECT(x) ((void)(x))

#define PACK_STRUCT_FIELD(x) x
#define PACK_STRUCT_STRUCT __attribute__((packed))
#define PACK_STRUCT_BEGIN
#define PACK_STRUCT_END

#endif /* LWIP_ARCH_CC_H */
