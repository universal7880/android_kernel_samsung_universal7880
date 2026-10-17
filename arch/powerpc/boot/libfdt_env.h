#ifndef _ARCH_POWERPC_BOOT_LIBFDT_ENV_H
#define _ARCH_POWERPC_BOOT_LIBFDT_ENV_H

#include <types.h>
#include <stdbool.h>
#include <string.h>

typedef u8 uint8_t;
typedef u16 uint16_t;
typedef u32 uint32_t;
typedef u64 uint64_t;
typedef unsigned long uintptr_t;

#define LIBFDT_ENV_H

#define INT_MAX ((int)(~0U >> 1))
#define INT32_MAX ((s32)(~0U >> 1))
#define UINT32_MAX (~0U)

typedef u16 fdt16_t;
typedef u32 fdt32_t;
typedef u64 fdt64_t;

#define fdt16_to_cpu(x)		(x)
#define cpu_to_fdt16(x)		(x)
#define fdt32_to_cpu(x)		(x)
#define cpu_to_fdt32(x)		(x)
#define fdt64_to_cpu(x)		(x)
#define cpu_to_fdt64(x)		(x)

#endif /* _ARCH_POWERPC_BOOT_LIBFDT_ENV_H */
