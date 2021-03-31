#ifndef _LINUX_CAPABILITY_H
#define _LINUX_CAPABILITY_H

#include <linux/types.h>
#include <linux/compiler.h>

#ifdef STRICT_CAP_T_TYPECHECKS

typedef struct kernel_cap_struct {
	__u32 cap;
} kernel_cap_t;

#else

typedef __u32 kernel_cap_t;

#endif

#endif