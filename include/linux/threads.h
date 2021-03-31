#ifndef _LINUX_THREADS_H
#define _LINUX_THREADS_H

#include <linux/config.h>

#ifdef CONFIG_SMP
#define NR_CPUS		CONFIG_NR_CPUS
#else
#define NR_CPUS		1
#endif

#endif