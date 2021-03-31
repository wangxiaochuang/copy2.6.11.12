#include <linux/types.h>
#include <linux/threads.h>

typedef struct { DECLARE_BITMAP(bits, NR_CPUS); } cpumask_t;