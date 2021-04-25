#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/swap.h>
#include <linux/timex.h>
#include <linux/jiffies.h>

void out_of_memory(int gfp_mask)
{
    mypanic("in out of memory");
}