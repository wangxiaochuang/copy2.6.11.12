#include <linux/config.h>
#include <linux/module.h>
#include <linux/profile.h>
#include <linux/bootmem.h>
#include <linux/notifier.h>
#include <linux/mm.h>
#include <linux/cpumask.h>
#include <linux/cpu.h>
#include <linux/profile.h>
#include <linux/highmem.h>
#include <asm/sections.h>
#include <asm/semaphore.h>

static int prof_on;

void __init profile_init(void) {
    if (!prof_on)
        return;
}