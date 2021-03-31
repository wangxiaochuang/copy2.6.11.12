#ifndef _LINUX_TIMER_H
#define _LINUX_TIMER_H

#include <linux/config.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/stddef.h>

struct tvec_t_base_s;

struct timer_list {
	struct list_head entry;
	unsigned long expires;

	spinlock_t lock;
	unsigned long magic;

	void (*function)(unsigned long);
	unsigned long data;

	struct tvec_t_base_s *base;
};

#endif