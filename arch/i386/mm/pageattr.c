/* 
 * Copyright 2002 Andi Kleen, SuSE Labs. 
 * Thanks to Ben LaHaise for precious feedback.
 */ 

#include <linux/config.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/highmem.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <asm/uaccess.h>
#include <asm/processor.h>
#include <asm/tlbflush.h>

static DEFINE_SPINLOCK(cpa_lock);
static struct list_head df_list = LIST_HEAD_INIT(df_list);


int change_page_attr(struct page *page, int numpages, pgprot_t prot)
{
}

void global_flush_tlb(void)
{ 
}