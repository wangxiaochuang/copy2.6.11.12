#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/errno.h>
#include <linux/time.h>
#include <linux/aio_abi.h>
#include <linux/module.h>
#include <linux/syscalls.h>

#define DEBUG 0

#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/aio.h>
#include <linux/highmem.h>
#include <linux/workqueue.h>
#include <linux/security.h>

#include <asm/kmap_types.h>
#include <asm/uaccess.h>
#include <asm/mmu_context.h>

ssize_t fastcall wait_on_sync_kiocb(struct kiocb *iocb)
{
	while (iocb->ki_users) {
		set_current_state(TASK_UNINTERRUPTIBLE);
		if (!iocb->ki_users)
			break;
		schedule();
	}
	__set_current_state(TASK_RUNNING);
	return iocb->ki_user_data;
}