#include <linux/blkdev.h>
#include <linux/errno.h>
#include <linux/signal.h>
#include <linux/interrupt.h>
#include <linux/timer.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/genhd.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/ioport.h>
#include <linux/mc146818rtc.h> /* CMOS defines */
#include <linux/init.h>
#include <linux/blkpg.h>
#include <linux/hdreg.h>

#define REALLY_SLOW_IO
#include <asm/system.h>
#include <asm/io.h>
#include <asm/uaccess.h>

#ifdef __arm__
#undef  HD_IRQ
#endif
#include <asm/irq.h>
#ifdef __arm__
#define HD_IRQ IRQ_HARDDISK
#endif



static DEFINE_SPINLOCK(hd_lock);
static struct request_queue *hd_queue;

#define MAJOR_NR HD_MAJOR
#define QUEUE (hd_queue)
#define CURRENT elv_next_request(hd_queue)

#define TIMEOUT_VALUE	(6*HZ)
#define	HD_DELAY	0

#define MAX_ERRORS     16	/* Max read/write errors/sector */
#define RESET_FREQ      8	/* Reset controller every 8th retry */
#define RECAL_FREQ      4	/* Recalibrate every 4th retry */
#define MAX_HD		2

#define STAT_OK		(READY_STAT|SEEK_STAT)
#define OK_STATUS(s)	(((s)&(STAT_OK|(BUSY_STAT|WRERR_STAT|ERR_STAT)))==STAT_OK)

static void recal_intr(void);
static void bad_rw_intr(void);

static int reset;
static int hd_error;

/*
 *  This struct defines the HD's and their types.
 */
struct hd_i_struct {
	unsigned int head,sect,cyl,wpcom,lzone,ctl;
	int unit;
	int recalibrate;
	int special_op;
};
	
#ifdef HD_TYPE
static struct hd_i_struct hd_info[] = { HD_TYPE };
static int NR_HD = ((sizeof (hd_info))/(sizeof (struct hd_i_struct)));
#else
static struct hd_i_struct hd_info[MAX_HD];
static int NR_HD;
#endif

static struct gendisk *hd_gendisk[MAX_HD];

static struct timer_list device_timer;

#define TIMEOUT_VALUE (6*HZ)

#define SET_TIMER							\
	do {								\
		mod_timer(&device_timer, jiffies + TIMEOUT_VALUE);	\
	} while (0)

static void (*do_hd)(void) = NULL;
#define SET_HANDLER(x) \
if ((do_hd = (x)) != NULL) \
	SET_TIMER; \
else \
	del_timer(&device_timer);


#if (HD_DELAY > 0)
unsigned long last_req;

unsigned long read_timer(void)
{
        extern spinlock_t i8253_lock;
	unsigned long t, flags;
	int i;

	spin_lock_irqsave(&i8253_lock, flags);
	t = jiffies * 11932;
    	outb_p(0, 0x43);
	i = inb_p(0x40);
	i |= inb(0x40) << 8;
	spin_unlock_irqrestore(&i8253_lock, flags);
	return(t - i);
}
#endif



static void hd_times_out(unsigned long dummy)
{
	panic("in hd_times_out");
}

static void hd_request(void)
{
	panic("in hd_request");
}

static void do_hd_request (request_queue_t * q)
{
	disable_irq(HD_IRQ);
	hd_request();
	enable_irq(HD_IRQ);
}

static int hd_ioctl(struct inode * inode, struct file * file,
	unsigned int cmd, unsigned long arg)
{
	panic("in hd_ioctl");
	return 0;
}

static irqreturn_t hd_interrupt(int irq, void *dev_id, struct pt_regs *regs)
{
	panic("in hd_interrupt");
	return 0;
}

static struct block_device_operations hd_fops = {
	.ioctl =	hd_ioctl,
};

static int __init hd_init(void)
{
    int drive;

	if (register_blkdev(MAJOR_NR, "hd"))
		return -1;

    hd_queue = blk_init_queue(do_hd_request, &hd_lock);
	if (!hd_queue) {
		unregister_blkdev(MAJOR_NR,"hd");
		return -ENOMEM;
	}

	blk_queue_max_sectors(hd_queue, 255);
	init_timer(&device_timer);
	device_timer.function = hd_times_out;
	blk_queue_hardsect_size(hd_queue, 512);

#ifdef __i386__
	if (!NR_HD) {
		extern struct drive_info drive_info;
		unsigned char *BIOS = (unsigned char *) &drive_info;
		unsigned long flags;
		int cmos_disks;

		for (drive=0 ; drive<2 ; drive++) {
			hd_info[drive].cyl = *(unsigned short *) BIOS;
			hd_info[drive].head = *(2+BIOS);
			hd_info[drive].wpcom = *(unsigned short *) (5+BIOS);
			hd_info[drive].ctl = *(8+BIOS);
			hd_info[drive].lzone = *(unsigned short *) (12+BIOS);
			hd_info[drive].sect = *(14+BIOS);
#ifdef does_not_work_for_everybody_with_scsi_but_helps_ibm_vp
			if (hd_info[drive].cyl && NR_HD == drive)
				NR_HD++;
#endif
			BIOS += 16;
		}

		spin_lock_irqsave(&rtc_lock, flags);
		cmos_disks = CMOS_READ(0x12);
		spin_unlock_irqrestore(&rtc_lock, flags);

		if (cmos_disks & 0xf0) {
			if (cmos_disks & 0x0f)
				NR_HD = 2;
			else
				NR_HD = 1;
		}
	}
#endif /* __i386__ */
#ifdef __arm__
#error "__asm__"
#endif
	if (!NR_HD)
		goto out;

	for (drive=0 ; drive < NR_HD ; drive++) {
		struct gendisk *disk = alloc_disk(64);
		struct hd_i_struct *p = &hd_info[drive];
		if (!disk)
			goto Enomem;
		disk->major = MAJOR_NR;
		disk->first_minor = drive << 6;
		disk->fops = &hd_fops;
		sprintf(disk->disk_name, "hd%c", 'a'+drive);
		disk->private_data = p;
		set_capacity(disk, p->head * p->sect * p->cyl);
		disk->queue = hd_queue;
		p->unit = drive;
		hd_gendisk[drive] = disk;
		printk ("%s: %luMB, CHS=%d/%d/%d\n",
			disk->disk_name, (unsigned long)get_capacity(disk)/2048,
			p->cyl, p->head, p->sect);
	}

	if (request_irq(HD_IRQ, hd_interrupt, SA_INTERRUPT, "hd", NULL)) {
		printk("hd: unable to get IRQ%d for the hard disk driver\n",
			HD_IRQ);
		goto out1;
	}
	if (!request_region(HD_DATA, 8, "hd")) {
		printk(KERN_WARNING "hd: port 0x%x busy\n", HD_DATA);
		goto out2;
	}
	if (!request_region(HD_CMD, 1, "hd(cmd)")) {
		printk(KERN_WARNING "hd: port 0x%x busy\n", HD_CMD);
		goto out3;
	}

	/* Let them fly */
	for(drive=0; drive < NR_HD; drive++)
		add_disk(hd_gendisk[drive]);

	return 0;

out3:
	release_region(HD_DATA, 8);
out2:
	free_irq(HD_IRQ, NULL);
out1:
	for (drive = 0; drive < NR_HD; drive++)
		put_disk(hd_gendisk[drive]);
	NR_HD = 0;
out:
	del_timer(&device_timer);
	unregister_blkdev(MAJOR_NR,"hd");
	blk_cleanup_queue(hd_queue);
	return -1;
Enomem:
	while (drive--)
		put_disk(hd_gendisk[drive]);
	goto out;
}

module_init(hd_init);