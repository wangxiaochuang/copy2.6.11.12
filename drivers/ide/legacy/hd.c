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

static void __init hd_setup(char *str, int *ints)
{
	panic("in hd_setup");
}

static void dump_status (const char *msg, unsigned int stat)
{
	char *name = "hd?";
	if (CURRENT)
		name = CURRENT->rq_disk->disk_name;
#ifdef VERBOSE_ERRORS
#else
	printk("%s: %s: status=0x%02x.\n", name, msg, stat & 0xff);
	if ((stat & ERR_STAT) == 0) {
		hd_error = 0;
	} else {
		hd_error = inb(HD_ERROR);
		printk("%s: %s: error=0x%02x.\n", name, msg, hd_error & 0xff);
	}
#endif
}

static void check_status(void)
{
	int i = inb_p(HD_STATUS);

	if (!OK_STATUS(i)) {
		dump_status("check_status", i);
		bad_rw_intr();
	}
}

static int controller_busy(void)
{
	int retries = 100000;
	unsigned char status;

	do {
		status = inb_p(HD_STATUS);
	} while ((status & BUSY_STAT) && --retries);
	return status;
}

static int status_ok(void)
{
	unsigned char status = inb_p(HD_STATUS);

	if (status & BUSY_STAT)
		return 1;	/* Ancient, but does it make sense??? */
	if (status & WRERR_STAT)
		return 0;
	if (!(status & READY_STAT))
		return 0;
	if (!(status & SEEK_STAT))
		return 0;
	return 1;
}

static int controller_ready(unsigned int drive, unsigned int head)
{
	int retry = 100;

	do {
		if (controller_busy() & BUSY_STAT)
			return 0;
		outb_p(0xA0 | (drive<<4) | head, HD_CURRENT);
		if (status_ok())
			return 1;
	} while (--retry);
	return 0;
}

static void hd_out(struct hd_i_struct *disk,
		   unsigned int nsect,
		   unsigned int sect,
		   unsigned int head,
		   unsigned int cyl,
		   unsigned int cmd,
		   void (*intr_addr)(void))
{
	unsigned short port;

#if (HD_DELAY > 0)
	while (read_timer() - last_req < HD_DELAY)
		/* nothing */;
#endif
	if (reset)
		return;
	if (!controller_ready(disk->unit, head)) {
		reset = 1;
		return;
	}
	SET_HANDLER(intr_addr);
	outb_p(disk->ctl,HD_CMD);
	port=HD_DATA;
	outb_p(disk->wpcom>>2,++port);
	outb_p(nsect,++port);
	outb_p(sect,++port);
	outb_p(cyl,++port);
	outb_p(cyl>>8,++port);
	outb_p(0xA0|(disk->unit<<4)|head,++port);
	outb_p(cmd,++port);
}

static void hd_request (void);

static int drive_busy(void)
{
	unsigned int i;
	unsigned char c;

	for (i = 0; i < 500000 ; i++) {
		c = inb_p(HD_STATUS);
		if ((c & (BUSY_STAT | READY_STAT | SEEK_STAT)) == STAT_OK)
			return 0;
	}
	dump_status("reset timed out", c);
	return 1;
}

static void reset_controller(void)
{
	int	i;

	outb_p(4,HD_CMD);
	for(i = 0; i < 1000; i++) barrier();
	outb_p(hd_info[0].ctl & 0x0f,HD_CMD);
	for(i = 0; i < 1000; i++) barrier();
	if (drive_busy())
		printk("hd: controller still busy\n");
	else if ((hd_error = inb(HD_ERROR)) != 1)
		printk("hd: controller reset failed: %02x\n",hd_error);
}

static void reset_hd(void)
{
	static int i;

repeat:
	if (reset) {
		reset = 0;
		i = -1;
		reset_controller();
	} else {
		check_status();
		if (reset)
			goto repeat;
	}
	if (++i < NR_HD) {
		struct hd_i_struct *disk = &hd_info[i];
		disk->special_op = disk->recalibrate = 1;
		hd_out(disk, disk->sect, disk->sect, disk->head-1,
			disk->cyl, WIN_SPECIFY, &reset_hd);
		if (reset)
			goto repeat;
	} else
		hd_request();
}

static void unexpected_hd_interrupt(void)
{
	panic("in unexpected_hd_interrupt");
}

static void bad_rw_intr(void)
{
	struct request *req = CURRENT;
	if (req != NULL) {
		struct hd_i_struct *disk = req->rq_disk->private_data;
		if (++req->errors >= MAX_ERRORS || (hd_error & BBD_ERR)) {
			end_request(req, 0);
			disk->special_op = disk->recalibrate = 1;
		} else if (req->errors % RESET_FREQ == 0)
			reset = 1;
		else if ((hd_error & TRK0_ERR) || req->errors % RECAL_FREQ == 0)
			disk->special_op = disk->recalibrate = 1;
		/* Otherwise just retry */
	}
}

static inline int wait_DRQ(void)
{
	panic("in wait_DRQ");
	return 0;
}

static void read_intr(void)
{
	struct request *req;
	int i, retries = 100000;

	do {
		i = (unsigned) inb_p(HD_STATUS);
		if (i & BUSY_STAT)
			continue;
		if (!OK_STATUS(i))
			break;
		if (i & DRQ_STAT)
			goto ok_to_read;
	} while (--retries > 0);
	dump_status("read_intr", i);
	bad_rw_intr();
	hd_request();
	return;
ok_to_read:
	req = CURRENT;
	insw(HD_DATA,req->buffer,256);
	req->sector++;
	req->buffer += 512;
	req->errors = 0;
	i = --req->nr_sectors;
	--req->current_nr_sectors;
#ifdef DEBUG
	printk("%s: read: sector %ld, remaining = %ld, buffer=%p\n",
		req->rq_disk->disk_name, req->sector, req->nr_sectors,
		req->buffer+512));
#endif
	if (req->current_nr_sectors <= 0)
		end_request(req, 1);
	if (i > 0) {
		SET_HANDLER(&read_intr);
		return;
	}
	(void) inb_p(HD_STATUS);
#if (HD_DELAY > 0)
	last_req = read_timer();
#endif
	if (elv_next_request(QUEUE))
		hd_request();
	return;
}

static void write_intr(void)
{
	panic("in write_intr");
}

static void recal_intr(void)
{
	check_status();
#if (HD_DELAY > 0)
	last_req = read_timer();
#endif
	hd_request();
}

static void hd_times_out(unsigned long dummy)
{
	panic("in hd_times_out");
}

static int do_special_op(struct hd_i_struct *disk, struct request *req)
{
	if (disk->recalibrate) {
		disk->recalibrate = 0;
		hd_out(disk,disk->sect,0,0,0,WIN_RESTORE,&recal_intr);
		return reset;
	}
	if (disk->head > 16) {
		printk ("%s: cannot handle device with more than 16 heads - giving up\n", req->rq_disk->disk_name);
		end_request(req, 0);
	}
	disk->special_op = 0;
	return 1;
}

static void hd_request(void)
{
	unsigned int block, nsect, sec, track, head, cyl;
	struct hd_i_struct *disk;
	struct request *req;

	if (do_hd)
		return;
repeat:
	del_timer(&device_timer);
	local_irq_enable();

	req = CURRENT;
	if (!req) {
		do_hd = NULL;
		return;
	}

	if (reset) {
		local_irq_disable();
		reset_hd();
		return;
	}
	disk = req->rq_disk->private_data;
	block = req->sector;
	nsect = req->nr_sectors;
	if (block >= get_capacity(req->rq_disk) ||
	    ((block+nsect) > get_capacity(req->rq_disk))) {
		printk("%s: bad access: block=%d, count=%d\n",
			req->rq_disk->disk_name, block, nsect);
		end_request(req, 0);
		goto repeat;
	}

	if (disk->special_op) {
		if (do_special_op(disk, req))
			goto repeat;
		return;
	}
	sec   = block % disk->sect + 1;
	track = block / disk->sect;
	head  = track % disk->head;
	cyl   = track / disk->head;


	if (req->flags & REQ_CMD) {
		switch (rq_data_dir(req)) {
		case READ:
printk("%s: %sing: CHS=%d/%d/%d, sectors=%d, buffer=%p\n",
		req->rq_disk->disk_name, "read",
		cyl, head, sec, nsect, req->buffer);
			hd_out(disk,nsect,sec,head,cyl,WIN_READ,&read_intr);
			if (reset)
				goto repeat;
			break;
		case WRITE:
printk("%s: %sing: CHS=%d/%d/%d, sectors=%d, buffer=%p\n",
		req->rq_disk->disk_name, "write",
		cyl, head, sec, nsect, req->buffer);
			hd_out(disk,nsect,sec,head,cyl,WIN_WRITE,&write_intr);
			if (reset)
				goto repeat;
			if (wait_DRQ()) {
				bad_rw_intr();
				goto repeat;
			}
			outsw(HD_DATA,req->buffer,256);
			break;
		default:
			printk("unknown hd-command\n");
			end_request(req, 0);
			break;
		}
	}
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
	void (*handler)(void) = do_hd;

	do_hd = NULL;
	del_timer(&device_timer);
	if (!handler)
		handler = unexpected_hd_interrupt;
	handler();
	local_irq_enable();
	return IRQ_HANDLED;
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