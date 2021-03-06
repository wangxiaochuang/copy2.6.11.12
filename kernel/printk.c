#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/tty.h>
#include <linux/tty_driver.h>
#include <linux/smp_lock.h>
#include <linux/console.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/interrupt.h>			/* For in_interrupt() */
#include <linux/config.h>
#include <linux/delay.h>
#include <linux/smp.h>
#include <linux/security.h>
#include <linux/bootmem.h>
#include <linux/syscalls.h>

#include <asm/uaccess.h>

#define __LOG_BUF_LEN	(1 << CONFIG_LOG_BUF_SHIFT)

/* printk's without a loglevel use this.. */
#define DEFAULT_MESSAGE_LOGLEVEL 4 /* KERN_WARNING */

/* We show everything that is MORE important than this.. */
#define MINIMUM_CONSOLE_LOGLEVEL 1 /* Minimum loglevel we let people use */
#define DEFAULT_CONSOLE_LOGLEVEL 7 /* anything MORE serious than KERN_DEBUG */

DECLARE_WAIT_QUEUE_HEAD(log_wait);

int console_printk[4] = {
	DEFAULT_CONSOLE_LOGLEVEL,	/* console_loglevel */
	DEFAULT_MESSAGE_LOGLEVEL,	/* default_message_loglevel */
	MINIMUM_CONSOLE_LOGLEVEL,	/* minimum_console_loglevel */
	DEFAULT_CONSOLE_LOGLEVEL,	/* default_console_loglevel */
};

EXPORT_SYMBOL(console_printk);

int oops_in_progress;

static DECLARE_MUTEX(console_sem);
struct console *console_drivers;

static int console_locked;


static DEFINE_SPINLOCK(logbuf_lock);

static char __log_buf[__LOG_BUF_LEN];
static char *log_buf = __log_buf;
static int log_buf_len = __LOG_BUF_LEN;

#define LOG_BUF_MASK	(log_buf_len-1)
#define LOG_BUF(idx) (log_buf[(idx) & LOG_BUF_MASK])

static unsigned long log_start;	/* Index into log_buf: next char to be read by syslog() */
static unsigned long con_start;	/* Index into log_buf: next char to be sent to consoles */
static unsigned long log_end;	/* Index into log_buf: most-recently-written-char + 1 */
static unsigned long logged_chars; /* Number of chars produced since last read+clear operation */

/*
 *	Array of consoles built from command line options (console=)
 */
struct console_cmdline
{
	char	name[8];			/* Name of the driver	    */
	int	index;				/* Minor dev. to use	    */
	char	*options;			/* Options for the driver   */
};

#define MAX_CMDLINECONSOLES 8

static struct console_cmdline console_cmdline[MAX_CMDLINECONSOLES];
static int selected_console = -1;
static int preferred_console = -1;

static int console_may_schedule;

/*
 *	Setup a list of consoles. Called from init/main.c
 */
static int __init console_setup(char *str) {
	return 0;
}

static void __call_console_drivers(unsigned long start, unsigned long end)
{
	struct console *con;

	for (con = console_drivers; con; con = con->next) {
		if ((con->flags & CON_ENABLED) && con->write)
			con->write(con, &LOG_BUF(start), end - start);
	}
}

/*
 * Write out chars from start to end - 1 inclusive
 */
static void _call_console_drivers(unsigned long start,
				unsigned long end, int msg_log_level)
{
	if (msg_log_level < console_loglevel &&
			console_drivers && start != end) {
		if ((start & LOG_BUF_MASK) > (end & LOG_BUF_MASK)) {
			/* wrapped write */
			__call_console_drivers(start & LOG_BUF_MASK,
						log_buf_len);
			__call_console_drivers(0, end & LOG_BUF_MASK);
		} else {
			__call_console_drivers(start, end);
		}
	}
}

static void call_console_drivers(unsigned long start, unsigned long end)
{
	unsigned long cur_index, start_print;
	static int msg_level = -1;

	if (((long)(start - end)) > 0)
		BUG();

	cur_index = start;
	start_print = start;
	while (cur_index != end) {
		if (	msg_level < 0 &&
			((end - cur_index) > 2) &&
			LOG_BUF(cur_index + 0) == '<' &&
			LOG_BUF(cur_index + 1) >= '0' &&
			LOG_BUF(cur_index + 1) <= '7' &&
			LOG_BUF(cur_index + 2) == '>')
		{
			msg_level = LOG_BUF(cur_index + 1) - '0';
			cur_index += 3;
			start_print = cur_index;
		}
		while (cur_index != end) {
			char c = LOG_BUF(cur_index);
			cur_index++;

			if (c == '\n') {
				if (msg_level < 0) {
					/*
					 * printk() has already given us loglevel tags in
					 * the buffer.  This code is here in case the
					 * log buffer has wrapped right round and scribbled
					 * on those tags
					 */
					msg_level = default_message_loglevel;
				}
				_call_console_drivers(start_print, cur_index, msg_level);
				msg_level = -1;
				start_print = cur_index;
				break;
			}
		}
	}
	_call_console_drivers(start_print, end, msg_level);
}

static void emit_log_char(char c)
{
	LOG_BUF(log_end) = c;
	log_end++;
	if (log_end - log_start > log_buf_len)
		log_start = log_end - log_buf_len;
	if (log_end - con_start > log_buf_len)
		con_start = log_end - log_buf_len;
	if (logged_chars < log_buf_len)
		logged_chars++;
}

static void zap_locks(void)
{
    __asm__ ("hlt");
}

asmlinkage int printk(const char *fmt, ...) {
    va_list args;
	int r;

	va_start(args, fmt);
	r = vprintk(fmt, args);
	va_end(args);

	return r;
}

asmlinkage int vprintk(const char *fmt, va_list args)
{
	unsigned long flags;
	int printed_len;
	char *p;
	static char printk_buf[1024];
	static int log_level_unknown = 1;

	if (unlikely(oops_in_progress))
		zap_locks();

	/* This stops the holder of console_sem just where we want him */
	spin_lock_irqsave(&logbuf_lock, flags);

	/* Emit the output into the temporary buffer */
	printed_len = vscnprintf(printk_buf, sizeof(printk_buf), fmt, args);

	/*
	 * Copy the output into log_buf.  If the caller didn't provide
	 * appropriate log level tags, we insert them here
	 */
	for (p = printk_buf; *p; p++) {
		if (log_level_unknown) {
			if (p[0] != '<' || p[1] < '0' || p[1] > '7' || p[2] != '>') {
				emit_log_char('<');
				emit_log_char(default_message_loglevel + '0');
				emit_log_char('>');
			}
			log_level_unknown = 0;
		}
		emit_log_char(*p);
		if (*p == '\n')
			log_level_unknown = 1;
	}

	if (!cpu_online(smp_processor_id()) &&
	    system_state != SYSTEM_RUNNING) {
		/*
		 * Some console drivers may assume that per-cpu resources have
		 * been allocated.  So don't allow them to be called by this
		 * CPU until it is officially up.  We shouldn't be calling into
		 * random console drivers on a CPU which doesn't exist yet..
		 */
		spin_unlock_irqrestore(&logbuf_lock, flags);
		goto out;
	}
	if (!down_trylock(&console_sem)) {
		console_locked = 1;
		/*
		 * We own the drivers.  We can drop the spinlock and let
		 * release_console_sem() print the text
		 */
		spin_unlock_irqrestore(&logbuf_lock, flags);
		console_may_schedule = 0;
		release_console_sem();
	} else {
		/*
		 * Someone else owns the drivers.  We drop the spinlock, which
		 * allows the semaphore holder to proceed and to call the
		 * console drivers with the output which we just produced.
		 */
		spin_unlock_irqrestore(&logbuf_lock, flags);
	}
out:
	return printed_len;
}
EXPORT_SYMBOL(printk);
EXPORT_SYMBOL(vprintk);

/**
 * acquire_console_sem - lock the console system for exclusive use.
 *
 * Acquires a semaphore which guarantees that the caller has
 * exclusive access to the console system and the console_drivers list.
 *
 * Can sleep, returns nothing.
 */
void acquire_console_sem(void) {
	if (in_interrupt())
		BUG();
	down(&console_sem);
	console_locked = 1;
	console_may_schedule = 1;
}

int is_console_locked(void)
{
	return console_locked;
}
EXPORT_SYMBOL(is_console_locked);

void release_console_sem(void)
{
	unsigned long flags;
	unsigned long _con_start, _log_end;
	unsigned long wake_klogd = 0;

	for ( ; ; ) {
		spin_lock_irqsave(&logbuf_lock, flags);
		wake_klogd |= log_start - log_end;
		if (con_start == log_end)
			break;			/* Nothing to print */
		_con_start = con_start;
		_log_end = log_end;
		con_start = log_end;		/* Flush */
		spin_unlock(&logbuf_lock);
		call_console_drivers(_con_start, _log_end);
		local_irq_restore(flags);
	}
	console_locked = 0;
	console_may_schedule = 0;
	up(&console_sem);
	spin_unlock_irqrestore(&logbuf_lock, flags);
	if (wake_klogd && !oops_in_progress && waitqueue_active(&log_wait))
		wake_up_interruptible(&log_wait);
}
EXPORT_SYMBOL(release_console_sem);

void __sched console_conditional_schedule(void)
{
	if (console_may_schedule)
		cond_resched();
}
EXPORT_SYMBOL(console_conditional_schedule);

void console_print(const char *s)
{
	printk(KERN_EMERG "%s", s);
}
EXPORT_SYMBOL(console_print);

void console_unblank(void)
{
	panic("in console_unblank");
}

EXPORT_SYMBOL(console_unblank);

struct tty_driver *console_device(int *index)
{
	struct console *c;
	struct tty_driver *driver = NULL;

	acquire_console_sem();
	for (c = console_drivers; c != NULL; c = c->next) {
		if (!c->device)
			continue;
		driver = c->device(c, index);
		if (driver)
			break;
	}
	release_console_sem();
	return driver;
}
/*
 * The console driver calls this routine during kernel initialization
 * to register the console printing procedure with printk() and to
 * print any messages that were printed by the kernel before the
 * console driver was initialized.
 */
void register_console(struct console * console)
{
	int     i;
	unsigned long flags;

	if (preferred_console < 0)
		preferred_console = selected_console;

	/*
	 *	See if we want to use this console driver. If we
	 *	didn't select a console we take the first one
	 *	that registers here.
	 */
	if (preferred_console < 0) {
		if (console->index < 0)
			console->index = 0;
		if (console->setup == NULL ||
		    console->setup(console, NULL) == 0) {
			console->flags |= CON_ENABLED | CON_CONSDEV;
			preferred_console = 0;
		}
	}

	/*
	 *	See if this console matches one we selected on
	 *	the command line.
	 */
	for(i = 0; i < MAX_CMDLINECONSOLES && console_cmdline[i].name[0]; i++) {
		if (strcmp(console_cmdline[i].name, console->name) != 0)
			continue;
		if (console->index >= 0 &&
		    console->index != console_cmdline[i].index)
			continue;
		if (console->index < 0)
			console->index = console_cmdline[i].index;
		if (console->setup &&
		    console->setup(console, console_cmdline[i].options) != 0)
			break;
		console->flags |= CON_ENABLED;
		console->index = console_cmdline[i].index;
		if (i == preferred_console)
			console->flags |= CON_CONSDEV;
		break;
	}

	if (!(console->flags & CON_ENABLED))
		return;

	/*
	 *	Put this console in the list - keep the
	 *	preferred driver at the head of the list.
	 */
	acquire_console_sem();
	if ((console->flags & CON_CONSDEV) || console_drivers == NULL) {
		console->next = console_drivers;
		console_drivers = console;
	} else {
		console->next = console_drivers->next;
		console_drivers->next = console;
	}
	if (console->flags & CON_PRINTBUFFER) {
		/*
		 * release_console_sem() will print out the buffered messages
		 * for us.
		 */
		spin_lock_irqsave(&logbuf_lock, flags);
		con_start = log_start;
		spin_unlock_irqrestore(&logbuf_lock, flags);
	}
	release_console_sem();
}
EXPORT_SYMBOL(register_console);

int unregister_console(struct console * console)
{
        struct console *a,*b;
	int res = 1;

	acquire_console_sem();
	if (console_drivers == console) {
		console_drivers=console->next;
		res = 0;
	} else {
		for (a=console_drivers->next, b=console_drivers ;
		     a; b=a, a=b->next) {
			if (a == console) {
				b->next = a->next;
				res = 0;
				break;
			}  
		}
	}
	
	/* If last console is removed, we re-enable picking the first
	 * one that gets registered. Without that, pmac early boot console
	 * would prevent fbcon from taking over.
	 */
	if (console_drivers == NULL)
		preferred_console = selected_console;
		

	release_console_sem();
	return res;
}
EXPORT_SYMBOL(unregister_console);

int printk_ratelimit(void) {
	return 1;
}
EXPORT_SYMBOL(printk_ratelimit);

static void raw_print(const char * b) {
    unsigned char c;
    unsigned char *video = (unsigned char *) 0xb8000 + 24*160;
    while ((c = *(b++)) != 0) {
        video[0] = c;
        video[1] = 0x07;
        video += 2;
    }
}

void myprint(const char * fmt, ...) {
    static char mymybuf[32] = {'[', '['};
    va_list args;
    int len = 0;

    va_start(args, fmt);
    len = vsprintf(mymybuf+2, fmt, args);
    va_end(args);
    mymybuf[len + 2] = ']';
    mymybuf[len + 3] = ']';
    mymybuf[len + 4] = '\0';
    raw_print(mymybuf);
}

void mypanic(const char * fmt, ...) {
    static char mybuf[128] = {'[', '['};
    va_list args;
    int len = 0;

    va_start(args, fmt);
    len = vsprintf(mybuf+2, fmt, args);
    va_end(args);
    mybuf[len + 2] = ']';
    mybuf[len + 3] = ']';
    mybuf[len + 4] = '\0';
    raw_print(mybuf);
    for(;;) {
        __asm__("hlt");
    };
}