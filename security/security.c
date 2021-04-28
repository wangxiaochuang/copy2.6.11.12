#include <linux/config.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/security.h>

#define SECURITY_FRAMEWORK_VERSION	"1.0.0"

/* things that live in dummy.c */
extern struct security_operations dummy_security_ops;
extern void security_fixup_ops(struct security_operations *ops);

struct security_operations *security_ops;	/* Initialized to NULL */

static inline int verify(struct security_operations *ops)
{
	/* verify the security_operations structure exists */
	if (!ops)
		return -EINVAL;
	security_fixup_ops(ops);
	return 0;
}

static void __init do_security_initcalls(void)
{
	initcall_t *call;
	call = __security_initcall_start;
	while (call < __security_initcall_end) {
		(*call) ();
		call++;
	}
}

int __init security_init(void)
{
	printk(KERN_INFO "Security Framework v" SECURITY_FRAMEWORK_VERSION
	       " initialized\n");

	if (verify(&dummy_security_ops)) {
		printk(KERN_ERR "%s could not verify "
		       "dummy_security_ops structure.\n", __FUNCTION__);
		return -EIO;
	}

	security_ops = &dummy_security_ops;
	do_security_initcalls();

	return 0;
}