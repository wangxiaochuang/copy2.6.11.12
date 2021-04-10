#include <linux/compile.h>
#include <linux/module.h>
#include <linux/uts.h>
#include <linux/utsname.h>
#include <linux/version.h>

struct new_utsname system_utsname = {
	.sysname	= UTS_SYSNAME,
	.nodename	= UTS_NODENAME,
	.release	= UTS_RELEASE,
	.version	= UTS_VERSION,
	.machine	= UTS_MACHINE,
	.domainname	= UTS_DOMAINNAME,
};

EXPORT_SYMBOL(system_utsname);

const char linux_banner[] =
	"Linux version " UTS_RELEASE " (" LINUX_COMPILE_BY "@"
	LINUX_COMPILE_HOST ") (" LINUX_COMPILER ") " UTS_VERSION "\n";
