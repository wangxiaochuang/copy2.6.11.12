#include <linux/mm.h>
#include <linux/module.h>
#include <linux/security.h>
#include <linux/syscalls.h>
#include <asm/uaccess.h>

unsigned securebits = SECUREBITS_DEFAULT;