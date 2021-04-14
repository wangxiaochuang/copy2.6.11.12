#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/eisa.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/ioport.h>
#include <asm/io.h>

int EISA_bus;		/* for legacy drivers */
EXPORT_SYMBOL (EISA_bus);