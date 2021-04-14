#include <linux/module.h>
#include <linux/ctype.h>
#include <linux/errno.h>
#include <linux/bitmap.h>
#include <linux/bitops.h>
#include <asm/uaccess.h>

// 看bitmap对应的bits位是否为空
int __bitmap_empty(const unsigned long *bitmap, int bits) {
    int k, lim = bits / BITS_PER_LONG;
    for (k = 0; k < lim; ++k)
        if (bitmap[k])
            return 0;
    if (bits % BITS_PER_LONG)
        if (bitmap[k] & BITMAP_LAST_WORD_MASK(bits))
            return 0;
    return 1;
}