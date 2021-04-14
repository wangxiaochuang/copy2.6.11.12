#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>

unsigned long long memparse (char *ptr, char **retptr) {
    unsigned long long ret = simple_strtoull(ptr, retptr, 0);
    switch (**retptr) {
        case 'G':
        case 'g':
            ret <<= 30;
        case 'M':
        case 'm':
            ret <<= 20;
        case 'K':
        case 'k':
            ret <<= 10;
            (*retptr)++;
        default:
            break;
    }
    return ret;
}