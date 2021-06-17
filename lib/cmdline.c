#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/string.h>

int get_option (char **str, int *pint)
{
	char *cur = *str;

	if (!cur || !(*cur))
		return 0;
	*pint = simple_strtol (cur, str, 0);
	if (cur == *str)
		return 0;
	if (**str == ',') {
		(*str)++;
		return 2;
	}

	return 1;
}

char *get_options(const char *str, int nints, int *ints)
{
	int res, i = 1;

	while (i < nints) {
		res = get_option ((char **)&str, ints + i);
		if (res == 0)
			break;
		i++;
		if (res == 1)
			break;
	}
	ints[0] = i - 1;
	return (char *)str;
}

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