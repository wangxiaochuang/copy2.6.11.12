#include <linux/bitops.h>
#include <linux/module.h>

/**
 * find_next_bit - find the first set bit in a memory region
 * @addr: The address to base the search on
 * @offset: The bitnumber to start searching at
 * @size: The maximum size to search
 */
int find_next_bit(const unsigned long *addr, int size, int offset)
{
	const unsigned long *p = addr + (offset >> 5);
	int set = 0, bit = offset & 31, res;

	if (bit) {
		/*
		 * Look for nonzero in the first 32 bits:
		 */
		__asm__("bsfl %1,%0\n\t"
			"jne 1f\n\t"
			"movl $32, %0\n"
			"1:"
			: "=r" (set)
			: "r" (*p >> bit));
		if (set < (32 - bit))
			return set + offset;
		set = 32 - bit;
		p++;
	}
	/*
	 * No set bit yet, search remaining full words for a bit
	 */
	res = find_first_bit (p, size - 32 * (p - addr));
	return (offset + set + res);
}
EXPORT_SYMBOL(find_next_bit);

/**
 * find_next_zero_bit - find the first zero bit in a memory region
 * @addr: The address to base the search on
 * @offset: The bitnumber to start searching at
 * @size: The maximum size to search
 */
int find_next_zero_bit(const unsigned long *addr, int size, int offset) {
	// offset 除以32，因为addr的每一个元素是四个字节，总共32个位
	// 找到offset所在的addr的元素
	unsigned long *p = ((unsigned long *) addr) + (offset >> 5);
	// bit 为当前这一个32bit的变量中的位置
	int set = 0, bit = offset & 31, res;
	if (bit) {
		__asm__("bsfl %1, %0\n\t"
			"jne 1f\n\t"
			"movl $32, %0\n"
			"1:"
			: "=r" (set)
			: "r" (~(*p >> bit)));
		if (set < (32 - bit))
			return set + offset;
		set = 32 - bit;
		p++;
	}
	res = find_first_zero_bit(p, size - 32 * (p - (unsigned long *) addr));
	return (offset + set + res);
}
EXPORT_SYMBOL(find_next_zero_bit);
