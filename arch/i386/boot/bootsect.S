#include <linux/config.h>
#include <asm/boot.h>

SETUPSECS	= 4			/* default nr of setup-sectors */
BOOTSEG		= 0x07C0		/* original address of boot-sector */
INITSEG		= DEF_INITSEG		/* we move boot here - out of the way */
SETUPSEG	= DEF_SETUPSEG		/* setup starts here */
SYSSEG		= DEF_SYSSEG		/* system loaded at 0x10000 (65536) */
SYSSIZE		= DEF_SYSSIZE		/* system size: # of 16-byte clicks */

ROOT_DEV	= 0 			/* ROOT_DEV is now written by "build" */
SWAP_DEV	= 0			/* SWAP_DEV is now written by "build" */

#ifndef SVGA_MODE
#define SVGA_MODE ASK_VGA
#endif

#ifndef RAMDISK
#define RAMDISK 0
#endif 

#ifndef CONFIG_ROOT_RDONLY
#define CONFIG_ROOT_RDONLY 1
#endif

.code16
.text

.global _start
_start:
	movw $BOOTSEG, %ax
	movw %ax, %ds
	movw $INITSEG, %ax
	movw %ax, %es			# es=0x9000
	movw $256, %cx
	xorw %si, %si
	xorw %di, %di
	cld
	rep movsw
	ljmp $INITSEG, $go

go:
	movw	$0x4000-12, %di
	movw	%ax, %ds		# ds=0x9000
	movw	%ax, %ss
	movw	%di, %sp

	movw	%cx, %fs		# set fs to 0
	movw	$0x78, %bx
	pushw	%ds
	ldsw	%fs:(%bx), %si	# 修改 ds和si的值
	movb	$6, %cl
	pushw	%di
	rep movsw				# ds:si => es:di  0x9000:0x4000-12
	popw	%di
	popw	%ds
	movb	$36, 0x4(%di)
	movw	%di, %fs:(%bx)
	movw	%es, %fs:2(%bx)	# 修改硬盘参数的指向

load_setup:
	xorb	%ah, %ah		# reset FDC
	xorb	%dl, %dl
	int	$0x13
	xorw	%dx, %dx		# drive 0, head 0
	movb	$0x02, %cl		# sector 2, track 0
	movw	$0x0200, %bx	# read to 0x90200
	movb	$0x02, %ah		# service 2, read sector
	movb	setup_sects, %al	# assume all on head 0, track 0, 4 sectors
	int $0x13
	jnc ok_load_setup
	hlt						# @todo
ok_load_setup:
	movw	$disksizes, %si
probe_loop:
	lodsb					# ds:si => al
	cbtw					# extend byte to word
	movw	%ax, sectors
	cmpw	$disksizes+4, %si
	jae got_sectors

	xchgw	%cx, %ax		# cx = track and sector
	xorw	%dx, %dx		# drive 0, head 0
	xorb	%bl, %bl
	movb	setup_sects, %bh
	incb	%bh
	shlb	%bh
	movw	$0x0201, %ax	# service 2, read 1 sector
	int $0x13
	jc probe_loop

got_sectors:
	movw	$INITSEG, %ax
	movw	%ax, %es
	movb	$0x03, %ah		# read cursor pos
	xorb	%bh, %bh
	int $0x10
	movw	$9, %cx
	movw	$0x0007, %bx	# page 0, attribute 7 (normal)
	movw	$msg1, %bp
	movw	$0x1301, %ax	# write string, move cursor
	int $0x10
	movw	$SYSSEG, %ax
	movw	%ax, %es		# es: 0x10000, load system at 0x1000:0
	call	read_it
	call	kill_motor
	call	print_nl

# check which root-device to user
	movw	root_dev, %ax
	orw		%ax, %ax
	jne		root_defined
	movw	$0x0301, %ax		# hard disk
	je		root_defined

root_defined:
	movw	%ax, root_dev
	jmp		$SETUPSEG, $0

sread:	.word 0				# sectors read of current track
head:	.word 0				# current head
track:	.word 0				# current track

read_it:
	movb	setup_sects, %al
	incb	%al
	movb	%al, sread
	movw	%es, %ax
	testw	$0x0fff, %ax
die:		jne die

	xorw	%bx, %bx

rp_read:
#ifdef __BIG_KERNEL__
	bootsect_kludge = 0x220		# 0x200 (size of bootsector) + 0x20 (offset)
	lcall bootsect_kludge
#else
	movw	%es, %ax
	subw	$SYSSEG, %ax
#endif
	cmpw	syssize, %ax
	jbe ok1_read

	ret

ok1_read:
	movw	sectors, %ax
	subw	sread, %ax
	movw	%ax, %cx
	shlw	$9, %cx
	addw	%bx, %cx
	jnc	ok2_read
	
	je	ok2_read

	xorw	%ax, %ax
	subw	%bx, %ax
	shrw	$9, %ax
ok2_read:
	call	read_track
	movw	%ax, %cx
	addw	sread, %ax
	cmpw	sectors, %ax
	jne	ok3_read
	
	movw	$1, %ax
	subw	head, %ax
	jne	ok4_read
	
	incw	track
ok4_read:
	movw	%ax, head
	xorw	%ax, %ax
ok3_read:
	movw	%ax, sread
	shlw	$9, %cx
	addw	%cx, %bx
	jnc	rp_read
	
	movw	%es, %ax
	addb	$0x10, %ah
	movw	%ax, %es
	xorw	%bx, %bx
	jmp	rp_read
read_track:
	pusha
	pusha	
	movw	$0xe2e, %ax 			# loading... message 2e = .
	movw	$7, %bx
 	int	$0x10
	popa		
	movw	track, %dx
	movw	sread, %cx
	incw	%cx
	movb	%dl, %ch
	movw	head, %dx
	movb	%dl, %dh
	andw	$0x0100, %dx
	movb	$2, %ah
	pushw	%dx				# save for error dump
	pushw	%cx
	pushw	%bx
	pushw	%ax
	int	$0x13
	jc	bad_rt
	
	addw	$8, %sp
	popa
	ret

bad_rt:
	pushw	%ax				# save error code
	call	print_all			# ah = error, al = read
	xorb	%ah, %ah
	xorb	%dl, %dl
	int	$0x13
	addw	$10, %sp
	popa
	jmp read_track

print_all:
	movw	$5, %cx				# error code + 4 registers
	movw	%sp, %bp
print_loop:
	pushw	%cx				# save count left
	call	print_nl			# nl for readability
	cmpb	$5, %cl
	jae	no_reg				# see if register name is needed
	
	movw	$0xe05 + 'A' - 1, %ax
	subb	%cl, %al
	int	$0x10
	movb	$'X', %al
	int	$0x10
	movb	$':', %al
	int	$0x10
no_reg:
	addw	$2, %bp				# next register
	call	print_hex			# print it
	popw	%cx
	loop	print_loop
	ret

print_nl:
	movw	$0xe0d, %ax			# CR
	int	$0x10
	movb	$0xa, %al			# LF
	int 	$0x10
	ret

print_hex:
	movw	$4, %cx				# 4 hex digits
	movw	(%bp), %dx			# load word into dx
print_digit:
	rolw	$4, %dx				# rotate to use low 4 bits
	movw	$0xe0f, %ax			# ah = request
	andb	%dl, %al			# al = mask for nybble
	addb	$0x90, %al			# convert al to ascii hex
	daa					# in only four instructions!
	adc	$0x40, %al
	daa
	int	$0x10
	loop	print_digit
	ret

kill_motor:
	movw	$0x3f2, %dx
	xorb	%al, %al
	outb	%al, %dx
	ret

sectors:	.word 0
disksizes:	.byte 36, 18, 15, 9
msg1:		.byte 13, 10
		.ascii "Loading"

.org 497
setup_sects:	.byte SETUPSECS
root_flags:	.word CONFIG_ROOT_RDONLY
syssize:	.word SYSSIZE
swap_dev:	.word SWAP_DEV
ram_size:	.word RAMDISK
vid_mode:	.word SVGA_MODE
root_dev:	.word ROOT_DEV
boot_flag:	.word 0xAA55