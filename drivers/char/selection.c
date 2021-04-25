#include <linux/module.h>
#include <linux/tty.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/types.h>

#include <asm/uaccess.h>

#include <linux/vt_kern.h>
#include <linux/consolemap.h>
#include <linux/selection.h>
#include <linux/tiocl.h>
#include <linux/console.h>

/* Don't take this from <ctype.h>: 011-015 on the screen aren't spaces */
#define isspace(c)	((c) == ' ')

extern void poke_blanked_console(void);

/* Variables for selection control. */
/* Use a dynamic buffer, instead of static (Dec 1994) */
struct vc_data *sel_cons;		/* must not be disallocated */
static volatile int sel_start = -1; 	/* cleared by clear_selection */
static int sel_end;
static int sel_buffer_lth;
static char *sel_buffer;

/* clear_selection, highlight and highlight_pointer can be called
   from interrupt (via scrollback/front) */

/* set reverse video on characters s-e of console with selection. */
inline static void
highlight(const int s, const int e)
{
	invert_screen(sel_cons, s, e-s+2, 1);
}

/* use complementary color to show the pointer */
inline static void
highlight_pointer(const int where)
{
	complement_pos(sel_cons, where);
}

/* remove the current selection highlight, if any,
   from the console holding the selection. */
void
clear_selection(void) {
	highlight_pointer(-1); /* hide the pointer */
	if (sel_start != -1) {
		highlight(sel_start, sel_end);
		sel_start = -1;
	}
}