#ifndef __LINUX_SPINLOCK_H
#define __LINUX_SPINLOCK_H

#if (__GNUC__ > 2)
  typedef struct { } spinlock_t;
  #define SPIN_LOCK_UNLOCKED (spinlock_t) { }
#else
  typedef struct { int gcc_is_buggy; } spinlock_t;
  #define SPIN_LOCK_UNLOCKED (spinlock_t) { 0 }
#endif

#endif