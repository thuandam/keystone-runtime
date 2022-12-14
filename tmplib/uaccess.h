#ifndef _UACCESS_H_
#define _UACCESS_H_
#include <asm/asm.h>
#include <asm/csr.h>

/* This is a limited set of the features from linux uaccess, only the
   ones we need for now */

extern unsigned long __copy_user(void  *to,
				 const void  *from, unsigned long n);

static inline unsigned long
copy_to_user(void *to, const void *from, unsigned long n)
{
	return __copy_user(to, from, n);
}

static inline unsigned long
copy_from_user(void *to, const void *from, unsigned long n)
{
	return __copy_user(to, from, n);
}

/* Dangerous feature needed for a few things (ex: strlen on usermemory) */
#define ALLOW_USER_ACCESS(x) { \
  unsigned long tmp_storage; \
  asm volatile ("li %0, %1" : "=r" (tmp_storage) : "i" (SR_SUM));       \
  asm volatile ("csrs sstatus, %0" : "=r" (tmp_storage)); \
  (x);                                                    \
  asm volatile ("csrc sstatus, %0" : "=r" (tmp_storage)); \
  }
#endif /* _UACCESS_H_ */
