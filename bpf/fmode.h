// bpf/fmode.h

#ifndef FMODE_H_
#define FMODE_H_

/*
 * Dependent definitions for fmode_t.
 * Defined in include/linux/fs.h, but not exported to BPF.
 */
#ifdef __CHECKER__
#define __bitwise __attribute__((bitwise))
#define __force __attribute__((force))
#else
#define __bitwise
#define __force
#endif

typedef unsigned int __bitwise fmode_t;

/* file is open for reading */
#define FMODE_READ ((__force fmode_t)(1 << 0))
/* file is open for writing */
#define FMODE_WRITE ((__force fmode_t)(1 << 1))
/* file is seekable */
#define FMODE_LSEEK ((__force fmode_t)(1 << 2))
/* file can be accessed using pread */
#define FMODE_PREAD ((__force fmode_t)(1 << 3))
/* file can be accessed using pwrite */
#define FMODE_PWRITE ((__force fmode_t)(1 << 4))
/* File is opened for execution with sys_execve / sys_uselib */
#define FMODE_EXEC ((__force fmode_t)(1 << 5))
/* File writes are restricted (block device specific) */
#define FMODE_WRITE_RESTRICTED ((__force fmode_t)(1 << 6))
/* File supports atomic writes */
#define FMODE_CAN_ATOMIC_WRITE ((__force fmode_t)(1 << 7))
/* File is opened with O_PATH; almost nothing can be done with it */
#define FMODE_PATH ((__force fmode_t)(1 << 14))

#endif // FMODE_H_
