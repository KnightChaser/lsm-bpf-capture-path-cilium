// go:build ignore
//+build ignore

//  capture_path.bpf.c

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define MAX_PATH_LEN 384
#define MAX_PROCESS_NAME_LEN 32

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

enum {
    FILE_OP_READ = 0,
    FILE_OP_WRITE = 1,
    FILE_OP_OTHER = 2,
};

/* Event struct sent over ringbuf */
struct event {
    u32 pid;
    u32 file_opener_uid;     /* UID of the process opening the file */
    u32 file_opener_gid;     /* GID of the process opening the file */
    u32 file_owner_uid;      /* UID of the file’s owner */
    u32 file_owner_gid;      /* GID of the file’s owner */
    u32 mode;                /* inode mode bits (type + perms) */
    u32 f_mode;              /* file mode bits (type + perms) */
    u32 file_operation_type; /* 0 = read, 1 = write, 2 = other */
    u64 inode;               /* inode number */
    u64 size;                /* file size in bytes */
    char process_name[MAX_PROCESS_NAME_LEN];
    char path[MAX_PATH_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); /* 1 MiB ring buffer */
} events SEC(".maps");

/* Helper to get full path; uses new kfunc on >=6.8 or falls back */
static __always_inline int get_path_full(struct file *f, char *buf, int len) {
#ifdef bpf_path_d_path
    /* kernel >= 6.8 */
    return bpf_path_d_path(&f->f_path, buf, len);
#else
    /* Automatic fallback to the older kernel */
    return bpf_d_path(&f->f_path, buf, len);
#endif
}

/* Sleepable LSM hook on file_open */
SEC("lsm.s/file_open")
int BPF_PROG(capture_open, struct file *file) {
    struct event *e;
    struct inode *inode;
    int ret;

    /* Reserve space in ringbuf */
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    /* Process info */
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(e->process_name, sizeof(e->process_name));

    /* Opener’s credentials */
    {
        u64 uid_gid = bpf_get_current_uid_gid();
        e->file_opener_uid = uid_gid & 0xFFFFFFFF;
        e->file_opener_gid = uid_gid >> 32;
    }

    /* File’s inode metadata */
    inode = BPF_CORE_READ(file, f_inode);
    e->file_owner_uid = BPF_CORE_READ(inode, i_uid.val);
    e->file_owner_gid = BPF_CORE_READ(inode, i_gid.val);
    e->mode = BPF_CORE_READ(inode, i_mode);
    e->inode = BPF_CORE_READ(inode, i_ino);
    e->size = BPF_CORE_READ(inode, i_size);

    /* Classify the operation using f_mode bits */
    e->f_mode = BPF_CORE_READ(file, f_mode);
    if (e->f_mode & FMODE_PATH) {
        /*
         * FMODE_PATH is set when the file is opened with O_PATH.
         * This means that the file is not opened for reading or writing,
         * but only for obtaining a file descriptor.
         * This is not a read or write operation.
         * We can ignore this case.
         */
        e->file_operation_type = FILE_OP_OTHER;
    } else if (e->f_mode & FMODE_WRITE) {
        e->file_operation_type = FILE_OP_WRITE;
    } else if (e->f_mode & FMODE_READ) {
        e->file_operation_type = FILE_OP_READ;
    } else {
        e->file_operation_type = FILE_OP_OTHER;
    }

    /* Fetch full path; if it fails, discard the event */
    ret = get_path_full(file, e->path, sizeof(e->path));
    if (ret < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    /* Submit to userspace */
    bpf_ringbuf_submit(e, 0);

    return 0; /* allow the open() to proceed */
}

char LICENSE[] SEC("license") = "GPL";
