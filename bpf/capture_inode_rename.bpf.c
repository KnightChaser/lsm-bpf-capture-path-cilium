// go:build ignore
// +build ignore

// bpf/capture_inode_rename.bpf.c

#include "consts.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct event {
    u32 pid;
    u32 uid;
    u32 gid;
    char comm[MAX_PROCESS_NAME_LEN];
    char old_path[MAX_PATH_LEN];
    char new_path[MAX_PATH_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

/*
 * Gathers the path of a dentry. This is a simplified version that only
 * It gathers only the file name for now.
 * TODO: Implement a full path gathering function. But how...?
 */
static __always_inline int build_path(struct dentry *d, char *buf, int len) {
    if (!d || len < 2) {
        return -1;
    }

    /* Special case for root */
    if (d == BPF_CORE_READ(d, d_parent)) {
        buf[0] = '/';
        buf[1] = '\0';
        return 1;
    }

    /* Just get the immediate filename for simplicity */
    struct qstr d_name = BPF_CORE_READ(d, d_name);
    int name_len = bpf_probe_read_kernel_str(buf, len, d_name.name);

    if (name_len <= 0) {
        return -1;
    }

    /* It doesn't count the null terminator */
    return name_len - 1;
}

SEC("lsm.s/inode_rename")
int BPF_PROG(capture_rename,                                     // NOLINT
             struct inode *old_dir, struct dentry *old_dentry,   // NOLINT
             struct inode *new_dir, struct dentry *new_dentry) { // NOLINT
    struct event *e;
    int ret;

    /* Reserve space in ringbuf */
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    /* Tag PID/UID/GID and process name */
    u64 pid_tgid = bpf_get_current_pid_tgid();
    e->pid = pid_tgid >> 32;
    u64 uid_gid = bpf_get_current_uid_gid();
    e->uid = uid_gid >> 32;
    e->gid = uid_gid & 0xFFFFFFFF;
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    /* Get old path */
    if (build_path(old_dentry, e->old_path, sizeof(e->old_path)) < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    /* Get new path */
    if (build_path(new_dentry, e->new_path, sizeof(e->new_path)) < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    /* Submit event */
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
