// go:build ignore
// +build ignore

// bpf/capture_inode_rename.bpf.c

#include "consts.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

struct rename_path_frag_event {
    u64 event_id;
    u32 pid;
    u32 uid;
    u32 gid;
    char comm[MAX_PROCESS_NAME_LEN];
    u32 old_or_new; // 0 = old_dentry, 1 = new_dentry
    u32 depth;      // 0 = leaf, 1 = parent, 2 = grandparent, ...
    char d_name[MAX_NAME_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} frag_buf SEC(".maps");

/*
 * emit_frag - Emit a fragment of a path to the ring buffer.
 *
 * @d: The dentry to emit.
 * @old_or_new: 0 for old_dentry, 1 for new_dentry.
 * @depth: The depth of the dentry in the path.
 * @event_id: The event ID.
 * @pid: The PID of the process.
 * @uid: The UID of the process.
 * @gid: The GID of the process.
 */
static __always_inline void emit_frag(struct dentry *d, // NOLINT
                                      u32 old_or_new,   // NOLINT
                                      u32 depth,        // NOLINT
                                      u64 event_id,     // NOLINT
                                      u32 pid,          // NOLINT
                                      u32 uid,          // NOLINT
                                      u32 gid) {
    struct rename_path_frag_event *e =
        bpf_ringbuf_reserve(&frag_buf, sizeof(*e), 0);
    if (!e) {
        return;
    }

    e->event_id = event_id;
    e->pid = pid;
    e->uid = uid;
    e->gid = gid;
    e->old_or_new = old_or_new;
    e->depth = depth;

    /* Capture task comm */
    bpf_get_current_comm(e->comm, sizeof(e->comm));

    /* read d_name */
    struct qstr qs = BPF_CORE_READ(d, d_name);
    bpf_probe_read_kernel_str(&e->d_name, sizeof(e->d_name), qs.name);

    /* Submit event */
    bpf_ringbuf_submit(e, 0);
}

SEC("lsm.s/inode_rename")
int BPF_PROG(capture_rename,                                   // NOLINT
             struct inode *old_dir, struct dentry *old_dentry, // NOLINT
             struct inode *new_dir, struct dentry *new_dentry) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u64 event_id = bpf_ktime_get_ns();
    u64 uid_gid = bpf_get_current_uid_gid();
    u32 uid = uid_gid >> 32;
    u32 gid = uid_gid & 0xFFFFFFFF;

    // old path fragments
    struct dentry *d = old_dentry;
    for (int i = 0; i < MAX_DENTRY_TRAVERSAL_DEPTH; i++) {
        if (!d) {
            break;
        }
        if (d == BPF_CORE_READ(d, d_parent)) {
            break;
        }
        emit_frag(d, 0, i, event_id, pid, uid, gid);
        d = BPF_CORE_READ(d, d_parent);
    }

    // new path fragments
    d = new_dentry;
    for (int i = 0; i < MAX_DENTRY_TRAVERSAL_DEPTH; i++) {
        if (!d) {
            break;
        }
        if (d == BPF_CORE_READ(d, d_parent)) {
            break;
        }
        emit_frag(d, 1, i, event_id, pid, uid, gid);
        d = BPF_CORE_READ(d, d_parent);
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
