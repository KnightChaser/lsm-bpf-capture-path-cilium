// capture_path.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// Simple event struct placeholder (empty for now)
struct event {
    u32 pid;
};

// Ring buffer map for events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("lsm.s/file_open")
int capture_open(struct file *file) {
    // Reserve an event and submit (no data for now)
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }
    e->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
