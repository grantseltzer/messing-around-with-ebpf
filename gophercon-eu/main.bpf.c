//+build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>  

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

long ringbuffer_flags = 0;

struct event {
	u64 pid;
};

SEC("kprobe/sys_write")
int kprobe__sys_write(struct pt_regs *ctx)
{
    struct event *record;

    // Reserve space on the ringbuffer for the sample
    record = bpf_ringbuf_reserve(&events, sizeof(struct event), ringbuffer_flags);
    if (!record) {
        return 0;
    }

    u64 id = bpf_get_current_pid_tgid();
    (*record).pid = id; 

    bpf_ringbuf_submit(record, ringbuffer_flags);

    return 0;
}
