//+build ignore
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>  
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define TASK_COMM_LEN 16

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

long ringbuffer_flags = 0;

struct event {
	u32 pid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
};

SEC("kprobe/sys_execve")
int kprobe__sys_execve(struct pt_regs *ctx)
{
    struct event *record;

    // Reserve space on the ringbuffer for the sample
    record = bpf_ringbuf_reserve(&events, sizeof(struct event), ringbuffer_flags);
    if (!record) {
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    record->ppid = BPF_CORE_READ(task, pid);
    record->pid = BPF_CORE_READ(task, real_parent, pid);
    bpf_get_current_comm(&record->comm, sizeof(record->comm));

    bpf_ringbuf_submit(record, ringbuffer_flags);

    return 0;
}
