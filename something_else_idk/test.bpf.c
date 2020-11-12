#include "vmlinux.h"
#include <bpf/bpf_helpers.h>       /* most used helpers: SEC, __always_inline, etc */

#define TASK_COMM_LEN 16
#define NAME_MAX 255

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

struct event {
	__u64 ts;
	pid_t pid;
	uid_t uid;
	int ret;
	int flags;
	char comm[TASK_COMM_LEN];
	char fname[NAME_MAX];
};

SEC("tracepoint/syscalls/sys_enter_openat")
int tracepoint__syscalls__sys_enter_openat(struct trace_event_raw_sys_enter* ctx) {
	
	struct event event = {};
	event.pid = bpf_get_current_pid_tgid() >> 32;

	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
	return 0;
}
