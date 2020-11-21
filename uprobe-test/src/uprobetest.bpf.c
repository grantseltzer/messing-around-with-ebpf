#include "vmlinux.h"
#include <bpf/bpf_helpers.h>  
#include "uprobetest.h"     

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} ringbuf SEC(".maps");

long ringbuffer_flags = 0;

SEC("uprobe/tester/main.test_single_uint8")
int uprobe__tester_test_single_uint8(struct pt_regs *ctx)
{
	u64 id = bpf_get_current_pid_tgid();
	u32 tgid = id >> 32;
	struct process_info *process;

    // Reserve space on the ringbuffer for the sample
	process = bpf_ringbuf_reserve(&ringbuf, sizeof(struct process_info), ringbuffer_flags);
	if (!process) {
		return 0;
    }
	
	void* stackAddr = (void*)ctx->sp;
	char argument1;
	bpf_probe_read(&argument1, sizeof(argument1), stackAddr+8);

	process->pid = tgid;
	process->arg = argument1;
	bpf_ringbuf_submit(process, ringbuffer_flags);

    return 0;
}
