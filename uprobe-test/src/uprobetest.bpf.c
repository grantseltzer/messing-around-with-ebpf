#include "vmlinux.h"
#include <bpf/bpf_helpers.h>  
#include "uprobetest.h"     
#include <bpf/bpf_core_read.h>     /* for BPF CO-RE helpers */

char LICENSE[] SEC("license") = "GPL";

const volatile pid_t target_tgid = 0;

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} ringbuf SEC(".maps");

long ringbuffer_flags = 0;

static __always_inline
bool trace_allowed(u32 tgid)
{
	if (target_tgid && target_tgid != tgid) {
		return false;
    }
	return true;
}

SEC("uprobe/tester/main.test_single_uint8")
int uprobe__tester_test_single_uint8()
{
	struct task_struct* taskptr = (struct task_struct*)bpf_get_current_task();
	struct thread_struct thread = BPF_CORE_READ(taskptr, thread);
	
	void* stack = (void*)thread.sp;
	
	void* firstArgAddr = (void*)((char*)stack + 8);
	char firstArg;
	bpf_probe_read_kernel(&firstArg, sizeof(firstArg), firstArgAddr);

	u64 id = bpf_get_current_pid_tgid();
	u32 tgid = id >> 32;
	struct process_info *process;

	// Reserve space on the ringbuffer for the sample
	process = bpf_ringbuf_reserve(&ringbuf, sizeof(*process), ringbuffer_flags);
	if (!process) {
		return 0;
	}

	process->pid = (int)tgid;  
	process->uint8 = firstArg;

	bpf_ringbuf_submit(process, ringbuffer_flags);

    return 0;
}
