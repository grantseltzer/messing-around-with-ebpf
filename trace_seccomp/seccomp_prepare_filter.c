#include <linux/seccomp.h>
#include <linux/types.h>

// Maps
BPF_PERF_OUTPUT(output);

// proc_context_t holds data about the calling process
typedef struct proc_context {
    u32                 pid;
    u32                 tgid;
    u32                 ppid;
    char                comm[TASK_COMM_LEN];
} proc_context_t;

// init_bpf_seccomp_data reads the bpf program struct from the seccomp_prepare_filter calling procces
int init_bpf_seccomp_data(struct pt_regs *ctx) {

    proc_context_t proc = {};
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();

    proc.pid = task->pid;
    proc.tgid = task->tgid;
    proc.ppid = task->real_parent->pid;
    bpf_get_current_comm(&proc.comm, sizeof(proc.comm));

    output.perf_submit(ctx, &proc, sizeof(proc));
    
    return 0;
}

int kretprobe__seccomp_prepare_filter(struct pt_regs *ctx) {
    //FIXME: Going to have to find out how to get the syscall numbers
    // out of seccomp_filter. seccomp_data's are populated by a triggered
    // event (i.e. when seccomp program is run, what syscall is being used)

    // Go down rabbit hole of libseccomp??
    
}


// Instead of tracing syscall, do a kretprobe on seccomp_prepare_filter
// also do a kretprobe on the top level calling function to make sure
// it was installed succesfully