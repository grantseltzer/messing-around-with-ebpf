 #include <linux/sched.h>

// Context holds data about the calling process
typedef struct context {
    u32                 pid;
    u32                 tgid;
    u32                 ppid;
    char                comm[TASK_COMM_LEN];
    unsigned int        operation;
    unsigned int        flags;
    // void                *args;  // need to be a pointer to the seccomp structure
} context_t;

// Maps
BPF_PERF_OUTPUT(seccomps);

// Helper functions
static __always_inline int init_context(context_t *context) {
    
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();

    context->pid = task->pid;
    context->tgid = task->tgid;
    context->ppid = task->real_parent->pid;
    bpf_get_current_comm(context->comm, sizeof(context->comm));

    return 0;
}

// Kprobe functions
int trace_and_print_seccomp_calls(struct pt_regs *ctx) {
    
    context_t context = {};
    init_context(&context);

    bpf_probe_read(&context.operation, sizeof(context.operation), (void *)PT_REGS_PARM1(ctx));
    bpf_probe_read(&context.flags, sizeof(context.flags), (void *)PT_REGS_PARM2(ctx));

    seccomps.perf_submit(ctx, &context, sizeof(context));
    return 0;
}

