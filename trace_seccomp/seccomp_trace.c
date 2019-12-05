 #include <linux/sched.h>
 #include <linux/types.h>
 #include <linux/filter.h>


// Context holds data about the calling process
typedef struct context {
    u32                 pid;
    u32                 tgid;
    u32                 ppid;
    char                comm[TASK_COMM_LEN];
    unsigned int        operation;
    unsigned int        flags;
    void                *args;  // need to be a pointer to the seccomp structure
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

    struct pt_regs * ctx2 = (struct pt_regs *)ctx->di;
    bpf_probe_read(&context.operation, sizeof(context.operation), &ctx2->di);
    bpf_probe_read(&context.flags, sizeof(context.flags), &ctx2->si);
    bpf_probe_read(&context.args, sizeof(struct sock_fprog*), &ctx2->dx);

    if (context.flags == 1 && context.operation == 1 && context.args != NULL) {
        // args is a pointer to a sock_fprog struct
        

        struct sock_fprog *bpfprogptr = (struct sock_fprog*)context.args;
        struct sock_fprog bpfprog = {}; 
        bpf_probe_read(&bpfprog, sizeof(bpfprog), bpfprogptr);
        bpf_probe_read(&bpfprog.len, sizeof(bpfprog.len), &bpfprog.len);
        bpf_probe_read(&bpfprog.filter, sizeof(bpfprog.filter), &bpfprog.filter);

        bpf_trace_printk("%x\n", bpfprog);
        bpf_trace_printk("%d\n", bpfprog.len);
        bpf_trace_printk("%x\n", bpfprog.filter);


        // seccomps.perf_submit(ctx, &context, sizeof(context));
    }

    return 0;
}

