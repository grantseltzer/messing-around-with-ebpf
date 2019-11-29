 #include <linux/cred.h>
 #include <linux/sched.h>

// Types
typedef struct context {
    unsigned int		uid;
    unsigned int		gid;
    unsigned int        suid;
    unsigned int        sgid;
    unsigned int        euid;
    unsigned int        egid;
    u32                 pid;
    u32                 tgid;
    u32                 ppid;
    char                comm[TASK_COMM_LEN];
} context_t;

// Maps
BPF_PERF_OUTPUT(creds);

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
int print_commit_creds(struct pt_regs *ctx, struct cred *new) {
    
    context_t context = {};
    init_context(&context);
    context.uid = new->uid.val;
    context.gid = new->gid.val;

    creds.perf_submit(ctx, &context, sizeof(context));
    return 0;
}