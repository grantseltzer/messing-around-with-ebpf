 #include <linux/cred.h>
 #include <linux/sched.h>


// Types
typedef struct context {
    unsigned int		uid;
    unsigned int		gid;
    u32     pid;
    u32     tgid;
    u32     ppid;
    //TODO: add executable name (and parents)
    //TODO: add rest of 
} context_t;

// Maps
BPF_HASH(creds, u32, context_t);

// Helper functions
static __always_inline int init_context(context_t *context) {
    
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();

    context->pid = task->pid;
    context->tgid = task->tgid;
    context->ppid = task->real_parent->pid;

    return 0
}

// Kprobe functions
int print_commit_creds(struct pt_regs *ctx, struct cred *new) {
    
    context_t context = {};
    init_context(&context);
    context->uid = cred->uid->val;
    context->gid = cred->gid->val;

    // TODO: how to put in map?

    return 0;
}