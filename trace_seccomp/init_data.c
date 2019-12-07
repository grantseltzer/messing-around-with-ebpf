#include <linux/sched.h>
#include <linux/types.h>
#include <linux/filter.h>

// Maps
BPF_PERF_OUTPUT(output);
BPF_HASH(seccompf, u64, struct sock_fprog); 

// proc_context_t holds data about the calling process
typedef struct proc_context {
    u32                 pid;
    u32                 tgid;
    u32                 ppid;
    char                comm[TASK_COMM_LEN];
} proc_context_t;

// init_bpf_seccomp_data reads the bpf program struct from the seccomp(2) calling procces
int init_bpf_seccomp_data(struct pt_regs *ctx) {

    proc_context_t proc = {};
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();

    proc.pid = task->pid;
    proc.tgid = task->tgid;
    proc.ppid = task->real_parent->pid;
    bpf_get_current_comm(&proc.comm, sizeof(proc.comm));

    unsigned int        operation;
    unsigned int        flags;
    void                *args;

    // Read in seccomp(2) arguments manually from registers (can't use bcc bindings because of issue #___)
    struct pt_regs * ctx2 = (struct pt_regs *)ctx->di;
    bpf_probe_read(&operation, sizeof(operation), &ctx2->di);
    bpf_probe_read(&flags, sizeof(flags), &ctx2->si);
    bpf_probe_read(&args, sizeof(struct sock_fprog*), &ctx2->dx);

    // If call is installing filters
    if (operation == 1 && args != NULL) {

        // cast args from void* to a pointer to a sock_fprog struct
        // and then read the full structure into memory so BPF knows about it
        struct sock_fprog *bpfprog_ptr = (struct sock_fprog*)args;
        struct sock_fprog bpfprog = {}; 
        bpf_probe_read(&bpfprog, sizeof(bpfprog), bpfprog_ptr);
        bpf_probe_read(&bpfprog.len, sizeof(bpfprog.len), &bpfprog.len);
        bpf_probe_read(&bpfprog.filter, sizeof(bpfprog.filter), &bpfprog.filter);
       
        bpf_trace_printk("Number of filters: %d\n", bpfprog.len);
        bpf_trace_printk("%x\n", bpfprog.filter);

        u64 zero = 0;
        seccompf.update(&zero, &bpfprog);
        output.perf_submit(ctx, &proc, sizeof(proc));
    }

    return 0;
}

int interpret_bpf_progs_as_syscalls(struct pt_regs *ctx) {
    u64 zero = 0;
    struct sock_fprog *bpfprog_ptr  = (struct sock_fprog*)seccompf.lookup(&zero);
    if (bpfprog_ptr == NULL) {
        return -1;
    }

    struct sock_filter *curAddr = bpfprog_ptr->filter;
    int sizeOfSockFprog = sizeof(*curAddr);
    int i;
    u16 code;

    for (i = 0; i < 100; i++) {
        bpf_probe_read(&code, sizeof(code), &curAddr->code);
        bpf_trace_printk("code of instruction: %d\n", code);
        curAddr = curAddr + sizeOfSockFprog;
    }

    // loop through, incrementing a memory address where to find 'code' in sock_filter and print those out
    return 0;
}
