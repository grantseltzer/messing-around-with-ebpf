#include <linux/sched.h>
#include <linux/types.h>
#include <linux/filter.h>
#include <linux/bpf_common.h>
#include <linux/kernel.h>

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
       
        bpf_trace_printk("Number of instructions: %d\n", bpfprog.len);

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
    u32 k;

    u16 bpf_statement_code = (BPF_LD | BPF_W | BPF_ABS);
    u16 bpf_jump_code = (BPF_JMP | BPF_JEQ | BPF_K); //XXX: May also be other jumps (i.e. JNE) Extract the BPF_JUMP
    struct seccomp_data *my_data;

    //FIXME: If it's a jump, skip the pointer ahead evaluated amount
   
    for (i = 0; i < 100; i++) {

        bpf_probe_read(&code, sizeof(code), &curAddr->code);

        if (code == bpf_statement_code) {
            bpf_probe_read(&k, sizeof(k), &curAddr->k);
            my_data = (struct seccomp_data*)&k;
            // bpf_probe_read(&data_addr->nr, sizeof(data_addr->nr), &data_addr->nr);
            bpf_trace_printk("k of instruction: %d\n\n", my_data->nr);
        }

        curAddr = curAddr + sizeOfSockFprog;
    }

    return 0;
}


// Instead of tracing syscall, do a kretprobe on seccomp_prepare_filter
// also do a kretprobe on the top level calling function to make sure
// it was installed succesfully