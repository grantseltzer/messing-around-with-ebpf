 #include <linux/sched.h>
 #include <linux/types.h>
 #include <linux/filter.h>

// Maps
BPF_PERF_OUTPUT(seccomps);
BPF_HASH(pids, u64, u64); // 0 = pid
BPF_HASH(seccompf, u64, struct sock_fprog); 


// function that's actually called on process calling seccomp(2)
int trace_and_print_seccomp_calls(struct pt_regs *ctx) {
    
	u64 pid = bpf_get_current_pid_tgid();
    u64 z = 1;
    pids.update(&z, &pid);

    unsigned int        operation;
    unsigned int        flags;
    void                *args;

    // Read in seccomp(2) arguments manually from registers (can't use bcc bindings because of bug)
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
       
        bpf_trace_printk("%d\n", bpfprog.len);
        bpf_trace_printk("%x\n", bpfprog.filter);


        //XXX: Need to confirm that the bpfprog struct can be shared the way I want it
        //     (i.e. access it directly from another ebpf program (has sock_fprog imported) without having to re-bpf_probe_read)
        u64 zero = 0;
        seccompf.update(&zero, &bpfprog);

    
        // TODO: read through filters, determine the syscall numbers, put them in the context, then submit the context:
    }

    return 0;
}
