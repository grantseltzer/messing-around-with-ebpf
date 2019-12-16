#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>

int print_symbol_name(struct pt_regs *ctx) {
	bpf_trace_printk("Hello hi\n");
    return 0;
}
