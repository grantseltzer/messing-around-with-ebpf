#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/bpf.h>
#include <linux/kernel.h>
#include <uapi/linux/bpf.h>

BPF_PROG_ARRAY(prog_array, 10);

int tail_call(void *ctx) {
    bpf_trace_printk("tail-call\n");
    return 0;
}

int do_tail_call(void *ctx) {
    bpf_trace_printk("Original program\n");
    prog_array.call(ctx, 1);
    return 0;
}