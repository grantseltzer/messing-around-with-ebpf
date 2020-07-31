package main

import (
	"log"
	"os"
	"os/signal"

	"github.com/iovisor/gobpf/bcc"
)

const eBPF_Program = `
#include <uapi/linux/ptrace.h>

BPF_PERF_OUTPUT(events);

typedef struct args {
    unsigned long args[6]; //TODO: put actual fields for mmap args instead of all unsigned longs
} args_t;


int trace_mmap(struct pt_regs *ctx) {

	u32 pid = (u32)bpf_get_current_pid_tgid();
	args_t args = {};

	// In kernel 4.17+ the actual context is stored by reference in di register
	struct pt_regs * actualCtx = (struct pt_regs *)ctx->di;
	bpf_probe_read(&args.args[0], sizeof(args.args[0]), &actualCtx->di);
	bpf_probe_read(&args.args[1], sizeof(args.args[1]), &actualCtx->si);
	bpf_probe_read(&args.args[2], sizeof(args.args[2]), &actualCtx->dx);
	bpf_probe_read(&args.args[3], sizeof(args.args[3]), &actualCtx->r10);
	bpf_probe_read(&args.args[4], sizeof(args.args[4]), &actualCtx->r8);
	bpf_probe_read(&args.args[5], sizeof(args.args[5]), &actualCtx->r9);

	unsigned long fd;
	bpf_probe_read(&fd, sizeof(fd), &args.args[4]);
	
	bpf_trace_printk("(%d) %d\n", pid, fd);
	return 0;
}
`

func main() {

	bpfModule := bcc.NewModule(eBPF_Program, []string{})

	funcFD, err := bpfModule.LoadKprobe("trace_mmap")
	if err != nil {
		log.Fatal(err)
	}

	syscallPrefix := bcc.GetSyscallPrefix()

	err = bpfModule.AttachKprobe(syscallPrefix+"mmap", funcFD, -1)
	if err != nil {
		log.Fatal(err)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	<-c
}
