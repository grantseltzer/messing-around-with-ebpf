package main

import (
	"log"
	"os"
	"os/signal"
	"strings"

	"github.com/iovisor/gobpf/bcc"
)

//TODO:
// Return value of mmap is pointer to the region

const eBPF_Program = `
#include <uapi/linux/ptrace.h>

typedef struct mmap_args {
	void* addr;
	size_t length;
	int prot;
	int flags;
	int fd;
	off_t offset;
} args_t;


int trace_mmap(struct pt_regs *ctx) {

	u32 pid = (u32)bpf_get_current_pid_tgid();
	args_t args = {};

	// In kernel 4.17+ the actual context is stored by reference in di register
	struct pt_regs * actualCtx = (struct pt_regs *)ctx->di;
	bpf_probe_read(&args.addr, sizeof(args.addr), &actualCtx->di);
	bpf_probe_read(&args.length, sizeof(args.length), &actualCtx->si);
	bpf_probe_read(&args.prot, sizeof(args.prot), &actualCtx->dx);
	bpf_probe_read(&args.flags, sizeof(args.flags), &actualCtx->r10);
	bpf_probe_read(&args.fd, sizeof(args.fd), &actualCtx->r8);
	bpf_probe_read(&args.offset, sizeof(args.offset), &actualCtx->r9);

	bpf_trace_printk("(%d) %d\n", pid, args.fd);
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

func printMemoryProtectionFlag(flag uint32) string {
	var protectionFlags []string
	if flag == 0x0 {
		protectionFlags = append(protectionFlags, "PROT_NONE")
	}
	if flag&0x01 == 0x01 {
		protectionFlags = append(protectionFlags, "PROT_READ")
	}
	if flag&0x02 == 0x02 {
		protectionFlags = append(protectionFlags, "PROT_WRITE")
	}
	if flag&0x04 == 0x04 {
		protectionFlags = append(protectionFlags, "PROT_EXEC")
	}

	return strings.Join(protectionFlags, "|")
}
