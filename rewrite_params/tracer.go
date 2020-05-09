package main

import (
	"log"
	"os"
	"os/signal"

	"github.com/iovisor/gobpf/bcc"
)

const eBPF_Program = `
#include <uapi/linux/ptrace.h>
#include <linux/string.h>

BPF_PERF_OUTPUT(events);

inline int function_was_called(struct pt_regs *ctx) {

	void* stackAddr = (void*)ctx->sp;
	void* paramAddr = stackAddr+8;
	
	unsigned long data = 69;
	void* dataPtr = (void*)&data;

	bpf_probe_write_user(paramAddr, dataPtr, sizeof(data));
	return 0;
}
`

func main() {

	bpfModule := bcc.NewModule(eBPF_Program, []string{})

	uprobeFd, err := bpfModule.LoadUprobe("function_was_called")
	if err != nil {
		log.Fatal(err)
	}

	err = bpfModule.AttachUprobe(os.Args[1], "main.simpleFunction", uprobeFd, -1)
	if err != nil {
		log.Fatal(err)
	}
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	<-c
}
