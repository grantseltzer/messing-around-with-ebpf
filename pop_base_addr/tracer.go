package main

import (
	"log"
	"os"
	"os/signal"

	"github.com/iovisor/gobpf/bcc"
)

const eBPF_Program = `
#include <uapi/linux/ptrace.h>


int function(struct pt_regs *ctx) {
 

	void* stackAddr = (void*)ctx->sp;

	unsigned long returnAddress;

	void* returnAddressPtr = (void*)&returnAddress;

	bpf_probe_read(returnAddressPtr, sizeof(returnAddress), stackAddr);

	returnAddress -= 8;

	bpf_probe_write_user(stackAddr, returnAddressPtr, sizeof(returnAddress));

	return 0;
}

`

func main() {

	bpfModule := bcc.NewModule(eBPF_Program, []string{})

	funcFD, err := bpfModule.LoadUprobe("function")
	if err != nil {
		log.Fatal(err)
	}

	err = bpfModule.AttachUprobe(os.Args[1], "main.function", funcFD, -1)
	if err != nil {
		log.Fatal(err)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	<-c
}
