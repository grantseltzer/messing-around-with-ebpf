package main

import (
	"log"
	"os"
	"os/signal"

	"github.com/iovisor/gobpf/bcc"
)

const eBPF_Program = `
#include <uapi/linux/ptrace.h>

struct event_t {
	int pid;
};

BPF_HASH(addrs, struct event_t);

static inline __attribute__((always_inline)) void get_key(struct event_t* key) {
    key->pid = bpf_get_current_pid_tgid();
}

int function(struct pt_regs *ctx) {
    struct event_t key = {};
	get_key(&key);
	
	
	u64* addrVal = addrs.lookup(&key);

	if (!addrVal) {
		return -1;
	}

	u64 addrValue = *addrVal;

	void* addrValPtr = (void*)&addrValue;

	void* stackAddr = (void*)ctx->sp;
	bpf_probe_write_user(stackAddr, addrValPtr, sizeof(addrValue));

	return 0;
}

int main_function(struct pt_regs *ctx) {

    struct event_t key = {};
	get_key(&key);
	
	u64 stackAddr = (u64)ctx->sp;

	addrs.insert(&key, &stackAddr);



	return 0;
}
`

func main() {

	bpfModule := bcc.NewModule(eBPF_Program, []string{})

	mainFD, err := bpfModule.LoadUprobe("main_function")
	if err != nil {
		log.Fatal(err)
	}

	funcFD, err := bpfModule.LoadUprobe("function")
	if err != nil {
		log.Fatal(err)
	}

	err = bpfModule.AttachUprobe(os.Args[1], "main.main", mainFD, -1)
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
