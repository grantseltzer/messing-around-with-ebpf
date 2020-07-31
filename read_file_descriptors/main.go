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

int function(struct pt_regs *ctx) {
 
	const char* pathAddr;
	char path[100];
	bpf_probe_read(&pathAddr, sizeof(pathAddr), (void*)PT_REGS_PARM2(ctx));
	bpf_probe_read_user_str(&path, sizeof(path), pathAddr);
	bpf_trace_printk("%s\n", path);

	return 0;
}
`

func main() {

	bpfModule := bcc.NewModule(eBPF_Program, []string{})

	funcFD, err := bpfModule.LoadKprobe("function")
	if err != nil {
		log.Fatal(err)
	}

	possibleFuncs := []string{
		"do_sys_openat2",
		"__ia32_sys_openat2",
		"__x64_sys_openat2",
		"__x64_sys_openat",
		"__ia32_compat_sys_openat",
		"__ia32_sys_openat",
		"path_openat",
		"io_openat2",
	}

	for _, f := range possibleFuncs {
		err = bpfModule.AttachKprobe(f, funcFD, -1)
		if err != nil {
			log.Fatal(err)
		}
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	<-c
}

/*



	bpf_probe_read_user(&buf, sizeof(buf), (void *)PT_REGS_PARM1(ctx));
	bpf_trace_printk("%s %d", buf, PT_REGS_PARM2(ctx));



  int key;
  bpf_probe_read_user(&key, sizeof(key), (void*)pid_data->tls_key_addr);






struct event {
    char filename[16];
    int dfd;
    int flags;
    int mode;
};
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    int zero = 0;
    struct event event = {};
    bpf_probe_read_user_str(event.filename, sizeof(event.filename), args->filename);

*/
