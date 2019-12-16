package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/signal"
	"unsafe"

	bpf "github.com/iovisor/gobpf/bcc"
)

import "C"

const source string = `
#include <uapi/linux/ptrace.h>
#include <bcc/proto.h>

typedef struct {
	u32 pid;
	uid_t uid;
	gid_t gid;
	int ret;
	char filename[256];
} hello_event_t;

BPF_PERF_OUTPUT(hello_events);
BPF_HASH(hellocall, u64, hello_event_t);

int helloworld(struct pt_regs *ctx, int dfd, const char *filename, uid_t uid, gid_t gid, int flag)
{
	u64 pid = bpf_get_current_pid_tgid();
	hello_event_t event = {
		.pid = pid >> 32,
		.uid = uid,
		.gid = gid,
	};
	bpf_probe_read(&event.filename, sizeof(event.filename), (void *)filename);
	hellocall.update(&pid, &event);

	int ret = PT_REGS_RC(ctx);
	event.ret = ret;
	hello_events.perf_submit(ctx, &event, sizeof(event));
	hellocall.delete(&pid);
	bpf_trace_printk("Hello world from BPF!\n");
	return 0;
	}

`

type helloEvent struct {
	Pid         uint32
	Uid         uint32
	Gid         uint32
	ReturnValue int32
	Filename    [256]byte
}

func main() {
	m := bpf.NewModule(source, []string{})
	defer m.Close()

	helloKprobe, err := m.LoadKprobe("helloworld")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load helloworld: %s\n", err)
		os.Exit(1)
	}

	syscallName := bpf.GetSyscallFnName("clone")

	// passing -1 for maxActive signifies to use the default
	// according to the kernel kprobes documentation
	//
	err = m.AttachKprobe(syscallName, helloKprobe, -1)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach helloKprobe: %s\n", err)
		os.Exit(1)
	}

	table := bpf.NewTable(m.TableId("hello_events"), m)

	channel := make(chan []byte)

	helloMap, err := bpf.InitPerfMap(table, channel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init hello map: %s\n", err)
		os.Exit(1)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	go func() {
		var event helloEvent
		for {
			data := <-channel
			err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event)
			if err != nil {
				fmt.Printf("failed to decode received data: %s\n", err)
				continue
			}
			filename := (*C.char)(unsafe.Pointer(&event.Filename))
			fmt.Printf("uid %d gid %d pid %d called hello world from BPF via sys_clone on %s (return value: %d)\n",
				event.Uid, event.Gid, event.Pid, C.GoString(filename), event.ReturnValue)
		}
	}()

	helloMap.Start()
	<-sig
	helloMap.Stop()
}
