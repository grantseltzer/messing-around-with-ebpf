package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
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

BPF_PERF_OUTPUT(events);

typedef struct mmap_args {
	u32 pid;
	int fd;
	void* addr;
	size_t length;
	int prot;
	int flags;
	off_t offset;
} args_t;


int trace_mmap(struct pt_regs *ctx) {

	args_t args = {};
	args.pid = (u32)bpf_get_current_pid_tgid();
	
	// In kernel 4.17+ the actual context is stored by reference in di register
	struct pt_regs * actualCtx = (struct pt_regs *)ctx->di;
	bpf_probe_read(&args.addr, sizeof(args.addr), &actualCtx->di);
	bpf_probe_read(&args.length, sizeof(args.length), &actualCtx->si);
	bpf_probe_read(&args.prot, sizeof(args.prot), &actualCtx->dx);
	bpf_probe_read(&args.flags, sizeof(args.flags), &actualCtx->r10);
	bpf_probe_read(&args.fd, sizeof(args.fd), &actualCtx->r8);
	bpf_probe_read(&args.offset, sizeof(args.offset), &actualCtx->r9);

	// args_t TEST_ARGS = {};
	// TEST_ARGS.pid = 0xFFFFFFFF;
	// TEST_ARGS.fd = 0xFFFFFFFF;;
	// TEST_ARGS.addr = (void*)0xFFFFFFFFFFFFFFFF;
	// TEST_ARGS.length = 0xFFFFFFFFFFFFFFFF;
	// TEST_ARGS.prot = 0xFFFFFFFF;
	// TEST_ARGS.flags = 0xFFFFFFFF;
	// TEST_ARGS.offset = 0xFFFFFFFFFFFFFFFF;

	// bpf_trace_printk("1: %d\n", sizeof(TEST_ARGS));
	// bpf_trace_printk("2: %d\n\n\n", sizeof(TEST_ARGS.offset));

	events.perf_submit(ctx, &args, sizeof(args));

	return 0;
}
`

type mmap_args struct {
	processID uint32
	fd        uint32
	addr      uint64
	length    uint64
	prot      uint32
	flags     uint32
	offset    uint64
}

func (m *mmap_args) unmarshalBinaryData(data []byte) error {

	if len(data) != 44 {
		return errors.New("incorrect number of bytes in binary data for decoding")
	}

	m.processID = binary.LittleEndian.Uint32(data[0:4])
	m.fd = binary.LittleEndian.Uint32(data[4:8])
	m.addr = binary.LittleEndian.Uint64(data[8:16])
	m.length = binary.LittleEndian.Uint64(data[16:24])
	m.prot = binary.LittleEndian.Uint32(data[24:28])
	m.flags = binary.LittleEndian.Uint32(data[28:32])
	m.offset = binary.LittleEndian.Uint64(data[32:40])
	return nil
}

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

	table := bcc.NewTable(bpfModule.TableId("events"), bpfModule)
	channel := make(chan []byte)
	perfMap, err := bcc.InitPerfMap(table, channel, nil)
	if err != nil {
		log.Fatal(err)
	}

	go func() {
		for {
			value := <-channel
			mmapInfo := mmap_args{}
			err = mmapInfo.unmarshalBinaryData(value)
			if err != nil {
				log.Fatal(err)
			}
			printMMapArgs(&mmapInfo)
		}
	}()

	perfMap.Start()
	defer perfMap.Stop()

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)

	<-c
}

func printMMapArgs(m *mmap_args) error {

	x := struct {
		PID, Addr, Length, Protection, Flags, FileDescriptor, Offset string
	}{
		PID:            fmt.Sprint(m.processID),
		Addr:           sprintAddr(m.addr),
		Length:         fmt.Sprint(m.length),
		Protection:     sprintMemoryProtectionFlag(m.prot),
		Flags:          sprintMemoryVisibilityFlag(m.flags),
		FileDescriptor: fmt.Sprint(m.fd),
		Offset:         fmt.Sprint(m.offset),
	}

	jsonBytes, err := json.Marshal(x)
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", jsonBytes)
	return nil
}

func sprintAddr(addr uint64) string {
	if addr == 0 {
		return "NULL"
	}

	return fmt.Sprintf("%x", addr)
}

func sprintMemoryProtectionFlag(prot uint32) string {
	var protectionFlags []string
	if prot == 0x0 {
		protectionFlags = append(protectionFlags, "PROT_NONE")
	}
	if prot&0x01 == 0x01 {
		protectionFlags = append(protectionFlags, "PROT_READ")
	}
	if prot&0x02 == 0x02 {
		protectionFlags = append(protectionFlags, "PROT_WRITE")
	}
	if prot&0x04 == 0x04 {
		protectionFlags = append(protectionFlags, "PROT_EXEC")
	}

	return strings.Join(protectionFlags, "|")
}

func sprintMemoryVisibilityFlag(vis uint32) string {

	var visibilityFlags []string

	if vis&0x01 == 0x01 {
		visibilityFlags = []string{"MAP_SHARED"}
	}
	if vis&0x02 == 0x02 {
		visibilityFlags = []string{"MAP_PRIVATE"}
	}
	if vis&0x02 == 0x03 {
		visibilityFlags = []string{"MAP_SHARED_VALIDATE"}
	}
	if vis&0x0f == 0x10 {
		visibilityFlags = []string{"MAP_ANONYMOUS"}
	}
	if vis&0x0f == 0x100 {
		visibilityFlags = []string{"MAP_FIXED"}
	}
	if vis&0x0f == 0x40 {
		visibilityFlags = []string{"MAP_32BIT"}
	}
	if vis&0x0f == 0x200000 {
		visibilityFlags = []string{"MAP_FIXED_NOREPLACE"}
	}
	if vis&0x0f == 0x01000 {
		visibilityFlags = []string{"MAP_GROWSDOWN"}
	}
	if vis&0x0f == 0x100000 {
		visibilityFlags = []string{"MAP_HUGETLB"}
	}
	if vis&0x0f == 0x08000 {
		visibilityFlags = []string{"MAP_LOCKED"}
	}
	if vis&0x0f == 0x40000 {
		visibilityFlags = []string{"MAP_NONBLOCK"}
	}
	if vis&0x0f == 0x20000 {
		visibilityFlags = []string{"MAP_POPULATE"}
	}
	if vis&0x0f == 0x10000 {
		visibilityFlags = []string{"MAP_NORESERVE"}
	}
	if vis&0x0f == 0x80000 {
		visibilityFlags = []string{"MAP_STACK"}
	}
	if vis&0x0f == 0x4000000 {
		visibilityFlags = []string{"MAP_UNINITIALIZED"}
	}

	return strings.Join(visibilityFlags, "|")
}
