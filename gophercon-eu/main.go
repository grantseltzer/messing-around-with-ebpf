package main

import "C"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"

	bpf "github.com/aquasecurity/libbpfgo"
)

type Event struct {
	PID  uint32
	PPID uint32
	COMM [16]byte
}

func main() {

	bpfModule, err := bpf.NewModuleFromFile("main.bpf.o")
	if err != nil {
		os.Exit(-1)
	}
	defer bpfModule.Close()

	bpfModule.BPFLoadObject()
	prog, err := bpfModule.GetProgram("kprobe__sys_execve")
	if err != nil {
		os.Exit(-1)
	}

	_, err = prog.AttachKprobe("__x64_sys_execve")
	if err != nil {
		os.Exit(-1)
	}

	eventsChannel := make(chan []byte)
	rb, err := bpfModule.InitRingBuf("events", eventsChannel)
	if err != nil {
		os.Exit(-1)
	}

	rb.Start()

	for {
		b := <-eventsChannel
		buffer := bytes.NewBuffer(b)
		ev := Event{}
		binary.Read(buffer, binary.LittleEndian, &ev)
		fmt.Printf("PID: %d PPID: %d COMM: %s\n", ev.PID, ev.PPID, ev.COMM[:])
	}

	rb.Stop()
	rb.Close()
}
