package main

import (
	"io/ioutil"
	"log"
	"time"

	"github.com/iovisor/gobpf/bcc"
)

func main() {
	content, err := ioutil.ReadFile("./program.c")
	if err != nil {
		log.Fatal(err)
	}

	mod := bcc.NewModule(string(content), nil)

	sfd, err := mod.LoadKprobe("tail_call")
	if err != nil {
		log.Fatal(err)
	}

	progTable := bcc.NewTable(mod.TableId("prog_array"), mod)
	progTable.Set([]byte{2}, []byte{byte(sfd)})

	dfd, err := mod.LoadKprobe("do_tail_call")
	if err != nil {
		log.Fatal(err)
	}

	err = mod.AttachKprobe("__x64_sys_getcwd", dfd, 2)
	if err != nil {
		log.Fatal(err)
	}

	time.Sleep(time.Minute)
}
