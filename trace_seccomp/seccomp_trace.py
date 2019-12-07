#!/usr/bin/python3

import ctypes
import json
from bcc import BPF

class SeccompTracer:

    def __init__(self):
        seccomp_interpret = "./init_data.c"

        seccomp_interpret_code = self.read_bpf_program(seccomp_interpret)

        self.b = BPF(text=seccomp_interpret_code)
       
        seccompFnName = self.b.get_syscall_fnname("seccomp")
        self.b.attach_kprobe(event=seccompFnName, fn_name="interpret_bpf_progs_as_syscalls")
        self.b.attach_kprobe(event=seccompFnName, fn_name="init_bpf_seccomp_data")            # init is attached last so that it's executed first (go figure...)

        self.b["output"].open_perf_buffer(self.print_event)

    def print_event(self, cpu, data, size):
        event = self.b["output"].event(data)

        eventDict = {
            "command":           event.comm.decode('utf-8'),
            "process-id":        event.pid,
            "parent-process-id": event.ppid,
            "thread-group-id":   event.tgid
        }

        eventJSON = json.dumps(eventDict)
        print(eventJSON)

    def read_bpf_program(self, prog):
        with open(prog, "r") as f:
            bpf = f.read()
        return bpf

def main():
    c = SeccompTracer()
    while True:
        try:
            c.b.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()

if __name__ == "__main__":
    main()
