#!/usr/bin/python3

import ctypes
import json
from bcc import BPF

class SeccompTracer:

    def __init__(self):
        BPF_PROGRAM = "./init_data.c"
        bpf_text = self.read_bpf_program(BPF_PROGRAM)

        self.b = BPF(text=bpf_text)
       
        seccompFnName = self.b.get_syscall_fnname("seccomp")
        self.b.attach_kprobe(event=seccompFnName, fn_name="trace_and_print_seccomp_calls")
        self.b["seccomps"].open_perf_buffer(self.print_event)

    def print_event(self, cpu, data, size):
        event = self.b["seccomps"].event(data)

        eventDict = {
            "command":           event.comm.decode('utf-8'),
            "process-id":        event.pid,
            "parent-process-id": event.ppid,
            "operation":         event.operation,
            "flags":             event.flags,
            "args":              event.args
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
