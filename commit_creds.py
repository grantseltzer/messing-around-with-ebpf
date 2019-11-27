#!/usr/bin/python3

import ctypes
import json
from bcc import BPF
from time import sleep

class Dredge:
    
    def __init__(self):
        BPF_PROGRAM = "./commit_creds.c"
        bpf_text = self.read_bpf_program(BPF_PROGRAM)

        self.b = BPF(text=bpf_text)
        self.b.attach_kprobe(event="commit_creds", fn_name="print_commit_creds")
        self.b["creds"].open_perf_buffer(self.print_event)

    def print_event(self, cpu, data, size):
            event = self.b["creds"].event(data)

            eventDict = {
                "command":           event.comm.decode('utf-8'),
                "process-id":        event.pid,
                "parent-process-id": event.ppid,
                "real-uid":          event.uid,
                "real-gid":          event.gid,
                "saved-uid":         event.suid,
                "saved-gid":         event.sgid,
                "effective-uid":     event.euid,
                "effective-gid":     event.egid
            }
            
            eventJSON = json.dumps(eventDict)
            print(eventJSON)

    def read_bpf_program(self, prog):
        with open(prog, "r") as f:
            bpf = f.read()
        return bpf

def main():
    dredge = Dredge()
    while True:
        try:
            dredge.b.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()

if __name__ == "__main__":
    main()
