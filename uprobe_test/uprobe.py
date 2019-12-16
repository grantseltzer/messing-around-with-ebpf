#!/usr/bin/python3

import ctypes
import json
import sys
import time
from bcc import BPF

class UprobeTracer:

    def __init__(self):
        uprobe_file_name = "./uprobe.c"

        uprobe_code = self.read_bpf_program(uprobe_file_name)

        self.b = BPF(text=uprobe_code)
        self.b.attach_uprobe(name=sys.argv[1], sym="main.main", fn_name="print_symbol_name")

    def read_bpf_program(self, prog):
        with open(prog, "r") as f:
            bpf = f.read()
        return bpf

def main():
    c = UprobeTracer()
    while True:
        time.sleep(5)

if __name__ == "__main__":
    main()
