import os
import socket
import time
import logging
import signal
import sys
import zmq
import json
import yaml
import netifaces as ni
from bcc import BPF
from ctypes import *

b = BPF(src_file="tailcall_test.c")

tail_fn = b.load_func("tail_call", BPF.KPROBE)

prog_array = b.get_table("prog_array")

prog_array[c_int(2)] = c_int(tail_fn.fd)

b.attach_kprobe(event="__x64_sys_getcwd", fn_name = "do_tail_call")

time.sleep(60)