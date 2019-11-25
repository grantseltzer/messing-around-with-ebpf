#!/usr/bin/python3

from bcc import BPF
from time import sleep


def load_bpf_program():
    with open(BPF_PROGRAM, "r") as f:
        bpf = f.read()
    return bpf

BPF_PROGRAM = "./commit_creds.c"
bpf_text = load_bpf_program()
b = BPF(text=bpf_text)
b.attach_kprobe(event="commit_creds", fn_name="print_commit_creds")

while True:
    sleep(2)
    for k,v in b["creds"].items():
        print(k,v)

# #!/usr/bin/python2
# from bcc import BPF
# from time import sleep
#
# program = """
#     BPF_HASH(syscalls);
#
#     int hello(void *ctx) {
#         u64 counter = 0;
#         u64 key = 56;
#         u64 *p;
#
#         p = syscalls.lookup(&key);
#         if (p != 0) {
#             counter = *p;
#         }
#
#         counter++;
#         syscalls.update(&key, &counter);
# 
#         return 0;
#     }
# """
#
# b = BPF(text=program)
# b.attach_kprobe(event="__x64_sys_clone", fn_name="hello")
#
# while True:
#     sleep(3)
#     for k,v in b["syscalls"].items():
#         print(k,v)
