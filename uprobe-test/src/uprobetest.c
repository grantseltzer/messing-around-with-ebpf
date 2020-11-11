#include <argp.h>
#include <unistd.h>
#include "uprobetest.h"
#include "uprobetest.skel.h"
#include "trace_helpers.h"  

static struct env {
	pid_t pid;
    bool verbose;
} env = {};

static const struct argp_option opts[] = {
    { "pid", 'p', "PID", 0, "Process ID to trace"},
    { "verbose", 'v', NULL, 0, "Verbose debug output" },
    {},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    static int pos_args;
    long int pid;

    switch (key) {
        case 'p':
            errno = 0;
            pid = strtol(arg, NULL, 10);
            if (errno || pid <= 0) {
                fprintf(stderr, "INVALID PID: %s\n", arg);
            }
            env.pid = pid;
		    break;
        case 'v':
		    env.verbose = true;
		    break;
        case ARGP_KEY_ARG:
            if (pos_args++) {
                fprintf(stderr, "Unrecognized positional argument: %s\n", arg);
            }
            errno = 0;
            break;
        default:
            return 0;
    }
    return 0;
}

int libbpf_print_fn(enum libbpf_print_level level,
		    const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static int handle_event(void *ctx, void *data, size_t len)
{
    struct process_info *s = (struct process_info*)data;
	printf("%u\n", s->uint8);
	return 0;
}


void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

int main(int argc, char **argv) 
{

	int err;

	err = bump_memlock_rlimit();
	if (err) {
		return err;
	}
    
    static const struct argp argp = {
        .options = opts,
        .parser = parse_arg,
    };

    struct uprobetest_bpf *obj;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err) {
        return err;
    }

    libbpf_set_print(libbpf_print_fn);
    obj = uprobetest_bpf__open();
	if (!obj) {
		fprintf(stderr, "failed to open and/or load BPF object\n");
		return 1;
	}

	obj->rodata->target_tgid = env.pid;

    err = uprobetest_bpf__load(obj);
    if (err) {
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(obj->obj, "uprobe__tester_test_single_uint8");
    if (!prog) {
        fprintf(stderr, "fick\n");
        goto cleanup; 
    }

    struct bpf_link *link;
    link = bpf_program__attach_uprobe(prog, false, -1, "/home/grant/tester", 0x5dba0); /* Got this offset from objdump but I dropped the leading digit i.e.: `000000000045dc60 g    F .text	0000000000000001 main.test_combined_byte`*/
    if (!link) {
        fprintf(stderr, "fack\n");
        goto cleanup;
    }

    struct ring_buffer *ringbuffer;
	int ringbuffer_fd;
    ringbuffer_fd = bpf_map__fd(obj->maps.ringbuf);

	ringbuffer = ring_buffer__new(ringbuffer_fd, handle_event, NULL, NULL);
    if (!ringbuffer) {
        fprintf(stderr, "fook\n");
        goto cleanup;
    }

    while (1) {
		// poll for new data with a timeout of -1 ms, waiting indefinitely
		ring_buffer__poll(ringbuffer, -1);
	}
cleanup:
	uprobetest_bpf__destroy(obj);
}