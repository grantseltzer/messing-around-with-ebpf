#include <argp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "skeleton.h"

/* Tune the buffer size and wakeup rate. These settings cope with roughly
 * 50k opens/sec.
 */
#define PERF_BUFFER_PAGES	64
#define PERF_BUFFER_TIME_MS	10
#define PERF_POLL_TIMEOUT_MS	100
#define NSEC_PER_SEC		1000000000ULL

static struct env {
	pid_t pid;
	pid_t tid;
	uid_t uid;
	int duration;
	bool verbose;
	bool timestamp;
	bool print_uid;
	bool extended;
	bool failed;
	char *name;
} env = {};

unsigned long long get_ktime_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * NSEC_PER_SEC + ts.tv_nsec;
}

void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
    printf("WOW!\n");
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

int main(int arg, char **argv)
{
    struct perf_buffer_opts pb_opts;
    struct perf_buffer *pb = NULL;
	struct test *obj;
    int err;
	__u64 time_end = get_ktime_ns();

    obj = test__open();
    if (!obj) {
        fprintf(stderr, "failed to open and/or load BPF object\n");
		return 1;
    }

    err = test__load(obj);
    if (err) {
        fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
    }

    err = test__attach(obj);
    if (err) {
        fprintf(stderr, "failed to attach BPF program\n");
        goto cleanup;
    }

	/* setup event callbacks */
	pb_opts.sample_cb = handle_event;
	pb_opts.lost_cb = handle_lost_events;
    pb = perf_buffer__new(bpf_map__fd(obj->maps.events), PERF_BUFFER_PAGES, &pb_opts);
    
    err = libbpf_get_error(pb);
	if (err) {
		pb = NULL;
		fprintf(stderr, "failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

    while (1) {
        usleep(PERF_BUFFER_TIME_MS * 1000);
        if ((err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS)) < 0) {
			break;
        }
		if (env.duration && get_ktime_ns() > time_end) {
			goto cleanup;
        }
    }

cleanup:
    perf_buffer__free(pb);
    test__destroy(obj);

    return err != 0;
}