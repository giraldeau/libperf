/*
 * libperf_signal.c
 *
 *  Created on: Mar 20, 2015
 *      Author: francis
 */

#define _GNU_SOURCE
#include <assert.h>
#include <fcntl.h>
#include <inttypes.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stropts.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>
#include <linux/perf_event.h>
#include <signal.h>
#include <pthread.h>

#define TRACEPOINT_DEFINE
#define TRACEPOINT_CREATE_PROBES
#include "tp.h"

static int __thread fd;
static void *rb;
static int __thread rank;
static int __thread count = 0;
static int disable = 0;
static int repeat_in_handler = 1;

#define ACCESS_ONCE(x) (*(volatile typeof(x) *)&(x))

pthread_mutex_t mutex;

static long sys_perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
		int cpu, int group_fd, unsigned long flags)
{
	return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd,
			flags);
}

static void
do_page_faults(int repeat)
{
	int i;
	char *buf;
	int pgsz = getpagesize();

	for (i = 0; i < repeat; i++) {
		buf = mmap(NULL, pgsz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		assert(buf);
		memset(buf, 0x42, pgsz);
		munmap(buf, pgsz);
		madvise(buf, pgsz, MADV_DONTNEED);
	}
}

static void signal_handler(int signum, siginfo_t *info, void *arg)
{
    int tid = syscall(__NR_gettid);
    tracepoint(libperf, signal_entry, tid, signum);
	if (disable)
		ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
	//count++;
	//do_page_faults(repeat_in_handler);
	//__sync_synchronize();
	if (disable)
		ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
	tracepoint(libperf, signal_exit, tid, signum);
}

static void setup_mmap(int fd)
{
    size_t pg = getpagesize();
    size_t len = (512 * 1024) / pg;
    void *addr = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (!addr)
        return;
    rb = addr;
}

void do_hog()
{
    volatile x = 1000000;
    while(x)
        x--;
}

pthread_barrier_t barrier;
pthread_mutex_t lock;
static int id = 0;
static int period = 10000;
void *do_work(void *args)
{
	int repeat = *((int *) args);
	uint64_t val;
	int tid;
	int ret;
	int flags;
	struct sigaction sigact;
	struct perf_event_attr attr = {
		.type = PERF_TYPE_SOFTWARE,
		.size = sizeof(attr),
		.config = PERF_COUNT_SW_CPU_CLOCK,
		.sample_period = period,
	};
	pthread_mutex_lock(&lock);
	rank = id++;
	pthread_mutex_unlock(&lock);
	repeat = repeat * (rank + 1);

	tid = syscall(__NR_gettid);
	fd = sys_perf_event_open(&attr, tid, -1, -1, 0);
	assert(fd > 0);

	// install signal handler
	sigact.sa_sigaction = signal_handler;
	sigact.sa_flags = SA_SIGINFO;
	ret = sigaction(SIGIO, &sigact, NULL);
	assert(ret == 0);

	// fasync setup
	struct f_owner_ex ex = {
		.type = F_OWNER_TID,
		.pid = tid,
	};
	ret = fcntl(fd, F_SETOWN_EX, &ex);
	assert(ret == 0);
	flags = fcntl(fd, F_GETFL);
	ret = fcntl(fd, F_SETFL, flags | FASYNC | O_ASYNC);
	assert(ret == 0);

	ret = fcntl(fd, F_GETOWN_EX, &ex);
	assert(ret == 0);
	switch (ex.type) {
	case F_OWNER_TID:
		printf("type F_OWNER_TID\n");
		break;
	case F_OWNER_PID:
		printf("type F_OWNER_PID\n");
		break;
	case F_OWNER_PGRP:
		printf("type F_OWNER_PGRP\n");
		break;
	default:
		printf("type unkown\n");
		break;
	}

	setup_mmap(fd);

	//do_page_faults(repeat);
	do_hog();
	pthread_barrier_wait(&barrier);
	ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);

	ret = read(fd, &val, sizeof(val));
	__sync_synchronize();

	printf("tid=%d ret=%d repeat=%d counter=%" PRId64 " signals=%d\n",
			tid, ret, repeat, val, count);
	pthread_barrier_wait(&barrier);

	/*
	 * hum... there are more page faults than expected, and it is
	 * non-deterministic, so sometimes even with large threshold
	 * this test may fail.
	 */
	int threshold = 40;
	int exp_counter = repeat;
	if (!disable)
		exp_counter += repeat * repeat_in_handler;
	int err_counter = abs(val - exp_counter);
	int exp_signals = repeat / period;
	if (!disable)
		exp_signals += (repeat * repeat_in_handler) / period;
	int err_signals = abs(count - exp_signals);
	printf("exp_counter=%d act_counter=%lu err=%d exp_signals=%d act_signals=%d err=%d\n",
			exp_counter, val, err_counter, exp_signals, count, err_signals);
	assert(err_counter < threshold);
	assert(err_signals < threshold);
	return NULL;
}

int main(int argc, char **argv)
{
	int i;
	int th = 4;
	int repeat = 100;
	pthread_t pth[th];

	if (argc > 1) {
		ACCESS_ONCE(disable) = !!atoi(argv[1]);
	}

	pthread_barrier_init(&barrier, NULL, th);

	for (i = 0; i < th; i++) {
		pthread_create(&pth[i], NULL, do_work, &repeat);
	}

	for (i = 0; i < th; i++) {
		pthread_join(pth[i], NULL);
	}

	return 0;
}
