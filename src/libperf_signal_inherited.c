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

static int fd;
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
	if (disable)
		ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
	count++;
	do_page_faults(repeat_in_handler);
	__sync_synchronize();
	if (disable)
		ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
}

pthread_barrier_t barrier;
pthread_mutex_t lock;
static int id = 0;
static int period = 2;

void setup_perf(int inherit)
{
	int tid;
	int ret;
	int flags;

	struct perf_event_attr attr = {
		.type = PERF_TYPE_SOFTWARE,
		.size = sizeof(attr),
		.config = PERF_COUNT_SW_PAGE_FAULTS,
		.sample_period = period,
		.inherit = inherit,
	};

	tid = syscall(__NR_gettid);
	fd = sys_perf_event_open(&attr, tid, -1, -1, 0);
	assert(fd > 0);
}

void setup_sighand(void)
{
	int ret;
	struct sigaction sigact;

	// install signal handler
	sigact.sa_sigaction = signal_handler;
	sigact.sa_flags = SA_SIGINFO;
	ret = sigaction(SIGIO, &sigact, NULL);
	assert(ret == 0);
}

void setup_fasync(int fd, int type, int pid)
{
	int ret;
	int flags;
	struct f_owner_ex ex = {
		.type = type,
		.pid = pid,
	};
	ret = fcntl(fd, F_SETOWN_EX, &ex);
	assert(ret == 0);
	flags = fcntl(fd, F_GETFL);
	ret = fcntl(fd, F_SETFL, flags | FASYNC | O_ASYNC);
	assert(ret == 0);

	ret = fcntl(fd, F_GETOWN_EX, &ex);
	assert(ret == 0);
	assert(ex.type == type);
}

void *do_work(void *args)
{
	int repeat = *((int *) args);
	uint64_t val;
	int flags;
	int tid = syscall(__NR_gettid);

	pthread_mutex_lock(&lock);
	rank = id++;
	pthread_mutex_unlock(&lock);
	repeat = repeat * (rank + 1);

	do_page_faults(repeat);
	pthread_barrier_wait(&barrier);

	printf("tid=%d repeat=%d signals=%d\n", tid, repeat, count);
	return NULL;
}

int main(int argc, char **argv)
{
	int i;
	int th = 4;
	int repeat = 100;
	int inherit = 1;
	int ret;
	long val;
	pthread_t pth[th];
	int tid = syscall(__NR_gettid);
	int pid = getpid();

	if (argc > 1) {
		ACCESS_ONCE(disable) = !!atoi(argv[1]);
	}

	pthread_barrier_init(&barrier, NULL, th);

	setup_perf(inherit);
	setup_sighand();
	setup_fasync(fd, F_OWNER_TID, pid);

	for (i = 0; i < th; i++) {
		pthread_create(&pth[i], NULL, do_work, &repeat);
	}

	for (i = 0; i < th; i++) {
		pthread_join(pth[i], NULL);
	}

	ret = read(fd, &val, sizeof(val));
	assert(ret == 8);
	printf("counter=%ld, signals=%d\n", val, count);
	return 0;
}
