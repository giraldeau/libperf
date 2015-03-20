/*
 * libperf_signal.c
 *
 *  Created on: Mar 20, 2015
 *      Author: francis
 */

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
#include <execinfo.h>

static int fd;
static int count = 0;
static int disable = 0;

#define ACCESS_ONCE(x) (*(volatile typeof(x) *)&(x))

static long sys_perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
		int cpu, int group_fd, unsigned long flags)
{
	return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd,
			flags);
}

static void signal_handler(int signum, siginfo_t *info, void *arg)
{
	if (disable)
		ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
	if (!count) {
		static int depth = 20;
		void *buffer[20];
		backtrace(buffer, depth);
		backtrace_symbols_fd(buffer, depth, 1);
	}
	++count;
	__sync_synchronize();
	if (disable)
		ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
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

int main(int argc, char **argv)
{
	uint64_t val;
	int ret;
	int flags;
	int repeat = 100;
	struct sigaction sigact;
	struct perf_event_attr attr = {
		.type = PERF_TYPE_SOFTWARE,
		.size = sizeof(attr),
		.config = PERF_COUNT_SW_PAGE_FAULTS,
		.sample_period = 1,
	};

	if (argc > 1) {
		ACCESS_ONCE(disable) = atoi(argv[1]);
	}

	fd = sys_perf_event_open(&attr, getpid(), -1, -1, 0);
	assert(fd > 0);

	// install signal handler
	sigact.sa_sigaction = signal_handler;
	sigact.sa_flags = SA_SIGINFO;
	ret = sigaction(SIGIO, &sigact, NULL);
	assert(ret == 0);

	// fasync setup
	fcntl(fd, F_SETOWN, getpid());
	flags = fcntl(fd, F_GETFL);
	fcntl(fd, F_SETFL, flags | FASYNC);

	do_page_faults(repeat);
	ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);

	ret = read(fd, &val, sizeof(val));
	__sync_synchronize();

	printf("ret=%d repeat=%d counter=%" PRId64 " signals=%d\n", ret, repeat, val, count);
	/*
	 * There should be at least repeat page faults. There are about 50 more
	 * page faults then repeat if the event counter is not disabled within
	 * the signal handler.
	 */
	int threshold = 5;
	int diff = disable ? 0 : 55;
	assert(abs(val - (repeat + diff)) < threshold);
	assert(abs(val - (count + diff)) < threshold);
	return 0;
}
