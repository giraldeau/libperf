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

static long
sys_perf_event_open(struct perf_event_attr *hw_event,
                    pid_t pid, int cpu, int group_fd,
                    unsigned long flags)
{
  return syscall(__NR_perf_event_open, hw_event, pid, cpu,
                 group_fd, flags);
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
	int repeat = 100;
	struct perf_event_attr attr = {
		.type = PERF_TYPE_SOFTWARE,
		.config = PERF_COUNT_SW_PAGE_FAULTS,
		.size = sizeof(attr),
	};
	int fd = sys_perf_event_open(&attr, getpid(), -1, -1, 0);
	do_page_faults(repeat);
	ret = read(fd, &val, sizeof(val));
	printf("ret=%d val=%" PRId64 "\n", ret, val);
	assert(val >= repeat);
	return 0;
}
