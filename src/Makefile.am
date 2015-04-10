lib_LTLIBRARIES = libperf.la
check_PROGRAMS = test example benchmark test_signal test_signal_inherited

EXTRA_DIST = libperf.h perf_event.h libperf_example.c libperf_test.c libperf_benchmark.c

libperf_la_SOURCES = libperf.c

libperf_la_LDFLAGS = -version-info $(LIBPERF_SO_VERSION)

include_HEADERS = libperf.h

pkgconfigdir = $(libdir)/pkgconfig

pkgconfig_DATA = libperf.pc

test_SOURCES = libperf_test.c
test_LDADD = libperf.la

example_SOURCES = libperf_example.c
example_LDADD = libperf.la

benchmark_SOURCES = libperf_benchmark.c
benchmark_LDADD = libperf.la

test_signal_SOURCES = libperf_signal.c
test_signal_LDADD = libperf.la -llttng-ust -ldl
test_signal_CFLAGS = -pthread

test_signal_inherited_SOURCES = libperf_signal_inherited.c
test_signal_inherited_LDADD = libperf.la
test_signal_inherited_CFLAGS = -pthread