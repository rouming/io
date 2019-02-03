CC = $(CROSS_COMPILE)gcc
DEFINES = -D_GNU_SOURCE
CFLAGS = -g -O2 -Wall -Werror

SRCS := $(wildcard *-test.c *-server.c)
BINS := $(SRCS:%.c=%)

all: $(BINS)

%: %.c
	$(CC) $(DEFINES) $(CFLAGS) -o $@ $^ zmtp.c io.c poller.c

clean:
	$(RM) $(BINS) *~
