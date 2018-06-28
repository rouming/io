/**
 * zmtp-test.c - Smoke test for ZMTP protocol implementation.
 *               Creates REP ZMQ socket and listens for connections.
 *
 * Copyright 2017 Roman Pen	<r.peniaev@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version
 * 2 as published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#include <sys/signalfd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <assert.h>

#include "io.h"
#include "zmtp.h"
#include "list.h"

struct loop_ctx {
	int ssock;
	int sigfd;
	void *poller;
	struct poller_item items[2];
	struct list_head peers_to_free;
};

struct peer {
	struct list_head list;
	int psock;
	int sent;
	struct io_queue q;
	struct zmtp zmtp;
	struct loop_ctx *ctx;
};

static int create_signalfd(void)
{
	sigset_t set;
	int fd;

	sigfillset(&set);
	sigprocmask(SIG_BLOCK, &set, NULL);

	sigemptyset(&set);
	sigaddset(&set, SIGINT);
	fd = signalfd(-1, &set, 0);
	assert(fd >= 0);

	return fd;
}

const char *replies[] = {
	"1AAAA1",
	"2BBBBBB2",
	"3CCCCCCCCC3",
	"4DDDDDDDDDDD4",
	"5EEEEEEEEEEEEE5",
	"6FFFFFFFFFFFFFFF6"
};

static int on_read(struct io_req *req, int len);

static int on_write(struct io_req *req, int len)
{
	struct peer *peer = req->data;
	int err;

	io_req_put(req);
	if (len < 0)
		list_add_tail(&peer->list, &peer->ctx->peers_to_free);
	else if (peer->sent == ARRAY_SIZE(replies)) {
		/* Queue is ready for new requests */
		req = io_req_create(&peer->q, REQ_RD, peer, on_read);
		assert(req);
		req->buf = (struct io_buf){
			.iov_num  = 1,
			.is_vari_len = true,
		};
		err = io_queue_submit(req);
		assert(err == 0);
	} else {
		int flags = REQ_WR;
		int err;

		peer->sent++;

		flags |= peer->sent == ARRAY_SIZE(replies) ? 0 : REQ_MORE;
		req = io_req_create(&peer->q, flags, peer, on_write);
		assert(req);
		req->buf = (struct io_buf){
			.iov[0] = {
				.iov_base = (char *)replies[peer->sent-1],
				.iov_len  = strlen(replies[peer->sent-1])
			},
			.iov_num  = 1,
		};
		err = io_queue_submit(req);
		assert(err == 0);

		printf(" #%d chunk is sent\n", peer->sent);
		/*
		  sleep(1);
		*/
	}

	return len;
}

static int on_read(struct io_req *req, int len)
{
	struct peer *peer = req->data;
	bool more;
	int err;

	if (len < 0) {
		io_req_put(req);
		list_add_tail(&peer->list, &peer->ctx->peers_to_free);

		return len;
	}

	more = req->flags & REQ_MORE;
	printf("Got: len=%d, more=%d, '%.*s'\n",
	       len, more, len, (char *)req->buf.iov[0].iov_base);
	io_req_put(req);

	if (more) {
		req = io_req_create(&peer->q, REQ_RD, peer, on_read);
		assert(req);
		req->buf = (struct io_buf){
			.iov_num  = 1,
			.is_vari_len = true,
		};
		err = io_queue_submit(req);
		assert(err == 0);

		return len;
	}

	peer->sent = 1;
	req = io_req_create(&peer->q, REQ_WR | REQ_MORE, peer, on_write);
	assert(req);
	req->buf = (struct io_buf){
		.iov[0] = {
			.iov_base = (char *)replies[0],
			.iov_len  = strlen(replies[0])
		},
		.iov_num  = 1,
	};
	err = io_queue_submit(req);
	assert(err == 0);

	return len;
}

static int on_signal(void *poller, struct poller_item *item)
{
	ssize_t rd;
	struct signalfd_siginfo fdsi;

	while (1) {
		rd = read(item->fd, &fdsi, sizeof(fdsi));
		if (rd < 0 && errno == EAGAIN) {
			return 0;
		}
		else if (rd != sizeof(fdsi)) {
			/* Consider as fatal error */
			assert(0);
			return -1;
		}

		switch (fdsi.ssi_signo) {
		case SIGINT:
		case SIGTERM:
			/* Stop further processing, termination requested */
			return 1;
		default:
			assert(0);
			return -1;
		}
	}

	/* Unreachable line */
	assert(0);
	return -1;
}

static int on_sock_connection(void *poller, struct poller_item *item)
{
	int err, psock;
	struct sockaddr addr;
	socklen_t len = sizeof(addr);
	struct loop_ctx *ctx = item->data;
	struct io_req *req;
	struct peer *peer;

	psock = accept4(item->fd, &addr, &len, SOCK_CLOEXEC);
	if (psock < 0) {
		switch (errno) {
		case EWOULDBLOCK:
			break;
		default:
			err = -errno;
			assert(0);
			return err;
		}

		return 0;
	}

	peer = malloc(sizeof(*peer));
	assert(peer);
	peer->psock = psock;
	peer->ctx = ctx;
	INIT_LIST_HEAD(&peer->list);
	io_queue_init(&peer->q);
	err = io_queue_bind(&peer->q, ctx->poller, psock);
	assert(err == 0);
	err = zmtp_init(&peer->zmtp, &peer->q, ZMTP_REP);
	assert(err == 0);

	req = io_req_create(&peer->q, REQ_RD, peer, on_read);
	assert(req);
	req->buf = (struct io_buf){
		.iov_num  = 1,
		.is_vari_len = true,
	};
	err = io_queue_submit(req);
	assert(err == 0);

	return 0;
}

static void init_loop_ctx(struct loop_ctx *c, int sigfd, int ssock)
{
	int rc, i;

	memset(c, 0, sizeof(*c));
	INIT_LIST_HEAD(&c->peers_to_free);
	c->items[0] = (struct poller_item){
		.fd	= sigfd,
		.events = P_IN,
		.data	= NULL,
		.action = on_signal
	};
	c->items[1] = (struct poller_item){
		.fd	= ssock,
		.events = P_IN,
		.data	= c,
		.action = on_sock_connection
	};
	rc = poller_create(&c->poller);
	assert(rc == 0);
	for (i = 0; i < ARRAY_SIZE(c->items); i++) {
		rc = poller_ctl(c->poller, P_CTL_ADD, &c->items[i]);
		assert(rc == 0);
	}
	c->ssock = ssock;
	c->sigfd = sigfd;
}

static void deinit_loop_ctx(struct loop_ctx *c)
{
	if (c->poller) {
		poller_destroy(c->poller);
		c->poller = NULL;
	}
}

static void bh_execute(struct loop_ctx *ctx)
{
	struct peer *peer, *tmp;

	list_for_each_entry_safe(peer, tmp, &ctx->peers_to_free, list) {
		zmtp_deinit(&peer->zmtp);
		io_queue_unbind(&peer->q);
		io_queue_deinit(&peer->q);
		close(peer->psock);
		list_del(&peer->list);
		free(peer);
	}
}

static int run_event_loop(void)
{
	int err, sigfd, ssock;
	int exit_rc = EXIT_SUCCESS;
	struct loop_ctx ctx;
	struct sockaddr_in ip4addr = {
		.sin_family = AF_INET,
		.sin_port = htons(5555)
	};

	inet_pton(AF_INET, "127.0.0.1", &ip4addr.sin_addr);
	ssock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	assert(ssock >= 0);
	err = 1;
	err = setsockopt(ssock, SOL_SOCKET, SO_REUSEADDR, &err, sizeof(err));
	assert(err == 0);
	err = bind(ssock, (struct sockaddr *)&ip4addr, sizeof(ip4addr));
	assert(err == 0);
	err = listen(ssock, SOMAXCONN);
	assert(err == 0);
	sigfd = create_signalfd();
	assert(sigfd >= 0);

	init_loop_ctx(&ctx, sigfd, ssock);
	while (1) {
		int i;
		struct poller_item *items[16];

		err = poller_wait(ctx.poller, items, ARRAY_SIZE(items), INT_MAX);
		if (err == 0)
			continue;
		else if (err < 0) {
			printf("poller_wait() failed, errno=%d\n", -err);
			break;
		}
		/* Handle events */
		for (i = 0; i < err; i++) {
			err = poller_do_action(ctx.poller, items[i]);
			if (err) {
				/* We are done. */
				exit_rc = (err > 0 ? EXIT_SUCCESS :
						     EXIT_FAILURE);
				goto out;
			}
		}
		/* Handle bh */
		bh_execute(&ctx);
	}
out:
	deinit_loop_ctx(&ctx);
	close(sigfd);
	close(ssock);

	return exit_rc;
}

int main(void)
{
	printf("Way to connect:\n"
	       "   $ ./zmqcat -t REQ -e tcp://localhost:5555\n"
	       "   (https://github.com/EmielM/zmqcat.git)\n\n"
	       "Ctrl-C - exit\n");
	return run_event_loop();
}
