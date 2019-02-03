/**
 * http-test.c - Simple http server for performance measurements
 *
 * Copyright 2019 Roman Penyaev	<r.peniaev@gmail.com>
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
#include <err.h>

#include "io.h"
#include "list.h"

struct loop_ctx {
	bool shutdown;
	struct list_head dead_conns;
};

struct connection {
	struct loop_ctx *ctx;
	struct io_queue	cli_q;
	struct list_head dead_entry;
	int sock;
};

static inline char *strnstr(const char *s1, const char *s2, size_t len)
{
	size_t l2;

	l2 = strlen(s2);
	if (!l2)
		return (char *)s1;
	while (len >= l2) {
		len--;
		if (!memcmp(s1, s2, l2))
			return (char *)s1;
		s1++;
	}
	return NULL;
}

static int on_signal(struct io_req *req, int err)
{
	struct signalfd_siginfo *siginfo;
	struct loop_ctx *ctx = req->data;

	if (err < 0)
		return err;

	assert(err == sizeof(struct signalfd_siginfo));
	siginfo = req->buf.iov[0].iov_base;
	assert(siginfo->ssi_signo == SIGINT);

	/* Graceful exit */
	ctx->shutdown = true;

	return err;
}

static int create_signalfd(void)
{
	sigset_t set;
	int fd;

	sigfillset(&set);
	sigprocmask(SIG_BLOCK, &set, NULL);

	sigemptyset(&set);
	sigaddset(&set, SIGINT);
	fd = signalfd(-1, &set, 0);
	if (fd < 0)
		return -errno;

	return fd;
}

static int create_server_socket(const char *ip_address, int port)
{
	struct sockaddr addr;
	struct sockaddr_in *sin = (struct sockaddr_in *)&addr;
	int fd, err, val = 0;

	memset(&addr, 0, sizeof(addr));
	sin->sin_family = AF_INET;
	sin->sin_port = htons(port);

	err = inet_aton(ip_address, &sin->sin_addr);
	assert(err);

	fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
		    IPPROTO_TCP);
	assert(fd >= 0);

	if ((setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, 4) < 0) ||
	    (setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &val, 4) < 0))
		assert(0);

	err = bind(fd, &addr, sizeof(*sin));
	assert(err == 0);

	err = listen(fd, SOMAXCONN);
	assert(err == 0);

	return fd;
}

static int on_read__from_client(struct io_req *req, int len);

static int on_write__to_client(struct io_req *req, int len)
{
	struct connection *conn = req->data;
	int rc;

	io_req_put(req);
	if (len < 0) {
		list_add_tail(&conn->dead_entry, &conn->ctx->dead_conns);
	} else {
		req = io_req_create(&conn->cli_q, REQ_RD, conn,
				    on_read__from_client);
		assert(req);

		req->buf = (struct io_buf){
			.iov_num  = 1,
			.is_vari_len = true
		};
		rc = io_queue_submit(req);
		assert(rc == 0);
	}

	return len;
}

const char *http_response =
	"HTTP/1.1 200 Everything is fine\r\n"
	"Content-Length: 0\r\n"
	"Content-Type: text/html; charset=ISO-8859-1\r\n"
	"\r\n";

static int on_read__from_client(struct io_req *req, int len)
{
	struct connection *conn = req->data;
	struct io_req *wr_req;
	int rc;

	if (len < 0) {
		io_req_put(req);
		list_add_tail(&conn->dead_entry, &conn->ctx->dead_conns);
		/* Propagate error up */
		return len;
	}
	if (!strnstr(req->buf.iov[0].iov_base, "\r\n\r\n", len)) {
		/* Not enough, continue */
		return 0;
	}
	io_req_put(req);

	wr_req = io_req_create(&conn->cli_q, REQ_WR, conn,
			       on_write__to_client);
	assert(wr_req);

	wr_req->buf = (struct io_buf){
		.iov[0] = {
			.iov_base = (void *)http_response,
			.iov_len  = strlen(http_response)
		},
		.iov_num  = 1,
	};
	rc = io_queue_submit(wr_req);
	assert(rc == 0);

	/* Request will be put by the queue */
	return len;
}

static int on_sock_connection(void *poller, struct poller_item *item)
{
	struct sockaddr addr;
	socklen_t len = sizeof(addr);
	struct loop_ctx *ctx = item->data;
	struct connection *conn;
	struct io_req *req;

	int rc, peer;

	peer = accept4(item->fd, &addr, &len, SOCK_CLOEXEC | SOCK_NONBLOCK);
	if (peer < 0) {
		switch (errno) {
		case EWOULDBLOCK:
			break;
		case EMFILE:
		case ENFILE:
		case ENOBUFS:
		case ENOMEM:
		default:
			err(EXIT_FAILURE, "accept4 failed: errno=%d\n", errno);

			return rc;
		}

		return 0;
	}

	conn = calloc(1, sizeof(*conn));
	assert(conn);

	conn->ctx = ctx;
	conn->sock = peer;
	io_queue_init(&conn->cli_q);

	rc = io_queue_bind(&conn->cli_q, poller, peer);
	assert(rc == 0);

	req = io_req_create(&conn->cli_q, REQ_RD, conn,
			    on_read__from_client);
	assert(req);

	req->buf = (struct io_buf){
		.iov_num  = 1,
		.is_vari_len = true
	};
	rc = io_queue_submit(req);
	assert(rc == 0);

	/* Do not propagate an error up to avoid IO loop exit */
	return 0;
}

static void bh_execute(struct loop_ctx *ctx)
{
	struct connection *conn, *tmp;

	/* Free dead connections */
	list_for_each_entry_safe(conn, tmp, &ctx->dead_conns, dead_entry) {
		list_del(&conn->dead_entry);
		close(conn->sock);
		free(conn);
	}
}

static int run_event_loop(void)
{
	int err, sigfd;
	int exit_rc = EXIT_SUCCESS;
	void *poller = NULL;
	int server_sock;

	struct poller_item sock_item;
	struct loop_ctx ctx;
	struct io_queue sig_q;
	struct io_req sig_req;

	server_sock = create_server_socket("0.0.0.0", 8080);
	assert(server_sock >= 0);

	sock_item = (struct poller_item){
		.fd     = server_sock,
		.events = P_IN,
		.data   = &ctx,
		.action = on_sock_connection
	};

	sigfd = create_signalfd();
	assert(sigfd >= 0);

	io_queue_init(&sig_q);

	err = poller_create(&poller);
	assert(err == 0);
	assert(poller != NULL);

	err = io_queue_bind(&sig_q, poller, sigfd);
	assert(err == 0);

	io_req_init(&sig_req, &sig_q, REQ_RD, &ctx, on_signal);
	sig_req.buf = (struct io_buf){
		.iov[0] = {
			.iov_base = NULL,
			.iov_len  = sizeof(struct signalfd_siginfo)
		},
		.iov_num  = 1,
		.is_vari_len = false
	};

	err = io_queue_submit(&sig_req);
	assert(err == 0);

	err = poller_ctl(poller, P_CTL_ADD, &sock_item);
	assert(err == 0);

	ctx.shutdown = false;
	INIT_LIST_HEAD(&ctx.dead_conns);
	while (!ctx.shutdown) {
		struct poller_item *items[16];
		int i;

		err = poller_wait(poller, items, ARRAY_SIZE(items), INT_MAX);
		if (err == 0)
			continue;
		else if (err < 0) {
			printf("poller_wait() failed, errno=%d\n", -err);
			break;
		}
		/* Handle events */
		for (i = 0; i < err; i++) {
			err = poller_do_action(poller, items[i]);
			if (err) {
				/* We are done. */
				exit_rc = (err > 0 ? EXIT_SUCCESS :
					   EXIT_FAILURE);
				goto out;
			}
		}
		/* Handle bottom halves */
		bh_execute(&ctx);
	}
out:
	io_req_deinit(&sig_req);
	io_queue_unbind(&sig_q);
	io_queue_deinit(&sig_q);

	poller_destroy(poller);

	close(sigfd);
	close(server_sock);

	return exit_rc;
}

int main(void)
{
	printf("Ctrl-C - exit\n");

	return run_event_loop();
}
