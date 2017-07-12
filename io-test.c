/**
 * io-test.c - Smoke tests for socket IO library
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
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <assert.h>

#include "io.h"

struct loop_ctx {
	struct io_queue master;
	struct io_queue slave;
	bool shutdown;
};

typedef void (*action_t)(struct loop_ctx *ctx);
static int action_ind;

static int create_signalfd(void)
{
	sigset_t set;
	int fd;

	sigfillset(&set);
	sigprocmask(SIG_BLOCK, &set, NULL);

	sigemptyset(&set);
	sigaddset(&set, SIGINT);
	sigaddset(&set, SIGQUIT);
	fd = signalfd(-1, &set, 0);
	if (fd < 0)
		return -errno;

	return fd;
}

static int on_write_fixed_len_req__master_to_slave(struct io_req *req, int len)
{
	assert(len > 0);
	io_req_put(req);

	return len;
}

static int on_read_fixed_len_req__slave_from_master(struct io_req *req, int err)
{
	int len = buf_len(&req->buf);
	char msg[len];
	int nb;

	assert(strlen("fixed msg") == err);
	nb = buf_memcpy_to(&req->buf, 0, msg, len);
	assert(nb == len);

	printf("  FIXED LEN MSG: len=%d, msg='%.*s'\n", len, len, msg);
	io_req_put(req);

	return err;
}

static void do_fixed_len_req(struct loop_ctx *ctx)
{
	int rc;
	struct io_req *m_s_req1, *m_s_req2, *s_m_req;

	/* Write master->slave, part1 */
	m_s_req1 = io_req_create(&ctx->master, REQ_WR, ctx,
				 on_write_fixed_len_req__master_to_slave);
	assert(m_s_req1);
	m_s_req1->buf = (struct io_buf){
		.iov[0] = {
			.iov_base = "fixed ",
			.iov_len  = strlen("fixed ")
		},
		.iov_num  = 1,
		.is_vari_len = false
	};
	rc = io_queue_submit(m_s_req1);
	assert(rc == 0);

	/* Write master->slave, part1 */
	m_s_req2 = io_req_create(&ctx->master, REQ_WR, ctx,
				 on_write_fixed_len_req__master_to_slave);
	assert(m_s_req2);
	m_s_req2->buf = (struct io_buf){
		.iov[0] = {
			.iov_base = "msg",
			.iov_len  = strlen("msg")
		},
		.iov_num  = 1,
		.is_vari_len = false
	};
	rc = io_queue_submit(m_s_req2);
	assert(rc == 0);

	/* Read slave<-master, part1 + part2 */
	s_m_req = io_req_create(&ctx->slave, REQ_RD, ctx,
				on_read_fixed_len_req__slave_from_master);
	assert(s_m_req);
	s_m_req->buf = (struct io_buf){
		.iov[0] = {
			.iov_base = NULL,
			.iov_len  = 3
		},
		.iov[1] = {
			.iov_base = NULL,
			.iov_len  = 6
		},
		.iov_num  = 2,
		.is_vari_len = false
	};
	rc = io_queue_submit(s_m_req);
	assert(rc == 0);
}

static int on_write_vari_len_req1_3__master_to_slave(struct io_req *req, int len)
{
	assert(len > 0);
	io_req_put(req);

	return len;
}

static int on_write_vari_len_req1_2__master_to_slave(struct io_req *req, int len)
{
	int rc;
	struct io_req *m_s_req3;
	struct loop_ctx *ctx = req->data;

	assert(len > 0);
	io_req_put(req);

	/* Write master->slave, part3 */
	m_s_req3 = io_req_create(&ctx->master, REQ_WR, ctx,
				 on_write_vari_len_req1_3__master_to_slave);
	assert(m_s_req3);
	m_s_req3->buf = (struct io_buf){
		.iov[0] = {
			.iov_base = "2 vari",
			.iov_len  = strlen("2 vari")
		},
		.iov[1] = {
			.iov_base = " length 2",
			.iov_len  = strlen(" length 2")
		},
		.iov[2] = {
			.iov_base = "</msg>",
			.iov_len  = strlen("</msg>")
		},
		/* Data for next action */
		.iov[3] = {
			.iov_base = "GARBAGE<msg>3 vari length 3</msg>",
			.iov_len  = strlen("GARBAGE<msg>3 vari length 3</msg>"),
		},
		.iov_num  = 4,
		.is_vari_len = false
	};
	rc = io_queue_submit(m_s_req3);
	assert(rc == 0);

	return len;
}

static int on_write_vari_len_req1_1__master_to_slave(struct io_req *req, int len)
{
	int rc;
	struct io_req *m_s_req2;
	struct loop_ctx *ctx = req->data;

	assert(len > 0);
	io_req_put(req);

	/* Write master->slave, part2 */
	m_s_req2 = io_req_create(&ctx->master, REQ_WR, ctx,
				 on_write_vari_len_req1_2__master_to_slave);
	assert(m_s_req2);
	m_s_req2->buf = (struct io_buf){
		.iov[0] = {
			.iov_base = "</msg>",
			.iov_len  = strlen("</msg>")
		},
		.iov[1] = {
			.iov_base = "<msg>",
			.iov_len  = strlen("<msg>")
		},
		.iov_num  = 2,
		.is_vari_len = false
	};
	rc = io_queue_submit(m_s_req2);
	assert(rc == 0);

	return len;
}

static int on_read_vari_len_req1_2__slave_from_master(struct io_req *req, int len)
{
	int nb, stashed;
	char msg[len + 1], *str;

	nb = buf_memcpy_to(&req->buf, 0, msg, len);
	assert(nb == len);

	str = memmem(msg, nb, "</msg>", 6);
	if (str == NULL)
		return 0;

	nb = str - msg + strlen("</msg>");
	stashed = len - nb;
	len = nb;
	printf("   VARI LEN MSG 2: stashed=%2d, len=%2d, msg='%.*s'\n",
	       stashed, len, len, msg);
	io_req_put(req);

	return len;
}

static int on_read_vari_len_req1_1__slave_from_master(struct io_req *req, int len)
{
	int nb, rc, stashed;
	char msg[len], *str;
	struct io_req *s_m_req;
	struct loop_ctx *ctx = req->data;

	nb = buf_memcpy_to(&req->buf, 0, msg, len);
	assert(nb == len);

	str = memmem(msg, nb, "</msg>", 6);
	if (str == NULL)
		return 0;

	nb = str - msg + strlen("</msg>");
	stashed = len - nb;
	len = nb;
	printf(" VARI LEN MSG 1: stashed=%2d, len=%2d, msg='%.*s'\n",
	       stashed, len, len, msg);
	io_req_put(req);

	/* Read slave<-master, part2 */
	s_m_req = io_req_create(&ctx->slave, REQ_RD, ctx,
				on_read_vari_len_req1_2__slave_from_master);
	s_m_req->buf = (struct io_buf){
		.iov[0] = {
			.iov_base = NULL,
			.iov_len  = 0
		},
		.iov_num  = 1,
		.is_vari_len = true
	};
	rc = io_queue_submit(s_m_req);
	assert(rc == 0);

	return len;
}

static void do_vari_len_req1(struct loop_ctx *ctx)
{
	int rc;
	struct io_req *m_s_req1, *s_m_req1;

	/* Write master->slave, part1 */
	m_s_req1 = io_req_create(&ctx->master, REQ_WR, ctx,
				 on_write_vari_len_req1_1__master_to_slave);
	assert(m_s_req1);
	m_s_req1->buf = (struct io_buf){
		.iov[0] = {
			.iov_base = "<msg>",
			.iov_len  = strlen("<msg>")
		},
		.iov[1] = {
			.iov_base = "1 vari length 1",
			.iov_len  = strlen("1 vari length 1")
		},
		.iov_num  = 2,
		.is_vari_len = false
	};
	rc = io_queue_submit(m_s_req1);
	assert(rc == 0);

	/* Read slave<-master, part1 */
	s_m_req1 = io_req_create(&ctx->slave, REQ_RD, ctx,
				 on_read_vari_len_req1_1__slave_from_master);
	s_m_req1->buf = (struct io_buf){
		.iov[0] = {
			.iov_base = NULL,
			.iov_len  = 0
		},
		.iov_num  = 1,
		.is_vari_len = true
	};
	rc = io_queue_submit(s_m_req1);
	assert(rc == 0);
}

static int on_read_vari_len_req2__slave_from_master(struct io_req *req, int len)
{
	int nb, stashed;
	char msg[len + 1], *beg, *end;

	nb = buf_memcpy_to(&req->buf, 0, msg, len);
	assert(nb == len);

	beg = memmem(msg, nb, "<msg>", 5);
	if (beg == NULL)
		return 0;

	end = memmem(msg, nb, "</msg>", 6);
	if (end == NULL)
		return 0;

	nb = end - msg + strlen("</msg>");
	stashed = len - nb;
	nb = end - beg + strlen("</msg>");
	printf(" VARI LEN MSG 3: stashed=%2d, len=%2d, msg='%.*s'\n",
	       stashed, nb, nb, beg);
	io_req_put(req);

	return len;
}

static void do_vari_len_req2(struct loop_ctx *ctx)
{
	int rc;
	struct io_req *s_m_req;

	/*
	 * Here we test, that on the previous action
	 * something was stashed and here we submit
	 * new read request out of the IO loop, i.e.
	 * prewait actions should be called.
	 */

	/* Read slave<-master, reuse callback from do_vari_len_req1 */
	s_m_req = io_req_create(&ctx->slave, REQ_RD, ctx,
				on_read_vari_len_req2__slave_from_master);
	s_m_req->buf = (struct io_buf){
		.iov[0] = {
			.iov_base = NULL,
			.iov_len  = 0
		},
		.iov_num  = 1,
		.is_vari_len = true
	};
	rc = io_queue_submit(s_m_req);
	assert(rc == 0);
}

static action_t actions[] = {
	do_fixed_len_req,
	do_vari_len_req1,
	do_vari_len_req2,
};

static int on_signal(struct io_req *req, int err)
{
	int rc;
	struct signalfd_siginfo *siginfo;
	struct loop_ctx *ctx = req->data;

	if (err < 0)
		return err;
	assert(err == sizeof(struct signalfd_siginfo));
	siginfo = req->buf.iov[0].iov_base;
	if (siginfo->ssi_signo == SIGINT) {
		/* Graceful exit */
		ctx->shutdown = true;
		return err;
	}

	/* Repeat signal REQ_RD request */
	req->buf.pos.iov_off = 0;
	req->buf.pos.iov_ind = 0;
	rc = io_queue_submit(req);
	assert(rc == 0);

	actions[action_ind++](ctx);
	action_ind %= ARRAY_SIZE(actions);

	return err;
}

static int run_event_loop(void)
{
	int err, sigfd, socks[2];
	int exit_rc = EXIT_SUCCESS;
	void *poller = NULL;
	struct loop_ctx ctx;
	struct io_queue sig_q;
	struct io_req sig_req;

	err = socketpair(AF_UNIX, SOCK_STREAM, 0, socks);
	assert(err == 0);

	sigfd = create_signalfd();
	assert(sigfd >= 0);

	io_queue_init(&ctx.master);
	io_queue_init(&ctx.slave);
	io_queue_init(&sig_q);

	err = poller_create(&poller);
	assert(err == 0);
	assert(poller != NULL);

	err = io_queue_bind(&ctx.master, poller, socks[0]);
	assert(err == 0);
	err = io_queue_bind(&ctx.slave, poller, socks[1]);
	assert(err == 0);
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

	ctx.shutdown = false;
	while (!ctx.shutdown) {
		int i;
		struct poller_item *items[16];

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
	}
out:
	io_req_deinit(&sig_req);

	io_queue_unbind(&ctx.master);
	io_queue_unbind(&ctx.slave);
	io_queue_unbind(&sig_q);

	io_queue_deinit(&ctx.master);
	io_queue_deinit(&ctx.slave);
	io_queue_deinit(&sig_q);

	poller_destroy(poller);

	close(sigfd);
	close(socks[0]);
	close(socks[1]);

	return exit_rc;
}

int main(void)
{
	printf("Ctrl-\\ - send request\n"
	       "Ctrl-C - exit\n");
	return run_event_loop();
}
