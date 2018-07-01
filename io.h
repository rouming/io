/**
 * io.h - IO read/write library
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

#ifndef IO_H
#define IO_H

#include <sys/uio.h>

#include "types.h"
#include "poller.h"
#include "list.h"

enum {
	REQ_RD = 0,
	REQ_WR = 1,
	REQ_RDWR_MASK = (REQ_RD | REQ_WR),
	REQ_MORE = 2,
};

struct iovec_iter {
	size_t iov_ind;
	size_t iov_off;
};

/**
 * IO buffer descriptor. Consists of <= 16 IO vectors and is used for reading
 * or writing to a socket.  Buffer in read request can be of a variable length,
 * i.e. last IO vector in case of @is_vari_len can consists of zero base and
 * zero length, which will be correctly filled in after each successful read.
 * Also after each successful read req->io_fn() will be called, so it is up to
 * request submitter decide when to stop reading.
 */
struct io_buf {
	struct iovec iov[16];
	struct iovec_iter pos;
	bool   iov_free[16];
	size_t iov_num;
	bool   is_vari_len;
	struct {
		size_t read_hint;
	} __proto;               /* Only for private proto usage, e.g. proto
				  * hints how many exact bytes should be read. */
};

void buf_free(struct io_buf *buf);
int buf_pos(struct io_buf *buf);
int buf_len(struct io_buf *buf);
int buf_memcpy_to(struct io_buf *buf, size_t off, void *dst, size_t len);

struct io_req {
	struct list_head list;
	struct io_queue *q;
	void *data;
	int flags;
	int refs;
	struct io_buf buf;
	unsigned long long expire_ms;
	/*
	 * len value can be:
	 *   >0 - overall size of current request
	 *   <0 - error, all requests will be discarded
	 *   -ECONNRESET - EOF, all requests will be discarded
	 *
	 * return value can be:
	 *   >0 - this request is completed, but amount of bytes
	 *        indicates how much should be stashed:
	 *        o returned size is equal to len which was passed
	 *          - nothing is stashed, request consumed all.
	 *        o returned size < len which was passed
	 *          - stash the difference.
	 *        o returned size == INT_MAX
	 *          - stash everything.
	 *   =0 - continue filling this request
	 *   <0 - fatal error, discard and propagate error up
	 */
	int (*io_fn)(struct io_req *req, int len);
};

struct io_proto {
	struct io_queue *q;

	/*
	 * IO API for proto.
	 */
	int (*submit)(struct io_req *req, bool tail);

	/*
	 * Protocol callbacks.
	 *
	 * on_submit returns:
	 *   =0 - success.
	 *   <0 - fatal error happened, propagate error up.
	 */
	int (*on_submit)(struct io_proto *p, struct io_req *req);
};

struct io_queue {
	void *poller;
	struct poller_item item;
	struct list_head queue;
	int reqs_num[2];
	struct io_proto *proto;
	struct iovec stash;
	size_t stash_pos;
	bool in_proto;
	int refs;
};

void io_queue_init(struct io_queue *queue);
void io_queue_deinit(struct io_queue *queue);

int io_queue_bind(struct io_queue *queue, void *poller, int fd);
int io_queue_unbind(struct io_queue *queue);
void io_queue_reset(struct io_queue *queue);
bool io_queue_binded(struct io_queue *queue);
bool io_queue_stashed(struct io_queue *queue);

int io_queue_submit(struct io_req *req);
int io_queue_cancel(struct io_queue *queue);

int io_queue_set_proto(struct io_queue *queue, struct io_proto *proto);

void io_req_init(struct io_req *req, struct io_queue *q, int flags,
		 void *data, int (*io_fn)(struct io_req *req, int len));
void io_req_deinit(struct io_req *req);

struct io_req *io_req_create(struct io_queue *q, int flags, void *data,
			     int (*io_fn)(struct io_req *req, int len));
void io_req_get(struct io_req *req);
bool io_req_put(struct io_req *req);

#endif /* IO_H */
