/**
 * io.c - IO read/write library
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

#include <string.h>
#include <unistd.h>
#include <malloc.h>
#include <errno.h>
#include <assert.h>
#include <fcntl.h>
#include <limits.h>

#include "io.h"

#define _4K          4096
#define POLLER_RESET (void *)~0ull

#define CALL_PROTO(fn, q, ...) ({					\
	int __rc = 0;							\
									\
	if (q->proto && q->proto->fn && !q->in_proto) {			\
		q->in_proto = true;					\
		__rc = q->proto->fn(q->proto, ##__VA_ARGS__);		\
		q->in_proto = false;					\
	}								\
	__rc;								\
})

#define BEG_IT(buf) (struct iovec_iter){ 0 }
#define END_IT(buf) buf_vari_len(buf) ?					\
	(struct iovec_iter) {						\
		/* Vari length never reaches the end and absorbs all */ \
		.iov_ind = (buf)->iov_num,				\
		.iov_off = 0						\
	} :								\
	(struct iovec_iter) {						\
		.iov_ind = (buf)->iov_num-1,				\
		.iov_off = (buf)->iov[(buf)->iov_num-1].iov_len		\
	};								\

static int buf_it_cmp(struct iovec_iter *it1, struct iovec_iter *it2)
{
	if (it1->iov_ind < it2->iov_ind)
		return -1;
	if (it1->iov_ind > it2->iov_ind)
		return 1;
	if (it1->iov_off < it2->iov_off)
		return -1;
	if (it1->iov_off > it2->iov_off)
		return 1;

	return 0;
}

static size_t buf_it_iovlen(struct io_buf *buf, struct iovec_iter *beg,
			    struct iovec_iter *end)
{
	size_t len;

	if (buf_it_cmp(beg, end) >= 0)
		return 0;
	if (beg->iov_ind == end->iov_ind)
		len = end->iov_off;
	else
		len = buf->iov[beg->iov_ind].iov_len;

	return len - beg->iov_off;
}

static struct iovec *buf_it_iov(struct io_buf *buf, struct iovec_iter *it)
{
	return &buf->iov[it->iov_ind];
}

static void *buf_it_iovbase(struct io_buf *buf, struct iovec_iter *it)
{
	return buf_it_iov(buf, it)->iov_base + it->iov_off;
}

static bool buf_vari_len(struct io_buf *buf)
{
	return buf->is_vari_len;
}

static bool buf_it_tail(struct io_buf *buf, struct iovec_iter *it)
{
	return it->iov_ind == (buf->iov_num - 1);
}

static bool buf_it_end(struct io_buf *buf, struct iovec_iter *it)
{
	if (!buf_it_tail(buf, it))
		return false;

	return it->iov_off == buf_it_iov(buf, it)->iov_len;
}

static bool buf_it_vari_len_tail(struct io_buf *buf, struct iovec_iter *it)
{
	return buf_vari_len(buf) && buf_it_tail(buf, it);
}

static void buf_it_advance(struct io_buf *buf, struct iovec_iter *it, size_t sz)
{
	it->iov_off += sz;
	if (!buf_it_tail(buf, it) &&
	    buf_it_iov(buf, it)->iov_len == it->iov_off) {
		/*
		 * We advance if this is the end of iov
		 * and iov is not a tail
		 */
		it->iov_off = 0;
		it->iov_ind++;
	}
}

static int buf_it_len(struct io_buf *buf, struct iovec_iter *beg,
		      struct iovec_iter *end)
{
	size_t sz, nb;

	sz = 0;
	while (buf_it_cmp(beg, end) < 0) {
		nb = buf_it_iovlen(buf, beg, end);
		buf_it_advance(buf, beg, nb);
		sz += nb;
	}

	return sz;
}

static size_t buf_advance(struct io_buf *buf, struct iovec_iter *it,
			  size_t sz)
{
	size_t nb;
	struct iovec_iter end = END_IT(buf);

	while (buf_it_cmp(it, &end) < 0 && sz) {
		nb = min(sz, buf_it_iovlen(buf, it, &end));
		buf_it_advance(buf, it, nb);
		sz -= nb;
	}

	return sz;
}

static struct iovec_iter buf_it(struct io_buf *buf, size_t off)
{
	size_t sz;
	struct iovec_iter beg = BEG_IT(buf);
	struct iovec_iter end = END_IT(buf);

	while (buf_it_cmp(&beg, &end) < 0 && off) {
		sz = min(off, buf_it_iovlen(buf, &beg, &end));
		buf_it_advance(buf, &beg, sz);
		off -= sz;
	}

	return beg;
}

static int buf_it_realloc(struct io_buf *buf, struct iovec_iter *it, size_t sz)
{
	struct iovec *iov;

	/*
	 * Here we come because of two reasons:
	 *   1. !iov_len, !iov_base,  is_vari_len
	 *   2.  iov_len, !iov_base, !is_vari_len
	 *
	 * For 1 we reallocate the iov_len + sz.
	 * For 2 we allocate what is set in iov_len.
	 */

	iov = buf_it_iov(buf, it);
	if (buf_it_vari_len_tail(buf, it))
		sz += iov->iov_len;
	else
		sz  = iov->iov_len;
	iov->iov_base = realloc(iov->iov_base, sz);
	if (iov->iov_base == NULL)
		return -ENOMEM;
	buf->iov_free[it->iov_ind] = true;
	iov->iov_len = sz;

	return sz;
}

static int buf_it_append(struct io_buf *src, struct iovec_iter *it_s,
			 struct io_buf *dst, struct iovec_iter *it_d,
			 size_t len)
{
	int rc;
	size_t len_s, nb, sz;
	struct iovec_iter end_d = END_IT(dst);

	if (buf_it_cmp(it_s, &src->pos) >= 0)
		return 0;
	if (buf_it_cmp(it_d, &dst->pos) > 0)
		return 0;

	len = min(len, buf_pos(src));
	sz = 0;
	while (buf_it_cmp(it_s, &src->pos) < 0 &&
	       buf_it_cmp(it_d, &end_d) < 0 && len) {
		len_s = min(len, buf_it_iovlen(src, it_s, &src->pos));
		while (buf_it_cmp(it_d, &end_d) < 0 && len_s) {
			if (buf_it_end(dst, it_d) ||
			    buf_it_iovbase(dst, it_d) == NULL) {
				rc = buf_it_realloc(dst, it_d, len);
				if (rc < 0)
					return -ENOMEM;
			}
			nb = min(len_s, buf_it_iovlen(dst, it_d, &end_d));
			memcpy(buf_it_iovbase(dst, it_d),
			       buf_it_iovbase(src, it_s), nb);
			len_s -= nb;
			len -= nb;
			sz += nb;
			buf_it_advance(src, it_s, nb);
			buf_it_advance(dst, it_d, nb);
		}
	}
	if (buf_it_cmp(it_d, &dst->pos) > 0)
		dst->pos = *it_d;

	return sz;
}

void buf_free(struct io_buf *buf)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(buf->iov); i++)
		if (buf->iov_free[i])
			free(buf->iov[i].iov_base);
}

static int buf_check(struct io_buf *buf)
{
	int i;
	struct iovec *iov;

	if (buf->iov_num == 0)
		return -EINVAL;
	if (buf->iov_num >= ARRAY_SIZE(buf->iov))
		return -EINVAL;
	for (i = 0; i < buf->iov_num - 1; i++) {
		/* Only last vari length element can be zero */
		if (!buf->iov[i].iov_len)
			return -EINVAL;
	}
	iov = &buf->iov[buf->iov_num - 1];
	/* Last, not vari length iov must be with valid length */
	if (!buf_vari_len(buf) && !iov->iov_len)
		return -EINVAL;
	/* Last, vari length iov must be fully zeroed or fully alloc'ed */
	if (buf_vari_len(buf) && (!!iov->iov_len ^ !!iov->iov_base))
		return -EINVAL;
	if (buf->pos.iov_ind > buf->iov_num)
		return -EINVAL;
	iov = &buf->iov[buf->pos.iov_ind];
	if (iov->iov_base == NULL && buf->pos.iov_off)
		return -EINVAL;
	if (iov->iov_len && buf->pos.iov_off > iov->iov_len) {
		assert(0);
		return -EINVAL;
	}

	return 0;
}

static int req_check(struct io_req *req)
{
	int rc;

	rc = buf_check(&req->buf);
	if (rc)
		return rc;
	if ((req->flags & REQ_WR) && buf_vari_len(&req->buf))
		return -EINVAL;

	return 0;
}

int buf_pos(struct io_buf *buf)
{
	struct iovec_iter beg = BEG_IT(buf);

	return buf_it_len(buf, &beg, &buf->pos);
}

int buf_len(struct io_buf *buf)
{
	struct iovec_iter beg = BEG_IT(buf);
	struct iovec_iter end = END_IT(buf);

	return buf_it_len(buf, &beg, &end);
}

int buf_memcpy_to(struct io_buf *src, size_t off, void *ptr, size_t len)
{
	int rc;
	struct iovec_iter it_s;
	struct io_buf dst = {
		.iov[0] = {
			.iov_base = ptr,
			.iov_len = len,
		},
		.iov_num = 1,
	};
	struct iovec_iter beg_d = BEG_IT(&dst);

	rc = buf_check(src);
	if (rc)
		return rc;

	it_s = buf_it(src, off);

	return buf_it_append(src, &it_s, &dst, &beg_d, len);
}

static bool is_read_req(struct io_req *req)
{
	return (req->flags & REQ_RDWR_MASK) == REQ_RD;
}

static bool is_write_req(struct io_req *req)
{
	return (req->flags & REQ_RDWR_MASK) == REQ_WR;
}

static bool is_stashed(struct io_queue *q)
{
	return !!q->stash.iov_len;
}

static bool req_exists_to_read_from_stash(struct io_queue *q)
{
	struct io_req *req;

	req = list_first_entry_or_null(&q->queue, struct io_req, list);
	return is_stashed(q) && req && is_read_req(req);
}

static int stash_rest(struct io_req *req, size_t off, size_t end)
{
	struct io_queue *q = req->q;
	struct iovec *st = &q->stash;
	size_t len, sz;

	if (off == INT_MAX) {
		/* Special case, stash everything */
		off = 0;
	}
	len = end - off;

	assert(st->iov_len == 0);
	assert(q->stash_pos == 0);
	if (st->iov_base == NULL || malloc_usable_size(st->iov_base) < len) {
		sz = round_up(len, _4K);
		st->iov_base = realloc(st->iov_base, sz);
		if (st->iov_base == NULL) {
			q->stash.iov_len = 0;
			q->stash_pos = 0;

			return -ENOMEM;
		}
	}
	sz = buf_memcpy_to(&req->buf, off, st->iov_base, len);
	assert(sz == len);
	st->iov_len = len;

	return 0;
}

static void stash_free(struct io_queue *q)
{
	free(q->stash.iov_base);
	q->stash.iov_base = NULL;
	q->stash.iov_len  = 0;
	q->stash_pos      = 0;
}

static int read_from_stash(struct io_queue *q, void *dst, size_t len)
{
	if (q->stash.iov_len) {
		assert(q->stash_pos < q->stash.iov_len);
		len = min(q->stash.iov_len - q->stash_pos, len);
		memcpy(dst, q->stash.iov_base + q->stash_pos, len);
		q->stash_pos += len;
		if (q->stash.iov_len == q->stash_pos) {
			/* Stash fully consumed */
			q->stash.iov_len = 0;
			q->stash_pos = 0;
		}
	} else
		len = 0;

	return len;
}

#define SAFE_CALL(call) ({				\
	int err;					\
							\
	do {						\
		err = call;				\
	} while (err < 0 && errno == EINTR);		\
							\
	if (err < 0)					\
		err = -errno;				\
	err;						\
})

static int __read(int fd, struct io_req *req, size_t len)
{
	int ret, iovlen;
	void *dst;
	struct io_buf *buf = &req->buf;
	struct iovec_iter end = END_IT(buf);

	iovlen = buf_it_iovlen(buf, &buf->pos, &end);
	len = len ? min(len, iovlen) : iovlen;
	dst = buf_it_iovbase(buf, &buf->pos);

	/* Firstly consume stash */
	ret = read_from_stash(req->q, dst, len);
	if (!ret)
		ret = SAFE_CALL(read(fd, dst, len));

	return ret;
}

static int do_read(int fd, struct io_req *req, size_t hint)
{
	struct io_buf *buf = &req->buf;
	int sz;

	assert(req_check(req) == 0);
	if (buf_it_end(buf, &buf->pos) ||
	    buf_it_iovbase(buf, &buf->pos) == NULL) {
		sz = hint ? min(hint, _4K) : _4K;
		sz = buf_it_realloc(buf, &buf->pos, sz);
		if (sz < 0)
			return sz;
	}
	sz = __read(fd, req, hint);
	if (sz < 0) {
		if (sz == -EAGAIN)
			/* Yes, on Linux it is possible to observe
			 * spurious readiness notifications, when
			 * pollers see data available, but recv would
			 * block. See man 2 select, BUGS section.
			 */
			return 0;
	} else if (sz == 0) {
		/* Here we reuse ESHUTDOWN for indicating EOF since read()
		 * or write() never returns it and we can't mixed it up.
		 */
		return -ESHUTDOWN;
	}

	return sz;
}

static int __write(int fd, struct io_req *req)
{
	struct io_buf *buf = &req->buf;
	struct iovec *iov = buf_it_iov(buf, &buf->pos);
	struct iovec iov_stack[ARRAY_SIZE(buf->iov)];
	int iovcnt = buf->iov_num - buf->pos.iov_ind;
	struct iovec_iter end = END_IT(buf);

	if (iov->iov_base == NULL)
		return -EINVAL;
	if (!buf->pos.iov_off) {
		return SAFE_CALL(writev(fd, iov, iovcnt));
	} else {
		iov_stack[0] = (struct iovec){
			.iov_base = buf_it_iovbase(buf, &buf->pos),
			.iov_len  = buf_it_iovlen(buf, &buf->pos, &end)
		};
		if (iovcnt > 1)
			memcpy(iov_stack + 1, iov + 1,
			       sizeof(iov_stack[0]) * (iovcnt - 1));

		return SAFE_CALL(writev(fd, iov_stack, iovcnt));
	}
}

static int do_write(int fd, struct io_req *req)
{
	int sz;

	assert(req_check(req) == 0);
	sz = __write(fd, req);
	if (sz < 0) {
		if (sz == -EAGAIN || sz == -ENOMEM)
			/* Why EAGAIN? Yeah, that's weird. Check
			 * linux/net/ipv4/tcp.c:tcp_sendmsg():wait_for_memory,
			 * in case of memory preasure and nonblock
			 * send EAGAIN will be returned. So relax. */
			return 0;
	}

	return sz;
}

static int complete_req(struct io_req *req, int len)
{
	struct io_queue *q = req->q;

	bool keep_in_queue = false;
	int off, dir;

	dir = req->flags & REQ_RDWR_MASK;
	io_req_get(req);
	list_del_init(&req->list);
	off = req->io_fn(req, len);
	if (dir == REQ_RD) {
		/* Read path */
		if (off == 0) {
			/* Return to the request queue, continue filling in */
			list_add(&req->list, &q->queue);
			keep_in_queue = true;
		} else {
			if (off > 0 && off != len) {
				/* Stash the rest or everything. */
				off = stash_rest(req, off, len);
			}
		}
	}
	io_req_put(req);
	if (!keep_in_queue) {
		assert(q->reqs_num[dir] > 0);
		q->reqs_num[dir]--;
	}

	return off;
}

static void __queue_get(struct io_queue *q)
{
	assert(q->refs > 0);
	q->refs += 1;
}

static void __queue_put(struct io_queue *q)
{
	assert(q->refs > 0);
	q->refs -= 1;
}

static int __poller_ctl(void *poller, int op, struct poller_item *item)
{
	if (poller == POLLER_RESET)
		return 0;
	return poller_ctl(poller, op, item);
}

static int __poller_set(void *poller, struct poller_item *item, int new_events)
{
	int rc = 0, old_events = item->events;

	if (new_events ^ old_events) {
		item->events = new_events;
		if (old_events && new_events)
			rc = __poller_ctl(poller, P_CTL_MOD, item);
		else if (!old_events && new_events)
			rc = __poller_ctl(poller, P_CTL_ADD, item);
		else
			rc = __poller_ctl(poller, P_CTL_DEL, item);
	}

	return rc;
}

static int __poller_update(struct io_queue *q)
{
	struct io_req *req;

	int wr, ev;

	/*
	 * Take first request from the queue and update events.
	 */

	req = list_first_entry_or_null(&q->queue, struct io_req, list);
	if (req) {
		wr = req->flags & REQ_RDWR_MASK;
		ev = wr ? P_OUT : P_IN;
	} else
		ev = 0;

	return __poller_set(q->poller, &q->item, ev);
}

static int prewait_check_stash(void *poller, struct poller_item *item)
{
	struct io_queue *q;

	q = container_of(item, struct io_queue, item);
	if ((item->events & P_IN) && is_stashed(q))
		item->revents |= P_IN;

	return 0;
}

static int __poller_set_prewait(void *poller, struct poller_item *item)
{
	struct io_queue *q;
	struct io_req *req;

	/*
	 * Take first request from the queue and update prewait callback.
	 */

	q = container_of(item, struct io_queue, item);
	req = list_first_entry_or_null(&q->queue, struct io_req, list);
	if (!req || (req->flags & REQ_WR))
		return 0;

	item->prewait = prewait_check_stash;

	return poller_set_prewait(poller, item);
}

static int __poller_clr_prewait(void *poller, struct poller_item *item)
{
	item->prewait = NULL;

	return poller_set_prewait(poller, item);
}

static void __complete_all(struct io_queue *q, int err)
{
	struct io_req *req, *tmp;

	list_for_each_entry_safe(req, tmp, &q->queue, list) {
		(void)complete_req(req, err);
	}
}

static int __io_queue_cancel(struct io_queue *q, int err)
{
	__complete_all(q, err);
	return __poller_set(q->poller, &q->item, 0);
}

static bool can_complete_rd(struct io_buf *buf, size_t sz, size_t hint)
{

	if (hint == 0)
		/*
		 * No hint from proto, so we care only about vari length tail,
		 * which should be completed immediately.  If this is not a
		 * vari length - just check have we reached the end or not.
		 */
		return buf_it_vari_len_tail(buf, &buf->pos) ||
		       buf_it_end(buf, &buf->pos);
	else if (buf_it_vari_len_tail(buf, &buf->pos))
		/*
		 * Proto hinted us, and we are on vari length tail, that means
		 * we must absorb what was told by the proto to have a package
		 * of exact size.
		 */
		return sz == hint;
	else
		/*
		 * Even proto hinted us we have to follow restriction of the
		 * package and reach the end.
		 */
		return buf_it_end(buf, &buf->pos);
}

static int on_io_read(struct io_queue *q)
 {
	struct io_req *req;
	int sz, hint;

	if (!(q->item.revents & P_IN) && !req_exists_to_read_from_stash(q))
		/* Both sources (socket and stash) are empty */
		return 0;

	req = list_first_entry_or_null(&q->queue, struct io_req, list);
	assert(req);
	assert(is_read_req(req));

	hint = CALL_PROTO(dequeue_fn, q, &req);
	if (hint < 0)
		return hint;
	sz = do_read(q->item.fd, req, hint);
	CALL_PROTO(io_fn, q, req, sz, hint);
	if (sz > 0) {
		buf_advance(&req->buf, &req->buf.pos, sz);
		if (can_complete_rd(&req->buf, sz, hint)) {
			sz = buf_pos(&req->buf);
			sz = complete_req(req, sz);
		}
	}
	q->item.revents &= ~P_IN;

	return sz < 0 ? sz : 0;
}

static int on_io_write(struct io_queue *q)
{
	struct io_req *req;
	int sz, hint;

	if (!(q->item.revents & P_OUT))
		return 0;

	req = list_first_entry_or_null(&q->queue, struct io_req, list);
	assert(req);
	assert(is_write_req(req));

	hint = CALL_PROTO(dequeue_fn, q, &req);
	if (hint < 0)
		return hint;
	sz = do_write(q->item.fd, req);
	CALL_PROTO(io_fn, q, req, sz, hint);
	if (sz > 0) {
		buf_advance(&req->buf, &req->buf.pos, sz);
		if (buf_it_end(&req->buf, &req->buf.pos)) {
			sz = buf_pos(&req->buf);
			sz = complete_req(req, sz);
		}
	}
	q->item.revents &= ~P_OUT;

	return sz < 0 ? sz : 0;
}

static int on_io(void *poller, struct poller_item *item)
{
	struct io_queue *q;
	int rc = 0;

	q = container_of(item, struct io_queue, item);
	__queue_get(q);
	if (item->revents & P_ERR) {
		rc = -EIO;
		goto complete_w_error;
	}
	do {
		rc = on_io_write(q);
		if (rc < 0)
			goto complete_w_error;
		rc = on_io_read(q);
		if (rc < 0)
			goto complete_w_error;
	} while (item->revents || req_exists_to_read_from_stash(q));

	/* Clear prewait */
	__poller_clr_prewait(q->poller, &q->item);
	/* Update poller with new events */
	__poller_update(q);
out:
	__queue_put(q);

	return rc;

complete_w_error:
	rc = __io_queue_cancel(q, rc);
	goto out;
}

void io_queue_init(struct io_queue *q)
{
	memset(q, 0, sizeof(*q));
	INIT_LIST_HEAD(&q->queue);
}

void io_queue_deinit(struct io_queue *q)
{
	stash_free(q);
	assert(q->poller == NULL);
	assert(list_empty(&q->queue));
	assert(q->reqs_num[REQ_RD] == 0);
	assert(q->reqs_num[REQ_WR] == 0);
}

int io_queue_bind(struct io_queue *q, void *poller, int fd)
{
	int err, flags;

	if (q->poller)
		return -EINVAL;
	q->refs = 1;
	q->poller = poller;
	q->item = (struct poller_item){
		.fd     = fd,
		.events = 0,
		.data   = NULL,
		.action = on_io,
	};

	flags = fcntl(fd, F_GETFL, 0);
	if  (flags < 0)
		return -errno;
	err = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	if (err < 0)
		return -errno;

	return 0;
}

int io_queue_unbind(struct io_queue *q)
{
	int err;

	if (q->poller == NULL)
		return -EINVAL;
	if (q->refs == 0)
		return -EINVAL;
	if (q->refs > 1)
		return -EBUSY;

	err = __io_queue_cancel(q, -EIO);
	q->poller = NULL;
	q->refs = 0;

	return err;
}

/**
 * io_queue_reset() - resets poller for a queue
 *
 * That's a bit ugly and the only purpose of that call is to mark
 * poller as reset and exclude from further poller_ctl() calls.
 *
 * That is needed after a fork() in a child process, when child
 * can fully inherit poller descriptor and any poller_ctl() calls
 * on destruction path affects parent process.
 */
void io_queue_reset(struct io_queue *q)
{
	q->poller = POLLER_RESET;
}

bool io_queue_binded(struct io_queue *q)
{
	return q->refs != 0;
}

bool io_queue_stashed(struct io_queue *q)
{
	return is_stashed(q);
}

int io_queue_submit(struct io_req *req)
{
	struct io_queue *q = req->q;
	int rc, wr;

	if (q->poller == NULL)
		return -EINVAL;
	rc = req_check(req);
	if (rc)
		return -EINVAL;

	rc = CALL_PROTO(queue_fn, q, &req);
	if (rc < 0)
		return rc;
	if (req == NULL)
		/* Request was accepted by the proto */
		return 0;

	/* Assume proto did a good job */
	assert(req_check(req) == 0);

	wr = req->flags & REQ_RDWR_MASK;
	/*
	 * Firstly add request to the list (either to the head or to the tail)
	 * to simplify __poller_update() and _poller_set_prewait() logic, which
	 * simply picks up first request from the queue and updates poller events
	 * accordingly.
	 */
	if (tail)
		list_add_tail(&req->list, &q->queue);
	else
		list_add(&req->list, &q->queue);

	if (q->refs == 1) {
		if (!wr && is_stashed(q))
			/*
			 * We do submission outside the IO loop, but read can
			 * be completed right now from a stash, thus set prewait
			 * for an event to be called just before poller wait and
			 * then return to on_io.
			 */
			rc = __poller_set_prewait(q->poller, &q->item);

		if (rc == 0)
			rc = __poller_update(q);
	}
	if (rc)
		/* Rollback in case of error */
		list_del_init(&req->list);
	else
		/* Success, account added request */
		q->reqs_num[wr]++;

	return rc;
}

int io_queue_cancel(struct io_queue *q)
{
	if (q->poller == NULL)
		return -EINVAL;

	return __io_queue_cancel(q, -EIO);
}

int io_queue_set_proto(struct io_queue *q, struct io_proto *proto)
{
	if (proto) {
		if (q->proto)
			return -EINVAL;
		proto->q = q;
		q->proto = proto;
	} else {
		if (q->proto == NULL)
			return -EINVAL;
		q->proto->q = NULL;
		q->proto = NULL;
	}

	return 0;
}

void io_req_init(struct io_req *req, struct io_queue *q, int flags,
		 void *data, int (*io_fn)(struct io_req *req, int len))
{
	*req = (struct io_req){
		.list  = LIST_HEAD_INIT(req->list),
		.q     = q,
		.data  = data,
		.flags = flags,
		.refs  = 1,
		.io_fn = io_fn
	};
}

static void __io_req_deinit(struct io_req *req)
{
	assert(req->refs == 0);
	assert(list_empty(&req->list));
	buf_free(&req->buf);
}

void io_req_deinit(struct io_req *req)
{
	assert(req->refs == 1);
	req->refs = 0;
	__io_req_deinit(req);
}

struct io_req *io_req_create(struct io_queue *q, int flags, void *data,
			     int (*io_fn)(struct io_req *req, int len))
{
	struct io_req *req;

	req = malloc(sizeof(*req));
	if (req == NULL)
		return NULL;
	io_req_init(req, q, flags, data, io_fn);

	return req;
}

void io_req_get(struct io_req *req)
{
	assert(req->refs > 0);
	req->refs += 1;
}

bool io_req_put(struct io_req *req)
{
	int refs;

	assert(req->refs > 0);
	refs = --req->refs;
	if (!refs) {
		__io_req_deinit(req);
		free(req);
	}

	return !refs;
}

#ifdef IO_STANDALONE
#ifndef FIXED_LEN
#define FIXED_LEN 0 /* 0 means vari length */
#endif

int main()
{
	char b1[128];
	char b2[128];
	char b3[128];
	int sz;

	struct io_buf buf1 = {
		.iov[0] = {
			.iov_base = "12345",
			.iov_len = strlen("12345"),
		},
		.iov[1] = {
			.iov_base = "abcde",
			.iov_len = strlen("abcde"),
		},
		.iov[2] = {
			.iov_base = "ABCDE",
			.iov_len = strlen("ABCDE"),
		},
		.pos = {
			.iov_off = 5,
			.iov_ind = 2,
		},
		.iov_num = 3,
	};
	struct io_buf buf2 = {
		.iov[0] = {
			.iov_base = b1,
			.iov_len = 5,
		},
		.iov[1] = {
			.iov_base = b2,
			.iov_len = 1,
		},
		.iov[2] = {
			.iov_base = NULL,
			.iov_len = FIXED_LEN,
		},
		.is_vari_len = !FIXED_LEN,
		.iov_num = 3,
	};
	struct iovec_iter it1, it2, beg;

	it1 = buf_it(&buf1, 0);
	it2 = buf_it(&buf2, 0);
	sz = buf_it_append(&buf1, &it1, &buf2, &it2, 1);
	printf("buf_it_append()=%d\n", sz);
	printf("it1 = { .iov_ind=%ld, .iov_off=%ld }\n",
	       it1.iov_ind, it1.iov_off);
	printf("it2 = { .iov_ind=%ld, .iov_off=%ld }\n",
	       it2.iov_ind, it2.iov_off);
	printf("\n");

	it1 = buf_it(&buf1, 4);
	sz = buf_it_append(&buf1, &it1, &buf2, &it2, 128);
	printf("buf_it_append()=%d\n", sz);
	printf("it1 = { .iov_ind=%ld, .iov_off=%ld }\n",
	       it1.iov_ind, it1.iov_off);
	printf("it2 = { .iov_ind=%ld, .iov_off=%ld }\n",
	       it2.iov_ind, it2.iov_off);
	printf("\n");


	it1 = buf_it(&buf1, 14);
	sz = buf_it_append(&buf1, &it1, &buf2, &it2, 128);
	printf("buf_it_append()=%d\n", sz);
	printf("it1 = { .iov_ind=%ld, .iov_off=%ld }\n",
	       it1.iov_ind, it1.iov_off);
	printf("it2 = { .iov_ind=%ld, .iov_off=%ld }\n",
	       it2.iov_ind, it2.iov_off);
	printf("\n");


	beg = buf_it(&buf2, 0);
	printf("result buffers:\n");
	while (buf_it_cmp(&beg, &buf2.pos) < 0) {
		sz = buf_it_iovlen(&buf2, &beg, &buf2.pos);
		printf("  #%ld len=%d, '%.*s'\n",
		       beg.iov_ind, sz, sz,
		       (char *)buf_it_iovbase(&buf2, &beg));
		buf_it_advance(&buf2, &beg, sz);
	}

	sz = buf_memcpy_to(&buf2, 0, b3, sizeof(b3));
	printf("memcpy_to:\n");
	printf("  len=%d, '%.*s'\n", sz, (int)sz, b3);

	buf_free(&buf1);
	buf_free(&buf2);

	return 0;
}
#endif
