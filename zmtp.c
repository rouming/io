/**
 * zmtp.c - Simple and not full implementation of ZMTP protocol,
 *          based on socket IO library.
 *
 *    Implements ZMTP/20 and ZMTP/30 REP protocols:
 *
 *    https://rfc.zeromq.org/spec:15/ZMTP/
 *    https://rfc.zeromq.org/spec:23/ZMTP/
 *    https://rfc.zeromq.org/spec:28/REQREP
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

#include <stdint.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <endian.h>
#include <assert.h>
#include <sys/types.h>

#include "zmtp.h"

#define ZMTP_SIG_S    "\xFF\0\0\0\0\0\0\0\1\x7F"
#define ZMTP_NULL_S   "NULL"
#define ZMTP_DELIM_S  "\x01\0"

#define ZMTP_V2_REP_HS_S "\x04\0\0"
#define ZMTP_V2_REQ_HS_S "\x03\0\0"

#define ZMTP_V3_S        "\x03\x00"
#define ZMTP_V3_REP_HS_S "\x04\x19\x05READY\x0bSocket-Type\0\0\0\x03REP"
#define ZMTP_V3_REQ_HS_S         "\x05READY\x0bSocket-Type\0\0\0\x03REQ"

static uint8_t ZMTP_SIG[10]  = ZMTP_SIG_S;
static uint8_t ZMTP_DELIM[2] = ZMTP_DELIM_S;

static uint8_t ZMTP_V2_REP_HS[3] = ZMTP_V2_REP_HS_S;
static uint8_t ZMTP_V2_REQ_HS[3] = ZMTP_V2_REQ_HS_S;

static uint8_t ZMTP_V3_REP_HS[27] = ZMTP_V3_REP_HS_S;
static uint8_t ZMTP_V3_REQ_HS[25] = ZMTP_V3_REQ_HS_S;

struct zmtp_header {
	uint8_t sign[10];
	uint8_t majv;
};

struct zmtp_greeting_v3 {
	uint8_t minv;
	uint8_t mech[20];
	uint8_t serv;
	uint8_t padd[31];
};

static struct zmtp_header sign_and_maj = {
	.sign = ZMTP_SIG_S,
	.majv = 0x03
};

static struct zmtp_greeting_v3 v3_greet = {
	.minv = 0x00,
	.mech = ZMTP_NULL_S,
	.serv = 0x00,
	.padd = {0x00}
};

enum {
	ZMTP_UNKNOWN = 0,
	ZMTP_REP_IN_GREETING,
	ZMTP_REP_EST_IN_RECV,
	ZMTP_REP_EST_IN_SEND,
	ZMTP_REP_CLOSED,

	ZMTP_F_MORE    = 1,
	ZMTP_F_LONG    = 2,
	ZMTP_F_COMMAND = 4,
	ZMTP_F_MASK    = (ZMTP_F_MORE | ZMTP_F_LONG | ZMTP_F_COMMAND)
};

static int zmtp_expect_msg(struct zmtp *zmtp, struct io_req *req,
			   bool need_payload, bool *more);
static bool is_zmtp_req(struct io_req *req);

static void __complete_all(struct zmtp *zmtp, int err)
{
	struct io_req *req, *tmp;

	list_for_each_entry_safe(req, tmp, &zmtp->orig_reqs, list) {
		list_del(&req->list);
		req->io_fn(req, err);
	}
}

static int __queue_all(struct zmtp *zmtp, int rdwr)
{
	struct io_req *req, *tmp;
	int rc;

	list_for_each_entry_safe(req, tmp, &zmtp->orig_reqs, list) {
		if ((req->flags & REQ_RDWR_MASK) != rdwr)
			continue;
		list_del(&req->list);
		rc = io_queue_submit(req);
		if (rc < 0) {
			list_add(&req->list, &zmtp->orig_reqs);

			return rc;
		}
	}

	return 0;
}

int zmtp_signature_check(const void *buf, size_t len)
{
	if (len < sizeof(ZMTP_SIG))
		return -EINVAL;

	return !!memcmp(buf, ZMTP_SIG, sizeof(ZMTP_SIG));
}

static int zmtp_flags_to_size_len(uint8_t flags)
{
	return flags & ZMTP_F_LONG ? 8 : 1;
}

static int zmtp_parse_hshake(struct io_req *req, int proto)
{
	if (req->buf.iov_num != 3)
		return -EINVAL;
	switch (proto) {
	case ZMTP_REP:
		if (req->buf.iov[2].iov_len < sizeof(ZMTP_V3_REQ_HS))
			return -EINVAL;
		if (memcmp(req->buf.iov[2].iov_base, ZMTP_V3_REQ_HS,
			   sizeof(ZMTP_V3_REQ_HS)))
			return -EINVAL;

		return 0;
	default:
		assert(0);
		/* TODO: currently support only REP<-REQ */
		return -ENOTSUP;
	}
}


static int on_recv__REP(struct io_req *req, int len)
{
	struct zmtp *zmtp = req->data;
	bool more;
	int rc;

	if (len < 0)
		goto out;

	rc = zmtp_expect_msg(zmtp, req, false, &more);
	if (rc < 0) {
		rc = len;
		goto out;
	}
	if (rc == 0)
		/* Package is not fully received, continue */
		return 0;

	zmtp->read_len = rc;
	zmtp->read_more = more;

out:
	io_req_put(req);
	if (len < 0) {
		zmtp->inner_state = ZMTP_REP_CLOSED;
		__complete_all(zmtp, len);
	}

	return len;
}

static void zmtp_init_rd_hdr_req(struct zmtp *zmtp, struct io_req *req)
{
	buf_free(&req->buf);
	req->buf = (struct io_buf){
		.iov[0] = {
			.iov_base = &zmtp->hdr.flags,
			.iov_len  = 1
		},
		.iov_num  = 1,
	};
}

static struct io_req *zmtp_create_rd_hdr_req(struct zmtp *zmtp)
{
	struct io_req *req;

	req = io_req_create(zmtp->io_proto.q, REQ_RD, zmtp, on_recv__REP);
	if (req == NULL)
		return NULL;
	zmtp_init_rd_hdr_req(zmtp, req);

	return req;
}

static int on_send__REP(struct io_req *req, int len)
{
	struct zmtp *zmtp = req->data;

	io_req_put(req);
	if (len > 0) {
		zmtp->sent_num += 1;
		zmtp->hdr_sent = true;
	}

	return len;
}

static void zmtp_init_wr_hdr_req(struct zmtp *zmtp, struct io_req *hdr_req,
				 struct io_req *wr_req)
{
	struct iovec *iov;
	int len = buf_len(&wr_req->buf);

	if (!zmtp->sent_num) {
		/* Firstly set empty delimiter */
		hdr_req->buf.iov[0].iov_base = ZMTP_DELIM;
		hdr_req->buf.iov[0].iov_len  = sizeof(ZMTP_DELIM);
		hdr_req->buf.iov_num = 1;
	}
	iov = &hdr_req->buf.iov[hdr_req->buf.iov_num];
	/* Set flags */
	zmtp->hdr.flags  = wr_req->flags & REQ_MORE ? ZMTP_F_MORE : 0;
	zmtp->hdr.flags |= len > 255 ? ZMTP_F_LONG : 0;
	iov->iov_base = &zmtp->hdr.flags;
	iov->iov_len  = 1;
	iov += 1;
	/* Set size */
	if (len > 255) {
		zmtp->hdr.len = htobe64(len);
		iov->iov_len  = 8;
	} else {
		zmtp->hdr.len = len;
		iov->iov_len  = 1;

	}
	iov->iov_base = &zmtp->hdr.len;

	hdr_req->buf.iov_num += 2;
}

static struct io_req *zmtp_create_wr_hdr_req(struct zmtp *zmtp,
					     struct io_req *wr_req)
{
	struct io_req *req;

	req = io_req_create(zmtp->io_proto.q, REQ_WR, zmtp, on_send__REP);
	if (req == NULL)
		return NULL;
	zmtp_init_wr_hdr_req(zmtp, req, wr_req);

	return req;
}

static int zmtp_expect_msg(struct zmtp *zmtp, struct io_req *req,
			   bool need_payload, bool *more)
{
	int len;
	uint8_t flags;
	uint64_t size;

	assert(req->buf.iov_num >= 1);
	assert(req->buf.iov_num <= 3);

	assert(req->buf.iov[0].iov_len == 1);
	flags = *(uint8_t *)req->buf.iov[0].iov_base;
	if (flags & ~ZMTP_F_MASK) {
		/* TODO: probably respond with ERROR? */
		len = -EMSGSIZE;
		goto out;
	}
	if (req->buf.iov_num == 1) {
		/* Flag is received, size is required */

		len = zmtp_flags_to_size_len(flags);
		if (len < 0)
			goto out;
		/* Advance position by ourselves */
		req->buf.pos.iov_ind = req->buf.iov_num;
		req->buf.pos.iov_off = 0;
		/* Set length of a next buffer to receive */
		req->buf.iov[req->buf.iov_num].iov_len = len;
		req->buf.iov_num += 1;
		len = 0;
	} else {
		/* Flag+size are received */

		/* Short or long size? */
		if (req->buf.iov[1].iov_len == 1)
			size = *(uint8_t *)req->buf.iov[1].iov_base;
		else if (req->buf.iov[1].iov_len == 8) {
			size = *(uint64_t *)req->buf.iov[1].iov_base;
			size = be64toh(size);
		} else
			assert(0);
		if (size > INT_MAX) {
			/* That is insane */
			len = -EMSGSIZE;
			goto out;
		} else
			len = (int)size;
		if (len == 0) {
			/* Delimiter is received. Rewind a buffer and repeat. */
			zmtp_init_rd_hdr_req(zmtp, req);
		} else {
			if (need_payload && req->buf.iov_num == 2) {
				/* Advance position by ourselves */
				req->buf.pos.iov_ind = req->buf.iov_num;
				req->buf.pos.iov_off = 0;
				/* Set size for a payload */
				req->buf.iov[req->buf.iov_num].iov_len = size;
				req->buf.iov_num += 1;
				len = 0;
			}
			if (more)
				*more = !!(flags & ZMTP_F_MORE);
		}
	}

out:
	return len;
}

static int zmtp_switch_to_in_recv(struct zmtp *zmtp)
{
	zmtp->inner_state = ZMTP_REP_EST_IN_RECV;

	return __queue_all(zmtp, REQ_RD);
}

static int on_greet_v3_3_hshake_send__REP(struct io_req *req, int len)
{
	struct zmtp *zmtp = req->data;
	int rc;

	/*
	 * Our hshake is sent, submit all original RD requests.
	 */

	if (len < 0)
		goto out;

	rc = zmtp_switch_to_in_recv(zmtp);
	if (rc < 0) {
		len = rc;
		goto out;
	}

out:
	io_req_put(req);
	if (len < 0) {
		zmtp->inner_state = ZMTP_REP_CLOSED;
		__complete_all(zmtp, len);
	}

	return len;
}

static int on_greet_v3_3_hshake_recv__REP(struct io_req *req, int len)
{
	struct zmtp *zmtp = req->data;
	struct io_req *wr_req;
	int rc;

	/*
	 * Receive full hshake, validate and send our hshake
	 */

	if (len < 0)
		goto out;

	rc = zmtp_expect_msg(zmtp, req, true, NULL);
	if (rc < 0) {
		len = rc;
		goto out;
	}
	if (rc == 0)
		/* Package is not fully received, continue */
		return 0;

	rc = zmtp_parse_hshake(req, ZMTP_REP);
	if (rc < 0) {
		/* TODO: probably respond with ERROR? */
		len = rc;
		goto out;
	}

	/*
	 * Send hshake
	 */
	wr_req = io_req_create(zmtp->io_proto.q, REQ_WR, zmtp,
			       on_greet_v3_3_hshake_send__REP);
	if (wr_req == NULL) {
		len = -ENOMEM;
		goto out;
	}
	wr_req->buf = (struct io_buf){
		.iov[0] = {
			.iov_base = ZMTP_V3_REP_HS,
			.iov_len  = sizeof(ZMTP_V3_REP_HS)
		},
		.iov_num  = 1,
	};
	rc = io_queue_submit(wr_req);
	if (rc) {
		io_req_put(wr_req);
		len = rc;
		goto out;
	}

out:
	io_req_put(req);
	if (len < 0) {
		zmtp->inner_state = ZMTP_REP_CLOSED;
		__complete_all(zmtp, len);
	}

	return len;
}

static int on_greet_v3_2_rest_recv__REP(struct io_req *req, int len)
{
	struct zmtp *zmtp = req->data;
	struct io_req *rd_req;
	struct zmtp_greeting_v3 *greet;
	int rc;

	/*
	 * The rest is received, validate version and recv the REQ hshake
	 */

	if (len < 0)
		goto out;

	/* Validate the rest greeting */
	assert(len == sizeof(*greet));
	greet = req->buf.iov[0].iov_base;
	if (memcmp(&v3_greet, greet,  sizeof(*greet))) {
		len = -EMSGSIZE;
		goto out;
	}

	rd_req = io_req_create(zmtp->io_proto.q, REQ_RD, zmtp,
			       on_greet_v3_3_hshake_recv__REP);
	if (rd_req == NULL) {
		len = -ENOMEM;
		goto out;
	}
	/*
	 * TODO: probably we need generic function for that,
	 * TODO: like zmtp_init_rd_hdr_req() already does.
	 */
	rd_req->buf = (struct io_buf){
		.iov[0] = {
			.iov_len  = 1 /* Flag field to determin the size */
		},
		.iov_num  = 1,
	};
	rc = io_queue_submit(rd_req);
	if (rc) {
		io_req_put(rd_req);
		len = rc;
		goto out;
	}

out:
	io_req_put(req);
	if (len < 0) {
		zmtp->inner_state = ZMTP_REP_CLOSED;
		__complete_all(zmtp, len);
	}

	return len;
}

static int on_greet_v3_2_rest_send__REP(struct io_req *req, int len)
{
	struct zmtp *zmtp = req->data;
	struct io_req *rd_req;
	int rc;

	/*
	 * The rest is send, read the rest from the peer
	 */

	if (len < 0)
		goto out;
	rd_req = io_req_create(zmtp->io_proto.q, REQ_RD, zmtp,
			       on_greet_v3_2_rest_recv__REP);
	if (rd_req == NULL) {
		len = -ENOMEM;
		goto out;
	}
	rd_req->buf = (struct io_buf){
		.iov[0] = {
			.iov_len = sizeof(v3_greet)
		},
		.iov_num = 1,
	};
	rc = io_queue_submit(rd_req);
	if (rc) {
		io_req_put(rd_req);
		len = rc;
		goto out;
	}

out:
	io_req_put(req);
	if (len < 0) {
		zmtp->inner_state = ZMTP_REP_CLOSED;
		__complete_all(zmtp, len);
	}

	return len;
}

static int zmtp_greet_v3_rest_send(struct zmtp *zmtp)
{
	struct io_req *wr_req;
	int rc;

	wr_req = io_req_create(zmtp->io_proto.q, REQ_WR, zmtp,
			       on_greet_v3_2_rest_send__REP);
	if (wr_req == NULL)
		return -ENOMEM;

	wr_req->buf = (struct io_buf){
		.iov[0] = {
			.iov_base = &v3_greet,
			.iov_len  = sizeof(v3_greet)
		},
		.iov_num  = 1,
	};
	rc = io_queue_submit(wr_req);
	if (rc) {
		io_req_put(wr_req);

		return rc;
	}

	return 0;
}

static int on_greet_v2_2_rest_recv__REP(struct io_req *req, int len)
{
	struct zmtp *zmtp = req->data;
	void *greet;
	int rc;

	/*
	 * The rest is received, validate version and recv the REQ hshake
	 */

	if (len < 0)
		goto out;

	/* Validate the rest greeting */
	assert(len == sizeof(ZMTP_V2_REQ_HS));
	greet = req->buf.iov[0].iov_base;
	if (memcmp(ZMTP_V2_REQ_HS, greet,  sizeof(ZMTP_V2_REQ_HS))) {
		len = -EMSGSIZE;
		goto out;
	}

	rc = zmtp_switch_to_in_recv(zmtp);
	if (rc < 0)
		len = rc;

out:
	io_req_put(req);
	if (len < 0) {
		zmtp->inner_state = ZMTP_REP_CLOSED;
		__complete_all(zmtp, len);
	}

	return len;
}

static int on_greet_v2_2_rest_send__REP(struct io_req *req, int len)
{
	struct zmtp *zmtp = req->data;
	struct io_req *rd_req;
	int rc;

	/*
	 * The rest is send, read the rest from the peer
	 */

	if (len < 0)
		goto out;
	rd_req = io_req_create(zmtp->io_proto.q, REQ_RD, zmtp,
			       on_greet_v2_2_rest_recv__REP);
	if (rd_req == NULL) {
		len = -ENOMEM;
		goto out;
	}
	rd_req->buf = (struct io_buf){
		.iov[0] = {
			.iov_len = sizeof(ZMTP_V2_REQ_HS)
		},
		.iov_num = 1,
	};
	rc = io_queue_submit(rd_req);
	if (rc) {
		io_req_put(rd_req);
		len = rc;
		goto out;
	}

out:
	io_req_put(req);
	if (len < 0) {
		zmtp->inner_state = ZMTP_REP_CLOSED;
		__complete_all(zmtp, len);
	}

	return len;
}

static int zmtp_greet_v2_rest_send(struct zmtp *zmtp)
{
	struct io_req *wr_req;
	int rc;

	wr_req = io_req_create(zmtp->io_proto.q, REQ_WR, zmtp,
			       on_greet_v2_2_rest_send__REP);
	if (wr_req == NULL)
		return -ENOMEM;

	wr_req->buf = (struct io_buf){
		.iov[0] = {
			.iov_base = ZMTP_V2_REP_HS,
			.iov_len  = sizeof(ZMTP_V2_REP_HS)
		},
		.iov_num  = 1,
	};
	rc = io_queue_submit(wr_req);
	if (rc) {
		io_req_put(wr_req);

		return rc;
	}

	return 0;
}

static int on_greet_1_sign_recv__REP(struct io_req *req, int len)
{
	struct zmtp *zmtp = req->data;
	struct zmtp_header *hdr;
	int rc;

	/*
	 * Peer signature is received, validate and send the rest
	 */

	if (len < 0)
		goto out;

	/* Validate the signature */
	assert(len == sizeof(*hdr));
	hdr = req->buf.iov[0].iov_base;
	if (zmtp_signature_check(&hdr->sign, len)) {
		len = -EMSGSIZE;
		goto out;
	}

	switch (hdr->majv) {
	case 0x01:
		rc = zmtp_greet_v2_rest_send(zmtp);
		break;
	case 0x03:
		rc = zmtp_greet_v3_rest_send(zmtp);
		break;
	default:
		/* TODO: probably reply with some kind of ERROR? */
		len = -EMSGSIZE;
		goto out;
	}
	if (rc < 0)
		len = rc;

out:
	io_req_put(req);
	if (len < 0) {
		zmtp->inner_state = ZMTP_REP_CLOSED;
		__complete_all(zmtp, len);
	}

	return len;
}

static int on_greet_1_sign_send__REP(struct io_req *req, int len)
{
	struct zmtp *zmtp = req->data;
	struct io_req *rd_req;
	int rc;

	/*
	 * Signature is sent, recv a peer signature
	 */

	assert(zmtp->inner_state == ZMTP_REP_IN_GREETING);
	if (len < 0)
		goto out;
	rd_req = io_req_create(zmtp->io_proto.q, REQ_RD, zmtp,
			       on_greet_1_sign_recv__REP);
	if (rd_req == NULL) {
		len = -ENOMEM;
		goto out;
	}
	rd_req->buf = (struct io_buf){
		.iov[0] = {
			.iov_len  = sizeof(sign_and_maj)
		},
		.iov_num  = 1,
	};
	rc = io_queue_submit(rd_req);
	if (rc) {
		io_req_put(rd_req);
		len = rc;
		goto out;
	}

out:
	io_req_put(req);
	if (len < 0) {
		zmtp->inner_state = ZMTP_REP_CLOSED;
		__complete_all(zmtp, len);
	}

	return len;
}

static int zmtp_start_greeting_REP(struct zmtp *zmtp)
{
	struct io_req *wr_req;
	int rc;

	/*
	 * Start greeting for ZMTP_REP, send only the signature.
	 */

	assert(zmtp->inner_state == ZMTP_UNKNOWN);
	wr_req = io_req_create(zmtp->io_proto.q, REQ_WR, zmtp,
			       on_greet_1_sign_send__REP);
	if (wr_req == NULL)
		return -ENOMEM;
	wr_req->buf = (struct io_buf){
		.iov[0] = {
			.iov_base = &sign_and_maj,
			.iov_len  = sizeof(sign_and_maj)
		},
		.iov_num  = 1,
	};
	rc = io_queue_submit(wr_req);
	if (rc) {
		io_req_put(wr_req);

		return rc;
	}
	zmtp->inner_state = ZMTP_REP_IN_GREETING;

	return 0;
}

static bool is_zmtp_req(struct io_req *req)
{
	return (req->io_fn == on_recv__REP ||
		req->io_fn == on_send__REP ||

		req->io_fn == on_greet_v2_2_rest_recv__REP ||
		req->io_fn == on_greet_v2_2_rest_send__REP ||

		req->io_fn == on_greet_v3_3_hshake_send__REP ||
		req->io_fn == on_greet_v3_3_hshake_recv__REP ||
		req->io_fn == on_greet_v3_2_rest_recv__REP ||
		req->io_fn == on_greet_v3_2_rest_send__REP ||

		req->io_fn == on_greet_1_sign_recv__REP ||
		req->io_fn == on_greet_1_sign_send__REP);
}

static int on_proto_dequeue_REP(struct io_proto *p, struct io_req **req_)
{
	struct zmtp *zmtp;
	struct io_req *req = *req_;

	if (is_zmtp_req(req))
		return 0;

	zmtp = container_of(p, struct zmtp, io_proto);
	if (zmtp->inner_state == ZMTP_REP_CLOSED)
		/* That's all folks */
		return -EINVAL;

	if (req->flags & REQ_WR) {
		assert(zmtp->inner_state == ZMTP_REP_EST_IN_SEND);
		if (zmtp->hdr_sent) {
			zmtp->hdr_sent = false;

			return 0;
		}
		req = zmtp_create_wr_hdr_req(zmtp, req);
		if (req == NULL)
			return -ENOMEM;
	} else {
		if (zmtp->inner_state == ZMTP_REP_EST_IN_SEND) {
			/*
			 * Read requests can be observed in the queue when
			 * the state does not suppose reading in two cases:
			 *
			 * 1. More reads req were submitted, than peer has sent.
			 * 2. Read was returned to the queue (0 from io_fn).
			 */
			return -EINVAL;
		}
		assert(zmtp->inner_state == ZMTP_REP_EST_IN_RECV);
		if (io_queue_stashed(zmtp->io_proto.q))
			/* We handle only reads from socket, not from stash */
			return 0;
		if (zmtp->read_len)
			/* Still have something to read */
			return zmtp->read_len;
		req = zmtp_create_rd_hdr_req(zmtp);
		if (req == NULL)
			return -ENOMEM;
	}
	*req_ = req;

	return 0;
}

static int on_proto_io_REP(struct io_proto *p, struct io_req *req,
			   int len, int hint)
{
	struct zmtp *zmtp = container_of(p, struct zmtp, io_proto);
	int rc;

	if (len < 0) {
		/*
		 * We have to call completion only in certain case and that
		 * is a bit tricky.  ZMTP request can be orphaned and does
		 * not belong to any IO queue only when it was just created.
		 * Only in that particular case we have to call a completion.
		 * In other cases IO queue takes the onwership.
		 */
		if (is_zmtp_req(req) && list_empty(&req->list))
			/* Do not forget to call completion */
			req->io_fn(req, len);

		/* Even in case of error return 0 */
		return 0;
	}
	if (is_zmtp_req(req))
		return 0;

	if (req->flags & REQ_WR) {
		assert(zmtp->inner_state == ZMTP_REP_EST_IN_SEND);
		assert(zmtp->read_len == 0);
		assert(list_empty(&zmtp->orig_reqs));
		if (!(req->flags & REQ_MORE))
			/* Last message was sent */
			zmtp->inner_state = ZMTP_REP_CLOSED;
	} else {
		assert(zmtp->inner_state == ZMTP_REP_EST_IN_RECV);
		assert(zmtp->read_len > 0);
		assert(zmtp->read_len >= len);
		if (hint == 0) {
			/*
			 * Previous dequeue has returned 0 on read from a
			 * stash, do not account anything.
			 */
			return 0;
		}
		zmtp->read_len -= len;
		if (!zmtp->read_len && zmtp->read_more)
			req->flags |= REQ_MORE;
		if (!zmtp->read_len && !zmtp->read_more) {
			/* Do not expect reads any more, switch on send */
			zmtp->inner_state = ZMTP_REP_EST_IN_SEND;
			/*
			 * If read requests are still queued - they will
			 * be completed with error on attempt to dequeue.
			 */
			rc = __queue_all(zmtp, REQ_RD);
			if (rc < 0)
				goto err;
			rc = __queue_all(zmtp, REQ_WR);
			if (rc < 0)
				goto err;
		}
	}

	return 0;

err:
	zmtp->inner_state = ZMTP_REP_CLOSED;
	__complete_all(zmtp, rc);

	/* Yes, here we ignore errors by all means */
	return 0;
}

static int on_proto_queue_REP(struct io_proto *p, struct io_req **req_)
{
	struct io_req *req = *req_;
	struct zmtp *zmtp;
	int rc;

	if (is_zmtp_req(req))
		return 0;

	zmtp = container_of(p, struct zmtp, io_proto);
	switch (zmtp->inner_state) {
	case ZMTP_UNKNOWN:
		if (req->flags & REQ_WR)
			/* This is ZMTP_REP, first request is read request */
			return -EINVAL;
		/* Start greeting */
		rc = zmtp_start_greeting_REP(zmtp);
		if (rc < 0)
			return rc;
		/* Fall thru */
	case ZMTP_REP_IN_GREETING:
		/* Accumulate reqs */
		list_add_tail(&req->list, &zmtp->orig_reqs);
		*req_ = NULL;
		return 0;
	case ZMTP_REP_EST_IN_RECV:
		if (req->flags & REQ_WR) {
			list_add_tail(&req->list, &zmtp->orig_reqs);
			*req_ = NULL;
			return 0;
		}
		/* Will meet in dequeue_fn */
		return 0;
	case ZMTP_REP_EST_IN_SEND:
		if (!(req->flags & REQ_WR))
			/* This is ZMTP_REP, we expect write request */
			return -EINVAL;
		/* Will meet in dequeue_fn */
		return 0;
	case ZMTP_REP_CLOSED:
		/* That's all folks */
		return -ENOTCONN;
	default:
		assert(0);
		return -EINVAL;
	}
}

static int zmtp_init_REP(struct zmtp *zmtp, struct io_queue *q)
{
	*zmtp = (struct zmtp){
		.inner_state = ZMTP_UNKNOWN,
		.io_proto = {
			.queue_fn   = on_proto_queue_REP,
			.dequeue_fn = on_proto_dequeue_REP,
			.io_fn      = on_proto_io_REP
		},
	};
	INIT_LIST_HEAD(&zmtp->orig_reqs);

	return io_queue_set_proto(q, &zmtp->io_proto);
}

int zmtp_init(struct zmtp *zmtp, struct io_queue *q, int proto)
{
	switch(proto) {
	case ZMTP_REP:
		return zmtp_init_REP(zmtp, q);
	default:
		return -EINVAL;
	}
}

void zmtp_deinit(struct zmtp *zmtp)
{
	io_queue_set_proto(zmtp->io_proto.q, NULL);
}
