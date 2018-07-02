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

#define TO_HEAD false
#define TO_TAIL true

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
	ZMTP_REP_CONNECTED,
	ZMTP_REP_CLOSED,

	ZMTP_F_MORE    = 1,
	ZMTP_F_LONG    = 2,
	ZMTP_F_COMMAND = 4,
	ZMTP_F_MASK    = (ZMTP_F_MORE | ZMTP_F_LONG | ZMTP_F_COMMAND)
};

static int zmtp_expect_msg(struct zmtp *zmtp, struct io_req *req,
			   bool need_payload, bool *more);

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
	struct io_queue *q = zmtp->io_proto.q;
	struct io_req *rd_req;
	int exp_len;
	bool more;

	if (len < 0)
		goto out;

	exp_len = zmtp_expect_msg(zmtp, req, false, &more);
	if (exp_len < 0) {
		len = exp_len;
		goto out;
	}
	if (exp_len == 0)
		/* Package is not fully received, continue */
		return 0;

	rd_req = list_first_entry_or_null(&q->queue, struct io_req, list);
	/* Should be checked by on_proto_submit_REP() */
	assert(rd_req);
	assert((rd_req->flags & REQ_RDWR_MASK) == REQ_RD);

	if (!buf_vari_len(&rd_req->buf)) {
		/* Expect exact size if request is not of a variable length */
		if (exp_len != (buf_len(&rd_req->buf) - buf_pos(&rd_req->buf))) {
			len = -EPROTO;
			goto out;
		}
	} else {
		rd_req->buf.__proto.read_hint = exp_len;
	}
	if (more)
		rd_req->flags |= REQ_MORE;

out:
	io_req_put(req);
	if (len < 0)
		zmtp->inner_state = ZMTP_REP_CLOSED;

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
	io_req_put(req);

	return len;
}

static void zmtp_init_wr_hdr_req(struct zmtp *zmtp, struct io_req *hdr_req,
				 struct io_req *wr_req)
{
	int len = buf_len(&wr_req->buf);
	struct iovec *iov;
	uint8_t *hdr_flags;
	uint64_t *hdr_len;
	int hdr_len_sz;

	if (!zmtp->delim_sent) {
		zmtp->delim_sent = true;
		/* Firstly set empty delimiter */
		hdr_req->buf.iov[0].iov_base = ZMTP_DELIM;
		hdr_req->buf.iov[0].iov_len  = sizeof(ZMTP_DELIM);
		hdr_req->buf.iov_num = 1;
	}
	if (!(wr_req->flags & REQ_MORE))
		zmtp->delim_sent = false;

	BUILD_BUG_ON(sizeof(hdr_req->buf.__proto.stash) <
		     sizeof(*hdr_flags) + sizeof(*hdr_len));

	/* Set size */
	hdr_len = (typeof(hdr_len))hdr_req->buf.__proto.stash;
	if (len > 255) {
		*hdr_len = htobe64((uint64_t)len);
		hdr_len_sz = 8;
	} else {
		*hdr_len = (uint8_t)len;
		hdr_len_sz = 1;
	}

	/* Set flags */
	hdr_flags = (typeof(hdr_flags))hdr_len + 1;
	*hdr_flags  = wr_req->flags & REQ_MORE ? ZMTP_F_MORE : 0;
	*hdr_flags |= len > 255 ? ZMTP_F_LONG : 0;

	/* Apply pointers to iov */
	iov = &hdr_req->buf.iov[hdr_req->buf.iov_num];
	iov->iov_base = hdr_flags;
	iov->iov_len  = 1;
	iov += 1;
	iov->iov_base = hdr_len;
	iov->iov_len  = hdr_len_sz;
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

static int on_greet_v3_3_hshake_send__REP(struct io_req *req, int len)
{
	struct zmtp *zmtp = req->data;

	/*
	 * Our hshake is sent, ready for incoming data.
	 */
	io_req_put(req);

	if (len < 0)
		zmtp->inner_state = ZMTP_REP_CLOSED;

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
	rc = zmtp->io_proto.submit(wr_req, TO_HEAD);
	if (rc) {
		io_req_put(wr_req);
		len = rc;
		goto out;
	}

out:
	io_req_put(req);
	if (len < 0)
		zmtp->inner_state = ZMTP_REP_CLOSED;

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
	rc = zmtp->io_proto.submit(rd_req, TO_HEAD);
	if (rc) {
		io_req_put(rd_req);
		len = rc;
		goto out;
	}

out:
	io_req_put(req);
	if (len < 0)
		zmtp->inner_state = ZMTP_REP_CLOSED;

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
	rc = zmtp->io_proto.submit(rd_req, TO_HEAD);
	if (rc) {
		io_req_put(rd_req);
		len = rc;
		goto out;
	}

out:
	io_req_put(req);
	if (len < 0)
		zmtp->inner_state = ZMTP_REP_CLOSED;

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
	rc = zmtp->io_proto.submit(wr_req, TO_HEAD);
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
out:
	io_req_put(req);
	if (len < 0)
		zmtp->inner_state = ZMTP_REP_CLOSED;

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
	rc = zmtp->io_proto.submit(rd_req, TO_HEAD);
	if (rc) {
		io_req_put(rd_req);
		len = rc;
		goto out;
	}

out:
	io_req_put(req);
	if (len < 0)
		zmtp->inner_state = ZMTP_REP_CLOSED;

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
	rc = zmtp->io_proto.submit(wr_req, TO_HEAD);
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
	if (len < 0)
		zmtp->inner_state = ZMTP_REP_CLOSED;

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
	rc = zmtp->io_proto.submit(rd_req, TO_HEAD);
	if (rc) {
		io_req_put(rd_req);
		len = rc;
		goto out;
	}

out:
	io_req_put(req);
	if (len < 0)
		zmtp->inner_state = ZMTP_REP_CLOSED;

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
	rc = zmtp->io_proto.submit(wr_req, TO_HEAD);
	if (rc) {
		io_req_put(wr_req);

		return rc;
	}
	zmtp->inner_state = ZMTP_REP_CONNECTED;

	return 0;
}

static int on_proto_submit_REP(struct io_proto *p, struct io_req *req)
{
	struct io_req *hdr_req;
	struct zmtp *zmtp;
	int rc;

	zmtp = container_of(p, struct zmtp, io_proto);
	if (zmtp->inner_state == ZMTP_REP_CLOSED)
		/* That's all folks */
		return -ENOTCONN;

	if (req->flags & REQ_WR)
		hdr_req = zmtp_create_wr_hdr_req(zmtp, req);
	else
		hdr_req = zmtp_create_rd_hdr_req(zmtp);

	if (hdr_req == NULL)
		return -ENOMEM;

	rc = zmtp->io_proto.submit(hdr_req, TO_TAIL);
	if (rc)
		return rc;

	if (zmtp->inner_state == ZMTP_UNKNOWN)
		/* Start greeting */
		return zmtp_start_greeting_REP(zmtp);

	return 0;
}

static int zmtp_init_REP(struct zmtp *zmtp, struct io_queue *q)
{
	*zmtp = (struct zmtp){
		.inner_state = ZMTP_UNKNOWN,
		.io_proto = {
			.on_submit = on_proto_submit_REP,
		},
	};

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
