/**
 * zmtp.h - Simple and not full implementation of ZMTP protocol,
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

#ifndef ZMTP_H
#define ZMTP_H

#include <stdint.h>
#include "io.h"

enum {
	ZMTP_REP = 0,
};

struct zmtp {
	struct io_proto io_proto;
	struct {
		uint8_t  flags;
		uint64_t len;
	} hdr;
	int inner_state;
	bool delim_sent;
};

int zmtp_signature_check(const void *buf, size_t len);
int zmtp_init(struct zmtp *zmtp, struct io_queue *q, int proto);
void zmtp_deinit(struct zmtp *zmtp);

#endif /* ZMTP_H */
