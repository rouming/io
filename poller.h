/**
 * poller.h - FD poller library to deal with event loops
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

#ifndef POLLER_H
#define POLLER_H

#include "list.h"

enum {
	P_CTL_ADD = 0,
	P_CTL_MOD = 1,
	P_CTL_DEL = 2,

	P_ERR = 1,
	P_IN  = 2,
	P_OUT = 4,
};

struct poller_item;
struct prewait {
	void *poller;
	struct poller_item *item;
	struct list_head list;
};

struct poller_item {
	int fd;
	int events;
	int revents;
	void *data;
	int prews_num;
	struct prewait prews[8];
	int (*prewait)(void *poller, struct poller_item *item);
	int (*action)(void *poller, struct poller_item *item);
};

int poller_create(void **poller);
void poller_destroy(void *poller);
int poller_ctl(void *poller, int op, struct poller_item *item);
int poller_set_prewait(void *p, struct poller_item *item);
int poller_wait(void *poller, struct poller_item **items, int num, int timeout);
int poller_do_action(void *poller, struct poller_item *item);

#endif /* POLLER_H */
