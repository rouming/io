/**
 * poller.c - FD poller library to deal with event loops
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

#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <assert.h>
#include <sys/epoll.h>

#include "poller.h"
#include "clock.h"
#include "types.h"

struct poller {
	int epollfd;
	struct list_head prew_list;
};

static void __del_prewait(struct prewait *prew)
{
	assert(prew->item->prews_num);
	prew->item->prews_num -= 1;
	prew->poller = NULL;
	prew->item = NULL;
	list_del(&prew->list);
}

static void del_prewait(struct poller *poller, struct poller_item *item)
{
	int i, prews_num = item->prews_num;
	struct prewait *prew;

	for (i = 0; i < ARRAY_SIZE(item->prews) && prews_num; i++) {
		prew = &item->prews[i];
		if (prew->poller)
			prews_num--;
		if (poller == prew->poller) {
			__del_prewait(prew);
			break;
		}
	}
}

static void del_prewaits(struct poller *poller)
{
	struct prewait *prew, *tmp;

	list_for_each_entry_safe(prew, tmp, &poller->prew_list, list)
		__del_prewait(prew);
}

static int add_prewait(struct poller *poller, struct poller_item *item)
{
	int i, prews_num = item->prews_num;
	struct prewait *prew, *empty = NULL;

	if (prews_num >= ARRAY_SIZE(item->prews))
		return -ENOBUFS;
	for (i = 0; i < ARRAY_SIZE(item->prews); i++) {
		prew = &item->prews[i];
		if (poller == prew->poller)
			/* Already added */
			return 0;
		if (prew->poller) {
			assert(prews_num);
			prews_num -= 1;
		}
		else if (empty == NULL)
			empty = prew;
		if (!prews_num && empty)
			break;
	}
	assert(empty);
	empty->poller = poller;
	empty->item = item;
	list_add_tail(&empty->list, &poller->prew_list);
	item->prews_num += 1;
	assert(item->prews_num <= ARRAY_SIZE(item->prews));

	return 0;
}

static int call_prewaits(struct poller *poller, struct poller_item **pitems,
			 int num)
{
	int i, rc;
	struct prewait *prew;

	if (num == 0)
		return 0;

	i = 0;
	list_for_each_entry(prew, &poller->prew_list, list) {
		prew->item->revents = 0;
		rc = prew->item->prewait(poller, prew->item);
		if (rc)
			return rc;
		if (prew->item->revents) {
			pitems[i++] = prew->item;
			if (i == num)
				break;
		}
	}

	return i;
}

int poller_create(void **p)
{
	int rc;
	struct poller *poller;

	poller = malloc(sizeof(*poller));
	if (poller == NULL)
		return -ENOMEM;
	INIT_LIST_HEAD(&poller->prew_list);
	poller->epollfd = epoll_create1(0);
	if (poller->epollfd < 0) {
		rc = -errno;
		free(poller);

		return rc;
	}
	*p = poller;

	return 0;
}

void poller_destroy(void *p)
{
	struct poller *poller = p;

	if (poller) {
		del_prewaits(poller);
		close(poller->epollfd);
		free(poller);
	}
}

static int to_epoll_op(int op)
{
	int epollop = 0;

	if (op == P_CTL_ADD)
		epollop = EPOLL_CTL_ADD;
	else if (op == P_CTL_MOD)
		epollop = EPOLL_CTL_MOD;
	else if (op == P_CTL_DEL)
		epollop = EPOLL_CTL_DEL;
	else
		return -EINVAL;

	return epollop;
}

static int to_epoll_events(int ev)
{
	int epollev = 0;

	if (ev & P_IN)
		epollev |= EPOLLIN;
	if (ev & P_OUT)
		epollev |= EPOLLOUT;
	if (ev & P_ERR)
		epollev |= EPOLLERR;

	return epollev;
}

int poller_ctl(void *p, int op, struct poller_item *item)
{
	int rc, eop;
	struct poller *poller = p;
	struct epoll_event epollev;

	if (poller == NULL)
		return -EINVAL;
	eop = to_epoll_op(op);
	if (eop < 0)
		return eop;
	if (op == P_CTL_DEL || item->prewait == NULL)
		del_prewait(poller, item);

	epollev = (struct epoll_event){
		.events   = to_epoll_events(item->events),
		.data.ptr = item,
	};
	rc = epoll_ctl(poller->epollfd, eop, item->fd, &epollev);

	return (rc >= 0 ? rc : -errno);
}

int poller_set_prewait(void *p, struct poller_item *item)
{
	int rc = 0;
	struct poller *poller = p;

	if (item->prewait == NULL)
		del_prewait(poller, item);
	else if (item->prewait) {
		/*
		 * Item with a prewait action is a special case:
		 * it can belong to a limit amount of pollers,
		 * thus we have to check and return an error if
		 * no buffers left.
		 */
		rc = add_prewait(poller, item);
	}

	return rc;
}

static int from_epoll_events(int epollev)
{
	int ev = 0;

	if (epollev & EPOLLIN)
		ev |= P_IN;
	if (epollev & EPOLLOUT)
		ev |= P_OUT;
	if (epollev & EPOLLERR)
		ev |= P_ERR;

	return ev;
}

int poller_wait(void *p, struct poller_item **pitems, int num, int timeout)
{
	int rc, i;
	struct poller *poller = p;
	struct epoll_event epollevs[num];
	struct poller_item *item;

	if (poller == NULL)
		return -EINVAL;

	rc = call_prewaits(poller, pitems, num);
	if (rc)
		return rc;
	rc = epoll_wait(poller->epollfd, epollevs, num, tv_to_poll(timeout));
	if (rc > 0) {
		for (i = 0; i < rc; i++) {
			item = (struct poller_item *)epollevs[i].data.ptr;
			item->revents = from_epoll_events(epollevs[i].events);
			pitems[i] = item;
		}
	}

	return (rc >= 0 ? rc : -errno);
}

int poller_do_action(void *poller, struct poller_item *item)
{
	return item->action(poller, item);
}
