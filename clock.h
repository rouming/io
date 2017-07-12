/**
 * clock.h - Clock helper functions
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

#ifndef CLOCK_H
#define CLOCK_H

#include <unistd.h>
#include <time.h>
#include <limits.h>

enum {
	_5_SEC  = 5000,
	_10_MIN = 600000,
};

static inline unsigned long long msecs_epoch(void)
{
	struct timespec ts;
	unsigned long long msecs;

	clock_gettime(CLOCK_REALTIME, &ts);
	msecs  = ts.tv_sec * 1000ull;
	msecs += ts.tv_nsec / 1000000ull;

	return msecs;
}

static inline void tv_from_msecs(struct timespec *tv, int timeout)
{
	tv->tv_sec  = timeout / 1000;
	tv->tv_nsec = (timeout % 1000) * 1000000;
}

static inline struct timespec *tv_to_select(struct timespec *ts, int timeout)
{
	if (timeout == INT_MAX)
		return NULL;
	tv_from_msecs(ts, timeout);

	return ts;
}

static inline int tv_to_poll(int tv)
{
	return (tv == INT_MAX ? -1 : tv);
}

#endif /* CLOCK_H */
