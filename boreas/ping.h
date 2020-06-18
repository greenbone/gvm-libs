/* Copyright (C) 2020 Greenbone Networks GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef BOREAS_PING_H
#define BOREAS_PING_H

#include "alivedetection.h"

#include <netinet/in.h>

void
send_icmp_v6 (int, struct in6_addr *, int);

void
send_icmp_v4 (int, struct in_addr *);

void
send_tcp_v6 (struct scanner *, struct in6_addr *);

void
send_tcp_v4 (struct scanner *, struct in_addr *);

void
send_arp_v4 (int, struct in_addr *);

#endif /* not BOREAS_PING_H */
