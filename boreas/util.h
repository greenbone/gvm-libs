/* Copyright (C) 2020-2021 Greenbone Networks GmbH
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

#ifndef BOREAS_UTIL_H
#define BOREAS_UTIL_H

#include "alivedetection.h"
#include "boreas_error.h"

#include <stdint.h>

uint16_t
in_cksum (uint16_t *addr, int len);

int
get_source_mac_addr (char *, uint8_t *);

boreas_error_t
get_source_addr_v6 (int *, struct in6_addr *, struct in6_addr *);

boreas_error_t
get_source_addr_v4 (int *, struct in_addr *, struct in_addr *);

void fill_ports_array (gpointer, gpointer);

boreas_error_t
set_all_needed_sockets (struct scanner *, alive_test_t);

boreas_error_t
close_all_needed_sockets (struct scanner *, alive_test_t);

void
wait_until_so_sndbuf_empty (int, int);

/* Misc hashtable functions. */

int
count_difference (GHashTable *, GHashTable *);

#endif /* not BOREAS_UTIL_H */
