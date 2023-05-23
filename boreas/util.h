/* SPDX-FileCopyrightText: 2020-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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
set_all_needed_sockets (scanner_t *, alive_test_t);

boreas_error_t
close_all_needed_sockets (scanner_t *, alive_test_t);

void
wait_until_so_sndbuf_empty (int, int);

/* Misc hashtable functions. */

int
count_difference (GHashTable *, GHashTable *);

#endif /* not BOREAS_UTIL_H */
