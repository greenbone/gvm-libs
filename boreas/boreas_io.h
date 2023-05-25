/* SPDX-FileCopyrightText: 2020-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef BOREAS_IO_H
#define BOREAS_IO_H

#include "../base/hosts.h"
#include "../util/kb.h"
#include "alivedetection.h"
#include "boreas_error.h"

gvm_host_t *
get_host_from_queue (kb_t, gboolean *);

void
put_host_on_queue (kb_t, char *);

void
put_finish_signal_on_queue (void *);

void realloc_finish_signal_on_queue (kb_t);

int finish_signal_on_queue (kb_t);

void
send_dead_hosts_to_ospd_openvas (int);

void
init_scan_restrictions (scanner_t *, int);

void
handle_scan_restrictions (scanner_t *, gchar *);

gchar *
get_openvas_scan_id (const gchar *, int);

boreas_error_t
get_alive_test_methods (alive_test_t *);

const gchar *
get_alive_test_ports (void);

unsigned int
get_alive_test_wait_timeout (void);

int
get_alive_hosts_count (void);

#endif /* not BOREAS_IO_H */
