/* Copyright (C) 2020 Greenbone Networks GmbH
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
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

#ifndef BOREAS_IO_H
#define BOREAS_IO_H

#include "../base/hosts.h"
#include "../util/kb.h"
#include "alivedetection.h"
#include "boreas_error.h"

gvm_host_t *
get_host_from_queue (kb_t alive_hosts_kb, gboolean *alive_detection_finished);

void
put_host_on_queue (kb_t kb, char *addr_str);

void
put_finish_signal_on_queue (void *error);

int
send_dead_hosts_to_ospd_openvas (struct hosts_data *hosts_data);

gchar *
get_openvas_scan_id (const gchar *db_address, int db_id);

boreas_error_t
get_alive_test_methods (alive_test_t *alive_test);

#endif
