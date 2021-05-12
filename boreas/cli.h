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

#ifndef CLI_H
#define CLI_H

#include "alivedetection.h"
#include "boreas_error.h"

boreas_error_t
run_cli (gvm_hosts_t *, alive_test_t, const gchar *);

boreas_error_t
init_cli (scanner_t *, gvm_hosts_t *, alive_test_t, const gchar *, const int);

boreas_error_t
run_cli_scan (scanner_t *, alive_test_t);

boreas_error_t
free_cli (scanner_t *, alive_test_t);

#endif /* not CLI_H */
