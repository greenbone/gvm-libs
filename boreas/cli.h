/* SPDX-FileCopyrightText: 2020-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _GVM_BOREAS_CLI_H
#define _GVM_BOREAS_CLI_H

#include "alivedetection.h"
#include "boreas_error.h"

boreas_error_t
run_cli_extended (gvm_hosts_t *, alive_test_t, const gchar *,
                  const unsigned int);

boreas_error_t
run_cli (gvm_hosts_t *, alive_test_t, const gchar *);

boreas_error_t
is_host_alive (const char *, int *);

#endif /* not _GVM_BOREAS_CLI_H */
