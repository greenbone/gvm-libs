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

#include "hostalivedetection.h"

#include "../base/prefs.h"
#include "boreas_error.h"
#include "boreas_io.h"
#include "cli.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "libgvm boreas"

/**
 * @brief Scan all specified hosts in ip_str list.
 *
 * @param[in] ip_str list of hosts to alive test.
 * @param[out] count amount of alive host which were found alived.
 *
 * @return NO_ERROR (0) on success, boreas_error_t on error.
 */
boreas_error_t
is_host_alive (const char *ip_str, int *count)
{
  scanner_t scanner = {0};
  boreas_error_t init_err;
  boreas_error_t run_err;
  boreas_error_t free_err;
  boreas_error_t alive_test_err;
  alive_test_t alive_test;
  gvm_hosts_t *hosts;
  const int print_results = 0;
  const gchar *port_list = NULL;

  hosts = gvm_hosts_new (ip_str);
  if ((alive_test_err = get_alive_test_methods (&alive_test)) != 0)
    {
      g_warning ("%s: %s. Exit Boreas.", __func__,
                 str_boreas_error (alive_test_err));
      pthread_exit (0);
    }

  /* This port list is also used by openvas for scanning and was already
   * validated by openvas so we don't do it here again. */
  port_list = prefs_get ("port_range");

  init_err = init_cli (&scanner, hosts, alive_test, port_list, print_results);
  if (init_err)
    {
      printf ("Error initializing scanner.\n");
      return init_err;
    }

  run_err = run_cli_scan (&scanner, alive_test);
  if (run_err)
    {
      printf ("Error while running the scan.\n");
      return run_err;
    }
  *count = get_alive_hosts_count ();

  free_err = free_cli (&scanner, alive_test);
  if (free_err)
    {
      printf ("Error freeing scan data.\n");
      return free_err;
    }

  return NO_ERROR;
}
