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

#include "cli.h"

#include "../base/networking.h"
#include "../base/prefs.h"
#include "alivedetection.h"
#include "boreas_io.h"
#include "ping.h"
#include "sniffer.h"
#include "util.h"

#include <glib.h>
#include <glib/gprintf.h>
#include <unistd.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "libgvm boreas"

static boreas_error_t
init_cli (scanner_t *scanner, gvm_hosts_t *hosts, alive_test_t alive_test,
          const gchar *port_list, const int print_results)
{
  GPtrArray *portranges_array;
  gvm_host_t *host;
  int error;

  portranges_array = NULL;

  /* No kb used for cli mode.*/
  scanner->main_kb = NULL;
  scanner->print_results = print_results;

  /* hosts_data */
  scanner->hosts_data = g_malloc0 (sizeof (hosts_data_t));
  scanner->hosts_data->alivehosts =
    g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
  scanner->hosts_data->targethosts =
    g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
  for (host = gvm_hosts_next (hosts); host; host = gvm_hosts_next (hosts))
    g_hash_table_insert (scanner->hosts_data->targethosts,
                         gvm_host_value_str (host), host);

  /* Sockets. */
  if ((error = set_all_needed_sockets (scanner, alive_test)) != 0)
    return error;

  /* Only init portlist if either TCP-ACK or TCP-SYN ping is used. */
  if (alive_test & ALIVE_TEST_TCP_SYN_SERVICE
      || alive_test & ALIVE_TEST_TCP_ACK_SERVICE)
    {
      scanner->ports = g_array_new (FALSE, TRUE, sizeof (uint16_t));
      if (port_list)
        portranges_array = port_range_ranges (port_list);
      g_ptr_array_foreach (portranges_array, fill_ports_array, scanner->ports);
      array_free (portranges_array);
    }

  /* No scan restrictions. */
  init_scan_restrictions (scanner, 0);

  return error;
}

static boreas_error_t
free_cli (scanner_t *scanner, alive_test_t alive_test)
{
  int close_err;

  close_err = close_all_needed_sockets (scanner, alive_test);
  if (alive_test & ALIVE_TEST_TCP_SYN_SERVICE
      || alive_test & ALIVE_TEST_TCP_ACK_SERVICE)
    {
      g_array_free (scanner->ports, TRUE);
    }
  g_hash_table_destroy (scanner->hosts_data->alivehosts);
  g_hash_table_destroy (scanner->hosts_data->targethosts);
  g_free (scanner->hosts_data);

  return close_err;
}

static boreas_error_t
run_cli_scan (scanner_t *scanner, alive_test_t alive_test)
{
  int error;
  int number_of_dead_hosts;
  int number_of_targets;
  pthread_t sniffer_thread_id;
  struct timeval start_time, end_time;

  gettimeofday (&start_time, NULL);
  number_of_targets = g_hash_table_size (scanner->hosts_data->targethosts);

  if (scanner->print_results == 1)
    printf ("Alive scan started: Target has %d hosts.\n", number_of_targets);

  error = start_sniffer_thread (scanner, &sniffer_thread_id);
  if (error)
    return error;

  if (alive_test & (ALIVE_TEST_ICMP))
    {
      g_hash_table_foreach (scanner->hosts_data->targethosts, send_icmp,
                            scanner);
      wait_until_so_sndbuf_empty (scanner->icmpv4soc, 10);
      wait_until_so_sndbuf_empty (scanner->icmpv6soc, 10);
      usleep (500000);
    }
  if (alive_test & (ALIVE_TEST_TCP_SYN_SERVICE))
    {
      scanner->tcp_flag = 0x02; /* SYN */
      g_hash_table_foreach (scanner->hosts_data->targethosts, send_tcp,
                            scanner);
      wait_until_so_sndbuf_empty (scanner->tcpv4soc, 10);
      wait_until_so_sndbuf_empty (scanner->tcpv6soc, 10);
      usleep (500000);
    }
  if (alive_test & (ALIVE_TEST_TCP_ACK_SERVICE))
    {
      scanner->tcp_flag = 0x10; /* ACK */
      g_hash_table_foreach (scanner->hosts_data->targethosts, send_tcp,
                            scanner);
      wait_until_so_sndbuf_empty (scanner->tcpv4soc, 10);
      wait_until_so_sndbuf_empty (scanner->tcpv6soc, 10);
      usleep (500000);
    }
  if (alive_test & (ALIVE_TEST_ARP))
    {
      g_hash_table_foreach (scanner->hosts_data->targethosts, send_arp,
                            scanner);
      wait_until_so_sndbuf_empty (scanner->arpv4soc, 10);
      wait_until_so_sndbuf_empty (scanner->arpv6soc, 10);
      usleep (500000);
    }

  sleep (WAIT_FOR_REPLIES_TIMEOUT);

  stop_sniffer_thread (scanner, sniffer_thread_id);

  number_of_dead_hosts = count_difference (scanner->hosts_data->targethosts,
                                           scanner->hosts_data->alivehosts);
  gettimeofday (&end_time, NULL);
  if (scanner->print_results == 1)
    printf ("Alive scan finished in %ld seconds: %d alive hosts of %d.\n",
            end_time.tv_sec - start_time.tv_sec,
            number_of_targets - number_of_dead_hosts, number_of_targets);

  return error;
}

boreas_error_t
run_cli (gvm_hosts_t *hosts, alive_test_t alive_test, const gchar *port_list)
{
  scanner_t scanner = {0};
  boreas_error_t init_err;
  boreas_error_t run_err;
  boreas_error_t free_err;
  int print_results = 1;

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

  free_err = free_cli (&scanner, alive_test);
  if (free_err)
    {
      printf ("Error freeing scan data.\n");
      return free_err;
    }

  return NO_ERROR;
}

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
