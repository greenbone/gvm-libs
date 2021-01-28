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

#include "alivedetection.h"

#include "../base/networking.h" /* for validate_port_range(), port_range_ranges() */
#include "../base/prefs.h"      /* for prefs_get() */
#include "../util/kb.h"         /* for kb_t operations */
#include "boreas_error.h"
#include "boreas_io.h"
#include "ping.h"
#include "sniffer.h"
#include "util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <ifaddrs.h> /* for getifaddrs() */
#include <net/ethernet.h>
#include <net/if.h> /* for if_nametoindex() */
#include <net/if_arp.h>
#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netpacket/packet.h> /* for sockaddr_ll */
#include <pcap.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "alive scan"

struct scanner scanner;

/**
 * @brief Scan function starts a sniffing thread which waits for packets to
 * arrive and sends pings to hosts we want to test. Blocks until Scan is
 * finished or error occurred.
 *
 * Start a sniffer thread. Get what method of alive detection to use. Send
 * appropriate pings  for every host we want to test.
 *
 * @return 0 on success, <0 on failure.
 */
static int
scan (alive_test_t alive_test)
{
  int number_of_targets;
  int number_of_dead_hosts;
  pthread_t sniffer_thread_id;
  GHashTableIter target_hosts_iter;
  gpointer key, value;
  struct timeval start_time, end_time;
  int scandb_id;
  gchar *scan_id;

  gettimeofday (&start_time, NULL);
  number_of_targets = g_hash_table_size (scanner.hosts_data->targethosts);

  scandb_id = atoi (prefs_get ("ov_maindbid"));
  scan_id = get_openvas_scan_id (prefs_get ("db_address"), scandb_id);
  g_message ("Alive scan %s started: Target has %d hosts", scan_id,
             number_of_targets);

  sniffer_thread_id = 0;
  start_sniffer_thread (&scanner, &sniffer_thread_id);

  if (alive_test & ALIVE_TEST_ICMP)
    {
      g_debug ("%s: ICMP Ping", __func__);
      g_hash_table_foreach (scanner.hosts_data->targethosts, send_icmp,
                            &scanner);
      wait_until_so_sndbuf_empty (scanner.icmpv4soc, 10);
      wait_until_so_sndbuf_empty (scanner.icmpv6soc, 10);
      usleep (500000);
    }
  if (alive_test & ALIVE_TEST_TCP_SYN_SERVICE)
    {
      g_debug ("%s: TCP-SYN Service Ping", __func__);
      scanner.tcp_flag = TH_SYN; /* SYN */
      g_hash_table_foreach (scanner.hosts_data->targethosts, send_tcp,
                            &scanner);
      wait_until_so_sndbuf_empty (scanner.tcpv4soc, 10);
      wait_until_so_sndbuf_empty (scanner.tcpv6soc, 10);
      usleep (500000);
    }
  if (alive_test & ALIVE_TEST_TCP_ACK_SERVICE)
    {
      g_debug ("%s: TCP-ACK Service Ping", __func__);
      scanner.tcp_flag = TH_ACK; /* ACK */
      g_hash_table_foreach (scanner.hosts_data->targethosts, send_tcp,
                            &scanner);
      wait_until_so_sndbuf_empty (scanner.tcpv4soc, 10);
      wait_until_so_sndbuf_empty (scanner.tcpv6soc, 10);
      usleep (500000);
    }
  if (alive_test & ALIVE_TEST_ARP)
    {
      g_debug ("%s: ARP Ping", __func__);
      g_hash_table_foreach (scanner.hosts_data->targethosts, send_arp,
                            &scanner);
      wait_until_so_sndbuf_empty (scanner.arpv4soc, 10);
      wait_until_so_sndbuf_empty (scanner.arpv6soc, 10);
    }
  if (alive_test & ALIVE_TEST_CONSIDER_ALIVE)
    {
      g_debug ("%s: Consider Alive", __func__);
      for (g_hash_table_iter_init (&target_hosts_iter,
                                   scanner.hosts_data->targethosts);
           g_hash_table_iter_next (&target_hosts_iter, &key, &value);)
        {
          g_hash_table_add (scanner.hosts_data->alivehosts, g_strdup (key));
          handle_scan_restrictions (&scanner, key);
        }
    }

  g_debug (
    "%s: all ping packets have been sent, wait a bit for rest of replies.",
    __func__);

  /* If all targets are already identified as alive we do not need to wait for
   * replies anymore.*/
  if (number_of_targets
      != (int) g_hash_table_size (scanner.hosts_data->alivehosts))
    sleep (WAIT_FOR_REPLIES_TIMEOUT);

  stop_sniffer_thread (&scanner, sniffer_thread_id);

  number_of_dead_hosts = count_difference (scanner.hosts_data->targethosts,
                                           scanner.hosts_data->alivehosts);

  /* Send number of dead hosts to ospd-openvas. We need to consider the scan
   * restrictions.*/
  if (scanner.scan_restrictions->max_scan_hosts_reached)
    {
      send_dead_hosts_to_ospd_openvas (
        number_of_targets - scanner.scan_restrictions->max_scan_hosts);
    }
  else
    {
      send_dead_hosts_to_ospd_openvas (number_of_dead_hosts);
    }

  gettimeofday (&end_time, NULL);

  g_message ("Alive scan %s finished in %ld seconds: %d alive hosts of %d.",
             scan_id, end_time.tv_sec - start_time.tv_sec,
             number_of_targets - number_of_dead_hosts, number_of_targets);
  g_free (scan_id);

  return 0;
}

/**
 * @brief Initialise the alive detection scanner.
 *
 * Fill scanner struct with appropriate values.
 *
 * @param hosts gvm_hosts_t list of hosts to alive test.
 * @param alive_test methods to use for alive detection.
 *
 * @return 0 on success, boreas_error_t on error.
 */
static boreas_error_t
alive_detection_init (gvm_hosts_t *hosts, alive_test_t alive_test)
{
  g_debug ("%s: Initialise alive scanner. ", __func__);

  /* Used for ports array initialisation. */
  const gchar *port_list = NULL;
  GPtrArray *portranges_array = NULL;
  boreas_error_t error = NO_ERROR;

  /* Scanner */

  /* Sockets */
  if ((error = set_all_needed_sockets (&scanner, alive_test)) != 0)
    return error;

  /* kb_t redis connection */
  int scandb_id = atoi (prefs_get ("ov_maindbid"));
  if ((scanner.main_kb = kb_direct_conn (prefs_get ("db_address"), scandb_id))
      == NULL)
    return -7;
  /* TODO: pcap handle */
  // scanner.pcap_handle = open_live (NULL, FILTER_STR); //
  scanner.pcap_handle = NULL; /* is set in ping function */

  /* Results data */
  /* hashtables */
  scanner.hosts_data = g_malloc0 (sizeof (hosts_data_t));
  scanner.hosts_data->alivehosts =
    g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
  scanner.hosts_data->targethosts =
    g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);

  /* put all hosts we want to check in hashtable */
  gvm_host_t *host;
  for (host = gvm_hosts_next (hosts); host; host = gvm_hosts_next (hosts))
    {
      g_hash_table_insert (scanner.hosts_data->targethosts,
                           gvm_host_value_str (host), host);
    }
  /* reset hosts iter */
  hosts->current = 0;

  /* Init ports used for scanning. */
  scanner.ports = NULL;
  port_list = "80,137,587,3128,8081";
  if (validate_port_range (port_list))
    {
      g_warning ("%s: Invalid port range supplied for alive detection module. "
                 "Using global port range instead.",
                 __func__);
      /* This port list was already validated by openvas so we don't do it here
       * again. */
      port_list = prefs_get ("port_range");
    }
  /* Use uint16_t for port array elements. tcphdr port type is uint16_t. */
  scanner.ports = g_array_new (FALSE, TRUE, sizeof (uint16_t));
  if (port_list)
    portranges_array = port_range_ranges (port_list);
  else
    g_warning (
      "%s: Port list supplied by user is empty. Alive detection may not find "
      "any alive hosts when using TCP ACK/SYN scanning methods. ",
      __func__);
  /* Fill ports array with ports from the ranges. Duplicate ports are not
   * removed. */
  g_ptr_array_foreach (portranges_array, fill_ports_array, scanner.ports);
  array_free (portranges_array);

  /* Scan restrictions. max_scan_hosts related. */
  const gchar *pref_str;
  int max_scan_hosts = INT_MAX;
  if ((pref_str = prefs_get ("max_scan_hosts")) != NULL)
    max_scan_hosts = atoi (pref_str);

  init_scan_restrictions (&scanner, max_scan_hosts);

  g_debug ("%s: Initialisation of alive scanner finished.", __func__);

  return error;
}

/**
 * @brief Free all the data used by the alive detection scanner.
 *
 * @param[out] error Set to 0 on success, boreas_error_t on error.
 */
static void
alive_detection_free (void *error)
{
  boreas_error_t alive_test_err;
  boreas_error_t close_err;
  boreas_error_t error_out;
  alive_test_t alive_test;

  error_out = NO_ERROR;
  alive_test_err = get_alive_test_methods (&alive_test);
  if (alive_test_err)
    {
      g_warning ("%s: %s. Could not get info about which sockets to close.",
                 __func__, str_boreas_error (alive_test_err));
      error_out = BOREAS_CLEANUP_ERROR;
    }
  else
    {
      close_err = close_all_needed_sockets (&scanner, alive_test);
      if (close_err)
        error_out = BOREAS_CLEANUP_ERROR;
    }

  /*pcap_close (scanner.pcap_handle); //pcap_handle is closed in ping/scan
   * function for now */
  if ((kb_lnk_reset (scanner.main_kb)) != 0)
    {
      g_warning ("%s: error in kb_lnk_reset()", __func__);
      error_out = BOREAS_CLEANUP_ERROR;
    }

  /* Ports array. */
  g_array_free (scanner.ports, TRUE);

  g_hash_table_destroy (scanner.hosts_data->alivehosts);
  /* targethosts: (ipstr, gvm_host_t *)
   * gvm_host_t are freed by caller of start_alive_detection()! */
  g_hash_table_destroy (scanner.hosts_data->targethosts);
  g_free (scanner.hosts_data);

  /* Set error. */
  *(boreas_error_t *) error = error_out;
}

/**
 * @brief Start the scan of all specified hosts in gvm_hosts_t
 * list. Finish signal is put on Queue if scan is finished or an error occurred.
 *
 * @param hosts_to_test gvm_hosts_t list of hosts to alive test. which is to be
 * freed by caller.
 */
void *
start_alive_detection (void *hosts_to_test)
{
  boreas_error_t init_err;
  boreas_error_t alive_test_err;
  boreas_error_t fin_err;
  boreas_error_t free_err;
  gvm_hosts_t *hosts;
  alive_test_t alive_test;

  if ((alive_test_err = get_alive_test_methods (&alive_test)) != 0)
    {
      g_warning ("%s: %s. Exit Boreas.", __func__,
                 str_boreas_error (alive_test_err));
      put_finish_signal_on_queue (&fin_err);
      if (fin_err)
        g_warning ("%s: Could not put finish signal on Queue. Openvas needs to "
                   "be stopped manually. ",
                   __func__);
      pthread_exit (0);
    }

  hosts = (gvm_hosts_t *) hosts_to_test;
  if ((init_err = alive_detection_init (hosts, alive_test)) != 0)
    {
      g_warning (
        "%s. Boreas could not initialise alive detection. %s. Exit Boreas.",
        __func__, str_boreas_error (init_err));
      put_finish_signal_on_queue (&fin_err);
      if (fin_err)
        g_warning ("%s: Could not put finish signal on Queue. Openvas needs to "
                   "be stopped manually. ",
                   __func__);
      pthread_exit (0);
    }

  /* If alive detection thread returns, is canceled or killed unexpectedly all
   * used resources are freed and sockets, connections closed.*/
  pthread_cleanup_push (alive_detection_free, &free_err);
  /* If alive detection thread returns, is canceled or killed unexpectedly a
   * finish signal is put on the queue for openvas to process.*/
  pthread_cleanup_push (put_finish_signal_on_queue, &fin_err);

  /* Start the scan. */
  if (scan (alive_test) < 0)
    g_warning ("%s: error in scan()", __func__);

  /* Put finish signal on queue. */
  pthread_cleanup_pop (1);
  /* Free memory, close sockets and connections. */
  pthread_cleanup_pop (1);
  if (free_err)
    g_warning ("%s: %s. Exit Boreas thread none the less.", __func__,
               str_boreas_error (free_err));

  pthread_exit (0);
}
