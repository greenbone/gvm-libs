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

#include "sniffer.h"

#include "alivedetection.h"
#include "boreas_io.h"

#include <arpa/inet.h>
#include <errno.h>
#include <glib.h>
#include <net/if_arp.h>
#include <netinet/ip.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "alive scan"

/* for using int value in #defined string */
#define STR(X) #X
#define ASSTR(X) STR (X)
#define FILTER_STR                                                           \
  "(ip6 or ip or arp) and (ip6[40]=129 or icmp[icmptype] == icmp-echoreply " \
  "or dst port " ASSTR (FILTER_PORT) " or arp[6:2]=2)"

/* Conditional variable and mutex to make sure sniffer thread already started
 * before sending out pings. */
pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t cond = PTHREAD_COND_INITIALIZER;

/**
 * @brief open a new pcap handle ad set provided filter.
 *
 * @param iface interface to use.
 * @param filter pcap filter to use.
 *
 * @return pcap_t handle or NULL on error
 */
static pcap_t *
open_live (char *iface, char *filter)
{
  /* iface considerations:
   * pcap_open_live(iface, ...) sniffs on all interfaces(linux) if iface
   * argument is NULL pcap_lookupnet(iface, ...) is used to set ipv4 network
   * number and mask associated with iface pcap_compile(..., mask) netmask
   * specifies the IPv4 netmask of the network on which packets are being
   * captured; it is used only when checking for IPv4 broadcast addresses in the
   * filter program
   *
   *  If we are not checking for IPv4 broadcast addresses in the filter program
   * we do not need an iface (if we also want to listen on all interface) and we
   * do not need to call pcap_lookupnet
   */
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *pcap_handle;
  struct bpf_program filter_prog;

  /* iface, snapshot length of handle, promiscuous mode, packet buffer timeout
   * (ms), errbuff */
  errbuf[0] = '\0';
  pcap_handle = pcap_open_live (iface, 1500, 0, 100, errbuf);
  if (pcap_handle == NULL)
    {
      g_warning ("%s: %s", __func__, errbuf);
      return NULL;
    }
  if (g_utf8_strlen (errbuf, -1) != 0)
    {
      g_warning ("%s: %s", __func__, errbuf);
    }

  /* handle, struct bpf_program *fp, int optimize, bpf_u_int32 netmask */
  if (pcap_compile (pcap_handle, &filter_prog, filter, 1, PCAP_NETMASK_UNKNOWN)
      < 0)
    {
      char *msg = pcap_geterr (pcap_handle);
      g_warning ("%s: %s", __func__, msg);
      pcap_close (pcap_handle);
      return NULL;
    }

  if (pcap_setfilter (pcap_handle, &filter_prog) < 0)
    {
      char *msg = pcap_geterr (pcap_handle);
      g_warning ("%s: %s", __func__, msg);
      pcap_close (pcap_handle);
      return NULL;
    }
  pcap_freecode (&filter_prog);

  return pcap_handle;
}

/**
 * @brief Processes single packets captured by pcap. Is a callback function.
 *
 * For every packet we check if it is ipv4 ipv6 or arp and extract the sender ip
 * address. This ip address is then inserted into the alive_hosts table if not
 * already present and if in the target table.
 *
 * @param user_data Pointer to scanner.
 * @param header
 * @param packet  Packet to process.
 *
 * TODO: simplify and read https://tools.ietf.org/html/rfc826
 */
static void
got_packet (u_char *user_data,
            __attribute__ ((unused)) const struct pcap_pkthdr *header,
            const u_char *packet)
{
  struct ip *ip;
  unsigned int version;
  struct scanner *scanner;
  hosts_data_t *hosts_data;

  ip = (struct ip *) (packet + 16);
  version = ip->ip_v;
  scanner = (struct scanner *) user_data;
  hosts_data = (hosts_data_t *) scanner->hosts_data;

  if (version == 4)
    {
      gchar addr_str[INET_ADDRSTRLEN];
      struct in_addr sniffed_addr;
      /* was +26 (14 ETH + 12 IP) originally but was off by 2 somehow */
      memcpy (&sniffed_addr.s_addr, packet + 26 + 2, 4);
      if (inet_ntop (AF_INET, (const char *) &sniffed_addr, addr_str,
                     INET_ADDRSTRLEN)
          == NULL)
        g_debug (
          "%s: Failed to transform IPv4 address into string representation: %s",
          __func__, strerror (errno));

      /* Do not put already found host on Queue and only put hosts on Queue we
       * are searching for. */
      if (g_hash_table_add (hosts_data->alivehosts, g_strdup (addr_str))
          && g_hash_table_contains (hosts_data->targethosts, addr_str) == TRUE)
        {
          /* handle max_scan_hosts related restrictions. */
          handle_scan_restrictions (scanner, addr_str);
        }
    }
  else if (version == 6)
    {
      gchar addr_str[INET6_ADDRSTRLEN];
      struct in6_addr sniffed_addr;
      /* (14 ETH + 8 IP + offset 2)  */
      memcpy (&sniffed_addr.s6_addr, packet + 24, 16);
      if (inet_ntop (AF_INET6, (const char *) &sniffed_addr, addr_str,
                     INET6_ADDRSTRLEN)
          == NULL)
        g_debug ("%s: Failed to transform IPv6 into string representation: %s",
                 __func__, strerror (errno));

      /* Do not put already found host on Queue and only put hosts on Queue we
       * are searching for. */
      if (g_hash_table_add (hosts_data->alivehosts, g_strdup (addr_str))
          && g_hash_table_contains (hosts_data->targethosts, addr_str) == TRUE)
        {
          /* handle max_scan_hosts related restrictions. */
          handle_scan_restrictions (scanner, addr_str);
        }
    }
  /* TODO: check collision situations.
   * everything not ipv4/6 is regarded as arp.
   * It may be possible to get other types then arp replies in which case the
   * ip from inet_ntop should be bogus. */
  else
    {
      /* TODO: at the moment offset of 6 is set but arp header has variable
       * sized field. */
      /* read rfc https://tools.ietf.org/html/rfc826 for exact length or how
      to get it */
      struct arphdr *arp =
        (struct arphdr *) (packet + 14 + 2 + 6 + sizeof (struct arphdr));
      gchar addr_str[INET_ADDRSTRLEN];
      if (inet_ntop (AF_INET, (const char *) arp, addr_str, INET_ADDRSTRLEN)
          == NULL)
        g_debug ("%s: Failed to transform IP into string representation: %s",
                 __func__, strerror (errno));

      /* Do not put already found host on Queue and only put hosts on Queue
      we are searching for. */
      if (g_hash_table_add (hosts_data->alivehosts, g_strdup (addr_str))
          && g_hash_table_contains (hosts_data->targethosts, addr_str) == TRUE)
        {
          /* handle max_scan_hosts related restrictions. */
          handle_scan_restrictions (scanner, addr_str);
        }
    }
}

/**
 * @brief Sniff packets by starting pcap_loop with callback function.
 *
 * @param scanner_p Pointer to scanner struct.
 */
static void *
sniffer_thread (void *scanner_p)
{
  int ret;
  struct scanner *scanner = (struct scanner *) scanner_p;

  pthread_mutex_lock (&mutex);
  pthread_cond_signal (&cond);
  pthread_mutex_unlock (&mutex);

  /* reads packets until error or pcap_breakloop() */
  if ((ret =
         pcap_loop (scanner->pcap_handle, -1, got_packet, (u_char *) scanner))
      == PCAP_ERROR)
    g_debug ("%s: pcap_loop error %s", __func__,
             pcap_geterr (scanner->pcap_handle));
  else if (ret == 0)
    g_debug ("%s: count of packets is exhausted", __func__);
  else if (ret == PCAP_ERROR_BREAK)
    g_debug ("%s: Loop was successfully broken after call to pcap_breakloop",
             __func__);

  pthread_exit (0);
}

/**
 * @brief Stop the sniffer thread.
 *
 * @param scanner Pointer to scanner struct.
 * @param sniffer_thread_id pthread_t thread id.
 *
 * @return 0 on success, other on Error.
 */
int
stop_sniffer_thread (struct scanner *scanner, pthread_t sniffer_thread_id)
{
  int err;
  void *retval;

  g_debug ("%s: Try to stop thread which is sniffing for alive hosts. ",
           __func__);
  /* Try to break loop in sniffer thread. */
  pcap_breakloop (scanner->pcap_handle);
  /* Give thread chance to exit on its own. */
  sleep (2);

  /* Cancel thread. May be necessary if pcap_breakloop() does not break the
   * loop. */
  err = pthread_cancel (sniffer_thread_id);
  if (err == ESRCH)
    g_debug ("%s: pthread_cancel() returned ESRCH; No thread with the "
             "supplied ID could be found.",
             __func__);

  /* join sniffer thread*/
  err = pthread_join (sniffer_thread_id, &retval);
  if (err == EDEADLK)
    g_warning ("%s: pthread_join() returned EDEADLK.", __func__);
  if (err == EINVAL)
    g_warning ("%s: pthread_join() returned EINVAL.", __func__);
  if (err == ESRCH)
    g_warning ("%s: pthread_join() returned ESRCH.", __func__);
  if (retval == PTHREAD_CANCELED)
    g_debug ("%s: pthread_join() returned PTHREAD_CANCELED.", __func__);

  g_debug ("%s: Stopped thread which was sniffing for alive hosts.", __func__);

  /* close handle */
  if (scanner->pcap_handle != NULL)
    {
      pcap_close (scanner->pcap_handle);
    }

  return err;
}

/**
 * @brief Start up the sniffer thread.
 *
 * @param scanner Pointer to scanner struct.
 * @param sniffer_thread_id pthread_t thread id.
 *
 * @return 0 on success, other on Error.
 */
int
start_sniffer_thread (struct scanner *scanner, pthread_t *sniffer_thread_id)
{
  int err;

  scanner->pcap_handle = open_live (NULL, FILTER_STR);
  if (scanner->pcap_handle == NULL)
    {
      g_warning ("%s: Unable to open valid pcap handle.", __func__);
      return -1;
    }

  /* Start sniffer thread. */
  err = pthread_create (sniffer_thread_id, NULL, sniffer_thread, scanner);
  if (err == EAGAIN)
    g_warning ("%s: pthread_create() returned EAGAIN: Insufficient resources "
               "to create thread.",
               __func__);

  /* Wait for thread to start up before sending out pings. */
  pthread_mutex_lock (&mutex);
  pthread_cond_wait (&cond, &mutex);
  pthread_mutex_unlock (&mutex);
  /* Mutex and cond not needed anymore. */
  pthread_mutex_destroy (&mutex);
  pthread_cond_destroy (&cond);
  sleep (2);

  return err;
}
