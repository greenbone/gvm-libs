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

#ifndef ALIVE_DETECTION_H
#define ALIVE_DETECTION_H

#include "../base/hosts.h"
#include "../util/kb.h"

#include <pcap.h>

/* to how many hosts are packets send to at a time. value <= 0 for no rate limit
 */
#define BURST 100
/* how long (in microseconds) to wait until new BURST of packets is send */
#define BURST_TIMEOUT 100000
/* how tong (in sec) to wait for replies after last packet was sent */
#define WAIT_FOR_REPLIES_TIMEOUT 1
/* Src port of outgoing TCP pings. Used for filtering incoming packets. */
#define FILTER_PORT 9910

/* Redis related */

/* Queue (Redis list) for communicating with openvas main process. */
#define ALIVE_DETECTION_QUEUE "alive_detection"
/* Signal to put on ALIVE_DETECTION_QUEUE if alive detection finished. */
#define ALIVE_DETECTION_FINISHED "alive_detection_finished"

void *
start_alive_detection (void *);

typedef struct hosts_data hosts_data_t;
typedef struct scan_restrictions scan_restrictions_t;

/**
 * @brief The scanner struct holds data which is used frequently by the alive
 * detection thread.
 */
struct scanner
{
  /* sockets */
  int tcpv4soc;
  int tcpv6soc;
  int icmpv4soc;
  int icmpv6soc;
  int arpv4soc;
  int arpv6soc;
  /* UDP socket needed for getting the source IP for the TCP header. */
  int udpv4soc;
  int udpv6soc;
  /* TH_SYN or TH_ACK */
  uint8_t tcp_flag;
  /* ports used for TCP ACK/SYN */
  GArray *ports;
  /* redis connection */
  kb_t main_kb;
  /* pcap handle */
  pcap_t *pcap_handle;
  hosts_data_t *hosts_data;
  scan_restrictions_t *scan_restrictions;
};

/**
 * @brief The hosts_data struct holds the alive hosts and target hosts in
 * separate hashtables.
 */
struct hosts_data
{
  /* Set of the form (ip_str, ip_str).
   * Hosts which passed our pcap filter. May include hosts which are alive but
   * are not in the targethosts list */
  GHashTable *alivehosts;
  /* Hashtable of the form (ip_str, gvm_host_t *). The gvm_host_t pointers point
   * to hosts which are to be freed by the caller of start_alive_detection(). */
  GHashTable *targethosts;
};

/* Max_scan_hosts related struct. */
struct scan_restrictions
{
  /* Maximum number of hosts allowed to be scanned. No more alive hosts are put
   * on the queue after max_scan_hosts number of alive hosts is reached.
   * max_scan_hosts_reached is set to true and the finish signal is put on the
   * queue if max_scan_hosts is reached. */
  int max_scan_hosts;
  /* Count of unique identified alive hosts. */
  int alive_hosts_count;
  gboolean max_scan_hosts_reached;
};

/**
 * @brief Alive tests.
 *
 * These numbers are used in the database by gvmd, so if the number associated
 * with any symbol changes in gvmd we need to change them here too.
 */
typedef enum
{
  ALIVE_TEST_TCP_ACK_SERVICE = 1,
  ALIVE_TEST_ICMP = 2,
  ALIVE_TEST_ARP = 4,
  ALIVE_TEST_CONSIDER_ALIVE = 8,
  ALIVE_TEST_TCP_SYN_SERVICE = 16
} alive_test_t;

/**
 * @brief Type of socket.
 */
typedef enum
{
  TCPV4,
  TCPV6,
  ICMPV4,
  ICMPV6,
  ARPV4,
  ARPV6,
  UDPV4,
  UDPV6,
} socket_type_t;

#endif /* not ALIVE_DETECTION_H */
