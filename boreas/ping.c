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

#include "ping.h"

#include "../base/networking.h" /* for gvm_routethrough() */
#include "util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <glib.h>
#include <ifaddrs.h> /* for getifaddrs() */
#include <linux/sockios.h>
#include <net/ethernet.h>
#include <net/if.h> /* for if_nametoindex() */
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netpacket/packet.h> /* for sockaddr_ll */
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "alive scan"

struct v6pseudohdr
{
  struct in6_addr s6addr;
  struct in6_addr d6addr;
  u_short length;
  u_char zero1;
  u_char zero2;
  u_char zero3;
  u_char protocol;
  struct tcphdr tcpheader;
};

struct pseudohdr
{
  struct in_addr saddr;
  struct in_addr daddr;
  u_char zero;
  u_char protocol;
  u_short length;
  struct tcphdr tcpheader;
};

struct arp_hdr
{
  uint16_t htype;
  uint16_t ptype;
  uint8_t hlen;
  uint8_t plen;
  uint16_t opcode;
  uint8_t sender_mac[6];
  uint8_t sender_ip[4];
  uint8_t target_mac[6];
  uint8_t target_ip[4];
};

/**
 * @brief Get the size of the socket send buffer.
 *
 * @param[in]   soc         The socket to get the send buffer for.
 * @param[out]  so_sndbuf   The size of the send buffer.
 *
 * @return 0 on succes, -1 on error. so_sndbuf is set to -1 on error.
 */
static int
get_so_sndbuf (int soc, int *so_sndbuf)
{
  unsigned int optlen = sizeof (*so_sndbuf);
  if (getsockopt (soc, SOL_SOCKET, SO_SNDBUF, (void *) so_sndbuf, &optlen)
      == -1)
    {
      g_warning ("%s: getsockopt error: %s", __func__, strerror (errno));
      *so_sndbuf = -1;
      return -1;
    }
  return 0;
}

/**
 * @brief Wait until output queue is small enough for sending new packets.
 *
 * If calls to ioctl fail in this function we might not throttle as expected
 * and only delay by a fixed amount of time.
 *
 * @param soc       Socket.
 * @param so_sndbuf Size of the socket send buffer we do not want to exceed.
 */
static void
throttle (int soc, int so_sndbuf)
{
  // g_warning ("%s: so_sndbuf %d", __func__, so_sndbuf);
  int cur_so_sendbuf = -1;

  /* Get the current size of the output queue size */
  if (ioctl (soc, SIOCOUTQ, &cur_so_sendbuf) == -1)
    {
      g_warning ("%s: ioctl error: %s", __func__, strerror (errno));
      usleep (100000);
      return;
    }

  /* If setting of so_sndbuf or cur_so_sendbuf failed we do not enter the
   * throttling loop. Normally this should not occure but we really do not want
   * to get into an infinite loop here. */
  if (cur_so_sendbuf != -1 && so_sndbuf != -1)
    {
      /* Wait until output queue is empty enough. */
      while (cur_so_sendbuf >= so_sndbuf)
        {
          usleep (100000);
          if (ioctl (soc, SIOCOUTQ, &cur_so_sendbuf) == -1)
            {
              g_warning ("%s: ioctl error: %s", __func__, strerror (errno));
              usleep (100000);
              /* Do not risk getting into infinite loop */
              return;
            }
        }
    }

  return;
}

/**
 * @brief Send icmp ping.
 *
 * @param soc Socket to use for sending.
 * @param dst Destination address to send to.
 * @param type  Type of imcp. e.g. ND_NEIGHBOR_SOLICIT or ICMP6_ECHO_REQUEST.
 */
static void
send_icmp_v6 (int soc, struct in6_addr *dst, int type)
{
  struct sockaddr_in6 soca;
  char sendbuf[1500];
  int len;
  int datalen = 56;
  struct icmp6_hdr *icmp6;

  /* Throttling related variables */
  static int so_sndbuf = -1; // socket send buffer
  static int init = -1;

  icmp6 = (struct icmp6_hdr *) sendbuf;
  icmp6->icmp6_type = type; /* ND_NEIGHBOR_SOLICIT or ICMP6_ECHO_REQUEST */
  icmp6->icmp6_code = 0;
  icmp6->icmp6_id = 234;
  icmp6->icmp6_seq = 0;

  memset ((icmp6 + 1), 0xa5, datalen);
  gettimeofday ((struct timeval *) (icmp6 + 1), NULL); // only for testing
  len = 8 + datalen;

  /* send packet */
  memset (&soca, 0, sizeof (struct sockaddr_in6));
  soca.sin6_family = AF_INET6;
  soca.sin6_addr = *dst;

  /* Get size of empty SO_SNDBUF */
  if (init == -1)
    {
      if (get_so_sndbuf (soc, &so_sndbuf) == 0)
        init = 1;
    }
  /* Throttle speed if needed */
  throttle (soc, so_sndbuf);

  if (sendto (soc, sendbuf, len, MSG_NOSIGNAL, (struct sockaddr *) &soca,
              sizeof (struct sockaddr_in6))
      < 0)
    {
      g_warning ("%s: sendto(): %s", __func__, strerror (errno));
    }
}

/**
 * @brief Send icmp ping.
 *
 * @param soc Socket to use for sending.
 * @param dst Destination address to send to.
 */
static void
send_icmp_v4 (int soc, struct in_addr *dst)
{
  /* datalen + MAXIPLEN + MAXICMPLEN */
  char sendbuf[56 + 60 + 76];
  struct sockaddr_in soca;

  int len;
  int datalen = 56;
  struct icmphdr *icmp;

  /* Throttling related variables */
  static int so_sndbuf = -1; // socket send buffer
  static int init = -1;

  icmp = (struct icmphdr *) sendbuf;
  icmp->type = ICMP_ECHO;
  icmp->code = 0;

  len = 8 + datalen;
  icmp->checksum = 0;
  icmp->checksum = in_cksum ((u_short *) icmp, len);

  memset (&soca, 0, sizeof (soca));
  soca.sin_family = AF_INET;
  soca.sin_addr = *dst;

  /* Get size of empty SO_SNDBUF */
  if (init == -1)
    {
      if (get_so_sndbuf (soc, &so_sndbuf) == 0)
        init = 1;
    }
  /* Throttle speed if needed */
  throttle (soc, so_sndbuf);

  if (sendto (soc, sendbuf, len, MSG_NOSIGNAL, (const struct sockaddr *) &soca,
              sizeof (struct sockaddr_in))
      < 0)
    {
      g_warning ("%s: sendto(): %s", __func__, strerror (errno));
    }
}

/**
 * @brief Is called in g_hash_table_foreach(). Check if ipv6 or ipv4, get
 * correct socket and start appropriate ping function.
 *
 * @param key Ip string.
 * @param value Pointer to gvm_host_t.
 * @param scanner_p Pointer to scanner struct.
 */
void
send_icmp (gpointer key, gpointer value, gpointer scanner_p)
{
  struct scanner *scanner;
  struct in6_addr dst6;
  struct in6_addr *dst6_p = &dst6;
  struct in_addr dst4;
  struct in_addr *dst4_p = &dst4;
  static int count = 0;

  scanner = (struct scanner *) scanner_p;

  if (g_hash_table_contains (scanner->hosts_data->alivehosts, key))
    return;

  count++;
  if (count % BURST == 0)
    usleep (BURST_TIMEOUT);

  if (gvm_host_get_addr6 ((gvm_host_t *) value, dst6_p) < 0)
    g_warning ("%s: could not get addr6 from gvm_host_t", __func__);
  if (dst6_p == NULL)
    {
      g_warning ("%s: destination address is NULL", __func__);
      return;
    }
  if (IN6_IS_ADDR_V4MAPPED (dst6_p) != 1)
    {
      send_icmp_v6 (scanner->icmpv6soc, dst6_p, ICMP6_ECHO_REQUEST);
    }
  else
    {
      dst4.s_addr = dst6_p->s6_addr32[3];
      send_icmp_v4 (scanner->icmpv4soc, dst4_p);
    }
}

/**
 * @brief Send tcp ping.
 *
 * @param soc Socket to use for sending.
 * @param dst Destination address to send to.
 * @param tcp_flag  TH_SYN or TH_ACK.
 */
static void
send_tcp_v6 (struct scanner *scanner, struct in6_addr *dst_p)
{
  boreas_error_t error;
  struct sockaddr_in6 soca;
  struct in6_addr src;

  /* Throttling related variables */
  static int so_sndbuf = -1; // socket send buffer
  static int init = -1;

  GArray *ports = scanner->ports;
  int *udpv6soc = &(scanner->udpv6soc);
  int soc = scanner->tcpv6soc;
  uint8_t tcp_flag = scanner->tcp_flag;

  u_char packet[sizeof (struct ip6_hdr) + sizeof (struct tcphdr)];
  struct ip6_hdr *ip = (struct ip6_hdr *) packet;
  struct tcphdr *tcp = (struct tcphdr *) (packet + sizeof (struct ip6_hdr));

  /* Get source address for TCP header. */
  error = get_source_addr_v6 (udpv6soc, dst_p, &src);
  if (error)
    {
      char destination_str[INET_ADDRSTRLEN];
      inet_ntop (AF_INET6, (const void *) dst_p, destination_str,
                 INET_ADDRSTRLEN);
      g_debug ("%s: Destination: %s. %s", __func__, destination_str,
               str_boreas_error (error));
      return;
    }

  /* No ports in portlist. */
  if (ports->len == 0)
    return;

  /* For ports in ports array send packet. */
  for (guint i = 0; i < ports->len; i++)
    {
      memset (packet, 0, sizeof (packet));
      /* IPv6 */
      ip->ip6_flow = htonl ((6 << 28) | (0 << 20) | 0);
      ip->ip6_plen = htons (20); // TCP_HDRLEN
      ip->ip6_nxt = IPPROTO_TCP;
      ip->ip6_hops = 255; // max value

      ip->ip6_src = src;
      ip->ip6_dst = *dst_p;

      /* TCP */
      tcp->th_sport = htons (FILTER_PORT);
      tcp->th_dport = htons (g_array_index (ports, uint16_t, i));
      tcp->th_seq = htonl (0);
      tcp->th_ack = htonl (0);
      tcp->th_x2 = 0;
      tcp->th_off = 20 / 4; // TCP_HDRLEN / 4 (size of tcphdr in 32 bit words)
      tcp->th_flags = tcp_flag; // TH_SYN or TH_ACK
      tcp->th_win = htons (65535);
      tcp->th_urp = htons (0);
      tcp->th_sum = 0;

      /* CKsum */
      {
        struct v6pseudohdr pseudoheader;

        memset (&pseudoheader, 0, 38 + sizeof (struct tcphdr));
        memcpy (&pseudoheader.s6addr, &ip->ip6_src, sizeof (struct in6_addr));
        memcpy (&pseudoheader.d6addr, &ip->ip6_dst, sizeof (struct in6_addr));

        pseudoheader.protocol = IPPROTO_TCP;
        pseudoheader.length = htons (sizeof (struct tcphdr));
        memcpy ((char *) &pseudoheader.tcpheader, (char *) tcp,
                sizeof (struct tcphdr));
        tcp->th_sum = in_cksum ((unsigned short *) &pseudoheader,
                                38 + sizeof (struct tcphdr));
      }

      memset (&soca, 0, sizeof (soca));
      soca.sin6_family = AF_INET6;
      soca.sin6_addr = ip->ip6_dst;

      /* Get size of empty SO_SNDBUF */
      if (init == -1)
        {
          if (get_so_sndbuf (soc, &so_sndbuf) == 0)
            init = 1;
        }
      /* Throttle speed if needed */
      throttle (soc, so_sndbuf);

      /*  TCP_HDRLEN(20) IP6_HDRLEN(40) */
      if (sendto (soc, (const void *) ip, 40 + 20, MSG_NOSIGNAL,
                  (struct sockaddr *) &soca, sizeof (struct sockaddr_in6))
          < 0)
        {
          g_warning ("%s: sendto():  %s", __func__, strerror (errno));
        }
    }
}

/**
 * @brief Send tcp ping.
 *
 * @param scanner Scanner struct which includes all needed data for tcp_v4 ping.
 * @param dst Destination address to send to.
 */
static void
send_tcp_v4 (struct scanner *scanner, struct in_addr *dst_p)
{
  boreas_error_t error;
  struct sockaddr_in soca;
  struct in_addr src;

  /* Throttling related variables */
  static int so_sndbuf = -1; // socket send buffer
  static int init = -1;

  int soc = scanner->tcpv4soc;          /* Socket used for sending. */
  GArray *ports = scanner->ports;       /* Ports to ping. */
  int *udpv4soc = &(scanner->udpv4soc); /* Socket used for getting src addr */
  uint8_t tcp_flag = scanner->tcp_flag; /* SYN or ACK tcp flag. */

  u_char packet[sizeof (struct ip) + sizeof (struct tcphdr)];
  struct ip *ip = (struct ip *) packet;
  struct tcphdr *tcp = (struct tcphdr *) (packet + sizeof (struct ip));

  /* No ports in portlist. */
  if (ports->len == 0)
    return;

  /* Get source address for TCP header. */
  error = get_source_addr_v4 (udpv4soc, dst_p, &src);
  if (error)
    {
      char destination_str[INET_ADDRSTRLEN];
      inet_ntop (AF_INET, &(dst_p->s_addr), destination_str, INET_ADDRSTRLEN);
      g_debug ("%s: Destination: %s. %s", __func__, destination_str,
               str_boreas_error (error));
      return;
    }

  /* For ports in ports array send packet. */
  for (guint i = 0; i < ports->len; i++)
    {
      memset (packet, 0, sizeof (packet));
      /* IP */
      ip->ip_hl = 5;
      ip->ip_off = htons (0);
      ip->ip_v = 4;
      ip->ip_tos = 0;
      ip->ip_p = IPPROTO_TCP;
      ip->ip_id = rand ();
      ip->ip_ttl = 0x40;
      ip->ip_src = src;
      ip->ip_dst = *dst_p;
      ip->ip_sum = 0;

      /* TCP */
      tcp->th_sport = htons (FILTER_PORT);
      tcp->th_flags = tcp_flag; // TH_SYN TH_ACK;
      tcp->th_dport = htons (g_array_index (ports, uint16_t, i));
      tcp->th_seq = rand ();
      tcp->th_ack = 0;
      tcp->th_x2 = 0;
      tcp->th_off = 5;
      tcp->th_win = 2048;
      tcp->th_urp = 0;
      tcp->th_sum = 0;

      /* CKsum */
      {
        struct in_addr source, dest;
        struct pseudohdr pseudoheader;
        source.s_addr = ip->ip_src.s_addr;
        dest.s_addr = ip->ip_dst.s_addr;

        memset (&pseudoheader, 0, 12 + sizeof (struct tcphdr));
        pseudoheader.saddr.s_addr = source.s_addr;
        pseudoheader.daddr.s_addr = dest.s_addr;

        pseudoheader.protocol = IPPROTO_TCP;
        pseudoheader.length = htons (sizeof (struct tcphdr));
        memcpy ((char *) &pseudoheader.tcpheader, (char *) tcp,
                sizeof (struct tcphdr));
        tcp->th_sum = in_cksum ((unsigned short *) &pseudoheader,
                                12 + sizeof (struct tcphdr));
      }

      memset (&soca, 0, sizeof (soca));
      soca.sin_family = AF_INET;
      soca.sin_addr = ip->ip_dst;

      /* Get size of empty SO_SNDBUF */
      if (init == -1)
        {
          if (get_so_sndbuf (soc, &so_sndbuf) == 0)
            init = 1;
        }
      /* Throttle speed if needed */
      throttle (soc, so_sndbuf);

      if (sendto (soc, (const void *) ip, 40, MSG_NOSIGNAL,
                  (struct sockaddr *) &soca, sizeof (soca))
          < 0)
        {
          g_warning ("%s: sendto(): %s", __func__, strerror (errno));
        }
    }
}

/**
 * @brief Is called in g_hash_table_foreach(). Check if ipv6 or ipv4, get
 * correct socket and start appropriate ping function.
 *
 * @param key Ip string.
 * @param value Pointer to gvm_host_t.
 * @param scanner_p Pointer to scanner struct.
 */
void
send_tcp (gpointer key, gpointer value, gpointer scanner_p)
{
  struct scanner *scanner;
  struct in6_addr dst6;
  struct in6_addr *dst6_p = &dst6;
  struct in_addr dst4;
  struct in_addr *dst4_p = &dst4;
  static int count = 0;

  scanner = (struct scanner *) scanner_p;

  if (g_hash_table_contains (scanner->hosts_data->alivehosts, key))
    return;

  count++;
  if (count % BURST == 0)
    usleep (BURST_TIMEOUT);

  if (gvm_host_get_addr6 ((gvm_host_t *) value, dst6_p) < 0)
    g_warning ("%s: could not get addr6 from gvm_host_t", __func__);
  if (dst6_p == NULL)
    {
      g_warning ("%s: destination address is NULL", __func__);
      return;
    }
  if (IN6_IS_ADDR_V4MAPPED (dst6_p) != 1)
    {
      send_tcp_v6 (scanner, dst6_p);
    }
  else
    {
      dst4.s_addr = dst6_p->s6_addr32[3];
      send_tcp_v4 (scanner, dst4_p);
    }
}

/**
 * @brief Send arp ping.
 *
 * @param soc Socket to use for sending.
 * @param dst Destination address to send to.
 */
static void
send_arp_v4 (int soc, struct in_addr *dst_p)
{
  struct sockaddr_ll soca;
  struct arp_hdr arphdr;
  int frame_length;
  uint8_t *ether_frame;

  /* Throttling related variables */
  static int so_sndbuf = -1; // socket send buffer
  static int init = -1;

  static gboolean first_time_setup_done = FALSE;
  static struct in_addr src;
  static int ifaceindex;
  static uint8_t src_mac[6];
  static uint8_t dst_mac[6];

  memset (&soca, 0, sizeof (soca));

  /* Set up data which does not change between function calls. */
  if (!first_time_setup_done)
    {
      struct sockaddr_storage storage_src;
      struct sockaddr_storage storage_dst;
      struct sockaddr_in sin_src;
      struct sockaddr_in sin_dst;

      memset (&sin_src, 0, sizeof (struct sockaddr_in));
      memset (&sin_dst, 0, sizeof (struct sockaddr_in));
      sin_src.sin_family = AF_INET;
      sin_dst.sin_family = AF_INET;
      sin_dst.sin_addr = *dst_p;
      memcpy (&storage_dst, &sin_dst, sizeof (sin_dst));
      memcpy (&storage_src, &sin_src, sizeof (sin_src));

      /* Get interface and set src addr. */
      g_debug ("%s: Destination addr: %s", __func__, inet_ntoa (*dst_p));
      gchar *interface = gvm_routethrough (&storage_dst, &storage_src);
      if (!interface)
        {
          g_warning ("%s: No appropriate interface was found. Network may be "
                     "unreachable. No ARP ping send for host %s.",
                     __func__, inet_ntoa (*dst_p));
          return;
        }
      g_debug ("%s: interface to use: %s", __func__, interface);
      memcpy (&src, &((struct sockaddr_in *) (&storage_src))->sin_addr,
              sizeof (struct in_addr));
      g_debug ("%s: Source addr: %s", __func__, inet_ntoa (src));

      /* Get interface index for sockaddr_ll. */
      if ((ifaceindex = if_nametoindex (interface)) == 0)
        g_warning ("%s: if_nametoindex: %s", __func__, strerror (errno));

      /* Set MAC addresses. */
      memset (src_mac, 0, 6 * sizeof (uint8_t));
      memset (dst_mac, 0xff, 6 * sizeof (uint8_t));
      if (get_source_mac_addr (interface, (unsigned char *) src_mac) != 0)
        g_warning ("%s: get_source_mac_addr() returned error", __func__);

      g_debug ("%s: Source MAC address: %02x:%02x:%02x:%02x:%02x:%02x",
               __func__, src_mac[0], src_mac[1], src_mac[2], src_mac[3],
               src_mac[4], src_mac[5]);
      g_debug ("%s: Destination mac address: %02x:%02x:%02x:%02x:%02x:%02x",
               __func__, dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3],
               dst_mac[4], dst_mac[5]);

      first_time_setup_done = TRUE;
    }

  /* Fill in sockaddr_ll.*/
  soca.sll_ifindex = ifaceindex;
  soca.sll_family = AF_PACKET;
  memcpy (soca.sll_addr, src_mac, 6 * sizeof (uint8_t));
  soca.sll_halen = 6;

  /* Fill ARP header.*/
  /* IP addresses. */
  memcpy (&arphdr.target_ip, dst_p, 4 * sizeof (uint8_t));
  memcpy (&arphdr.sender_ip, &src, 4 * sizeof (uint8_t));
  /* Hardware type ethernet.
   * Protocol type IP.
   * Hardware address length is MAC address length.
   * Protocol address length is length of IPv4.
   * OpCode is ARP request. */
  arphdr.htype = htons (1);
  arphdr.ptype = htons (ETH_P_IP);
  arphdr.hlen = 6;
  arphdr.plen = 4;
  arphdr.opcode = htons (1);
  memcpy (&arphdr.sender_mac, src_mac, 6 * sizeof (uint8_t));
  memset (&arphdr.target_mac, 0, 6 * sizeof (uint8_t));

  /* Ethernet frame to send. */
  ether_frame = g_malloc0 (IP_MAXPACKET);
  /* (MAC + MAC + ethernet type + ARP_HDRLEN) */
  frame_length = 6 + 6 + 2 + 28;

  memcpy (ether_frame, dst_mac, 6 * sizeof (uint8_t));
  memcpy (ether_frame + 6, src_mac, 6 * sizeof (uint8_t));
  /* ethernet type code */
  ether_frame[12] = ETH_P_ARP / 256;
  ether_frame[13] = ETH_P_ARP % 256;
  /* ARP header.  ETH_HDRLEN = 14, ARP_HDRLEN = 28 */
  memcpy (ether_frame + 14, &arphdr, 28 * sizeof (uint8_t));

  /* Get size of empty SO_SNDBUF */
  if (init == -1)
    {
      if (get_so_sndbuf (soc, &so_sndbuf) == 0)
        init = 1;
    }
  /* Throttle speed if needed */
  throttle (soc, so_sndbuf);

  if ((sendto (soc, ether_frame, frame_length, MSG_NOSIGNAL,
               (struct sockaddr *) &soca, sizeof (soca)))
      <= 0)
    g_warning ("%s: sendto(): %s", __func__, strerror (errno));

  g_free (ether_frame);

  return;
}

/**
 * @brief Is called in g_hash_table_foreach(). Check if ipv6 or ipv4, get
 * correct socket and start appropriate ping function.
 *
 * @param key Ip string.
 * @param value Pointer to gvm_host_t.
 * @param scanner_p Pointer to scanner struct.
 */
void
send_arp (gpointer key, gpointer value, gpointer scanner_p)
{
  struct scanner *scanner;
  struct in6_addr dst6;
  struct in6_addr *dst6_p = &dst6;
  struct in_addr dst4;
  struct in_addr *dst4_p = &dst4;
  static int count = 0;

  scanner = (struct scanner *) scanner_p;

  if (g_hash_table_contains (scanner->hosts_data->alivehosts, key))
    return;

  count++;
  if (count % BURST == 0)
    usleep (BURST_TIMEOUT);

  if (gvm_host_get_addr6 ((gvm_host_t *) value, dst6_p) < 0)
    g_warning ("%s: could not get addr6 from gvm_host_t", __func__);
  if (dst6_p == NULL)
    {
      g_warning ("%s: destination address is NULL", __func__);
      return;
    }
  if (IN6_IS_ADDR_V4MAPPED (dst6_p) != 1)
    {
      /* IPv6 does simulate ARP by using the Neighbor Discovery Protocol with
       * ICMPv6. */
      send_icmp_v6 (scanner->arpv6soc, dst6_p, ND_NEIGHBOR_SOLICIT);
    }
  else
    {
      dst4.s_addr = dst6_p->s6_addr32[3];
      send_arp_v4 (scanner->arpv4soc, dst4_p);
    }
}
