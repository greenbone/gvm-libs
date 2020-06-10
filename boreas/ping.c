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

#include "ping.h"

#include "../base/networking.h" /* for gvm_routethrough() */
#include "util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <glib.h>
#include <ifaddrs.h> /* for getifaddrs() */
#include <net/ethernet.h>
#include <net/if.h> /* for if_nametoindex() */
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netpacket/packet.h> /* for sockaddr_ll */
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

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
 * @brief Send icmp ping.
 *
 * @param soc Socket to use for sending.
 * @param dst Destination address to send to.
 * @param type  Type of imcp. e.g. ND_NEIGHBOR_SOLICIT or ICMP6_ECHO_REQUEST.
 */
void
send_icmp_v6 (int soc, struct in6_addr *dst, int type)
{
  struct sockaddr_in6 soca;
  char sendbuf[1500];
  int len;
  int datalen = 56;
  struct icmp6_hdr *icmp6;

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
void
send_icmp_v4 (int soc, struct in_addr *dst)
{
  /* datalen + MAXIPLEN + MAXICMPLEN */
  char sendbuf[56 + 60 + 76];
  struct sockaddr_in soca;

  int len;
  int datalen = 56;
  struct icmphdr *icmp;

  icmp = (struct icmphdr *) sendbuf;
  icmp->type = ICMP_ECHO;
  icmp->code = 0;

  len = 8 + datalen;
  icmp->checksum = 0;
  icmp->checksum = in_cksum ((u_short *) icmp, len);

  memset (&soca, 0, sizeof (soca));
  soca.sin_family = AF_INET;
  soca.sin_addr = *dst;

  if (sendto (soc, sendbuf, len, MSG_NOSIGNAL, (const struct sockaddr *) &soca,
              sizeof (struct sockaddr_in))
      < 0)
    {
      g_warning ("%s: sendto(): %s", __func__, strerror (errno));
    }
}

/**
 * @brief Send tcp ping.
 *
 * @param soc Socket to use for sending.
 * @param dst Destination address to send to.
 * @param tcp_flag  TH_SYN or TH_ACK.
 */
void
send_tcp_v6 (struct scanner *scanner, struct in6_addr *dst_p)
{
  boreas_error_t error;
  struct sockaddr_in6 soca;
  struct in6_addr src;

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
void
send_tcp_v4 (struct scanner *scanner, struct in_addr *dst_p)
{
  boreas_error_t error;
  struct sockaddr_in soca;
  struct in_addr src;

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
      if (sendto (soc, (const void *) ip, 40, MSG_NOSIGNAL,
                  (struct sockaddr *) &soca, sizeof (soca))
          < 0)
        {
          g_warning ("%s: sendto(): %s", __func__, strerror (errno));
        }
    }
}

/**
 * @brief Send arp ping.
 *
 * @param soc Socket to use for sending.
 * @param dst Destination address to send to.
 */
void
send_arp_v4 (int soc, struct in_addr *dst_p)
{
  struct sockaddr_ll soca;
  struct arp_hdr arphdr;
  int frame_length;
  uint8_t *ether_frame;

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
      memcpy (&storage_dst, &sin_src, sizeof (sin_src));

      /* Get interface and set src addr. */
      gchar *interface = gvm_routethrough (&storage_dst, &storage_src);
      memcpy (&src, &((struct sockaddr_in *) (&storage_src))->sin_addr,
              sizeof (struct in_addr));
      g_warning ("%s: %s", __func__, inet_ntoa (src));

      if (!interface)
        g_warning ("%s: no appropriate interface was found", __func__);
      g_debug ("%s: interface to use: %s", __func__, interface);

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

  if ((sendto (soc, ether_frame, frame_length, MSG_NOSIGNAL,
               (struct sockaddr *) &soca, sizeof (soca)))
      <= 0)
    g_warning ("%s: sendto(): %s", __func__, strerror (errno));

  g_free (ether_frame);

  return;
}