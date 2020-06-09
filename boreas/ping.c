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
#include <netinet/ip_icmp.h>
#include <netpacket/packet.h> /* for sockaddr_ll */
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>

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
 * @brief Get the source mac address of the given interface
 * or of the first non lo interface.
 *
 * @param interface Interface to get mac address from or NULL if first non lo
 * interface should be used.
 * @param[out]  mac Location where to store mac address.
 *
 * @return 0 on success, -1 on error.
 */
static int
get_source_mac_addr (gchar *interface, uint8_t *mac)
{
  struct ifaddrs *ifaddr = NULL;
  struct ifaddrs *ifa = NULL;
  int interface_provided = 0;

  if (interface)
    interface_provided = 1;

  if (getifaddrs (&ifaddr) == -1)
    {
      g_debug ("%s: getifaddr failed: %s", __func__, strerror (errno));
      return -1;
    }
  else
    {
      for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
        {
          if ((ifa->ifa_addr) && (ifa->ifa_addr->sa_family == AF_PACKET)
              && !(ifa->ifa_flags & (IFF_LOOPBACK)))
            {
              if (interface_provided)
                {
                  if (g_strcmp0 (interface, ifa->ifa_name) == 0)
                    {
                      struct sockaddr_ll *s =
                        (struct sockaddr_ll *) ifa->ifa_addr;
                      memcpy (mac, s->sll_addr, 6 * sizeof (uint8_t));
                    }
                }
              else
                {
                  struct sockaddr_ll *s = (struct sockaddr_ll *) ifa->ifa_addr;
                  memcpy (mac, s->sll_addr, 6 * sizeof (uint8_t));
                }
            }
        }
      freeifaddrs (ifaddr);
    }
  return 0;
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