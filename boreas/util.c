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

#include "util.h"

#include <errno.h>
#include <glib.h>
#include <ifaddrs.h> /* for getifaddrs() */
#include <net/ethernet.h>
#include <net/if.h>           /* for if_nametoindex() */
#include <netpacket/packet.h> /* for sockaddr_ll */
#include <stdlib.h>
#include <sys/socket.h>

/**
 * @brief Checksum calculation.
 *
 * From W.Richard Stevens "UNIX NETWORK PROGRAMMING" book. libfree/in_cksum.c
 * TODO: Section 8.7 of TCPv2 has more efficient implementation
 **/
uint16_t
in_cksum (uint16_t *addr, int len)
{
  int nleft = len;
  uint32_t sum = 0;
  uint16_t *w = addr;
  uint16_t answer = 0;

  /*
   * Our algorithm is simple, using a 32 bit accumulator (sum), we add
   * sequential 16 bit words to it, and at the end, fold back all the
   * carry bits from the top 16 bits into the lower 16 bits.
   */
  while (nleft > 1)
    {
      sum += *w++;
      nleft -= 2;
    }

  /* mop up an odd byte, if necessary */
  if (nleft == 1)
    {
      *(unsigned char *) (&answer) = *(unsigned char *) w;
      sum += answer;
    }

  /* add back carry outs from top 16 bits to low 16 bits */
  sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
  sum += (sum >> 16);                 /* add carry */
  answer = ~sum;                      /* truncate to 16 bits */
  return (answer);
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
int
get_source_mac_addr (char *interface, uint8_t *mac)
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
 * @brief Set the SO_BROADCAST socket option for given socket.
 *
 * @param socket  The socket to apply the option to.
 *
 * @return 0 on success, boreas_error_t on error.
 */
static boreas_error_t
set_broadcast (int socket)
{
  boreas_error_t error = NO_ERROR;
  int broadcast = 1;
  if (setsockopt (socket, SOL_SOCKET, SO_BROADCAST, &broadcast,
                  sizeof (broadcast))
      < 0)
    {
      g_warning ("%s: failed to set socket option SO_BROADCAST: %s", __func__,
                 strerror (errno));
      error = BOREAS_SETTING_SOCKET_OPTION_FAILED;
    }
  return error;
}

/**
 * @brief Set a new socket of specified type.
 *
 * @param[in] socket_type  What type of socket to get.
 *
 * @param[out] scanner_socket  Location to save the socket into.
 *
 * @return 0 on success, boreas_error_t on error.
 */
boreas_error_t
set_socket (socket_type_t socket_type, int *scanner_socket)
{
  boreas_error_t error = NO_ERROR;
  int soc;
  switch (socket_type)
    {
    case UDPV4:
      {
        soc = socket (AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (soc < 0)
          {
            g_warning ("%s: failed to open UDPV4 socket: %s", __func__,
                       strerror (errno));
            error = BOREAS_OPENING_SOCKET_FAILED;
          }
      }
      break;
    case UDPV6:
      {
        soc = socket (AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
        if (soc < 0)
          {
            g_warning ("%s: failed to open UDPV4 socket: %s", __func__,
                       strerror (errno));
            error = BOREAS_OPENING_SOCKET_FAILED;
          }
      }
      break;
    case TCPV4:
      {
        soc = socket (AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (soc < 0)
          {
            g_warning ("%s: failed to open TCPV4 socket: %s", __func__,
                       strerror (errno));
            error = BOREAS_OPENING_SOCKET_FAILED;
          }
        else
          {
            int opt = 1;
            if (setsockopt (soc, IPPROTO_IP, IP_HDRINCL, (char *) &opt,
                            sizeof (opt))
                < 0)
              {
                g_warning (
                  "%s: failed to set socket options on TCPV4 socket: %s",
                  __func__, strerror (errno));
                error = BOREAS_SETTING_SOCKET_OPTION_FAILED;
              }
          }
      }
      break;
    case TCPV6:
      {
        soc = socket (AF_INET6, SOCK_RAW, IPPROTO_RAW);
        if (soc < 0)
          {
            g_warning ("%s: failed to open TCPV6 socket: %s", __func__,
                       strerror (errno));
            error = BOREAS_OPENING_SOCKET_FAILED;
          }
        else
          {
            int opt_on = 1;
            if (setsockopt (soc, IPPROTO_IPV6, IP_HDRINCL,
                            (char *) &opt_on, // IPV6_HDRINCL
                            sizeof (opt_on))
                < 0)
              {
                g_warning (
                  "%s: failed to set socket options on TCPV6 socket: %s",
                  __func__, strerror (errno));
                error = BOREAS_SETTING_SOCKET_OPTION_FAILED;
              }
          }
      }
      break;
    case ICMPV4:
      {
        soc = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (soc < 0)
          {
            g_warning ("%s: failed to open ICMPV4 socket: %s", __func__,
                       strerror (errno));
            error = BOREAS_OPENING_SOCKET_FAILED;
          }
      }
      break;
    case ARPV6:
    case ICMPV6:
      {
        soc = socket (AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
        if (soc < 0)
          {
            g_warning ("%s: failed to open ARPV6/ICMPV6 socket: %s", __func__,
                       strerror (errno));
            error = BOREAS_OPENING_SOCKET_FAILED;
          }
      }
      break;
    case ARPV4:
      {
        soc = socket (PF_PACKET, SOCK_RAW, htons (ETH_P_ALL));
        if (soc < 0)
          {
            g_warning ("%s: failed to open ARPV4 socket: %s", __func__,
                       strerror (errno));
            return BOREAS_OPENING_SOCKET_FAILED;
          }
      }
      break;
    default:
      error = BOREAS_OPENING_SOCKET_FAILED;
      break;
    }

  /* set SO_BROADCAST socket option. If not set we get permission denied error
   * on pinging broadcast address */
  if (!error)
    {
      if ((error = set_broadcast (soc)) != 0)
        return error;
    }

  *scanner_socket = soc;
  return error;
}
