/* Copyright (C) 2020 Greenbone Networks GmbH
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

#include "util.h"

#include "../base/networking.h" /* for range_t */

#include <errno.h>
#include <glib.h>
#include <ifaddrs.h> /* for getifaddrs() */
#include <net/ethernet.h>
#include <net/if.h>           /* for if_nametoindex() */
#include <netpacket/packet.h> /* for sockaddr_ll */
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "alive scan"

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
 * @brief Figure out source address for given destination.
 *
 * This function uses a well known trick for getting the source address used
 * for a given destination by calling connect() and getsockname() on an udp
 * socket.
 *
 * @param[in]   udpv6soc  Location of the socket to use.
 * @param[in]   dst       Destination address.
 * @param[out]  src       Source address.
 *
 * @return 0 on success, boreas_error_t on failure.
 */
boreas_error_t
get_source_addr_v6 (int *udpv6soc, struct in6_addr *dst, struct in6_addr *src)
{
  struct sockaddr_storage storage;
  struct sockaddr_in6 sin;
  socklen_t sock_len;
  boreas_error_t error;

  memset (&sin, 0, sizeof (struct sockaddr_in6));
  sin.sin6_family = AF_INET6;
  sin.sin6_addr = *dst;
  sin.sin6_port = htons (9); /* discard port (see RFC 863) */
  memcpy (&storage, &sin, sizeof (sin));

  error = NO_ERROR;
  sock_len = sizeof (storage);
  if (connect (*udpv6soc, (const struct sockaddr *) &storage, sock_len) < 0)
    {
      g_warning ("%s: connect() on udpv6soc failed: %s %d", __func__,
                 strerror (errno), errno);
      /* State of the socket is unspecified.  Close the socket and create a new
       * one. */
      if ((close (*udpv6soc)) != 0)
        {
          g_debug ("%s: Error in close(): %s", __func__, strerror (errno));
        }
      set_socket (UDPV6, udpv6soc);
      error = BOREAS_NO_SRC_ADDR_FOUND;
    }
  else
    {
      if (getsockname (*udpv6soc, (struct sockaddr *) &storage, &sock_len) < 0)
        {
          g_debug ("%s: getsockname() on updv6soc failed: %s", __func__,
                   strerror (errno));
          error = BOREAS_NO_SRC_ADDR_FOUND;
        }
    }

  if (!error)
    {
      /* Set source address. */
      memcpy (src, &((struct sockaddr_in6 *) (&storage))->sin6_addr,
              sizeof (struct in6_addr));

      /* Dissolve association so we can connect() on same socket again in later
       * call to get_source_addr_v4(). */
      sin.sin6_family = AF_UNSPEC;
      sock_len = sizeof (storage);
      memcpy (&storage, &sin, sizeof (sin));
      if (connect (*udpv6soc, (const struct sockaddr *) &storage, sock_len) < 0)
        g_debug ("%s: connect() on udpv6soc to dissolve association failed: %s",
                 __func__, strerror (errno));
    }

  return error;
}

/**
 * @brief Figure out source address for given destination.
 *
 * This function uses a well known trick for getting the source address used
 * for a given destination by calling connect() and getsockname() on an udp
 * socket.
 *
 * @param[in]   udpv4soc  Location of the socket to use.
 * @param[in]   dst       Destination address.
 * @param[out]  src       Source address.
 *
 * @return 0 on success, boreas_error_t on failure.
 */
boreas_error_t
get_source_addr_v4 (int *udpv4soc, struct in_addr *dst, struct in_addr *src)
{
  struct sockaddr_storage storage;
  struct sockaddr_in sin;
  socklen_t sock_len;
  boreas_error_t error;

  memset (&sin, 0, sizeof (struct sockaddr_in));
  sin.sin_family = AF_INET;
  sin.sin_addr.s_addr = dst->s_addr;
  sin.sin_port = htons (9); /* discard port (see RFC 863) */
  memcpy (&storage, &sin, sizeof (sin));

  error = NO_ERROR;
  sock_len = sizeof (storage);
  if (connect (*udpv4soc, (const struct sockaddr *) &storage, sock_len) < 0)
    {
      g_warning ("%s: connect() on udpv4soc failed: %s", __func__,
                 strerror (errno));
      /* State of the socket is unspecified.  Close the socket and create a new
       * one. */
      if ((close (*udpv4soc)) != 0)
        {
          g_debug ("%s: Error in close(): %s", __func__, strerror (errno));
        }
      set_socket (UDPV4, udpv4soc);
      error = BOREAS_NO_SRC_ADDR_FOUND;
    }
  else
    {
      if (getsockname (*udpv4soc, (struct sockaddr *) &storage, &sock_len) < 0)
        {
          g_debug ("%s: getsockname() on updv4soc failed: %s", __func__,
                   strerror (errno));
          error = BOREAS_NO_SRC_ADDR_FOUND;
        }
    }

  if (!error)
    {
      /* Set source address. */
      memcpy (src, &((struct sockaddr_in *) (&storage))->sin_addr,
              sizeof (struct in_addr));

      /* Dissolve association so we can connect() on same socket again in later
       * call to get_source_addr_v4(). */
      sin.sin_family = AF_UNSPEC;
      sock_len = sizeof (storage);
      memcpy (&storage, &sin, sizeof (sin));
      if (connect (*udpv4soc, (const struct sockaddr *) &storage, sock_len) < 0)
        g_debug ("%s: connect() on udpv4soc to dissolve association failed: %s",
                 __func__, strerror (errno));
    }

  return error;
}

/**
 * @brief Put all ports of a given port range into the ports array.
 *
 * @param range Pointer to a range_t.
 * @param ports_array Pointer to an GArray.
 */
void
fill_ports_array (gpointer range, gpointer ports_array)
{
  gboolean range_exclude;
  int range_start;
  int range_end;
  int port;

  range_start = ((range_t *) range)->start;
  range_end = ((range_t *) range)->end;
  range_exclude = ((range_t *) range)->exclude;

  /* If range should be excluded do not use it. */
  if (range_exclude)
    return;

  /* Only single port in range. */
  if (range_end == 0 || (range_start == range_end))
    {
      g_array_append_val (ports_array, range_start);
      return;
    }
  else
    {
      for (port = range_start; port <= range_end; port++)
        g_array_append_val (ports_array, port);
    }
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
