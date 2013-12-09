/* openvas-libraries/base
 * $Id$
 * Description: Implementation of OpenVAS Networking related API.
 *
 * Authors:
 * Hani Benhabiles <hani.benhabiles@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2013 Greenbone Networks GmbH
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * or, at your option, any later version as published by the Free
 * Software Foundation
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

#include "openvas_networking.h"

 /* Global variables */

/* Source interface name eg. eth1. */
char global_source_iface[IFNAMSIZ] = { '\0' };

/* Source IPv4 address. */
struct in_addr global_source_addr = { .s_addr = 0 };

/* Source IPv6 address. */
struct in6_addr global_source_addr6 = { .s6_addr32 = { 0, 0, 0, 0 } };

 /* Source Interface/Address related functions. */

/**
 * @brief Initializes the source network interface name and related information.
 *
 * @param[in]  iface    Name of network interface to use as source interface.
 *
 * @return 0 if success. If error, return 1 and reset source values to default.
 */
int
openvas_source_iface_init (const char *iface)
{
  struct ifaddrs *ifaddr, *ifa;
  int ret = 1;

  bzero (global_source_iface, sizeof (global_source_iface));
  global_source_addr.s_addr = INADDR_ANY;
  global_source_addr6 = in6addr_any;

  if (iface == NULL)
    return ret;

  if (getifaddrs (&ifaddr) == -1)
    return ret;

  /* Search for the adequate interface/family. */
  for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
    {
      if (strcmp (iface, ifa->ifa_name) == 0)
        {
          /* Found iface related entry, set the global source information. */
          ret = 0;
          if (ifa->ifa_addr->sa_family == AF_INET)
            {
              struct in_addr *addr = &((struct sockaddr_in *)
                                       ifa->ifa_addr)->sin_addr;

              memcpy (&global_source_addr, addr, sizeof (global_source_addr));
            }
          else if (ifa->ifa_addr->sa_family == AF_INET6)
            {
              struct sockaddr_in6 *addr;

              addr = (struct sockaddr_in6 *) ifa->ifa_addr;
              memcpy (&global_source_addr6.s6_addr, &addr->sin6_addr,
                      sizeof (struct in6_addr));
            }
        }
    }

  /* At least one address for the interface was found. */
  if (ret == 0)
    strncpy (global_source_iface, iface, sizeof (global_source_iface));

  freeifaddrs (ifaddr);
  return ret;
}

int
openvas_source_iface_is_set ()
{
  return *global_source_iface != '\0';
}

/**
 * @brief Binds a socket to use the global source address.
 *
 * @param[in]  socket    Socket to set source address for.
 * @param[in]  port      Network port for socket.
 * @param[in]  family    Family of socket. AF_INET or AF_INET6.
 *
 * @return 0 if success, -1 if error.
 */
int
openvas_source_set_socket (int socket, int port, int family)
{
  if (family == AF_INET)
    {
      struct sockaddr_in addr;

      openvas_source_addr (&addr.sin_addr);
      addr.sin_port = htons (port);
      addr.sin_family = AF_INET;

      if (bind (socket, (struct sockaddr *) &addr, sizeof (addr)) < 0)
        return -1;
    }
  else if (family == AF_INET6)
    {
      struct sockaddr_in6 addr6;

      openvas_source_addr6 (&addr6.sin6_addr);
      addr6.sin6_port = htons (port);
      addr6.sin6_family = AF_INET6;

      if (bind (socket, (struct sockaddr *) &addr6, sizeof (addr6)) < 0)
        return -1;
    }
  else
    return -1;

  return 0;
}

/**
 * @brief Gives the source IPv4 address.
 *
 * @param[out]  addr  Buffer of at least 4 bytes.
 */
void
openvas_source_addr (void *addr)
{
  if (addr)
    memcpy (addr, &global_source_addr.s_addr, 4);
}

/**
 * @brief Gives the source IPv6 address.
 *
 * @param[out]  addr6  Buffer of at least 16 bytes.
 */
void
openvas_source_addr6 (void *addr6)
{
  if (addr6)
    memcpy (addr6, &global_source_addr6.s6_addr, 16);
}

/**
 * @brief Gives the source IPv4 mapped as an IPv6 address.
 * eg. 192.168.20.10 would map to ::ffff:192.168.20.10.
 *
 * @param[out]  addr6  Buffer of at least 16 bytes.
 */
void
openvas_source_addr_as_addr6 (struct in6_addr *addr6)
{
  if (addr6)
    ipv4_as_ipv6 (&global_source_addr, addr6);
}

/**
 * @brief Gives the source network interface name in string format.
 *
 * @return Source network interface name. Free with g_free().
 */
char *
openvas_source_iface_str ()
{
  return g_strdup (global_source_iface);
}

/**
 * @brief Gives the source IPv4 address in string format.
 *
 * @return Source IPv4 string. Free with g_free().
 */
char *
openvas_source_addr_str ()
{
  char *str = malloc (INET_ADDRSTRLEN);

  if (str == NULL)
    return NULL;

  inet_ntop (AF_INET, &global_source_addr.s_addr, str, INET_ADDRSTRLEN);
  return str;
}

/**
 * @brief Gives the source IPv6 address in string format.
 *
 * @return Source IPv6 string. Free with g_free().
 */
char *
openvas_source_addr6_str ()
{
  char *str = malloc (INET6_ADDRSTRLEN);

  if (str == NULL)
    return NULL;

  inet_ntop (AF_INET6, &global_source_addr6, str, INET6_ADDRSTRLEN);
  return str;
}

 /* Miscellaneous functions. */

/**
 * @brief Maps an IPv4 address as an IPv6 address.
 * eg. 192.168.10.20 would map to ::ffff:192.168.10.20.
 *
 * @param[in]  ip4  IPv4 address to map.
 * @param[out] ip6  Buffer to store the IPv6 address.
 */
void
ipv4_as_ipv6 (const struct in_addr *ip4, struct in6_addr *ip6)
{
  if (ip4 == NULL || ip6 == NULL)
    return;

  ip6->s6_addr32[0] = 0;
  ip6->s6_addr32[1] = 0;
  ip6->s6_addr32[2] = htonl (0xffff);
  memcpy (&ip6->s6_addr32[3], ip4, sizeof (struct in_addr));
}


/**
 * @brief Resolves a hostname to an IPv4 or IPv6 address.
 *
 * @param[in]   name    Hostname to resolve.
 * @param[out]  dst     Buffer to store resolved address. Size must be at least
 *                      4 bytes for AF_INET and 16 bytes for AF_INET6.
 * @param[in] family    Either AF_INET or AF_INET6.
 *
 * @return -1 if error, 0 otherwise.
 */
int
openvas_resolve (const char *name, void *dst, int family)
{
  struct addrinfo hints, *info, *p;

  if (name == NULL || dst == NULL
      || (family != AF_INET && family != AF_INET6 && family != AF_UNSPEC))
    return -1;

  bzero (&hints, sizeof (hints));
  hints.ai_family = family;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = 0;
  if ((getaddrinfo (name, NULL, &hints, &info)) != 0)
    return -1;

  p = info;
  while (p)
    {
      if (p->ai_family == family || family == AF_UNSPEC)
        {
          if (p->ai_family == AF_INET && family == AF_UNSPEC)
            {
              struct sockaddr_in *addrin = (struct sockaddr_in *) p->ai_addr;
              ipv4_as_ipv6 (&(addrin->sin_addr), dst);
            }
          else if (p->ai_family == AF_INET)
            {
              struct sockaddr_in *addrin = (struct sockaddr_in *) p->ai_addr;
              memcpy (dst, &(addrin->sin_addr), sizeof (struct in_addr));
            }
          else if (p->ai_family == AF_INET6)
            {
              struct sockaddr_in6 *addrin = (struct sockaddr_in6 *) p->ai_addr;
              memcpy (dst, &(addrin->sin6_addr), sizeof (struct in6_addr));
            }
          break;
        }

      p = p->ai_next;
    }

  freeaddrinfo (info);
  return 0;
}

/**
 * @brief Resolves a hostname to an IPv4-mapped IPv6 or IPv6 address.
 *
 * @param[in]   name    Hostname to resolve.
 * @param[out]  ip6     Buffer to store resolved address.
 *
 * @return -1 if error, 0 otherwise.
 */
int
openvas_resolve_as_addr6 (const char *name, struct in6_addr *ip6)
{
  return openvas_resolve (name, ip6, AF_UNSPEC);
}

