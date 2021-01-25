/* Copyright (C) 2013-2021 Greenbone Networks GmbH
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

/**
 * @file
 * @brief Implementation of GVM Networking related API.
 */

#include "networking.h"

#include <arpa/inet.h> /* for inet_ntop */
#include <assert.h>    /* for assert */
#include <ctype.h>     /* for isblank */
#include <errno.h>     /* for errno, EAFNOSUPPORT */
#include <glib/gstdio.h>
#include <ifaddrs.h>    /* for ifaddrs, freeifaddrs, getifaddrs */
#include <net/if.h>     /* for IFNAMSIZ */
#include <stdint.h>     /* for uint32_t, uint8_t */
#include <stdlib.h>     /* for atoi, strtol */
#include <string.h>     /* for memcpy, bzero, strchr, strlen, strcmp, strncpy */
#include <sys/socket.h> /* for AF_INET, AF_INET6, AF_UNSPEC, sockaddr_storage */
#include <unistd.h>     /* for close */

#ifdef __FreeBSD__
#include <netinet/in.h>
#define s6_addr32 __u6_addr.__u6_addr32
#endif

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "base networking"

/* Global variables */

/* Source interface name eg. eth1. */
char global_source_iface[IFNAMSIZ] = {'\0'};

/* Source IPv4 address. */
struct in_addr global_source_addr = {.s_addr = 0};

/* Source IPv6 address. */
struct in6_addr global_source_addr6 = {.s6_addr32 = {0, 0, 0, 0}};

/* Source Interface/Address related functions. */

/**
 * @brief Initializes the source network interface name and related information.
 *
 * @param[in]  iface    Name of network interface to use as source interface.
 *
 * @return 0 if success. If error, return 1 and reset source values to default.
 */
int
gvm_source_iface_init (const char *iface)
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
      if (ifa->ifa_addr && strcmp (iface, ifa->ifa_name) == 0)
        {
          if (ifa->ifa_addr->sa_family == AF_INET)
            {
              struct in_addr *addr =
                &((struct sockaddr_in *) ifa->ifa_addr)->sin_addr;

              memcpy (&global_source_addr, addr, sizeof (global_source_addr));
              ret = 0;
            }
          else if (ifa->ifa_addr->sa_family == AF_INET6)
            {
              struct sockaddr_in6 *addr;

              addr = (struct sockaddr_in6 *) ifa->ifa_addr;
              memcpy (&global_source_addr6.s6_addr, &addr->sin6_addr,
                      sizeof (struct in6_addr));
              ret = 0;
            }
        }
    }

  /* At least one address for the interface was found. */
  if (ret == 0)
    strncpy (global_source_iface, iface, sizeof (global_source_iface) - 1);

  freeifaddrs (ifaddr);
  return ret;
}

/**
 * @brief Check if global_source @ref global_source_iface is set.
 *
 * @return 1 if set, 0 otherwise.
 */
int
gvm_source_iface_is_set (void)
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
gvm_source_set_socket (int socket, int port, int family)
{
  if (family == AF_INET)
    {
      struct sockaddr_in addr;

      bzero (&addr, sizeof (addr));
      gvm_source_addr (&addr.sin_addr);
      addr.sin_port = htons (port);
      addr.sin_family = AF_INET;

      if (bind (socket, (struct sockaddr *) &addr, sizeof (addr)) < 0)
        return -1;
    }
  else if (family == AF_INET6)
    {
      struct sockaddr_in6 addr6;

      bzero (&addr6, sizeof (addr6));
      gvm_source_addr6 (&addr6.sin6_addr);
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
gvm_source_addr (void *addr)
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
gvm_source_addr6 (void *addr6)
{
  if (addr6)
    memcpy (addr6, &global_source_addr6.s6_addr, 16);
}

/**
 * @brief Gives the source IPv4 mapped as an IPv6 address.
 * eg. 192.168.20.10 would map to \::ffff:192.168.20.10.
 *
 * @param[out]  addr6  Buffer of at least 16 bytes.
 */
void
gvm_source_addr_as_addr6 (struct in6_addr *addr6)
{
  if (addr6)
    ipv4_as_ipv6 (&global_source_addr, addr6);
}

/**
 * @brief Gives the source IPv4 address in string format.
 *
 * @return Source IPv4 string. Free with g_free().
 */
char *
gvm_source_addr_str (void)
{
  char *str = g_malloc0 (INET_ADDRSTRLEN);

  inet_ntop (AF_INET, &global_source_addr.s_addr, str, INET_ADDRSTRLEN);
  return str;
}

/**
 * @brief Gives the source IPv6 address in string format.
 *
 * @return Source IPv6 string. Free with g_free().
 */
char *
gvm_source_addr6_str (void)
{
  char *str = g_malloc0 (INET6_ADDRSTRLEN);

  inet_ntop (AF_INET6, &global_source_addr6, str, INET6_ADDRSTRLEN);
  return str;
}

/* Miscellaneous functions. */

/**
 * @brief Maps an IPv4 address as an IPv6 address.
 * eg. 192.168.10.20 would map to \::ffff:192.168.10.20.
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
 * @brief Stringifies an IP address.
 *
 * @param[in]   addr6   IP address.
 * @param[out]  str     Buffer to output IP.
 */
void
addr6_to_str (const struct in6_addr *addr6, char *str)
{
  if (!addr6)
    return;
  if (IN6_IS_ADDR_V4MAPPED (addr6))
    inet_ntop (AF_INET, &addr6->s6_addr32[3], str, INET6_ADDRSTRLEN);
  else
    inet_ntop (AF_INET6, addr6, str, INET6_ADDRSTRLEN);
}

/**
 * @brief Stringifies an IP address.
 *
 * @param[in]   addr6   IP address.
 *
 * @return      IP as string. NULL otherwise.
 */
char *
addr6_as_str (const struct in6_addr *addr6)
{
  char *str;

  if (!addr6)
    return NULL;

  str = g_malloc0 (INET6_ADDRSTRLEN);
  addr6_to_str (addr6, str);
  return str;
}

/**
 * @brief Convert an IP address to string format.
 *
 * @param[in]   addr    Address to convert.
 * @param[out]  str     Buffer of INET6_ADDRSTRLEN size.
 */
void
sockaddr_as_str (const struct sockaddr_storage *addr, char *str)
{
  if (!addr || !str)
    return;

  if (addr->ss_family == AF_INET)
    {
      struct sockaddr_in *saddr = (struct sockaddr_in *) addr;
      inet_ntop (AF_INET, &saddr->sin_addr, str, INET6_ADDRSTRLEN);
    }
  else if (addr->ss_family == AF_INET6)
    {
      struct sockaddr_in6 *s6addr = (struct sockaddr_in6 *) addr;
      if (IN6_IS_ADDR_V4MAPPED (&s6addr->sin6_addr))
        inet_ntop (AF_INET, &s6addr->sin6_addr.s6_addr[12], str,
                   INET6_ADDRSTRLEN);
      else
        inet_ntop (AF_INET6, &s6addr->sin6_addr, str, INET6_ADDRSTRLEN);
    }
  else if (addr->ss_family == AF_UNIX)
    {
      g_snprintf (str, INET6_ADDRSTRLEN, "unix_socket");
    }
  else if (addr->ss_family == AF_UNSPEC)
    {
      g_snprintf (str, INET6_ADDRSTRLEN, "unknown_socket");
    }
  else
    {
      g_snprintf (str, INET6_ADDRSTRLEN, "type_%d_socket", addr->ss_family);
    }
}

/**
 * @brief Returns a list of addresses that a hostname resolves to.
 *
 * @param[in]   name    Hostname to resolve.
 *
 * @return List of addresses, NULL otherwise.
 */
GSList *
gvm_resolve_list (const char *name)
{
  struct addrinfo hints, *info, *p;
  GSList *list = NULL;

  if (name == NULL)
    return NULL;

  bzero (&hints, sizeof (hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_protocol = 0;
  if ((getaddrinfo (name, NULL, &hints, &info)) != 0)
    return NULL;

  p = info;
  while (p)
    {
      struct in6_addr dst;

      if (p->ai_family == AF_INET)
        {
          struct sockaddr_in *addrin = (struct sockaddr_in *) p->ai_addr;
          ipv4_as_ipv6 (&(addrin->sin_addr), &dst);
          list = g_slist_prepend (list, g_memdup (&dst, sizeof (dst)));
        }
      else if (p->ai_family == AF_INET6)
        {
          struct sockaddr_in6 *addrin = (struct sockaddr_in6 *) p->ai_addr;
          memcpy (&dst, &(addrin->sin6_addr), sizeof (struct in6_addr));
          list = g_slist_prepend (list, g_memdup (&dst, sizeof (dst)));
        }
      p = p->ai_next;
    }

  freeaddrinfo (info);
  return list;
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
gvm_resolve (const char *name, void *dst, int family)
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
gvm_resolve_as_addr6 (const char *name, struct in6_addr *ip6)
{
  return gvm_resolve (name, ip6, AF_UNSPEC);
}

/* Ports related. */

/**
 * @brief Validate a port range string.
 *
 * Accepts ranges in form of "103,U:200-1024,3000-4000,T:3-4,U:7".
 *
 * @param[in]   port_range  A port range.
 *
 * @return 0 success, 1 failed.
 */
int
validate_port_range (const char *port_range)
{
  gchar **split, **point, *range, *range_start;

  if (!port_range)
    return 1;

  while (*port_range && isblank (*port_range))
    port_range++;
  if (*port_range == '\0')
    return 1;

  /* Treat newlines like commas. */
  range = range_start = g_strdup (port_range);
  while (*range)
    {
      if (*range == '\n')
        *range = ',';
      range++;
    }

  split = g_strsplit (range_start, ",", 0);
  g_free (range_start);
  point = split;

  while (*point)
    {
      gchar *hyphen, *element;

      /* Strip off any outer whitespace. */

      element = g_strstrip (*point);

      /* Strip off any leading type specifier and following whitespace. */

      if ((strlen (element) >= 2)
          && ((element[0] == 'T') || (element[0] == 'U')))
        {
          element++;
          while (*element && isblank (*element))
            element++;
          if (*element == ':')
            element++;
        }

      /* Look for a hyphen. */

      hyphen = strchr (element, '-');
      if (hyphen)
        {
          long int number1, number2;
          const char *first;
          char *end;

          hyphen++;

          /* Check the first number. */

          first = element;
          while (*first && isblank (*first))
            first++;
          if (*first == '-')
            goto fail;

          errno = 0;
          number1 = strtol (first, &end, 10);
          while (*end && isblank (*end))
            end++;
          if (errno || (*end != '-'))
            goto fail;
          if (number1 == 0)
            goto fail;
          if (number1 > 65535)
            goto fail;

          /* Check the second number. */

          while (*hyphen && isblank (*hyphen))
            hyphen++;
          if (*hyphen == '\0')
            goto fail;

          errno = 0;
          number2 = strtol (hyphen, &end, 10);
          while (*end && isblank (*end))
            end++;
          if (errno || *end)
            goto fail;
          if (number2 == 0)
            goto fail;
          if (number2 > 65535)
            goto fail;

          if (number1 > number2)
            goto fail;
        }
      else
        {
          long int number;
          const char *only;
          char *end;

          /* Check the single number. */

          only = element;
          while (*only && isblank (*only))
            only++;
          /* Empty ranges are OK. */
          if (*only)
            {
              errno = 0;
              number = strtol (only, &end, 10);
              while (*end && isblank (*end))
                end++;
              if (errno || *end)
                goto fail;
              if (number == 0)
                goto fail;
              if (number > 65535)
                goto fail;
            }
        }
      point += 1;
    }

  g_strfreev (split);
  return 0;

fail:
  g_strfreev (split);
  return 1;
}

/**
 * @brief Create a range array from a port_range string.
 *
 * @param[in]   port_range  Valid port_range string.
 *
 * @return Range array or NULL if port_range invalid or NULL.
 */
array_t *
port_range_ranges (const char *port_range)
{
  gchar **split, **point, *range_start, *current;
  array_t *ranges;
  int tcp, err;

  if (!port_range)
    return NULL;

  /* port_range needs to be a valid port_range string. */
  err = validate_port_range (port_range);
  if (err)
    return NULL;

  ranges = make_array ();

  while (*port_range && isblank (*port_range))
    port_range++;

  /* Accepts T: and U: before any of the ranges.  This toggles the remaining
   * ranges, as in nmap.  Treats a leading naked range as TCP, whereas nmap
   * treats it as TCP and UDP. */

  /* Treat newlines like commas. */
  range_start = current = g_strdup (port_range);
  while (*current)
    {
      if (*current == '\n')
        *current = ',';
      current++;
    }

  tcp = 1;
  split = g_strsplit (range_start, ",", 0);
  g_free (range_start);
  point = split;

  while (*point)
    {
      gchar *hyphen, *element;
      range_t *range;
      int element_strlen;

      element = g_strstrip (*point);
      element_strlen = strlen (element);

      if (element_strlen >= 2)
        {
          if ((element[0] == 'T'))
            {
              element++;
              while (*element && isblank (*element))
                element++;
              if (*element == ':')
                {
                  element++;
                  tcp = 1;
                }
            }
          else if ((element[0] == 'U'))
            {
              element++;
              while (*element && isblank (*element))
                element++;
              if (*element == ':')
                {
                  element++;
                  tcp = 0;
                }
            }
          /* Else tcp stays as it is. */
        }

      /* Skip any space that followed the type specifier. */
      while (*element && isblank (*element))
        element++;

      hyphen = strchr (element, '-');
      if (hyphen)
        {
          *hyphen = '\0';
          hyphen++;
          while (*hyphen && isblank (*hyphen))
            hyphen++;
          assert (*hyphen); /* Validation checks this. */

          /* A range. */

          range = (range_t *) g_malloc0 (sizeof (range_t));

          range->start = atoi (element);
          range->end = atoi (hyphen);
          range->type = tcp ? PORT_PROTOCOL_TCP : PORT_PROTOCOL_UDP;
          range->exclude = 0;

          array_add (ranges, range);
        }
      else if (*element)
        {
          /* A single port. */

          range = (range_t *) g_malloc0 (sizeof (range_t));

          range->start = atoi (element);
          range->end = range->start;
          range->type = tcp ? PORT_PROTOCOL_TCP : PORT_PROTOCOL_UDP;
          range->exclude = 0;

          array_add (ranges, range);
        }
      /* Else skip over empty range. */
      point += 1;
    }
  g_strfreev (split);
  return ranges;
}

/**
 * @brief Checks if a port num is in port ranges array.
 *
 * @param[in]  pnum     Port number.
 * @param[in]  ptype    Port type.
 * @param[in]  pranges  Array of port ranges.
 *
 * @return 1 if port in port ranges, 0 otherwise.
 */
int
port_in_port_ranges (int pnum, port_protocol_t ptype, array_t *pranges)
{
  unsigned int i;

  if (pranges == NULL || pnum < 0 || pnum > 65536)
    return 0;

  for (i = 0; i < pranges->len; i++)
    {
      range_t *range = (range_t *) g_ptr_array_index (pranges, i);
      if (range->type != ptype)
        continue;
      if (range->start <= pnum && pnum <= range->end)
        return 1;
    }
  return 0;
}

/**
 * @brief Checks if IPv6 support is enabled.
 *
 * @return 1 if IPv6 is enabled, 0 if disabled.
 */
int
ipv6_is_enabled ()
{
  int sock = socket (PF_INET6, SOCK_STREAM, 0);

  if (sock < 0)
    {
      if (errno == EAFNOSUPPORT)
        return 0;
    }
  else
    close (sock);

  return 1;
}

/* Functions used by alive detection module (Boreas). */

/**
 * @brief Determine if IP is localhost.
 *
 * @return True if IP is localhost, else false.
 */
gboolean
ip_islocalhost (struct sockaddr_storage *storage)
{
  struct in_addr addr;
  struct in_addr *addr_p;
  struct in6_addr addr6;
  struct in6_addr *addr6_p;
  struct sockaddr_in *sin_p;
  struct sockaddr_in6 *sin6_p;
  struct ifaddrs *ifaddr, *ifa;
  int family;

  family = storage->ss_family;
  addr6_p = &addr6;
  addr_p = &addr;

  if (family == AF_INET)
    {
      sin_p = (struct sockaddr_in *) storage;
      addr = sin_p->sin_addr;

      if (addr_p == NULL)
        return FALSE;
      /* addr is 0.0.0.0 */
      if ((addr_p)->s_addr == 0)
        return TRUE;
      /* addr starts with 127.0.0.1 */
      if (((addr_p)->s_addr & htonl (0xFF000000)) == htonl (0x7F000000))
        return TRUE;
    }
  if (family == AF_INET6)
    {
      sin6_p = (struct sockaddr_in6 *) storage;
      addr6 = sin6_p->sin6_addr;

      if (IN6_IS_ADDR_V4MAPPED (&addr6))
        {
          /* addr is 0.0.0.0 */
          if (addr6_p->s6_addr32[3] == 0)
            return 1;

          /* addr starts with 127.0.0.1 */
          if ((addr6_p->s6_addr32[3] & htonl (0xFF000000))
              == htonl (0x7F000000))
            return 1;
        }
      if (IN6_IS_ADDR_LOOPBACK (addr6_p))
        return 1;
    }

  if (getifaddrs (&ifaddr) == -1)
    {
      g_debug ("%s: getifaddr failed: %s", __func__, strerror (errno));
      return FALSE;
    }
  else
    {
      struct sockaddr_in *sin;
      struct sockaddr_in6 *sin6;

      for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
        {
          if (ifa->ifa_addr == NULL)
            continue;
          if (ifa->ifa_addr->sa_family == AF_INET)
            {
              sin = (struct sockaddr_in *) (ifa->ifa_addr);
              /* Check if same address as local interface. */
              if (addr_p->s_addr == sin->sin_addr.s_addr)
                return TRUE;
            }
          if (ifa->ifa_addr->sa_family == AF_INET6)
            {
              sin6 = (struct sockaddr_in6 *) (ifa->ifa_addr);
              /* Check if same address as local interface. */
              if (IN6_ARE_ADDR_EQUAL (&(sin6->sin6_addr), addr6_p))
                return TRUE;
            }
        }
      freeifaddrs (ifaddr);
    }

  return FALSE;
}

typedef struct route_entry route_entry_t;

/** Entry of routing table /proc/net/route */
struct route_entry
{
  gchar *interface;
  unsigned long mask;
  unsigned long dest;
};

/**
 * @brief Get the entries of /proc/net/route as list of route_entry structs.
 *
 * @return  GSList of route_entry structs. NULL if no routes found or Error.
 */
static GSList *
get_routes (void)
{
  GSList *routes;
  GError *err;
  GIOChannel *file_channel;
  gchar *line;
  gchar **items_in_line;
  int status;
  route_entry_t *entry;

  err = NULL;
  routes = NULL;
  line = NULL;

  /* Open "/proc/net/route". */
  file_channel = g_io_channel_new_file ("/proc/net/route", "r", &err);
  if (file_channel == NULL)
    {
      g_warning ("%s: %s. ", __func__,
                 err ? err->message : "Error opening /proc/net/ipv6_route");
      err = NULL;
      return NULL;
    }

  /* Skip first first line of file. */
  status = g_io_channel_read_line (file_channel, &line, NULL, NULL, &err);
  if (status != G_IO_STATUS_NORMAL || !line || err)
    {
      g_warning ("%s: %s", __func__,
                 err ? err->message
                     : "g_io_channel_read_line() status != G_IO_STATUS_NORMAL");
      err = NULL;
    }
  g_free (line);

  /* Until EOF or err we go through lines of file and extract Iface, Mask and
   * Destination and put it into the to be returned list of routes.*/
  while (1)
    {
      gchar *interface, *char_p;
      unsigned long mask, dest;
      int count;

      /* Get new line. */
      line = NULL;
      status = g_io_channel_read_line (file_channel, &line, NULL, NULL, &err);
      if ((status != G_IO_STATUS_NORMAL) || !line || err)
        {
          if (status == G_IO_STATUS_AGAIN)
            g_warning ("%s: /proc/net/route unavailable.", __func__);
          if (err || status == G_IO_STATUS_ERROR)
            g_warning (
              "%s: %s", __func__,
              err ? err->message
                  : "g_io_channel_read_line() status == G_IO_STATUS_ERROR");
          err = NULL;
          g_free (line);
          break;
        }

      /* Get items in line. */
      items_in_line = g_strsplit (line, "\t", -1);
      /* Check for missing entries in line of "/proc/net/route". */
      for (count = 0; items_in_line[count]; count++)
        ;
      if (11 != count)
        {
          g_strfreev (items_in_line);
          g_free (line);
          continue;
        }

      interface = g_strndup (items_in_line[0], 64);
      /* Cut interface str after ":" if IP aliasing is used. */
      if ((char_p = strchr (interface, ':')))
        {
          *char_p = '\0';
        }
      dest = strtoul (items_in_line[1], NULL, 16);
      mask = strtoul (items_in_line[7], NULL, 16);

      /* Fill GSList entry. */
      entry = g_malloc0 (sizeof (route_entry_t));
      entry->interface = interface;
      entry->dest = dest;
      entry->mask = mask;
      routes = g_slist_append (routes, entry);

      g_strfreev (items_in_line);
      g_free (line);
    }

  status = g_io_channel_shutdown (file_channel, TRUE, &err);
  if ((G_IO_STATUS_NORMAL != status) || err)
    g_warning ("%s: %s", __func__,
               err ? err->message
                   : "g_io_channel_shutdown() was not successful");

  return routes;
}

/**
 * @brief Get Interface which should be used for routing to destination addr.
 *
 * This function should be used sparingly as it parses /proc/net/route for
 * every call.
 *
 * @param[in]   storage_dest    Destination address.
 * @param[out]  storage_source  Source address. Is set to either address of the
 * interface we use or global source address if set. Only gets filled if
 * storage_source != NULL.
 *
 * @return Interface name of interface used for routing to destination address.
 * NULL if no interface found or Error.
 */
gchar *
gvm_routethrough (struct sockaddr_storage *storage_dest,
                  struct sockaddr_storage *storage_source)
{
  struct ifaddrs *ifaddr, *ifa;
  gchar *interface_out;

  interface_out = NULL;

  if (!storage_dest)
    return NULL;

  if (getifaddrs (&ifaddr) == -1)
    {
      g_debug ("%s: getifaddr failed: %s", __func__, strerror (errno));
      return NULL;
    }

  /* IPv4. */
  if (storage_dest->ss_family == AF_INET)
    {
      GSList *routes;
      GSList *routes_p;

      routes = get_routes ();

      /* Set storage_source to localhost if storage_source was supplied and
       * return name of loopback interface. */
      if (ip_islocalhost (storage_dest))
        {
          // TODO: check for (storage_source->ss_family == AF_INET)
          if (storage_source)
            {
              struct sockaddr_in *sin_p = (struct sockaddr_in *) storage_source;
              sin_p->sin_addr.s_addr = htonl (0x7F000001);
            }

          for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
            {
              if (ifa->ifa_addr && (ifa->ifa_addr->sa_family == AF_INET)
                  && (ifa->ifa_flags & (IFF_LOOPBACK)))
                {
                  interface_out = g_strdup (ifa->ifa_name);
                  break;
                }
            }
        }
      else
        {
          struct sockaddr_in *sin_dest_p, *sin_src_p;
          struct in_addr global_src;
          unsigned long best_match;

          /* Check if global_source_addr in use. */
          gvm_source_addr (&global_src);

          sin_dest_p = (struct sockaddr_in *) storage_dest;
          sin_src_p = (struct sockaddr_in *) storage_source;
          /* Check routes for matching address. Get interface name and set
           * storage_source*/
          for (best_match = 0, routes_p = routes; routes_p;
               routes_p = routes_p->next)
            {
              if (((sin_dest_p->sin_addr.s_addr
                    & ((route_entry_t *) (routes_p->data))->mask)
                   == ((route_entry_t *) (routes_p->data))->dest)
                  && (((route_entry_t *) (routes_p->data))->mask >= best_match))
                {
                  /* Interface of matching route.*/
                  g_free (interface_out);
                  interface_out =
                    g_strdup (((route_entry_t *) (routes_p->data))->interface);
                  best_match = ((route_entry_t *) (routes_p->data))->mask;

                  if (!storage_source)
                    continue;

                  /* Set storage_source to global source if global source
                   * present.*/
                  if (global_src.s_addr != INADDR_ANY)
                    sin_src_p->sin_addr.s_addr = global_src.s_addr;
                  /* Set storage_source to addr of matching interface if no
                   * global source present.*/
                  else
                    {
                      for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
                        {
                          if (ifa->ifa_addr
                              && (ifa->ifa_addr->sa_family == AF_INET)
                              && (g_strcmp0 (interface_out, ifa->ifa_name)
                                  == 0))
                            {
                              sin_src_p->sin_addr.s_addr =
                                ((struct sockaddr_in *) (ifa->ifa_addr))
                                  ->sin_addr.s_addr;
                              break;
                            }
                        }
                    }
                }
            }
        }
      /* Free GSList. */
      if (routes)
        {
          for (routes_p = routes; routes_p; routes_p = routes_p->next)
            {
              if (((route_entry_t *) (routes_p->data))->interface)
                g_free (((route_entry_t *) (routes_p->data))->interface);
            }
          g_slist_free (routes);
        }
    }
  else if (storage_dest->ss_family == AF_INET6)
    {
      g_warning ("%s: IPv6 not yet implemented for this function. Will be "
                 "implemented soon. Thanks for your patience.",
                 __func__);
    }

  return interface_out != NULL ? interface_out : NULL;
}
