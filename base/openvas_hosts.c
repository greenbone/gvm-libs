/* openvas-libraries/base
 * $Id$
 * Description: Implementation of API to handle Hosts objects
 *
 * Authors:
 * Hani Benhabiles <hani.benhabiles@greenbone.net>
 * Jan-Oliver Wagner <jan-oliver.wagner@greenbone.net>
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

/**
 * @file hosts.c
 * @brief Implementation of an API to handle Hosts objects
 *
 * This file contains all methods to handle Hosts collections (openvas_hosts_t)
 * and single hosts objects (openvas_host_t.)
 *
 * The module consequently uses glib datatypes.
 */

#include "openvas_hosts.h"

/* Static variables */

gchar *host_type_str[HOST_TYPE_MAX] = {
  [HOST_TYPE_NAME] = "Hostname",
  [HOST_TYPE_IPV4] = "IPv4",
  [HOST_TYPE_IPV6] = "IPv6",
  [HOST_TYPE_CIDR_BLOCK] = "IPv4 CIDR block",
  [HOST_TYPE_RANGE_SHORT] = "IPv4 short range",
  [HOST_TYPE_RANGE_LONG] = "IPv4 long range"
};

/* Function definitions */

/**
 * @brief Checks if a buffer points to a valid IPv4 address.
 * "192.168.11.1" is valid, "192.168.1.300" and "192.168.1.1e" are not.
 *
 * @param[in]   str Buffer to check in.
 *
 * @return 1 if valid IPv4 address, 0 otherwise.
 */
static int
is_ipv4_address (const char *str)
{
  struct sockaddr_in sa;

  return inet_pton(AF_INET, str, &(sa.sin_addr)) == 1;
}

/**
 * @brief Checks if a buffer points to a valid IPv6 address.
 * "0:0:0:0:0:0:0:1", "::1" and "::FFFF:192.168.13.55" are valid "::1g" is not.
 *
 * @param[in]   str Buffer to check in.
 *
 * @return 1 if valid IPv6 address, 0 otherwise.
 */
static int
is_ipv6_address (const char *str)
{
  struct sockaddr_in6 sa6;

  return inet_pton(AF_INET6, str, &(sa6.sin6_addr)) == 1;
}

/**
 * @brief Checks if a buffer points to an IPv4 CIDR-exprpessed block.
 * "192.168.12.3/24" is valid, "192.168.1.3/31" is not.
 *
 * @param[in]   str Buffer to check in.
 *
 * @return 1 if valid CIDR-expressed block, 0 otherwise.
 */
static int
is_cidr_block (const char *str)
{
  long block;
  char *addr_str, *block_str, *p;

  addr_str = g_strdup (str);
  block_str = strchr (addr_str, '/');
  if (block_str == NULL)
    {
      g_free (addr_str);
      return 0;
    }

  /* Separate the address from the block value. */
  *block_str = '\0';
  block_str++;

  if (!is_ipv4_address (addr_str) || !isdigit (*block_str))
    {
      g_free (addr_str);
      return 0;
    }

  p = NULL;
  block = strtol (block_str, &p, 10);
  g_free (addr_str);

  if (*p || block <= 0 || block > 30)
    return 0;

  return 1;
}

/**
 * @brief Gets the network block value from a CIDR-expressed block string.
 * For "192.168.1.1/24" it is 24.
 *
 * @param[in]   str     Buffer containing CIDR-expressed block.
 * @param[out]  block   Variable to store block value.
 *
 * @return -1 if error, 0 otherwise.
 */
static int
cidr_get_block (const char *str, unsigned int *block)
{
  if (str == NULL || block == NULL)
    return -1;

  if (sscanf (str, "%*[0-9.]/%2u", block)
      != 1)
    return -1;

  return 0;
}

/**
 * @brief Gets the IPv4 value from a CIDR-expressed block.
 * eg. For "192.168.1.10/24" it is "192.168.1.10".
 *
 * @param[in]   str     String containing CIDR-expressed block.
 * @param[out]  addr    Variable to store the IPv4 address value.
 *
 * @return -1 if error, 0 otherwise.
 */
static int
cidr_get_ip (const char *str, struct in_addr *addr)
{
  gchar *addr_str, *tmp;

  if (str == NULL || addr == NULL)
    return -1;

  addr_str = g_strdup (str);
  tmp = strchr (addr_str, '/');
  if (tmp == NULL)
    {
      g_free (addr_str);
      return -1;
    }
  *tmp = '\0';

  if (inet_pton (AF_INET, addr_str, addr) != 1)
    return -1;

  g_free (addr_str);
  return 0;
}

/**
 * @brief Gets the first and last usable IPv4 addresses from a CIDR-expressed
 * block. eg. "192.168.1.0/24" would give 192.168.1.1 as first and 192.168.1.254
 * as last.
 *
 * Both network and broadcast addresses are skipped:
 * - They are _never_ used as a host address. Not being included is the expected
 *   behaviour from users.
 * - When needed, short/long ranges (eg. 192.168.1.0-255) are available.
 *
 * @param[in]   str     Buffer containing CIDR-expressed block.
 * @param[out]  first   First IPv4 address in block.
 * @param[out]  last    Last IPv4 address in block.
 *
 * @return -1 if error, 0 else.
 */
static int
cidr_block_ips (const char *str, struct in_addr *first, struct in_addr *last)
{
  unsigned int block;

  if (str == NULL || first == NULL || last == NULL)
    return -1;

  /* Get IP and block values. */
  if (cidr_get_block (str, &block) == -1)
    return -1;
  if (cidr_get_ip (str, first) == -1)
    return -1;

  /* First IP: And with mask and increment. */
  first->s_addr &= htonl (0xffffffff ^ ((1 << (32 - block)) - 1));
  first->s_addr = htonl (ntohl (first->s_addr) + 1);

  /* Last IP: First IP + Number of usable hosts - 1. */
  last->s_addr = htonl (ntohl (first->s_addr) + (1 << (32 - block)) - 3);
  return 0;
}

/**
 * @brief Checks if a buffer points to a valid long range-expressed network.
 * "192.168.12.1-192.168.13.50" is valid.
 *
 * @param[in]   str Buffer to check in.
 *
 * @return 1 if valid long range-expressed network, 0 otherwise.
 */
static int
is_long_range_network (const char *str)
{
  char *first_str, *second_str;
  int ret;

  first_str = g_strdup (str);
  second_str = strchr (first_str, '-');
  if (second_str == NULL)
    {
      g_free (first_str);
      return 0;
    }

  /* Separate the addresses. */
  *second_str = '\0';
  second_str++;

  ret = is_ipv4_address (first_str) && is_ipv4_address (second_str);
  g_free (first_str);

  return ret;
}

/**
 * @brief Gets the first and last IPv4 addresses from a long range-expressed
 * network. eg. "192.168.1.1-192.168.2.40" would give 192.168.1.1 as first and
 * 192.168.2.40 as last.
 *
 * @param[in]   str     String containing long range-expressed network.
 * @param[out]  first   First IP address in block.
 * @param[out]  last    Last IP address in block.
 *
 * @return -1 if error, 0 else.
 */
static int
long_range_network_ips (const char *str, struct in_addr *first,
                        struct in_addr *last)
{
  char *first_str, *last_str;

  if (str == NULL || first == NULL || last == NULL)
    return -1;

  first_str = g_strdup (str);
  last_str = strchr (first_str, '-');
  if (last_str == NULL)
    {
      g_free (first_str);
      return -1;
    }

  /* Separate the two IPs. */
  *last_str = '\0';
  last_str++;

  if (inet_pton (AF_INET, first_str, first) != 1
      || inet_pton (AF_INET, last_str, last) != 1)
  {
    g_free (first_str);
    return -1;
  }

  g_free (first_str);
  return 0;
}

/**
 * @brief Checks if a buffer points to a valid short range-expressed network.
 * "192.168.11.1-50" is valid, "192.168.1.1-50e" and "192.168.1.1-300" are not.
 *
 * @param   str String to check in.
 *
 * @return 1 if str points to a valid short range-network, 0 otherwise.
 */
static int
is_short_range_network (const char *str)
{
  long end;
  char *ip_str, *end_str, *p;

  ip_str = g_strdup (str);
  end_str = strchr (ip_str, '-');
  if (end_str == NULL)
    {
      g_free (ip_str);
      return 0;
    }

  /* Separate the addreses. */
  *end_str = '\0';
  end_str++;

  if (!is_ipv4_address (ip_str) || !isdigit (*end_str))
    {
      g_free (ip_str);
      return 0;
    }

  p = NULL;
  end = strtol (end_str, &p, 10);
  g_free (ip_str);

  if (*p || end < 0 || end > 255)
    return 0;

  return 1;
}

/**
 * @brief Gets the first and last IPv4 addresses from a short range-expressed
 * network. "192.168.1.1-40" would give 192.168.1.1 as first and 192.168.1.40 as
 * last.
 *
 * @param[in]   str     String containing short range-expressed network.
 * @param[out]  first   First IP address in block.
 * @param[out]  last    Last IP address in block.
 *
 * @return -1 if error, 0 else.
 */
static int
short_range_network_ips (const char *str, struct in_addr *first,
                         struct in_addr *last)
{
  char *first_str, *last_str;
  int end;

  if (str == NULL || first == NULL || last == NULL)
    return -1;

  first_str = g_strdup (str);
  last_str = strchr (first_str, '-');
  if (last_str == NULL)
    {
      g_free (first_str);
      return -1;
    }

  /* Separate the two IPs. */
  *last_str = '\0';
  last_str++;
  end = atoi (last_str);

  /* Get the first IP */
  if (inet_pton (AF_INET, first_str, first) != 1)
  {
    g_free (first_str);
    return -1;
  }

  /* Get the last IP */
  last->s_addr = htonl ((ntohl (first->s_addr) & 0xffffff00) + end);

  g_free (first_str);
  return 0;
}

/**
 * @brief Checks if a buffer points to a valid hostname.
 * Valid characters include: Alphanumerics, dot (.), dash (-) and underscore (_)
 * up to 255 characters.
 *
 * @param[in]   str Buffer to check in.
 *
 * @return 1 if valid hostname, 0 otherwise.
 */
static int
is_hostname (const char *str)
{
  const char *h = str;

  while (*h && (isalnum (*h) || strchr ("-_.", *h)))
    h++;

  /* Valid string if no other chars, and length is 255 at most. */
  if (*h == '\0' && h - str < 256)
    return 1;

  return 0;
}

/**
 * @brief Checks if a buffer points to an IPv6 CIDR-exprpessed block.
 * "2620:0:2d0:200::7/120" is valid, "2620:0:2d0:200::7/129" is not.
 *
 * @param[in]   str Buffer to check in.
 *
 * @return 1 if valid IPv6 CIDR-expressed block, 0 otherwise.
 */
static int
is_cidr6_block (const char *str)
{
  long block;
  char *addr6_str, *block_str, *p;

  addr6_str = g_strdup (str);
  block_str = strchr (addr6_str, '/');
  if (block_str == NULL)
    {
      g_free (addr6_str);
      return 0;
    }

  /* Separate the address from the block value. */
  *block_str = '\0';
  block_str++;

  if (!is_ipv6_address (addr6_str) || !isdigit (*block_str))
    {
      g_free (addr6_str);
      return 0;
    }

  p = NULL;
  block = strtol (block_str, &p, 10);
  g_free (addr6_str);

  if (*p || block <= 0 || block > 128)
    return 0;

  return 1;
}

/**
 * @brief Gets the network block value from a CIDR-expressed block string.
 * For "192.168.1.1/24" it is 24.
 *
 * @param[in]   str     Buffer containing CIDR-expressed block.
 * @param[out]  block   Variable to store block value.
 *
 * @return -1 if error, 0 otherwise.
 */
static int
cidr6_get_block (const char *str, unsigned int *block)
{
  if (str == NULL || block == NULL)
    return -1;

  if (sscanf (str, "%*[0-9a-fA-F.:]/%3u", block)
      != 1)
    return -1;

  return 0;
}

/**
 * @brief Gets the IPv4 value from a CIDR-expressed block.
 * eg. For "192.168.1.10/24" it is "192.168.1.10".
 *
 * @param[in]   str     String containing CIDR-expressed block.
 * @param[out]  addr    Variable to store the IPv4 address value.
 *
 * @return -1 if error, 0 otherwise.
 */
static int
cidr6_get_ip (const char *str, struct in6_addr *addr6)
{
  gchar *addr6_str, *tmp;

  if (str == NULL || addr6 == NULL)
    return -1;

  addr6_str = g_strdup (str);
  tmp = strchr (addr6_str, '/');
  if (tmp == NULL)
    {
      g_free (addr6_str);
      return -1;
    }
  *tmp = '\0';

  if (inet_pton (AF_INET6, addr6_str, addr6) != 1)
    return -1;

  g_free (addr6_str);
  return 0;
}

/**
 * @brief Gets the first and last usable IPv4 addresses from a CIDR-expressed
 * block. eg. "192.168.1.0/24 would give 192.168.1.1 as first and 192.168.1.254
 * as last. Thus, it skips the network and broadcast addresses.
 *
 * @param[in]   str     Buffer containing CIDR-expressed block.
 * @param[out]  first   First IPv4 address in block.
 * @param[out]  last    Last IPv4 address in block.
 *
 * @return -1 if error, 0 else.
 */
static int
cidr6_block_ips (const char *str, struct in6_addr *first, struct in6_addr *last)
{
  unsigned int block;
  int i, j;

  if (str == NULL || first == NULL || last == NULL)
    return -1;

  /* Get IP and block values. */
  if (cidr6_get_block (str, &block) == -1)
    return -1;
  if (cidr6_get_ip (str, first) == -1)
    return -1;
  memcpy (&last->s6_addr, &first->s6_addr, 16);

  /* /128 => Specified address is the first and last one. */
  if (block == 128)
    return 0;

  /* First IP: And with mask and increment to skip network address. */
  j = 15;
  for (i = (128 - block) / 8; i > 0; i--)
    {
      first->s6_addr[j] = 0;
      j--;
    }
  first->s6_addr[j] &= 0xff ^ ((1 << ((128 - block) % 8)) - 1);

  /* Last IP: Broadcast address - 1. */
  j = 15;
  for (i = (128 - block) / 8; i > 0; i--)
    {
      last->s6_addr[j] = 0xff;
      j--;
    }
  last->s6_addr[j] |= (1 << ((128 - block) % 8)) - 1;

  /* /127 => Only two addresses. Don't skip network / broadcast addresses.*/
  if (block == 127)
    return 0;

  /* Increment first IP. */
  for (i = 15; i >= 0; --i)
    if (first->s6_addr[i] < 255)
      {
        first->s6_addr[i]++;
        break;
      }
    else
      first->s6_addr[i] = 0;
  /* Decrement last IP. */
  for (i = 15; i >= 0; --i)
    if (last->s6_addr[i] > 0)
      {
        last->s6_addr[i]--;
        break;
      }
    else
      last->s6_addr[i] = 0xff;

  return 0;
}

/**
 * @brief Checks if a buffer points to a valid long IPv6 range-expressed
 * network. "::fee5-::1:530" is valid.
 *
 * @param[in]   str Buffer to check in.
 *
 * @return 1 if valid long range-expressed network, 0 otherwise.
 */
static int
is_long_range6_network (const char *str)
{
  char *first_str, *second_str;
  int ret;

  first_str = g_strdup (str);
  second_str = strchr (first_str, '-');
  if (second_str == NULL)
    {
      g_free (first_str);
      return 0;
    }

  /* Separate the addreses. */
  *second_str = '\0';
  second_str++;

  ret = is_ipv6_address (first_str) && is_ipv6_address (second_str);
  g_free (first_str);

  return ret;
}

/**
 * @brief Gets the first and last IPv6 addresses from a long range-expressed
 * network. eg. "::1:200:7-::1:205:500" would give ::1:200:7 as first and
 * ::1:205:500 as last.
 *
 * @param[in]   str     String containing long IPv6 range-expressed network.
 * @param[out]  first   First IPv6 address in range.
 * @param[out]  last    Last IPv6 address in range.
 *
 * @return -1 if error, 0 else.
 */
static int
long_range6_network_ips (const char *str, struct in6_addr *first,
                         struct in6_addr *last)
{
  char *first_str, *last_str;

  if (str == NULL || first == NULL || last == NULL)
    return -1;

  first_str = g_strdup (str);
  last_str = strchr (first_str, '-');
  if (last_str == NULL)
    {
      g_free (first_str);
      return -1;
    }

  /* Separate the two IPs. */
  *last_str = '\0';
  last_str++;

  if (inet_pton (AF_INET6, first_str, first) != 1
      || inet_pton (AF_INET6, last_str, last) != 1)
    {
      g_free (first_str);
      return -1;
    }

  g_free (first_str);
  return 0;
}

/**
 * @brief Checks if a buffer points to a valid short IPv6 range-expressed
 * network. "::200:ff:1-fee5" is valid.
 *
 * @param   str String to check in.
 *
 * @return 1 if str points to a valid short-range IPv6 network, 0 otherwise.
 */
static int
is_short_range6_network (const char *str)
{
  char *ip_str, *end_str, *p;

  ip_str = g_strdup (str);
  end_str = strchr (ip_str, '-');
  if (end_str == NULL)
    {
      g_free (ip_str);
      return 0;
    }

  /* Separate the addresses. */
  *end_str = '\0';
  end_str++;

  if (!is_ipv6_address (ip_str) || *end_str == '\0')
    {
      g_free (ip_str);
      return 0;
    }

  p = end_str;
  /* Check that the 2nd part is at most 4 hexadecimal characters. */
  while (isxdigit (*p) && p++);
  if (*p || p - end_str > 4)
    {
      g_free (ip_str);
      return 0;
    }

  g_free (ip_str);
  return 1;
}

/**
 * @brief Gets the first and last IPv6 addresses from a short range-expressed
 * network. eg. "::ffee:1:1001-1005" would give ::ffee:1:1001 as first and
 * ::ffee:1:1005 as last.
 *
 * @param[in]   str     String containing short IPv6 range-expressed network.
 * @param[out]  first   First IPv6 address in range.
 * @param[out]  last    Last IPv6 address in range.
 *
 * @return -1 if error, 0 else.
 */
static int
short_range6_network_ips (const char *str, struct in6_addr *first,
                          struct in6_addr *last)
{
  char *first_str, *last_str;
  long int end;

  if (str == NULL || first == NULL || last == NULL)
    return -1;

  first_str = g_strdup (str);
  last_str = strchr (first_str, '-');
  if (last_str == NULL)
    {
      g_free (first_str);
      return -1;
    }

  /* Separate the first IP. */
  *last_str = '\0';
  last_str++;

  if (inet_pton (AF_INET6, first_str, first) != 1)
    {
      g_free (first_str);
      return -1;
    }

  /* Calculate the last IP. */
  memcpy (last, first, sizeof (*last));
  end = strtol (last_str, NULL, 16);
  memcpy (&last->s6_addr[15], &end, 1);
  memcpy (&last->s6_addr[14], ((char *) &end) + 1, 1);

  g_free (first_str);
  return 0;
}

/**
 * @brief Determines the host type in a buffer.
 *
 * @param[in] str   Buffer that contains host definition, could a be hostname,
 *                  single IPv4 or IPv6, CIDR-expressed block etc,.
 *
 * @return Host_TYPE_*, -1 if error.
 */
static int
determine_host_type (const gchar *str_stripped)
{
  /*
   * We have a single element with no leading or trailing
   * white spaces. This element could represent different host
   * definitions: single IPs, host names, CIDR-expressed blocks,
   * range-expressed networks, IPv6 addresses.
   */

  /* Null or empty string. */
  if (str_stripped == NULL || *str_stripped == '\0')
    return -1;

  /* Check for regular single IPv4 address. */
  if (is_ipv4_address (str_stripped))
    return HOST_TYPE_IPV4;

  /* Check for regular single IPv6 address. */
  if (is_ipv6_address (str_stripped))
    return HOST_TYPE_IPV6;

  /* Check for regular IPv4 CIDR-expressed block like "192.168.12.0/24" */
  if (is_cidr_block (str_stripped))
    return HOST_TYPE_CIDR_BLOCK;

  /* Check for short range-expressed networks "192.168.12.5-40" */
  if (is_short_range_network (str_stripped))
    return HOST_TYPE_RANGE_SHORT;

  /* Check for long range-expressed networks "192.168.1.0-192.168.3.44" */
  if (is_long_range_network (str_stripped))
    return HOST_TYPE_RANGE_LONG;

  /* Check for regular IPv6 CIDR-expressed block like "2620:0:2d0:200::7/120" */
  if (is_cidr6_block (str_stripped))
    return HOST_TYPE_CIDR6_BLOCK;

  /* Check for short range-expressed networks "::1-ef12" */
  if (is_short_range6_network (str_stripped))
    return HOST_TYPE_RANGE6_SHORT;

  /* Check for long IPv6 range-expressed networks like "::1:20:7-::1:25:3" */
  if (is_long_range6_network (str_stripped))
    return HOST_TYPE_RANGE6_LONG;

  /* Check for hostname. */
  if (is_hostname (str_stripped))
    return HOST_TYPE_NAME;

  /* @todo: If everything else fails, fallback to hostname ? */
  return -1;
}

/**
 * @brief Creates a new openvas_host_t object.
 *
 * @return Pointer to new host object, NULL if creation fails.
 */
static openvas_host_t *
openvas_host_new ()
{
  openvas_host_t *host;

  host = g_malloc0 (sizeof (openvas_host_t));

  return host;
}

/**
 * @brief Frees the memory occupied by an openvas_host_t object.
 *
 * @param[in] host  Host to free.
 */
static void
openvas_host_free (gpointer host)
{
  openvas_host_t *h = host;
  if (h == NULL)
    return;

  /* If host of type hostname, free the name buffer, first. */
  if (h->type == HOST_TYPE_NAME)
    g_free (h->name);

  g_free (h);
}

/**
 * @brief Removes duplicate hosts values from an openvas_hosts_t structure.
 * Also resets the iterator current position.
 *
 * @param[in] hosts hosts collection from which to remove duplicates.
 */
static void
openvas_hosts_deduplicate (openvas_hosts_t *hosts)
{
  /**
   * Uses a hash table in order to deduplicate the hosts list in O(N) time.
   */
  GList *element;
  GHashTable *name_table;
  int duplicates = 0;

  if (hosts == NULL)
    return;
  element = hosts->hosts;
  name_table = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);

  while (element)
    {
      gchar *name;

      if ((name = openvas_host_value_str (element->data)))
        {
          if (g_hash_table_lookup (name_table, name))
            {
              GList *tmp;

              tmp = element;
              element = element->next;
              openvas_host_free (tmp->data);
              hosts->hosts = g_list_delete_link (hosts->hosts, tmp);
              duplicates++;
              g_free (name);
            }
          else
            {
              /* Insert in hash table. Value not important, but not NULL. */
              g_hash_table_insert (name_table, name, hosts);
              element = element->next;
            }
        }
      else
        element = element->next;
    }

  g_hash_table_destroy (name_table);
  hosts->count -= duplicates;
  hosts->removed += duplicates;
  hosts->current = hosts->hosts;
}

/**
 * @brief Creates a new openvas_hosts_t structure and the associated hosts
 * objects from the provided hosts_str.
 *
 * @param[in] hosts_str The hosts string. A copy will be created of this within
 *                      the returned struct.
 * @param[in] max_hosts Max number of hosts in hosts_str. 0 means unlimited.
 *
 * @return NULL if error or hosts_str contains more than max hosts. otherwise, a
 * hosts structure that should be released using @ref openvas_hosts_free.
 */
openvas_hosts_t *
openvas_hosts_new_with_max (const gchar *hosts_str, unsigned int max_hosts)
{
  openvas_hosts_t *hosts;
  gchar **host_element, **split;
  gchar *str;

  if (hosts_str == NULL)
    return NULL;

  hosts = g_malloc0 (sizeof (openvas_hosts_t));
  if (hosts == NULL)
    return NULL;

  hosts->orig_str = g_strdup (hosts_str);
  /* Normalize separator: Transform newlines into commas. */
  str = hosts->orig_str;
  while (*str)
    {
      if (*str == '\n') *str = ',';
      str++;
    }

  /* Split comma-separeted list into single host-specifications */
  split = g_strsplit (hosts->orig_str, ",", 0);

  /* first element of the splitted list */
  host_element = split;
  while (*host_element)
    {
      int host_type;
      gchar *stripped = g_strstrip (*host_element);

      if (stripped == NULL || *stripped == '\0')
        {
          host_element++;
          continue;
        }

      /* IPv4, hostname, IPv6, collection (short/long range, cidr block) etc,. ? */
      /* -1 if error. */
      host_type = determine_host_type (stripped);

      switch (host_type)
        {
          case HOST_TYPE_NAME:
          case HOST_TYPE_IPV4:
          case HOST_TYPE_IPV6:
            {
              /* New host. */
              openvas_host_t *host = openvas_host_new ();
              host->type = host_type;
              if (host_type == HOST_TYPE_NAME)
                host->name = g_strdup (stripped);
              else if (host_type == HOST_TYPE_IPV4)
                inet_pton (AF_INET, stripped, &host->addr);
              else if (host_type == HOST_TYPE_IPV6)
                inet_pton (AF_INET6, stripped, &host->addr6);
              /* Prepend to list of hosts. */
              hosts->hosts = g_list_prepend (hosts->hosts, host);
              hosts->count++;
              break;
            }
          case HOST_TYPE_CIDR_BLOCK:
          case HOST_TYPE_RANGE_SHORT:
          case HOST_TYPE_RANGE_LONG:
            {
              struct in_addr first, last;
              uint32_t current;
              int (*ips_func) (const char *, struct in_addr *, struct in_addr *);

              if (host_type == HOST_TYPE_CIDR_BLOCK)
                ips_func = cidr_block_ips;
              else if (host_type == HOST_TYPE_RANGE_SHORT)
                ips_func = short_range_network_ips;
              else if (host_type == HOST_TYPE_RANGE_LONG)
                ips_func = long_range_network_ips;
              else
                break;

              if (ips_func (stripped, &first, &last) == -1)
                break;

              /* Make sure that first actually comes before last */
              if (ntohl (first.s_addr) > ntohl (last.s_addr))
                break;

              /* Add addresses from first to last as single hosts. */
              current = first.s_addr;
              while (ntohl (current) <= ntohl (last.s_addr))
                {
                  openvas_host_t *host = openvas_host_new ();
                  host->type = HOST_TYPE_IPV4;
                  host->addr.s_addr = current;
                  hosts->hosts = g_list_prepend (hosts->hosts, host);
                  hosts->count++;
                  if (max_hosts > 0 && hosts->count > max_hosts)
                    {
                      g_strfreev (split);
                      openvas_hosts_free (hosts);
                      return NULL;
                    }
                  /* Next IP address. */
                  current = htonl (ntohl (current) + 1);
                }
              break;
            }
          case HOST_TYPE_CIDR6_BLOCK:
          case HOST_TYPE_RANGE6_LONG:
          case HOST_TYPE_RANGE6_SHORT:
            {
              struct in6_addr first, last;
              unsigned char current[16];
              int (*ips_func) (const char *, struct in6_addr *, struct in6_addr *);

              if (host_type == HOST_TYPE_CIDR6_BLOCK)
                ips_func = cidr6_block_ips;
              else if (host_type == HOST_TYPE_RANGE6_SHORT)
                ips_func = short_range6_network_ips;
              else if (host_type == HOST_TYPE_RANGE6_LONG)
                ips_func = long_range6_network_ips;
              else
                continue;

              if (ips_func (stripped, &first, &last) == -1)
                break;

              /* Make sure the first comes before the last. */
              if (memcmp (&first.s6_addr, &last.s6_addr, 16) > 0)
                break;

              /* Add addresses from first to last as single hosts. */
              memcpy (current, &first.s6_addr, 16);
              while (memcmp (current, &last.s6_addr, 16) <= 0)
                {
                  int i;

                  openvas_host_t *host = openvas_host_new ();
                  host->type = HOST_TYPE_IPV6;
                  memcpy (host->addr6.s6_addr, current, 16);
                  hosts->hosts = g_list_prepend (hosts->hosts, host);
                  hosts->count++;
                  if (max_hosts > 0 && hosts->count > max_hosts)
                    {
                      g_strfreev (split);
                      openvas_hosts_free (hosts);
                      return NULL;
                    }
                  /* Next IPv6 address. */
                  for (i = 15; i >= 0; --i)
                    if (current[i] < 255)
                      {
                        current[i]++;
                        break;
                      }
                    else
                      current[i] = 0;
                 }
              break;
            }
          case -1:
          default:
            /* Invalid host string. */
            g_strfreev (split);
            openvas_hosts_free (hosts);
            return NULL;
        }
      host_element++; /* move on to next element of splitted list */
      if (max_hosts > 0 && hosts->count > max_hosts)
        {
          g_strfreev (split);
          openvas_hosts_free (hosts);
          return NULL;
        }
    }

  /* Reverse list, as we were prepending (for performance) to the list. */
  hosts->hosts = g_list_reverse (hosts->hosts);

  /* Remove duplicated values. */
  openvas_hosts_deduplicate (hosts);

  /* Set current to start of hosts list. */
  hosts->current = hosts->hosts;

  g_strfreev (split);
  return hosts;
}

/**
 * @brief Creates a new openvas_hosts_t structure and the associated hosts
 * objects from the provided hosts_str.
 *
 * @param[in] hosts_str The hosts string. A copy will be created of this within
 *                      the returned struct.
 *
 * @return NULL if error, otherwise, a hosts structure that should be released
 * using @ref openvas_hosts_free.
 */
openvas_hosts_t *
openvas_hosts_new (const gchar *hosts_str)
{
  return openvas_hosts_new_with_max (hosts_str, 0);
}

/**
 * @brief Gets the next openvas_host_t from a openvas_hosts_t structure. The
 * state of iteration is kept internally within the openvas_hosts structure.
 *
 * @param[in]   hosts     openvas_hosts_t structure to get next host from.
 *
 * @return Pointer to host. NULL if error or end of hosts.
 */
openvas_host_t *
openvas_hosts_next (openvas_hosts_t *hosts)
{
  openvas_host_t *next;

  if (hosts == NULL || hosts->current == NULL)
    return NULL;

  next = hosts->current->data;
  hosts->current = g_list_next (hosts->current);

  return next;
}

/**
 * @brief Frees memory occupied by an openvas_hosts_t structure.
 *
 * @param[in] hosts The hosts collection to free.
 *
 */
void
openvas_hosts_free (openvas_hosts_t *hosts)
{
  if (hosts == NULL)
    return;

  if (hosts->orig_str)
    g_free (hosts->orig_str);

  // Free list in two steps for glib < 2.28 compatibility.
  g_list_foreach (hosts->hosts, (GFunc) openvas_host_free, NULL);
  g_list_free (hosts->hosts);

  g_free (hosts);
}

/**
 * @brief Randomizes the order of the hosts objects in the collection.
 * Not to be used while iterating over the single hosts as it resets the
 * iterator.
 *
 * @param[in] hosts The hosts collection to shuffle.
 */
void
openvas_hosts_shuffle (openvas_hosts_t *hosts)
{
  int count;
  GList *new_list;
  GRand *rand;

  if (hosts == NULL)
    return;

  count = openvas_hosts_count (hosts);
  new_list = NULL;

  rand = g_rand_new ();

  while (count)
    {
      GList *element;

      /* Get element from random position [0, count[. */
      element = g_list_nth (hosts->hosts, g_rand_int_range (rand, 0, count));
      /* Remove it. */
      hosts->hosts = g_list_remove_link (hosts->hosts, element);
      /* Insert it in new list */
      new_list = g_list_concat (element, new_list);
      count--;
    }
  hosts->hosts = new_list;
  hosts->current = hosts->hosts;

  g_rand_free (rand);
}

/**
 * @brief Reverses the order of the hosts objects in the collection.
 * Not to be used while iterating over the single hosts as it resets the
 * iterator.
 *
 * @param[in] hosts The hosts collection to reverse.
 */
void
openvas_hosts_reverse (openvas_hosts_t *hosts)
{
  if (hosts == NULL || hosts->hosts == NULL)
    return;

  hosts->hosts = g_list_reverse (hosts->hosts);
  hosts->current = hosts->hosts;
}

/**
 * @brief Removes an element from the hosts list and frees the host object.
 *
 * @param[in] hosts     The hosts collection from which to remove.
 * @param[in] element   Element to remove from the list.
 *
 * @return Next element value.
 */
static GList *
openvas_hosts_remove_element (openvas_hosts_t *hosts, GList *element)
{
  GList *tmp;

  tmp = element;
  element = element->next;
  openvas_host_free (tmp->data);
  hosts->hosts = g_list_delete_link (hosts->hosts, tmp);
  return element;
}

/**
 * @brief Resolves host objects of type name in a hosts collection, replacing
 * hostnames with IPv4 values.
 * Not to be used while iterating over the single hosts as it resets the
 * iterator.
 *
 * @param[in] hosts         The hosts collection from which to exclude.
 */
void
openvas_hosts_resolve (openvas_hosts_t *hosts)
{
  openvas_host_t *host;

  hosts->current = hosts->hosts;

  while ((host = openvas_hosts_next (hosts)))
    {
      struct in_addr addr;

      if (host->type != HOST_TYPE_NAME)
        continue;

      if (openvas_host_resolve (host, &addr, AF_INET) == 0)
        {
          g_free (host->name);
          host->type = HOST_TYPE_IPV4;
          memcpy (&host->addr, &addr, sizeof (host->addr));
        }
    }

  hosts->current = hosts->hosts;
}

/**
 * @brief Excludes a set of hosts provided as a string from a hosts collection.
 * Not to be used while iterating over the single hosts as it resets the
 * iterator.
 *
 * @param[in] hosts         The hosts collection from which to exclude.
 * @param[in] excluded_str  String of hosts to exclude.
 * @param[in] resolve       Boolean. Whether to resolve the hostnames in
 *                          excluded_str before excluding.
 *
 * @return Number of excluded hosts, -1 if error.
 */
int
openvas_hosts_exclude (openvas_hosts_t *hosts, const char *excluded_str,
                       int resolve)
{
  /**
   * Uses a hash table in order to exclude hosts in O(N+M) time.
   */
  openvas_hosts_t *excluded_hosts;
  GList *element;
  GHashTable *name_table;
  int excluded = 0;

  if (hosts == NULL || excluded_str == NULL)
    return -1;

  excluded_hosts = openvas_hosts_new (excluded_str);
  if (excluded_hosts == NULL)
    return -1;

  if (resolve)
    openvas_hosts_resolve (excluded_hosts);

  if (openvas_hosts_count (excluded_hosts) == 0)
    {
      openvas_hosts_free (excluded_hosts);
      return 0;
    }

  /* Hash host values from excluded hosts list. */
  element = excluded_hosts->hosts;
  name_table = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
  while (element)
    {
      gchar *name;

      if ((name = openvas_host_value_str (element->data)))
        g_hash_table_insert (name_table, name, hosts);
      element = element->next;
    }

  /* Check for hosts values in hash table. */
  element = hosts->hosts;
  while (element)
    {
      gchar *name;

      if ((name = openvas_host_value_str (element->data)))
        {
          if (g_hash_table_lookup (name_table, name))
            {
              element = openvas_hosts_remove_element (hosts, element);
              excluded++;
            }
          else
            element = element->next;

          g_free (name);
        }
      else
        element = element->next;
    }

  /* Cleanup. */
  hosts->count -= excluded;
  hosts->removed += excluded;
  hosts->current = hosts->hosts;
  g_hash_table_destroy (name_table);
  openvas_hosts_free (excluded_hosts);
  return excluded;
}

/**
 * @brief Checks for a host object reverse dns lookup existence.
 *
 * @param[in] host The host to reverse-lookup.
 *
 * @return Result of look-up or name if host of type name already, NULL
 * otherwise. Free with g_free().
 */
static gchar *
openvas_host_reverse_lookup (openvas_host_t *host)
{

  if (host == NULL)
    return NULL;

  if (host->type == HOST_TYPE_NAME)
    return g_strdup (host->name);
  else if (host->type == HOST_TYPE_IPV4)
    {
      struct sockaddr_in sa;
      gchar hostname[1000];

      bzero (&sa, sizeof (struct sockaddr));
      sa.sin_addr = host->addr;
      sa.sin_family = AF_INET;

      if (getnameinfo ((struct sockaddr *) &sa, sizeof (sa), hostname,
                       sizeof (hostname), NULL, 0, NI_NAMEREQD))
        return NULL;
      else
        return g_strdup (hostname);
    }
  else if (host->type == HOST_TYPE_IPV6)
    {
      struct sockaddr_in6 sa;
      char hostname[1000];

      bzero (&sa, sizeof (struct sockaddr));
      memcpy (&sa.sin6_addr, &host->addr6, 16);
      sa.sin6_family = AF_INET6;

      if (getnameinfo ((struct sockaddr *) &sa, sizeof (sa), hostname,
                       sizeof (hostname), NULL, 0, NI_NAMEREQD))
        return NULL;
      else
        return g_strdup (hostname);
    }
  else
    return NULL;
}

/**
 * @brief Removes hosts that don't reverse-lookup from the hosts collection.
 * Not to be used while iterating over the single hosts as it resets the
 * iterator.
 *
 * @param[in] hosts The hosts collection to filter.
 *
 * @return Number of hosts removed, -1 if error.
 */
int
openvas_hosts_reverse_lookup_only (openvas_hosts_t *hosts)
{
  int count;
  GList *element;

  if (hosts == NULL)
    return -1;

  count = 0;
  element = hosts->hosts;
  while (element)
    {
      gchar *name = openvas_host_reverse_lookup (element->data);

      if (name == NULL)
        {
          element = openvas_hosts_remove_element (hosts, element);
          count++;
        }
      else
        {
          g_free (name);
          element = element->next;
        }
    }

  hosts->count -= count;
  hosts->removed += count;
  hosts->current = hosts->hosts;
  return count;
}

/**
 * @brief Removes hosts duplicates that reverse-lookup to the same value.
 * Not to be used while iterating over the single hosts as it resets the
 * iterator.
 *
 * @param[in] hosts The hosts collection to filter.
 *
 * @return Number of hosts removed, -1 if error.
 */
int
openvas_hosts_reverse_lookup_unify (openvas_hosts_t *hosts)
{
  /**
   * Uses a hash table in order to unify the hosts list in O(N) time.
   */
  int count;
  GList *element;
  GHashTable *name_table;

  if (hosts == NULL)
    return -1;

  name_table = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
  count = 0;
  element = hosts->hosts;
  while (element)
    {
      gchar *name;

      if ((name = openvas_host_reverse_lookup (element->data)))
        {
          if (g_hash_table_lookup (name_table, name))
            {
              element = openvas_hosts_remove_element (hosts, element);
              count++;
              g_free (name);
            }
          else
            {
              /* Insert in the hash table. Value not important. */
              g_hash_table_insert (name_table, name, hosts);
              element = element->next;
            }
        }
      else
        element = element->next;
    }

  g_hash_table_destroy (name_table);
  hosts->removed += count;
  hosts->count -= count;
  hosts->current = hosts->hosts;
  return count;
}

/**
 * @brief Gets the count of single hosts objects in a hosts collection.
 *
 * @param[in] hosts The hosts collection to count hosts of.
 *
 * @return The number of single hosts.
 */
unsigned int
openvas_hosts_count (const openvas_hosts_t *hosts)
{
  return hosts ? hosts->count : 0;
}

/**
 * @brief Gets the count of single values in hosts string that were removed
 * (duplicates / excluded.)
 *
 * @param[in] hosts The hosts collection.
 *
 * @return The number of removed values.
 */
unsigned int
openvas_hosts_removed (const openvas_hosts_t *hosts)
{
    return hosts ? hosts->removed : 0;
}

/**
 * @brief Returns whether a host has an equal host in a hosts collection.
 * eg. 192.168.10.1 has an equal in list created from
 * "192.168.10.1-5, 192.168.10.10-20" string while 192.168.10.7 doesn't.
 *
 * @param[in] host  The host object.
 * @param[in] addr  Optional pointer to ip address. Could be used so that host
 *                  isn't resolved multiple times when type is HOST_TYPE_NAME.
 * @param[in] hosts Hosts collection.
 *
 * @return 1 if host has equal in hosts, 0 otherwise.
 */
int
openvas_host_in_hosts (const openvas_host_t *host, const struct in6_addr *addr,
                       const openvas_hosts_t *hosts)
{
  char *host_str;
  GList *element;

  if (host == NULL || hosts == NULL)
    return 0;

  host_str = openvas_host_value_str (host);

  element = hosts->hosts;
  while (element)
    {
      char *tmp = openvas_host_value_str (element->data);

      if (strcasecmp (host_str, tmp) == 0)
        {
          g_free (host_str);
          g_free (tmp);
          return 1;
        }
      g_free (tmp);

      /* Hostnames in hosts list shouldn't be resolved. */
      if (addr && openvas_host_type (element->data) != HOST_TYPE_NAME)
        {
          struct in6_addr tmpaddr;
          openvas_host_get_addr6 (element->data, &tmpaddr);

          if (memcmp (addr->s6_addr, &tmpaddr.s6_addr, 16) == 0)
            {
              g_free (host_str);
              return 1;
            }

        }
      element = element->next;
    }

  g_free (host_str);
  return 0;
}

/**
 * @brief Gets a host object's type.
 *
 * @param[in] host  The host object.
 *
 * @return Host type.
 */
int
openvas_host_type (const openvas_host_t *host)
{
  return host ? host->type : -1;
}

/**
 * @brief Gets a host's type in printable format.
 *
 * @param[in] host  The host object.
 *
 * @return String representing host type. Statically allocated, thus, not to be
 * freed.
 */
gchar *
openvas_host_type_str (const openvas_host_t *host)
{
  if (host == NULL)
    return NULL;

  return host_type_str[host->type];
}

/**
 * @brief Gets a host's value in printable format.
 *
 * @param[in] host  The host object.
 *
 * @return String representing host value. To be freed with g_free().
 */
gchar *
openvas_host_value_str (const openvas_host_t *host)
{
  if (host == NULL)
    return NULL;

  switch (host->type)
    {
      case HOST_TYPE_NAME:
        return g_strdup (host->name);
        break;
      case HOST_TYPE_IPV4:
      case HOST_TYPE_IPV6:
        /* Handle both cases using inet_ntop(). */
        {
          int family, size;
          gchar *str;
          const void *srcaddr;

          if (host->type == HOST_TYPE_IPV4)
            {
              family = AF_INET;
              size = INET_ADDRSTRLEN;
              srcaddr = &host->addr;
            }
          else
            {
              family = AF_INET6;
              size = INET6_ADDRSTRLEN;
              srcaddr = &host->addr6;
            }

          str = g_malloc0 (size);
          if (str == NULL)
            {
              perror ("g_malloc0");
              return NULL;
            }
          if (inet_ntop (family, srcaddr, str, size) == NULL)
            {
              perror ("inet_ntop");
              g_free (str);
              return NULL;
            }
          return str;
        }
      default:
       return g_strdup ("Erroneous host type: Should be Hostname/IPv4/IPv6.");
    }
}

/**
 * @brief Resolves a host object's name to an IPv4 or IPv6 address. Host object
 * should be of type HOST_TYPE_NAME.
 *
 * @param[in] host      The host object whose name to resolve.
 * @param[out] dst      Buffer to store resolved address. Size must be at least
 *                      4 bytes for AF_INET and 16 bytes for AF_INET6.
 * @param[in] family    Either AF_INET or AF_INET6.
 *
 * @return -1 if error, 0 otherwise.
 */
int
openvas_host_resolve (const openvas_host_t *host, void *dst, int family)
{
  if (host == NULL || dst == NULL || host->type != HOST_TYPE_NAME)
    return -1;

  return openvas_resolve (host->name, dst, family);
}

/**
 * @brief Gives a host object's value as an IPv6 address.
 * If the host type is hostname, it resolves the IPv4 address then gives an
 * IPv4-mapped IPv6 address (eg. ::ffff:192.168.1.1 .)
 * If the host type is IPv4, it gives an IPv4-mapped IPv6 address.
 * If the host's type is IPv6, it gives the value directly.
 *
 * @param[in]  host     The host object whose value to get as IPv6.
 * @param[out] ip6      Buffer to store the IPv6 address.
 *
 * @return -1 if error, 0 otherwise.
 */
int
openvas_host_get_addr6 (const openvas_host_t *host, struct in6_addr *ip6)
{
  if (host == NULL || ip6 == NULL)
    return -1;

  switch (openvas_host_type (host))
    {
      case HOST_TYPE_IPV6:
        memcpy (ip6, &host->addr6, sizeof (struct in6_addr));
        return 0;

      case HOST_TYPE_IPV4:
        ipv4_as_ipv6 (&host->addr, ip6);
        return 0;

      case HOST_TYPE_NAME:
        {
          struct in_addr ip4;

          if (openvas_host_resolve (host, &ip4, AF_INET) == -1)
            return -1;

          ipv4_as_ipv6 (&ip4, ip6);
          return 0;
        }

      default:
        return -1;
    }
}

