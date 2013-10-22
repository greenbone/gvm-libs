/* Hostloop2 -- the Hostloop Library, version 2.0
 * Copyright (C) 1999 Renaud Deraison
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <arpa/inet.h>          /* for inet_aton */
#include <ctype.h>              /* for isdigit */
#include <stdio.h>              /* for scanf */
#include <stdlib.h>             /* for free */
#include <string.h>             /* for strlen */

#include "network.h"            /* for convipv4toipv4mappedaddr */
#include "support.h"

#include "hosts_gatherer.h"
#include "hg_utils.h"
#include "hg_filter.h"
#include "hg_add_hosts.h"
#include "hg_subnet.h"

/**
 * @file
 * Functions to add hosts to a hg_globals host list.
 *
 * Possible input values for host/hostname:
 *
 * 'hostname' or 'xx.xx.xx.xx' or 'hostname/netmask'
 * or 'xx.xx.xx.xx/netmask'
 * or '[xx|xx-xx].[xx|xx-xx].[xx|xx-xx].[xx|xx-xx]' (by Alex Butcher, Articon-Integralis AG)
 */
/** @TODO Document what kind of input for ipv6 adresses is acceppted, move
 *        description of valid "hostnames" to a better place (this is really
 *        interesting for a user), document how to list multiple hosts (space,
 *        comma, semicolon- separated?).
 */

#define OCTETRANGE "%3d%*1[-]%3d"
#define OCTET "%3d"
#define DOT "%*1[.]"
#define COMP "%7[0-9-]"
#define REMINDER "%s"

/**
 * @param[out] family (AF_INET6 for ipv6, AF_INET for ipv4, -1 for invalid)
 *
 * @return 0 if (numeric) ip is a valid ipv4 or ipv6 address and set family to
 *         appropriate value, else return -1 and set family to -1.
 */
static int
getaddrfamily (char *ip, int *family)
{
  struct in_addr inaddr;
  struct in6_addr in6addr;

  if (inet_pton (AF_INET6, ip, &in6addr) == 1)
    {
      *family = AF_INET6;
      return 0;
    }
  else if (inet_aton (ip, &inaddr))
    {
      *family = AF_INET;
      return 0;
    }
  *family = -1;
  return -1;
}

/** @TODO real_ip should not be used as a check whether a string describes an
 *        ip or being improved. In current code, bogus.bugs.openvas.org is
 *        considered as "real" ip. */
/**
 * @brief Counts numbers of dots ('.') in string s, returns 1 if 3 dots were
 * @brief found, 0 otherwise.
 *
 * @param s Input string.
 *
 * @return 1 if 3 dots ('.') in \ref s present, 0 otherwise.
 */
static int
real_ip (char *s)
{
  int i;
  int n = 0;
  for (i = 0; s[i]; i++)
    {
      if (s[i] == '.')
        n++;
    }

  if (n == 3)
    return 1;
  else
    return 0;
}

/**
 * @brief From a string representation of an ips octet range (like 2-10)
 * @brief retrieves start (like 2) and end (10) of the range. Works with single
 * @brief numbers (like 2), too.
 *
 * @param[in]  data Input string (like "2-13", "22-1"). Can also be a single
 *                  number. Numbers have been between 0 and 255.
 * @param[out] s    On successfull exit, contains start of range.
 * @param[out] e    On successfull exit, contains end of range.
 *
 * @return 0 on success, -1 if input is not a valid range.
 */
static int
range (char *data, int *start, int *end)
{
  int convs;
  int first, last;

  convs = sscanf (data, OCTETRANGE, &first, &last);
  if (convs != 2)
    {
      /* It didn't work out, so we try converting it as an OCTET (xxx). */
      convs = sscanf (data, OCTET, &first);
      if (convs != 1)
        {
          /* That didn't work out either, so it's not a range. */
          return (-1);
        }
      else
        {
          /* We'll use these as loop ranges later. */
          last = first;
        }
    }

  if ((first < 0) || (first > 255) || (last < 0) || (last > 255))
    return (-1);

  if (first > last)
    {
      /* Swap the two vars. */
      first ^= last;
      last ^= first;
      first ^= last;
    }

  if (start)
    *start = first;
  if (end)
    *end = last;
  return 0;
}

/**
 * @brief Transforms a netmask in dot notation (e.g. 255.255.255.0) to a cidr
 * @brief "number" (e.g. 24).
 *
 * @param[in] nm Netmask to transform into cidr.
 *
 * @return cidr notation "number" (between 0 and 32).
 */
static int
netmask_to_cidr_netmask (struct in_addr nm)
{
  int ret = 32;

  // Start looking from end how many 0 bits we have.
  nm.s_addr = ntohl (nm.s_addr);
  while (!(nm.s_addr & 1))
    {
      ret--;
      nm.s_addr >>= 1;
    }
  return ret;
}

/**
 * @brief Adds host(s) to the hg_globals hostslist.
 *
 * @param[in,out] globals   Pointer to hg_globals struct to add hosts to.
 * @param[in]     hostname  String describing host(s) to add.
 *
 * @TODO verify @return 0 if successfull, -1 otherwise?
 */
static int
hg_add_host (struct hg_globals *globals, char *hostname)
{
  int cidr_netmask = 32;
  char *t;
  char *q;
  char *copy;
  struct in_addr ip;
  struct in6_addr ip6;
  struct in_addr nm;

  int o1first, o1last;          /* octet range boundaries */
  int o2first, o2last;
  int o3first, o3last;
  int o4first, o4last;
  int o1, o2, o3, o4;           /* octet loop counters */
  int convs;                    /* number of conversions made by sscanf */
  char rangehost[20];           /* used to store string representation of ip */

  char comp1[8], comp2[8], comp3[8], comp4[8];
  char *reminder;
  int unquote = 0;

  *comp1 = *comp2 = *comp3 = *comp4 = '\0';

  // Dealing with ranges
  t = strchr (hostname, '-');
  if (t != NULL)
    {
      struct in_addr ip;
      t[0] = '\0';
      // If string describing a host could not be transformed to an in_addr
      // or does not contain three dots.
      if ((inet_aton (hostname, &ip) == 0) || !real_ip (hostname))
        {
          t[0] = '-';
          goto next;
        }

      if (real_ip (hostname) && real_ip (&(t[1])))
        {
          struct in_addr start, end;
          struct in6_addr start6, end6;

          hg_resolv (hostname, &start6, AF_INET);
          hg_resolv (&(t[1]), &end6, AF_INET);
          start.s_addr = start6.s6_addr32[3];
          end.s_addr = end6.s6_addr32[3];

          if (globals->flags & HG_DISTRIBUTE)
            {
              int jump;
              unsigned long diff;
              int i, j;

              diff = ntohl (end.s_addr) - ntohl (start.s_addr);
              if (diff > 255)
                jump = 255;
              else if (diff > 128)
                jump = 10;
              else
                jump = 1;

              for (j = 0; j < jump; j++)
                {
                  for (i = j; i <= diff; i += jump)
                    {
                      struct in_addr ia;
                      ia.s_addr = htonl (ntohl (start.s_addr) + i);
                      if (ntohl (ia.s_addr) > ntohl (end.s_addr))
                        break;

                      hg_add_host_with_options (globals, inet_ntoa (ia), ia, 1,
                                                32, 1, &ia);
                    }
                }
            }
          else
            hg_add_host_with_options (globals, inet_ntoa (start), start, 1, 32,
                                      1, &end);
          return 0;
        }
      t[0] = '-';
    }

next:

  reminder = malloc (strlen (hostname));

  // Hostname wrapped by singe quotes ('')?
  if ((hostname[0] == '\'') && (hostname[strlen (hostname) - 1] == '\''))
    {
      unquote++;
      goto noranges;
    }

  for (t = hostname; *t != '\0'; t++)
    if (!isdigit (*t) && *t != '-' && *t != '.')
      break;

  if (*t == '\0')
    convs =
      sscanf (hostname, COMP DOT COMP DOT COMP DOT COMP REMINDER, comp1, comp2,
              comp3, comp4, reminder);
  else
    convs = 0;

  free (reminder);
  if (convs != 4)
    goto noranges;              /* There are definitely no ranges here, so
                                   skip all this */

  /* Try to convert components as OCTETRANGE (xxx-xxx). */
  if (range (comp1, &o1first, &o1last) || range (comp2, &o2first, &o2last)
      || range (comp3, &o3first, &o3last) || range (comp4, &o4first, &o4last))
    goto noranges;


  /* Generate and add the range. */
  for (o1 = o1first; o1 <= o1last; o1++)
    {
      for (o2 = o2first; o2 <= o2last; o2++)
        {
          for (o3 = o3first; o3 <= o3last; o3++)
            {
              for (o4 = o4first; o4 <= o4last; o4++)
                {
                  snprintf (rangehost, 17, "%d.%d.%d.%d", o1, o2, o3, o4);
                  hg_resolv (rangehost, &ip6, AF_INET);
                  ip.s_addr = ip6.s6_addr32[3];
                  if (ip.s_addr != INADDR_NONE)
                    {
                      hg_add_host_with_options (globals, rangehost, ip, 0, 32,
                                                0, NULL);
                    }
                }
            }
        }
    }
  return 0;

noranges:
  if (unquote)
    {
      copy = malloc (strlen (hostname) - 1);
      strncpy (copy, &(hostname[1]), strlen (&(hostname[1])) - 1);
    }
  else
    {
      copy = malloc (strlen (hostname) + 1);
      strncpy (copy, hostname, strlen (hostname) + 1);
    }

  hostname = copy;

  // Checks for slash, which might indicate cidr notation
  t = strchr (hostname, '/');
  if (t)
    {
      t[0] = '\0';
      if ((atoi (t + 1) > 32) && inet_aton (t + 1, &nm))
        {
          cidr_netmask = netmask_to_cidr_netmask (nm);
        }
      else
        cidr_netmask = atoi (t + 1);
      if ((cidr_netmask < 1) || (cidr_netmask > 32))
        cidr_netmask = 32;
    }
  ip.s_addr = INADDR_NONE;

  // Use only string between braces ([192.168.32.1]).
  q = strchr (hostname, '[');

  if (q != NULL)
    {
      t = strchr (q, ']');

      if (t != NULL)
        {
          t[0] = '\0';
          hg_resolv (&q[1], &ip6, AF_INET6);
          ip.s_addr = ip6.s6_addr32[3];
          q[0] = '\0';
        }
    }

  if (ip.s_addr == INADDR_NONE)
    {
      hg_resolv (hostname, &ip6, AF_INET6);
      ip.s_addr = ip6.s6_addr32[3];
    }

  if (!IN6_ARE_ADDR_EQUAL (&ip6, &in6addr_any) && IN6_IS_ADDR_V4MAPPED (&ip6))
    {
      if (cidr_netmask == 32)
        {
          hg_add_host_with_options (globals, hostname, ip, 0, cidr_netmask, 0,
                                    NULL);
        }
      else
        {
          struct in_addr first = cidr_get_first_ip (ip, cidr_netmask);
          struct in_addr last = cidr_get_last_ip (ip, cidr_netmask);

          if ((globals->flags & HG_DISTRIBUTE) != 0 && cidr_netmask <= 29)
            {
              struct in_addr c_end;
              struct in_addr c_start;
              struct in6_addr c_start6;
              int addition;

              if (cidr_netmask <= 21)
                addition = 8;
              else if (cidr_netmask <= 24)
                addition = 5;
              else
                addition = 2;

              c_start = first;
              c_end = cidr_get_last_ip (c_start, cidr_netmask + addition);

              memset(&c_start6, 0, sizeof(struct in6_addr));
              c_start6.s6_addr32[3]=c_start.s_addr;
              c_start6.s6_addr16[5]=(unsigned short)0xFFFF;

              for (;;)
                {
                  int dobreak = 0;

                  if (ntohl (c_end.s_addr) >= ntohl (last.s_addr))
                    dobreak = 1;

                  // @TODO fix bufferlength argument.
                  hg_get_name_from_ip (&c_start6, hostname, strlen(hostname)+1);

                  c_start.s_addr = c_start6.s6_addr32[3];
                  hg_add_host_with_options (globals, strdup (hostname), c_start,
                                            1, 32, 1, &c_end);
                  c_start.s_addr = htonl (ntohl (c_end.s_addr) + 2);
                  c_end = cidr_get_last_ip (c_start, cidr_netmask + addition);
                  c_start.s_addr = htonl (ntohl (c_start.s_addr) - 1);

                  if (dobreak == 1)
                    break;
                }
            }
          else
            hg_add_host_with_options (globals, hostname, first, 1, 32, 1,
                                      &last);
        }
    }
  else if (!IN6_ARE_ADDR_EQUAL (&ip6, &in6addr_any))
    {
      hg_add_ipv6host_with_options (globals, hostname, &ip6, 0, 128, 0, &ip6);
    }
  else
    {
      free (copy);
      return -1;
    }

  free (copy);
  return 0;
}


/**
 * Add hosts of the form :
 *
 * host1/nm,host2/nm,xxx.xxx.xxx.xxx/xxx, ....
 *
 * , progressing the "marker" of the globals argument.
 * Hosts can be separated by comma or semicolons.
 *
 * @param[in,out] globals hg_globals to add hosts to.
 * @param[in]     limit   Maximum number of hosts to resolve, might well break
 *                        before. Smaller or equal to 0 means "no limit".
 *
 * @return 0 if all or \ref limit hosts have been added, -1 on errors.
 */
int
hg_add_comma_delimited_hosts (struct hg_globals *globals, int limit)
{
  // p will point to position in string where currently looked at host starts,
  // v to the (temporary) end of the string.
  char *p, *v;
  int n = 0;
  int family;
  struct in6_addr ip6;

  p = globals->marker;
  while (p)
    {
      int len;
      /* Don't resolve more than 256 host names in a row */
      if (limit > 0 && n > limit)
        {
          globals->marker = p;
          return 0;
        }

      // Skip leading spaces
      while ((*p == ' ') && (p != '\0'))
        p++;

      // Terminate string at ',' or ';'
      v = strchr (p + 1, ',');
      if (v == NULL)
        v = strchr (p + 1, ';');

      if (v != NULL)
        v[0] = '\0';

      // Strip trailing spaces
      len = strlen (p);
      while (p[len - 1] == ' ')
        {
          p[len - 1] = '\0';
          len--;
        }

      /* Check whether ip is of type ipv6. Right now we support only ipv6
       * addresses without any range or netmask. */
      if (!getaddrfamily (p, &family))
        {
          if (family == AF_INET6)
            {
              inet_pton (AF_INET6, p, &ip6);
              hg_add_ipv6host_with_options (globals, p, &ip6, 0, 128, 0, &ip6);
            }
          else
            {
              if (hg_add_host (globals, p) < 0)
                {
                  if (v != NULL)
                    globals->marker = v + 1;
                  else
                    globals->marker = NULL;
                  return -1;
                }
            }
        }
      else
        {
          if (hg_add_host (globals, p) < 0)
            {
              if (v != NULL)
                globals->marker = v + 1;
              else
                globals->marker = NULL;
              return -1;
            }
        }

      n++;
      if (v != NULL)
        p = v + 1;
      else
        p = NULL;
    }

  globals->marker = NULL;
  return 0;
}

/**
 * @param ip_max Ignored.
 */
void
hg_add_ipv6host_with_options (struct hg_globals *globals, char *hostname,
                              struct in6_addr *ip, int alive, int netmask,
                              int use_max, struct in6_addr *ip_max)
{
  char *c_hostname = NULL;
  struct hg_host *host;
  int i;
  char local_hostname[1024];

  /** @TODO We will probably segfault sooner or later if inet_ntop fails. */
  if (inet_ntop (AF_INET6, ip, local_hostname, sizeof (local_hostname)))
    c_hostname = strdup (hostname);

  for (i = 0; i < strlen (hostname); i++)
    c_hostname[i] = tolower (c_hostname[i]);

  host = globals->host_list;
  while (host->next)
    host = host->next;
  host->next = malloc (sizeof (struct hg_host));
  bzero (host->next, sizeof (struct hg_host));

  host->hostname = c_hostname;
  host->domain = hostname ? hg_name_to_domain (c_hostname) : "";
  host->cidr_netmask = netmask;
  host->tested = 0;
  host->alive = alive;
  /*host->addr = ip;
     convipv4toipv4mappedaddr(host->addr, &host->in6addr); */
  memcpy (&host->in6addr, ip, sizeof (struct in6_addr));
  host->use_max = use_max ? 1 : 0;
}

/**
 * @brief Appends a new hg_host to the hg_globals hostlist.
 *
 * @param[in,out] globals  hg_globals to add host to.
 * @param[in]     hostname hostname.
 */
/** @TODO consider const for hostname parameter */
void
hg_add_host_with_options (struct hg_globals *globals, char *hostname,
                          struct in_addr ip, int alive, int netmask,
                          int use_max, struct in_addr *ip_max)
{
  char *c_hostname;
  struct hg_host *host;
  int i;

  c_hostname = strdup (hostname);
  for (i = 0; i < strlen (hostname); i++)
    c_hostname[i] = tolower (c_hostname[i]);

  // Alloc host at end of list
  host = globals->host_list;
  while (host->next)
    host = host->next;
  host->next = malloc (sizeof (struct hg_host));
  bzero (host->next, sizeof (struct hg_host));

  host->hostname = c_hostname;
  host->domain = hostname ? hg_name_to_domain (c_hostname) : "";
  host->cidr_netmask = netmask;
  if (netmask != 32)
    printf ("Error ! Bad netmask\n");
  host->tested = 0;
  host->alive = alive;
  host->addr = ip;
  convipv4toipv4mappedaddr (host->addr, &host->in6addr);
  host->use_max = use_max ? 1 : 0;
  if (ip_max)
    {
      host->max.s_addr = ip_max->s_addr;
      host->min = cidr_get_first_ip (ip, netmask);
      if (ntohl (host->max.s_addr) < ntohl (host->min.s_addr))
        {
          fprintf (stderr, "hg_add_host: error - ip_max < ip_min !\n");
          host->max.s_addr = host->min.s_addr;
        }
      convipv4toipv4mappedaddr (host->max, &host->max6);
      convipv4toipv4mappedaddr (host->min, &host->min6);
    }
}

void
hg_add_domain (struct hg_globals *globals, char *domain)
{
  struct hg_host *list = globals->tested;
  int len;

  while (list && list->next)
    list = list->next;
  list->next = malloc (sizeof (struct hg_host));
  bzero (list->next, sizeof (struct hg_host));

  len = strlen (domain);
  list->domain = malloc (len + 1);
  strncpy (list->domain, domain, len + 1);
}

void
hg_add_subnet (struct hg_globals *globals, struct in_addr ip, int netmask)
{
  struct hg_host *list = globals->tested;

  while (list && list->next)
    list = list->next;
  list->next = malloc (sizeof (struct hg_host));
  bzero (list->next, sizeof (struct hg_host));

  list->addr = ip;
  list->cidr_netmask = netmask;
}
