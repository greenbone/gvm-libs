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
 * @brief Stand-alone tool to test module "hosts".
 *
 * This file offers a command line interface to test the functionalities
 * of the hosts object.
 */

#include "../base/hosts.h" /* for gvm_host_type_str, gvm_host_resolve, gvm_... */

#include <arpa/inet.h>  /* for inet_ntop */
#include <glib.h>       /* for g_free */
#include <netinet/in.h> /* for INET6_ADDRSTRLEN, INET_ADDRSTRLEN, in6_addr */
#include <stdio.h>      /* for printf, fprintf, NULL, stderr */
#include <sys/socket.h> /* for AF_INET, AF_INET6 */

static void
print_vhosts (gvm_host_t *host)
{
  GSList *tmp = host->vhosts;
  while (tmp)
    {
      gvm_vhost_t *vhost = tmp->data;
      printf (" %s [%s]", vhost->value, vhost->source);
      tmp = tmp->next;
    }
  if (host->vhosts)
    printf ("\n");
}
int
main (int argc, char **argv)
{
  gvm_hosts_t *hosts;
  gvm_host_t *host;
  int i;

  if (argc < 2)
    return 1;
  hosts = gvm_hosts_new (argv[1]);
  if (hosts == NULL)
    return 1;
  if (argv[2])
    {
      if (gvm_hosts_exclude (hosts, argv[2]) == -1)
        return 2;
    }
  gvm_hosts_resolve (hosts);

  printf ("Count: %u\n", gvm_hosts_count (hosts));
  printf ("Removed: %u\n", gvm_hosts_removed (hosts));

  i = 1;
  while ((host = gvm_hosts_next (hosts)))
    {
      char *str;

      gvm_host_add_reverse_lookup (host);
      str = gvm_host_value_str (host);
      if (gvm_host_type (host) == HOST_TYPE_NAME)
        {
          char name[INET_ADDRSTRLEN], name6[INET6_ADDRSTRLEN];
          struct in_addr addr;
          struct in6_addr addr6;

          if (gvm_host_resolve (host, &addr, AF_INET) == -1)
            {
              fprintf (stderr, "ERROR - %s: Couldn't resolve IPv4 address.\n",
                       host->name);
              printf ("#%d %s %s\n", i, gvm_host_type_str (host), str);
              i++;
              g_free (str);
              continue;
            }
          if (inet_ntop (AF_INET, &addr, name, sizeof (name)) == NULL)
            {
              printf ("inet_ntop() error.\n");
              break;
            }

          if (gvm_host_resolve (host, &addr6, AF_INET6) == -1)
            {
              fprintf (stderr, "ERROR - %s: Couldn't resolve IPv6 address.\n",
                       host->name);
              printf ("#%d %s %s (%s)\n", i, gvm_host_type_str (host), str,
                      name);
              i++;
              g_free (str);
              continue;
            }
          if (inet_ntop (AF_INET6, &addr6, name6, sizeof (name6)) == NULL)
            {
              printf ("inet_ntop() error.\n");
              break;
            }

          printf ("#%d %s %s (%s / %s)\n", i, gvm_host_type_str (host), str,
                  name, name6);
        }
      else
        printf ("#%d %s %s\n", i, gvm_host_type_str (host), str);
      print_vhosts (host);

      i++;
      g_free (str);
    }

  gvm_hosts_free (hosts);
  return 0;
}
