/* openvas-libraries/base
 * $Id$
 * Description: Stand-alone tool to test module "openvas_hosts".
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

/**
 * @file tests-hosts.c
 * @brief Stand-alone tool to test module "openvas_hosts".
 *
 * This file offers a command line interface to test the functionalities
 * of the hosts object.
 */

#include <stdio.h>

#include "openvas_hosts.h"

int
main (int argc, char **argv)
{
  openvas_hosts_t *hosts;
  openvas_host_t *host;
  int i;

  hosts = openvas_hosts_new (argv[1]);
  if (hosts == NULL)
    return 1;

  printf ("Count: %d\n", openvas_hosts_count (hosts));
  printf ("Removed: %d\n", openvas_hosts_removed (hosts));

  i = 1;
  while ((host = openvas_hosts_next (hosts)))
    {
      char *str;

      str = openvas_host_value_str (host);
      if (openvas_host_type (host) == HOST_TYPE_NAME)
        {
          char name[INET_ADDRSTRLEN], name6[INET6_ADDRSTRLEN];
          struct in_addr addr;
          struct in6_addr addr6;

          if (openvas_host_resolve (host, &addr, AF_INET) == -1)
            {
              fprintf (stderr, "ERROR - %s: Couldn't resolve IPv4 address.\n",
                       host->name);
              printf ("#%d %s %s\n", i, openvas_host_type_str (host), str);
              i++;
              g_free (str);
              continue;
            }
          if (inet_ntop (AF_INET, &addr, name, sizeof (name)) == NULL)
            {
                printf ("inet_ntop() error.\n");
                break;
            }

          if (openvas_host_resolve (host, &addr6, AF_INET6) == -1)
            {
              fprintf (stderr, "ERROR - %s: Couldn't resolve IPv6 address.\n",
                       host->name);
              printf ("#%d %s %s (%s)\n", i, openvas_host_type_str (host),
                      str, name);
              i++;
              g_free (str);
              continue;
            }
          if (inet_ntop (AF_INET6, &addr6, name6, sizeof (name6)) == NULL)
            {
                printf ("inet_ntop() error.\n");
                break;
            }

          printf ("#%d %s %s (%s / %s)\n", i, openvas_host_type_str (host), str,
                  name, name6);
        }
      else
        printf ("#%d %s %s\n", i, openvas_host_type_str (host), str);

      i++;
      g_free (str);
    }

  openvas_hosts_free (hosts);
  return 0;
}
