/* openvas-libraries/base
 * $Id$
 * Description: OpenVAS Networking related API.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <glib.h>

#ifndef _OPENVAS_NETWORKING_H
#define _OPENVAS_NETWORKING_H

int
openvas_source_iface_init (const char *);

int
openvas_source_iface_is_set ();

int
openvas_source_set_socket (int, int, int);

void
openvas_source_addr (void *);

void
openvas_source_addr6 (void *);

void
openvas_source_addr_as_addr6 (struct in6_addr *);

char *
openvas_source_iface_str ();

char *
openvas_source_addr_str ();

char *
openvas_source_addr6_str ();

void
ipv4_as_ipv6 (const struct in_addr *, struct in6_addr *);

int
openvas_resolve (const char *, void *, int);

int
openvas_resolve_as_addr6 (const char *, struct in6_addr *);

#endif /* not _OPENVAS_NETWORKING_H */
