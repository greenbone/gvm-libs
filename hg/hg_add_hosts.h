/*
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
 * Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#ifndef HG_ADD_HOSTS_H__
#define HG_ADD_HOSTS_H__

int hg_add_comma_delimited_hosts (struct hg_globals *, int);
void hg_add_host_with_options (struct hg_globals *, char *, struct in_addr,
                               int, int,int, struct in_addr *);
void hg_add_ipv6host_with_options (struct hg_globals *, char *,
                                   struct in6_addr *, int, int, int,
                                   struct in6_addr *);
void hg_add_domain (struct hg_globals *, char *);
void hg_add_subnet (struct hg_globals *, struct in_addr, int);

#endif
