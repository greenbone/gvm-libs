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

#ifndef HL2_UTILS_H__
#define HL2_UTILS_H__

int hg_resolv (char* , struct in6_addr *, int );
char * hg_name_to_domain(char * name);
void hg_hosts_cleanup(struct hg_host *);
void hg_host_cleanup(struct hg_host *);
int hg_get_name_from_ip (struct in6_addr *, char *, int);
int hg_valid_ip_addr(char *);
#endif
