/* OpenVAS
 * $Id$
 * Description: Header file for module pcap.
 *
 * Authors:
 * Jan-Oliver Wagner <jan-oliver.wagner@intevation.de>
 *
 * Copyright:
 * Copyright (C) 2008 Intevation GmbH
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef OPENVAS_PCAP_H
#define OPENVAS_PCAP_H

#include <pcap.h>

int is_local_ip(struct in_addr);
int get_mac_addr(struct in_addr, char**);
int islocalhost(struct in_addr *);
int get_datalink_size(int);
char *routethrough(struct in_addr *, struct in_addr *);

#endif
