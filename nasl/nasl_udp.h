/* Nessus Attack Scripting Language
 *
 * Copyright (C) 2002 - 2004 Tenable Network Security
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

#ifndef OPENVAS_UDP_H__
#define OPENVAS_UDP_H__

#ifdef HAVE_STRUCT_UDPHDR
#include <netinet/udp.h>
#endif

#if !defined(HAVE_STRUCT_UDPHDR) || HAVE_STRUCT_UDPHDR == 0
#define HAVE_STRUCT_UDPHDR 1
struct udphdr
{
  u_short uh_sport;             /* source port */
  u_short uh_dport;             /* destination port */
  u_short uh_ulen;              /* udp length */
  u_short uh_sum;               /* udp checksum */
};
#endif

#if defined(HAVE_STRUCT_UDPHDR) && !defined(HAVE_BSD_STRUCT_UDPHDR) && !defined(_CYGWIN_)
#define uh_sport source
#define uh_dport dest
#define uh_ulen len
#define uh_sum check
#endif

#endif
