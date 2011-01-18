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

#ifndef OPENVAS_IP_H__

#include <netinet/ip.h>

#ifndef IP_RF
#define	IP_RF 0x8000            /* reserved fragment flag */
#endif

#ifndef IP_DF
#define	IP_DF 0x4000            /* dont fragment flag */
#endif

#ifndef IP_MF
#define	IP_MF 0x2000            /* more fragments flag */
#endif

#ifndef IP_OFFMASK
#define	IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
#endif

// TODO: this deactivates most of the following code which
// perhaps can be deleted eventually. Actually this whole file
// seems to be candidate for removal.
#define HAVE_STRUCT_IP 1

#if !defined(HAVE_STRUCT_IP) || (HAVE_STRUCT_IP == 0)

#undef _IP_VHL

#define HAVE_STRUCT_IP 1
struct ip
{
#if !WORDS_BIGENDIAN
  u_char ip_hl:4,               /* header length */
    ip_v:4;                     /* version */
#else
  u_char ip_v:4,                /* version */
    ip_hl:4;                    /* header length */
#endif
  u_char ip_tos;                /* type of service */
  u_short ip_len;               /* total length */
  u_short ip_id;                /* identification */
  u_short ip_off;               /* fragment offset field */
  u_char ip_ttl;                /* time to live */
  u_char ip_p;                  /* protocol */
  u_short ip_sum;               /* checksum */
  struct in_addr ip_src, ip_dst;        /* source and dest address */
};

#endif /* not defined(HAVE_STRUCT_IP) */

#endif
