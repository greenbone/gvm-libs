/* Copyright (C) 2020 Greenbone Networks GmbH
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
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

#include "ping.h"

#include <errno.h>
#include <glib.h>
#include <netinet/icmp6.h>
#include <netinet/ip_icmp.h>
#include <sys/time.h>
#include <sys/types.h>

/**
 * @brief Checksum calculation.
 *
 * From W.Richard Stevens "UNIX NETWORK PROGRAMMING" book. libfree/in_cksum.c
 * TODO: Section 8.7 of TCPv2 has more efficient implementation
 **/
static uint16_t
in_cksum (uint16_t *addr, int len)
{
  int nleft = len;
  uint32_t sum = 0;
  uint16_t *w = addr;
  uint16_t answer = 0;

  /*
   * Our algorithm is simple, using a 32 bit accumulator (sum), we add
   * sequential 16 bit words to it, and at the end, fold back all the
   * carry bits from the top 16 bits into the lower 16 bits.
   */
  while (nleft > 1)
    {
      sum += *w++;
      nleft -= 2;
    }

  /* mop up an odd byte, if necessary */
  if (nleft == 1)
    {
      *(unsigned char *) (&answer) = *(unsigned char *) w;
      sum += answer;
    }

  /* add back carry outs from top 16 bits to low 16 bits */
  sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
  sum += (sum >> 16);                 /* add carry */
  answer = ~sum;                      /* truncate to 16 bits */
  return (answer);
}

/**
 * @brief Send icmp ping.
 *
 * @param soc Socket to use for sending.
 * @param dst Destination address to send to.
 * @param type  Type of imcp. e.g. ND_NEIGHBOR_SOLICIT or ICMP6_ECHO_REQUEST.
 */
void
send_icmp_v6 (int soc, struct in6_addr *dst, int type)
{
  struct sockaddr_in6 soca;
  char sendbuf[1500];
  int len;
  int datalen = 56;
  struct icmp6_hdr *icmp6;

  icmp6 = (struct icmp6_hdr *) sendbuf;
  icmp6->icmp6_type = type; /* ND_NEIGHBOR_SOLICIT or ICMP6_ECHO_REQUEST */
  icmp6->icmp6_code = 0;
  icmp6->icmp6_id = 234;
  icmp6->icmp6_seq = 0;

  memset ((icmp6 + 1), 0xa5, datalen);
  gettimeofday ((struct timeval *) (icmp6 + 1), NULL); // only for testing
  len = 8 + datalen;

  /* send packet */
  memset (&soca, 0, sizeof (struct sockaddr_in6));
  soca.sin6_family = AF_INET6;
  soca.sin6_addr = *dst;

  if (sendto (soc, sendbuf, len, MSG_NOSIGNAL, (struct sockaddr *) &soca,
              sizeof (struct sockaddr_in6))
      < 0)
    {
      g_warning ("%s: sendto(): %s", __func__, strerror (errno));
    }
}

/**
 * @brief Send icmp ping.
 *
 * @param soc Socket to use for sending.
 * @param dst Destination address to send to.
 */
void
send_icmp_v4 (int soc, struct in_addr *dst)
{
  /* datalen + MAXIPLEN + MAXICMPLEN */
  char sendbuf[56 + 60 + 76];
  struct sockaddr_in soca;

  int len;
  int datalen = 56;
  struct icmphdr *icmp;

  icmp = (struct icmphdr *) sendbuf;
  icmp->type = ICMP_ECHO;
  icmp->code = 0;

  len = 8 + datalen;
  icmp->checksum = 0;
  icmp->checksum = in_cksum ((u_short *) icmp, len);

  memset (&soca, 0, sizeof (soca));
  soca.sin_family = AF_INET;
  soca.sin_addr = *dst;

  if (sendto (soc, sendbuf, len, MSG_NOSIGNAL, (const struct sockaddr *) &soca,
              sizeof (struct sockaddr_in))
      < 0)
    {
      g_warning ("%s: sendto(): %s", __func__, strerror (errno));
    }
}