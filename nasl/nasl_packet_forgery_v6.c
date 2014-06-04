
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 *
 * Modified for IPv6 packet forgery - 04/02/2010
 * Preeti Subramanian <spreeti@secpod.com>
 * Srinivas NL <nl.srinivas@gmail.com>
 *
 * Modified for ICMPv6, IPv6 packet forgery support for IGMP and UDP - 09/02/2010
 * Preeti Subramanian <spreeti@secpod.com>
 */

/**
 * @file nasl_packet_forgery_v6.c
 *
 * @brief NASL IPv6 Packet Forgery functions
 *
 * Provides IPv6 Packet Forgery functionalities
 * The API set offers forgery for,
 * 1. TCP
 * 2. IPv6
 */


#include <arpa/inet.h>          /* for inet_aton */
#include <ctype.h>              /* for isprint */
#include <pcap.h>               /* for PCAP_ERRBUF_SIZE */
#include <stdlib.h>             /* for rand */
#include <string.h>             /* for bcopy */
#include <sys/time.h>           /* for gettimeofday */
#include <unistd.h>             /* for close */
#include <netinet/icmp6.h>      /* ICMPv6 */

#include "bpf_share.h"          /* for bpf_open_live */
#include "pcap_openvas.h"       /* for routethrough */
#include "plugutils.h"          /* plug_get_host_ip */
#include "system.h"             /* for emalloc */

#include "nasl_raw.h"

#include "nasl_tree.h"
#include "nasl_global_ctxt.h"
#include "nasl_func.h"
#include "nasl_var.h"
#include "nasl_lex_ctxt.h"
#include "exec.h"
#include "nasl_socket.h"

#include "nasl_debug.h"
#include "capture_packet.h"
#include "strutils.h"
#include "nasl_packet_forgery_v6.h"

/** @todo: It still needs to be taken care
 * BSD_BYTE_ORDERING gets here if defined (e.g. by config.h) */
#ifdef BSD_BYTE_ORDERING
#define FIX(n) (n)
#define UNFIX(n) (n)
#else
#define FIX(n) htons(n)
#define UNFIX(n) ntohs(n)
#endif

/*--------------[ cksum ]-----------------------------------------*/

/*
 * Checksum routine for Internet Protocol family headers (C Version)
 * From ping examples in W.Richard Stevens "UNIX NETWORK PROGRAMMING" book.
 */
static int
np_in_cksum (p, n)
     u_short *p;
     int n;
{
  register u_short answer = 0;
  register long sum = 0;
  u_short odd_byte = 0;

  while (n > 1)
    {
      sum += *p++;
      n -= 2;
    }

  /* mop up an odd byte, if necessary */
  if (n == 1)
    {
      *(u_char *) (&odd_byte) = *(u_char *) p;
      sum += odd_byte;
    }

  sum = (sum >> 16) + (sum & 0xffff);   /* add hi 16 to low 16 */
  sum += (sum >> 16);           /* add carry */
  answer = (int) ~sum;          /* ones-complement, truncate */
  return (answer);
}


/*--------------[ IP ]--------------------------------------------*/
/**
 * @brief Forge IPv6 packet.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return tree_cell with the forged IP packet.
 */
tree_cell *
forge_ipv6_packet (lex_ctxt * lexic)
{
  tree_cell *retc;
  struct ip6_hdr *pkt;
  char *s;
  struct arglist *script_infos = lexic->script_infos;
  struct in6_addr *dst_addr;
  char *data;
  int data_len;
  int version;
  int tc;
  int fl;

  dst_addr = plug_get_host_ip (script_infos);

  if (dst_addr == NULL || (IN6_IS_ADDR_V4MAPPED (dst_addr) == 1))
    return NULL;

  data = get_str_local_var_by_name (lexic, "data");
  data_len = get_local_var_size_by_name (lexic, "data");

  retc = alloc_tree_cell (0, NULL);
  retc->type = CONST_DATA;
  retc->size = sizeof (struct ip6_hdr) + data_len;

  pkt = (struct ip6_hdr *) emalloc (sizeof (struct ip6_hdr) + data_len);
  retc->x.str_val = (char *) pkt;

  version = get_int_local_var_by_name (lexic, "ip6_v", 6);
  tc = get_int_local_var_by_name (lexic, "ip6_tc", 0);
  fl = get_int_local_var_by_name (lexic, "ip6_fl", 0);

  pkt->ip6_ctlun.ip6_un1.ip6_un1_flow = version | tc | fl;

  pkt->ip6_plen = FIX (data_len);       /* No extension headers ? */
  pkt->ip6_nxt = get_int_local_var_by_name (lexic, "ip6_p", 0);
  pkt->ip6_hlim = get_int_local_var_by_name (lexic, "ip6_hlim", 64);

  /* source */
  s = get_str_local_var_by_name (lexic, "ip6_src");
  if (s != NULL)
    inet_pton (AF_INET6, s, &pkt->ip6_src);
  /* else this host address? */

  s = get_str_local_var_by_name (lexic, "ip6_dst");
  if (s != NULL)
    inet_pton (AF_INET6, s, &pkt->ip6_dst);
  else
    pkt->ip6_dst = *dst_addr;

  if (data != NULL)
    {
      bcopy (data, retc->x.str_val + sizeof (struct ip6_hdr), data_len);
    }

  /*
     There is no checksum for ipv6. Only upper layer
     calculates a checksum using pseudoheader
   */
  return retc;
}

/*--------------[   TCP   ]--------------------------------------------*/

struct v6pseudohdr
{
  struct in6_addr s6addr;
  struct in6_addr d6addr;
  u_short length;
  u_char zero1;
  u_char zero2;
  u_char zero3;
  u_char protocol;
  struct tcphdr tcpheader;
};

/*--------------[       UDP     ]--------------------------------------------*/
/*
 * @brief UDP header.
 */

struct v6pseudo_udp_hdr
{
  struct in6_addr s6addr;
  struct in6_addr d6addr;
  char proto;
  unsigned short len;
  struct udphdr udpheader;
};


/*
 * @brief Forge v6 packet for UDP.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return tree_cell with the forged UDP packet containing IPv6 header.
 */
tree_cell *
forge_udp_v6_packet (lex_ctxt * lexic)
{
  tree_cell *retc;
  struct ip6_hdr *ip6 =
    (struct ip6_hdr *) get_str_local_var_by_name (lexic, "ip6");

  if (ip6 != NULL)
    {
      char *data = get_str_local_var_by_name (lexic, "data");
      int data_len = get_local_var_size_by_name (lexic, "data");
      u_char *pkt;
      struct ip6_hdr *udp_packet;
      struct udphdr *udp;

      pkt = emalloc (sizeof (struct udphdr) + 40 + data_len);
      udp_packet = (struct ip6_hdr *) pkt;
      udp = (struct udphdr *) (pkt + 40);

      udp->uh_sum = get_int_local_var_by_name (lexic, "uh_sum", 0);
      bcopy ((char *) ip6, pkt, 40);

      udp->uh_sport = htons (get_int_local_var_by_name (lexic, "uh_sport", 0));
      udp->uh_dport = htons (get_int_local_var_by_name (lexic, "uh_dport", 0));
      udp->uh_ulen =
        htons (get_int_local_var_by_name
               (lexic, "uh_ulen", data_len + sizeof (struct udphdr)));

      if (data_len != 0 && data != NULL)
        bcopy (data, (pkt + 40 + sizeof (struct udphdr)), data_len);

      if (!udp->uh_sum)
        {
          struct v6pseudo_udp_hdr pseudohdr;
          char *udpsumdata =
            (char *) emalloc (sizeof (struct v6pseudo_udp_hdr) +
                              (data_len % 2 ? data_len + 1 : data_len));

          bzero (&pseudohdr, sizeof (struct v6pseudo_udp_hdr));
          memcpy (&pseudohdr.s6addr, &ip6->ip6_src, sizeof (struct in6_addr));
          memcpy (&pseudohdr.d6addr, &ip6->ip6_dst, sizeof (struct in6_addr));

          pseudohdr.proto = IPPROTO_UDP;
          pseudohdr.len = htons (sizeof (struct udphdr) + data_len);
          bcopy ((char *) udp, (char *) &pseudohdr.udpheader,
                 sizeof (struct udphdr));
          bcopy ((char *) &pseudohdr, udpsumdata, sizeof (pseudohdr));
          if (data != NULL)
            {
              bcopy ((char *) data, udpsumdata + sizeof (pseudohdr), data_len);
            }
          udp->uh_sum =
            np_in_cksum ((unsigned short *) udpsumdata,
                         38 + sizeof (struct udphdr) + data_len);
          efree (&udpsumdata);
        }


      if (UNFIX (udp_packet->ip6_ctlun.ip6_un1.ip6_un1_plen) <= 40)
        {
          int v = get_int_local_var_by_name (lexic, "update_ip6_len", 1);
          if (v != 0)
            {
              udp_packet->ip6_ctlun.ip6_un1.ip6_un1_plen =
                FIX (ntohs (udp->uh_ulen));
            }
        }

      retc = alloc_tree_cell (0, NULL);
      retc->type = CONST_DATA;
      retc->x.str_val = (char *) pkt;
      retc->size = 8 + 40 + data_len;

      return retc;
    }
  else
    printf ("Error ! You must supply the 'ip6' argument !\n");

  return NULL;
}

/*
 * @brief Get UDP Header element.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return tree_cell with the forged UDP packet.
 */
tree_cell *
get_udp_v6_element (lex_ctxt * lexic)
{
  tree_cell *retc;
  char *udp;
  char *element;
  int ipsz;
  struct udphdr *udphdr;
  int ret;

  udp = get_str_local_var_by_name (lexic, "udp");
  ipsz = get_local_var_size_by_name (lexic, "udp");

  element = get_str_local_var_by_name (lexic, "element");
  if (udp == NULL || element == NULL)
    {
      printf ("get_udp_v6_element() usage :\n");
      printf ("element = get_udp_v6_element(udp:<udp>,element:<element>\n");
      return NULL;
    }

  if (40 + sizeof (struct udphdr) > ipsz)
    return NULL;

  udphdr = (struct udphdr *) (udp + 40);
  if (!strcmp (element, "uh_sport"))
    ret = ntohs (udphdr->uh_sport);
  else if (!strcmp (element, "uh_dport"))
    ret = ntohs (udphdr->uh_dport);
  else if (!strcmp (element, "uh_ulen"))
    ret = ntohs (udphdr->uh_ulen);
  else if (!strcmp (element, "uh_sum"))
    ret = ntohs (udphdr->uh_sum);
  else if (!strcmp (element, "data"))
    {
      int sz;
      retc = alloc_tree_cell (0, NULL);
      retc->type = CONST_DATA;
      sz = ntohs (udphdr->uh_ulen) - sizeof (struct udphdr);

      if (ntohs (udphdr->uh_ulen) - 40 - sizeof (struct udphdr) > ipsz)
        sz = ipsz - 40 - sizeof (struct udphdr);

      retc->x.str_val = emalloc (sz);
      retc->size = sz;
      bcopy (udp + 40 + sizeof (struct udphdr), retc->x.str_val, sz);
      return retc;
    }
  else
    {
      printf ("%s is not a value of a udp packet\n", element);
      return NULL;
    }

  retc = alloc_tree_cell (0, NULL);
  retc->type = CONST_INT;
  retc->x.i_val = ret;
  return retc;
}

/*--------------[  ICMP  ]--------------------------------------------*/
/*
 * @brief ICMPv6 header.
*/

struct v6pseudo_icmp_hdr
{
  struct in6_addr s6addr;
  struct in6_addr d6addr;
  char proto;
  unsigned short len;
  struct icmp6_hdr icmpheader;
};


/*
 * @brief Forge ICMPv6 packet.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return tree_cell with the forged ICMPv6 packet containing IPv6 header.
 */
tree_cell *
forge_icmp_v6_packet (lex_ctxt * lexic)
{
  tree_cell *retc = NULL;
  struct ip6_hdr *ip6;
  struct ip6_hdr *ip6_icmp;
  int ip6_sz, size = 0, sz = 0;
  struct icmp6_hdr *icmp;
  struct nd_router_solicit *routersolicit = NULL;
  struct nd_router_advert *routeradvert = NULL;
  struct nd_neighbor_solicit *neighborsolicit = NULL;
  struct nd_neighbor_advert *neighboradvert = NULL;

  char *data, *p;
  int len;
  u_char *pkt;
  int t;
  ip6 = (struct ip6_hdr *) get_str_local_var_by_name (lexic, "ip6");
  ip6_sz = get_local_var_size_by_name (lexic, "ip6");

  if (ip6 != NULL)
    {
      retc = alloc_tree_cell (0, NULL);
      retc->type = CONST_DATA;
      data = get_str_local_var_by_name (lexic, "data");
      len = data == NULL ? 0 : get_var_size_by_name (lexic, "data");
      t = get_int_local_var_by_name (lexic, "icmp_type", 0);
      if (40 > ip6_sz)
        return NULL;

      /* ICMP header size is 8 */
      pkt = emalloc (ip6_sz + 8 + len);
      ip6_icmp = (struct ip6_hdr *) pkt;

      bcopy (ip6, ip6_icmp, ip6_sz);
      p = (char *) (pkt + ip6_sz);

      icmp = (struct icmp6_hdr *) p;

      icmp->icmp6_code = get_int_local_var_by_name (lexic, "icmp_code", 0);
      icmp->icmp6_type = t;

      switch (t)
        {
        case ICMP6_ECHO_REQUEST:
          {
            if (data != NULL)
              bcopy (data, &(p[8]), len);
            icmp->icmp6_id = get_int_local_var_by_name (lexic, "icmp_id", 0);
            icmp->icmp6_seq = get_int_local_var_by_name (lexic, "icmp_seq", 0);
            size = ip6_sz + 8 + len;
            sz = 8;
          }
          break;
        case ND_ROUTER_SOLICIT:
          {
            if (data != NULL)
              bcopy (data, &(p[8]), len);
            routersolicit = emalloc (sizeof (struct nd_router_solicit));
            pkt =
              realloc (pkt, ip6_sz + sizeof (struct nd_router_solicit) + len);
            ip6_icmp = (struct ip6_hdr *) pkt;
            p = (char *) (pkt + ip6_sz);
            struct icmp6_hdr *rs = &routersolicit->nd_rs_hdr;
            routersolicit = (struct nd_router_solicit *) p;
            rs->icmp6_type = icmp->icmp6_type;
            rs->icmp6_code = icmp->icmp6_code;
            rs->icmp6_cksum = icmp->icmp6_cksum;
            size = ip6_sz + sizeof (struct nd_router_solicit) + len;
            sz = 4;             /*type-1 byte, code-1byte, cksum-2bytes */
          }
          break;
        case ND_ROUTER_ADVERT:
          {
            if (data != NULL)
              bcopy (data, &(p[8]), len);
            routeradvert = emalloc (sizeof (struct nd_router_advert));
            /*do we need lifetime?? Not taking lifetime?? */
            pkt = realloc (pkt, ip6_sz + sizeof (struct nd_router_advert) - 8 + len);   /*not taking lifetime(8 bytes) into consideration */
            ip6_icmp = (struct ip6_hdr *) pkt;
            p = (char *) (pkt + ip6_sz);
            struct icmp6_hdr *ra = &routeradvert->nd_ra_hdr;
            routeradvert = (struct nd_router_advert *) p;
            ra->icmp6_type = icmp->icmp6_type;
            ra->icmp6_code = icmp->icmp6_code;
            ra->icmp6_cksum = icmp->icmp6_cksum;
            routeradvert->nd_ra_reachable =
              get_int_local_var_by_name (lexic, "reacheable_time", 0);
            routeradvert->nd_ra_retransmit =
              get_int_local_var_by_name (lexic, "retransmit_timer", 0);
            routeradvert->nd_ra_curhoplimit = ip6_icmp->ip6_hlim;
            routeradvert->nd_ra_flags_reserved =
              get_int_local_var_by_name (lexic, "flags", 0);
            size = ip6_sz + sizeof (struct nd_router_advert) - 8 + len; /*not taking lifetime(8 bytes) into consideration */
            sz = 5;             /*type-1 byte, code-1byte, cksum-2bytes, current hoplimit-1byte */
          }
          break;
        case ND_NEIGHBOR_SOLICIT:
          {
            neighborsolicit = emalloc (sizeof (struct nd_neighbor_solicit));
            pkt =
              realloc (pkt, ip6_sz + sizeof (struct nd_neighbor_solicit) + len);
            ip6_icmp = (struct ip6_hdr *) pkt;
            p = (char *) (pkt + ip6_sz);
            struct icmp6_hdr *ns = &neighborsolicit->nd_ns_hdr;
            neighborsolicit = (struct nd_neighbor_solicit *) p;
            if (data != NULL)
              bcopy (data, &(p[24]), len);
            ns->icmp6_type = icmp->icmp6_type;
            ns->icmp6_code = icmp->icmp6_code;
            ns->icmp6_cksum = icmp->icmp6_cksum;
            memcpy (&neighborsolicit->nd_ns_target, &ip6_icmp->ip6_dst, sizeof (struct in6_addr));      /*dst ip should be link local */
            size = ip6_sz + sizeof (struct nd_neighbor_solicit) + len;
            sz = 4;             /*type-1 byte, code-1byte, cksum-2bytes */
          }
          break;
        case ND_NEIGHBOR_ADVERT:
          {
            neighboradvert = emalloc (sizeof (struct nd_neighbor_advert));
            pkt =
              realloc (pkt, ip6_sz + sizeof (struct nd_neighbor_advert) + len);
            ip6_icmp = (struct ip6_hdr *) pkt;
            p = (char *) (pkt + 40);
            struct icmp6_hdr *na = &neighboradvert->nd_na_hdr;
            neighboradvert = (struct nd_neighbor_advert *) p;
            na->icmp6_type = icmp->icmp6_type;
            na->icmp6_code = icmp->icmp6_code;
            na->icmp6_cksum = icmp->icmp6_cksum;
            neighboradvert->nd_na_flags_reserved =
              get_int_local_var_by_name (lexic, "flags", 0);
            if (neighboradvert->nd_na_flags_reserved & 0x00000020)
              memcpy (&neighboradvert->nd_na_target, &ip6_icmp->ip6_src, sizeof (struct in6_addr));     /*dst ip should be link local */
            else
              {
                if (get_var_size_by_name (lexic, "target") != 0)
                  inet_pton (AF_INET6,
                             get_str_local_var_by_name (lexic, "target"),
                             &neighboradvert->nd_na_target);
                else
                  {
                    nasl_perror (lexic,
                                 "forge_icmp_v6_packet: missing 'target' parameter required for constructing response to a Neighbor Solicitation\n");
                    return NULL;
                  }
              }
            size = ip6_sz + sizeof (struct nd_neighbor_advert) + len;
            sz = 4;             /*type-1 byte, code-1byte, cksum-2bytes */
          }
          break;
        default:
          {
            nasl_perror (lexic, "forge_icmp_v6_packet: unknown type\n");
          }
        }

      if (UNFIX (ip6_icmp->ip6_ctlun.ip6_un1.ip6_un1_plen) <= 40)
        {
          if (get_int_local_var_by_name (lexic, "update_ip_len", 1) != 0)
            {
              ip6_icmp->ip6_ctlun.ip6_un1.ip6_un1_plen = FIX (size - ip6_sz);
            }
        }
      if (get_int_local_var_by_name (lexic, "icmp_cksum", -1) == -1)
        {
          struct v6pseudo_icmp_hdr pseudohdr;
          char *icmpsumdata =
            (char *) emalloc (sizeof (struct v6pseudo_icmp_hdr) +
                              (len % 2 ? len + 1 : len));

          bzero (&pseudohdr, sizeof (struct v6pseudo_icmp_hdr));
          memcpy (&pseudohdr.s6addr, &ip6->ip6_src, sizeof (struct in6_addr));
          memcpy (&pseudohdr.d6addr, &ip6->ip6_dst, sizeof (struct in6_addr));

          pseudohdr.proto = 0x3a;       /*ICMPv6 */
          pseudohdr.len = htons (size - ip6_sz);
          bcopy ((char *) icmp, (char *) &pseudohdr.icmpheader, sz);
          bcopy ((char *) &pseudohdr, icmpsumdata, sizeof (pseudohdr));
          if (data != NULL)
            bcopy ((char *) data, icmpsumdata + sizeof (pseudohdr), len);
          icmp->icmp6_cksum =
            np_in_cksum ((unsigned short *) icmpsumdata, size);
          efree (&icmpsumdata);
        }
      else
        icmp->icmp6_cksum =
          htons (get_int_local_var_by_name (lexic, "icmp_cksum", 0));
      switch (t)
        {
        case ICMP6_ECHO_REQUEST:
          break;
        case ND_ROUTER_SOLICIT:
          {
            routersolicit->nd_rs_hdr.icmp6_cksum = icmp->icmp6_cksum;
          }
          break;
        case ND_ROUTER_ADVERT:
          {
            routeradvert->nd_ra_hdr.icmp6_cksum = icmp->icmp6_cksum;
          }
          break;
        case ND_NEIGHBOR_SOLICIT:
          {
            neighborsolicit->nd_ns_hdr.icmp6_cksum = icmp->icmp6_cksum;
          }
          break;
        case ND_NEIGHBOR_ADVERT:
          {
            neighboradvert->nd_na_hdr.icmp6_cksum = icmp->icmp6_cksum;
          }
          break;
        default:
          {
          }
        }

      retc->x.str_val = (char *) pkt;
      retc->size = size;
    }
  else
    nasl_perror (lexic, "forge_icmp_v6_packet: missing 'ip6' parameter\n");

  return retc;
}

/*--------------[  IGMP  ]--------------------------------------------*/
/*
 * @brief Forge v6 IGMP packet.
 */

/*---------------------------------------------------------------------------*/

/**
 * @brief Performs TCP Connect to test if host is alive.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return tree_cell > 0 if host is alive, 0 otherwise.
 */
tree_cell *
nasl_tcp_v6_ping (lex_ctxt * lexic)
{
  int port;
  u_char packet[sizeof (struct ip6_hdr) + sizeof (struct tcphdr)];
  int soc;
  struct ip6_hdr *ip = (struct ip6_hdr *) packet;
  struct tcphdr *tcp = (struct tcphdr *) (packet + sizeof (struct ip6_hdr));
  struct arglist *script_infos = lexic->script_infos;
  struct in6_addr *dst = plug_get_host_ip (script_infos);
  struct in6_addr src;
  struct sockaddr_in6 soca;
  int flag = 0;
  int i = 0;
  int bpf;
  char filter[255];
  u_char *pk = NULL;
  tree_cell *retc;
  int opt = 1;
  struct timeval tv;
  int len;

#define rnd_tcp_port() (rand() % 65535 + 1024)
  int sports[] =
    { 0, 0, 0, 0, 0, 1023, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 53, 0, 0,
20, 0, 25, 0, 0, 0 };
  int ports[] =
    { 139, 135, 445, 80, 22, 515, 23, 21, 6000, 1025, 25, 111, 1028, 9100, 1029,
79, 497, 548, 5000, 1917, 53, 161, 9001, 65535, 443, 113, 993, 8080, 0 };
  int num_ports = 0;
  char addr[INET6_ADDRSTRLEN];

  if (dst == NULL || (IN6_IS_ADDR_V4MAPPED (dst) == 1))
    return NULL;

  for (i = 0; i < sizeof (sports) / sizeof (int); i++)
    {
      if (sports[i] == 0)
        sports[i] = rnd_tcp_port ();
    }

  for (i = 0; ports[i]; i++)
    num_ports++;
  i = 0;

  soc = socket (AF_INET6, SOCK_RAW, IPPROTO_RAW);
  if (soc < 0)
    return NULL;

#ifdef IP_HDRINCL
  if (setsockopt (soc, IPPROTO_IPV6, IP_HDRINCL, (char *) &opt, sizeof (opt)) <
      0)
    perror ("setsockopt");
#endif

  port = get_int_local_var_by_name (lexic, "port", -1);
  if (port == -1)
    port = plug_get_host_open_port (script_infos);
  if (v6_islocalhost (dst) > 0)
    src = *dst;
  else
    {
      bzero (&src, sizeof (src));
      v6_routethrough (dst, &src);
    }

  snprintf (filter, sizeof (filter), "ip6 and src host %s", inet_ntop (AF_INET6, dst, addr, sizeof (addr)));    /* RATS: ignore */
  bpf = init_v6_capture_device (*dst, src, filter);

  if (v6_islocalhost (dst) != 0)
    flag++;
  else
    {
      for (i = 0; i < sizeof (sports) / sizeof (int) && !flag; i++)
        {
          bzero (packet, sizeof (packet));
          /* IPv6 */
          int version = 0x60, tc = 0, fl = 0;
          ip->ip6_ctlun.ip6_un1.ip6_un1_flow = version | tc | fl;
          ip->ip6_nxt = 0x06, ip->ip6_hlim = 0x40, ip->ip6_src = src;
          ip->ip6_dst = *dst;
          ip->ip6_ctlun.ip6_un1.ip6_un1_plen = FIX (sizeof (struct tcphdr));

          /* TCP */
          tcp->th_sport =
            port ? htons (rnd_tcp_port ()) : htons (sports[i % num_ports]);
          tcp->th_flags = TH_SYN;
          tcp->th_dport = port ? htons (port) : htons (ports[i % num_ports]);
          tcp->th_seq = rand ();
          tcp->th_ack = 0;
          tcp->th_x2 = 0;
          tcp->th_off = 5;
          tcp->th_win = htons (512);
          tcp->th_urp = 0;
          tcp->th_sum = 0;

          /* CKsum */
          {
            struct v6pseudohdr pseudoheader;

            bzero (&pseudoheader, 38 + sizeof (struct tcphdr));
            memcpy (&pseudoheader.s6addr, &ip->ip6_src,
                    sizeof (struct in6_addr));
            memcpy (&pseudoheader.d6addr, &ip->ip6_dst,
                    sizeof (struct in6_addr));

            pseudoheader.protocol = IPPROTO_TCP;
            pseudoheader.length = htons (sizeof (struct tcphdr));
            bcopy ((char *) tcp, (char *) &pseudoheader.tcpheader,
                   sizeof (struct tcphdr));
            tcp->th_sum =
              np_in_cksum ((unsigned short *) &pseudoheader,
                           38 + sizeof (struct tcphdr));
          }

          bzero (&soca, sizeof (soca));
          soca.sin6_family = AF_INET6;
          soca.sin6_addr = ip->ip6_dst;
          sendto (soc, (const void *) ip,
                  sizeof (struct tcphdr) + sizeof (struct ip6_hdr), 0,
                  (struct sockaddr *) &soca, sizeof (struct sockaddr_in6));
          tv.tv_sec = 0;
          tv.tv_usec = 100000;
          if (bpf >= 0 && (pk = bpf_next_tv (bpf, &len, &tv)))
            flag++;
        }
    }

  retc = alloc_tree_cell (0, NULL);
  retc->type = CONST_INT;
  retc->x.i_val = flag;
  if (bpf >= 0)
    bpf_close (bpf);
  close (soc);
  return retc;
}

/**
 * @brief Send forged IPv6 Packet.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return tree_cell with the response to the sent packet.
 */
tree_cell *
nasl_send_v6packet (lex_ctxt * lexic)
{
  tree_cell *retc = FAKE_CELL;
  int bpf = -1;
  u_char *answer;
  int answer_sz;
  struct sockaddr_in6 sockaddr;
  char *ip = NULL;
  struct ip6_hdr *sip = NULL;
  int vi = 0, b = 0, len = 0;
  int soc;
  int use_pcap = get_int_local_var_by_name (lexic, "pcap_active", 1);
  int to = get_int_local_var_by_name (lexic, "pcap_timeout", 5);
  char *filter = get_str_local_var_by_name (lexic, "pcap_filter");
  int dfl_len = get_int_local_var_by_name (lexic, "length", -1);
  struct arglist *script_infos = lexic->script_infos;
  struct in6_addr *dstip = plug_get_host_ip (script_infos);
  int offset = 1;
  char name[INET6_ADDRSTRLEN];

  if (dstip == NULL || (IN6_IS_ADDR_V4MAPPED (dstip) == 1))
    return NULL;
  soc = socket (AF_INET6, SOCK_RAW, IPPROTO_RAW);
  if (soc < 0)
    return NULL;

#ifdef IP_HDRINCL
  if (setsockopt
      (soc, IPPROTO_IPV6, IP_HDRINCL, (char *) &offset, sizeof (offset)) < 0)
    perror ("setsockopt");
#endif
  while ((ip = get_str_var_by_num (lexic, vi)) != NULL)
    {
      int sz = get_var_size_by_num (lexic, vi);
      vi++;

      if (sz < sizeof (struct ip6_hdr))
        {
          nasl_perror (lexic, "send_packet(): packet is too short!\n");
          continue;
        }

      sip = (struct ip6_hdr *) ip;
      if (use_pcap != 0 && bpf < 0)
        bpf = init_v6_capture_device (sip->ip6_dst, sip->ip6_src, filter);

      bzero (&sockaddr, sizeof (struct sockaddr_in6));
      sockaddr.sin6_family = AF_INET6;
      sockaddr.sin6_addr = sip->ip6_dst;
      if (dstip != NULL && !IN6_ARE_ADDR_EQUAL (&sockaddr.sin6_addr, dstip))
        {
          char txt1[64], txt2[64];
          strncpy (txt1,
                   inet_ntop (AF_INET6, &sockaddr.sin6_addr, name,
                              INET6_ADDRSTRLEN), sizeof (txt1));
          txt1[sizeof (txt1) - 1] = '\0';
          strncpy (txt2, inet_ntop (AF_INET6, dstip, name, INET6_ADDRSTRLEN),
                   sizeof (txt2));
          txt2[sizeof (txt2) - 1] = '\0';
          nasl_perror (lexic,
                       "send_packet: malicious or buggy script is trying to send packet to %s instead of designated target %s\n",
                       txt1, txt2);
          if (bpf >= 0)
            bpf_close (bpf);
          close (soc);
          return NULL;
        }

      if (dfl_len > 0 && dfl_len < sz)
        len = dfl_len;
      else
        len = sz;

      b =
        sendto (soc, (u_char *) ip, len, 0, (struct sockaddr *) &sockaddr,
                sizeof (struct sockaddr_in6));
      /* if(b < 0) perror("sendto "); */
      if (b >= 0 && use_pcap != 0 && bpf >= 0)
        {
          if (v6_islocalhost (&sip->ip6_dst))
            {
              answer = (u_char *) capture_next_v6_packet (bpf, to, &answer_sz);
              while (answer != NULL
                     &&
                     (!memcmp (answer, (char *) ip, sizeof (struct ip6_hdr))))
                {
                  efree (&answer);
                  answer =
                    (u_char *) capture_next_v6_packet (bpf, to, &answer_sz);
                }
            }
          else
            {
              answer = (u_char *) capture_next_v6_packet (bpf, to, &answer_sz);
            }
          if (answer)
            {
              retc = alloc_tree_cell (0, NULL);
              retc->type = CONST_DATA;
              retc->x.str_val = (char *) answer;
              retc->size = answer_sz;
              break;
            }
        }
    }
  if (bpf >= 0)
    bpf_close (bpf);
  close (soc);
  return retc;
}
