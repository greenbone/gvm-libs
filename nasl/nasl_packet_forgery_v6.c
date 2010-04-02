
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
 *
 * Modified for IPv6 packet forgery - 04/02/2010
 * Preeti Subramanian <spreeti@secpod.com>
 * Srinivas NL <nl.srinivas@gmail.com>
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


#include <arpa/inet.h> /* for inet_aton */
#include <ctype.h> /* for isprint */
#include <pcap.h> /* for PCAP_ERRBUF_SIZE */
#include <stdlib.h> /* for rand */
#include <string.h> /* for bcopy */
#include <sys/time.h> /* for gettimeofday */
#include <unistd.h> /* for close */

#include "bpf_share.h" /* for bpf_open_live */
#include "pcap_openvas.h" /* for routethrough */
#include "plugutils.h" /* plug_get_host_ip */
#include "system.h" /* for emalloc */

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
static int np_in_cksum(p,n)
u_short *p; int n;
{
  register u_short answer;
  register long sum = 0;
  u_short odd_byte = 0;

  while( n > 1 )  { sum += *p++; n -= 2; }

  /* mop up an odd byte, if necessary */
  if( n == 1 ) {
      *(u_char *)(&odd_byte) = *(u_char *)p;
      sum += odd_byte;
  }

  sum = (sum >> 16) + (sum & 0xffff);  /* add hi 16 to low 16 */
  sum += (sum >> 16);      /* add carry */
  answer = (int)~sum;      /* ones-complement, truncate*/
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
tree_cell* forge_ipv6_packet(lex_ctxt* lexic)
{
  tree_cell *retc;
  struct ip6_hdr *pkt;
  char   *s;
  struct arglist * script_infos = lexic->script_infos;
  struct in6_addr * dst_addr;
  char * data;
  int data_len;
  int version;
  int tc;
  int fl;

  dst_addr = plug_get_host_ip(script_infos);

  if( dst_addr == NULL || (IN6_IS_ADDR_V4MAPPED(dst_addr) == 1))
    return NULL;

  data = get_str_local_var_by_name(lexic, "data");
  data_len = get_local_var_size_by_name(lexic, "data");

  retc = alloc_tree_cell(0, NULL);
  retc->type = CONST_DATA;
  retc->size = sizeof(struct ip6_hdr) + data_len;

  pkt = (struct ip6_hdr*)emalloc(sizeof(struct ip6_hdr) + data_len);
  retc->x.str_val = (char*)pkt;

  version = get_int_local_var_by_name(lexic, "ip6_v", 6);
  tc = get_int_local_var_by_name(lexic, "ip6_tc", 0);
  fl = get_int_local_var_by_name(lexic, "ip6_fl", 0);

  pkt->ip6_ctlun.ip6_un1.ip6_un1_flow = version | tc | fl;

  pkt->ip6_plen = FIX(data_len);     /* No extension headers ?*/
  pkt->ip6_nxt = get_int_local_var_by_name(lexic, "ip6_p", 0);
  pkt->ip6_hlim = get_int_local_var_by_name(lexic, "ip6_hlim", 64);

  /* source */
  s = get_str_local_var_by_name(lexic, "ip6_src");
  if (s != NULL)
    inet_pton(AF_INET6, s, &pkt->ip6_src);
  /* else this host address? */

  s = get_str_local_var_by_name(lexic, "ip6_dst");
  if (s != NULL)
    inet_pton(AF_INET6, s, &pkt->ip6_dst);
  else
    pkt->ip6_dst = *dst_addr;

  if( data != NULL )
  {
    bcopy(data, retc->x.str_val + sizeof(struct ip6_hdr), data_len);
  }

  /*
     There is no checksum for ipv6. Only upper layer
     calculates a checksum using pseudoheader
   */
  return retc;
}

/**
 * @brief Obtain IPv6 header element.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return tree_cell with the IP header element.
 */
tree_cell * get_ipv6_element(lex_ctxt * lexic)
{
  tree_cell * retc;
  struct ip6_hdr * ip6 = (struct ip6_hdr*)get_str_local_var_by_name(lexic, "ipv6");
  char * element = get_str_local_var_by_name(lexic, "element");
  char   ret_ascii[INET6_ADDRSTRLEN];
  int    ret_int = 0;
  int    flag = 0;

  if( ip6 == NULL )
  {
    nasl_perror(lexic, "get_ipv6_element : no valid 'ip' argument!\n");
    return NULL;
  }

  if( element == NULL)
  {
    nasl_perror(lexic, "get_ipv6_element : no valid 'element' argument!\n");
    return NULL;
  }

  if(!strcmp(element, "ip6_v"))    { ret_int = (ip6->ip6_flow & 0x3ffff); flag ++;    }
  else if(!strcmp(element, "ip6_tc"))  { ret_int = (ip6->ip6_flow >> 20 ) & 0xff; flag ++;  }
  else if(!strcmp(element, "ip6_fl"))  { ret_int = ip6->ip6_flow >> 28; flag ++;  }
  else if(!strcmp(element, "ip6_plen"))  { ret_int = (ip6->ip6_plen); flag ++;  }
  else if(!strcmp(element, "ip6_nxt"))  { ret_int = (ip6->ip6_nxt); flag ++;  }
  else if(!strcmp(element, "ip6_hlim"))  { ret_int = (ip6->ip6_hlim); flag ++;  }

  if(flag != 0)
  {
    retc = alloc_tree_cell(0, NULL);
    retc->type = CONST_INT;
    retc->x.i_val = ret_int;
    return retc;
  }

  if(!strcmp(element, "ip6_src"))
  {
    inet_ntop(AF_INET6, &ip6->ip6_src,ret_ascii,sizeof(ret_ascii));
    flag ++;
  }
  else if(!strcmp(element, "ip6_dst"))
  {
    inet_ntop(AF_INET6, &ip6->ip6_dst,ret_ascii,sizeof(ret_ascii));
    flag ++;
  }

  if( flag == 0) {
    printf("%s : unknown element\n", element);
    return NULL;
  }

  retc = alloc_tree_cell(0, NULL);
  retc->type = CONST_DATA;
  retc->size = strlen(ret_ascii);
  retc->x.str_val = estrdup(ret_ascii);

  return retc;
}

/**
 * @brief Set IPv6 header element.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return tree_cell with the forged IP packet.
 */
tree_cell * set_ipv6_elements(lex_ctxt * lexic)
{
  struct ip6_hdr * o_pkt = (struct ip6_hdr*)get_str_local_var_by_name(lexic, "ip6");
  int size = get_var_size_by_name(lexic, "ip6");
  tree_cell * retc = alloc_tree_cell(0, NULL);
  struct ip6_hdr * pkt;
  char * s;
  int ver;
  int tc;
  int fl;

  if(o_pkt == NULL)
  {
    nasl_perror(lexic, "set_ip_elements: missing <ip> field\n");
    return NULL;
  }

  pkt = (struct ip6_hdr*)emalloc(size);
  bcopy(o_pkt, pkt, size);

  ver  = get_int_local_var_by_name(lexic, "ip6_v",  (pkt->ip6_flow & 0x3ffff));
  tc = get_int_local_var_by_name(lexic, "ip6_tc", (pkt->ip6_flow >> 20) & 0xff);
  fl = get_int_local_var_by_name(lexic, "ip6_fl", pkt->ip6_flow >> 28);

  pkt->ip6_plen = get_int_local_var_by_name(lexic, "ip6_plen", pkt->ip6_plen);
  pkt->ip6_nxt = get_int_local_var_by_name(lexic, "ip6_nxt", pkt->ip6_nxt);
  pkt->ip6_hlim = get_int_local_var_by_name(lexic, "ip6_hlim", pkt->ip6_hlim);

  s = get_str_local_var_by_name(lexic, "ip6_src");
  if (s != NULL)
    inet_pton(AF_INET6,s, &pkt->ip6_src);

  retc->type = CONST_DATA;
  retc->size = size;
  retc->x.str_val = (char*)pkt;

  return retc;
}

/**
 * @brief Print IPv6 Header.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return Print and returns FAKE_CELL.
 */
tree_cell * dump_ipv6_packet(lex_ctxt * lexic)
{
  int i;
  char addr[INET6_ADDRSTRLEN];

  for(i=0;;i++)
  {
    struct ip6_hdr * ip6 = (struct ip6_hdr*)get_str_var_by_num(lexic, i);

    if(ip6 == NULL)
      break;
    else
    {
      printf("------\n");
      printf("\tip6_v  : %d\n", ip6->ip6_flow >> 28);
      printf("\tip6_tc: %d\n", (ip6->ip6_flow >> 20) & 0xff);
      printf("\tip6_fl: %d\n", (ip6->ip6_flow ) & 0x3ffff);
      printf("\tip6_plen: %d\n", UNFIX(ip6->ip6_plen));
      printf("\tip6_nxt : %d\n", ntohs(ip6->ip6_nxt));
      printf("\tip6_hlim : %d\n", ntohs(ip6->ip6_hlim));
      switch(ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt)
      {
        case IPPROTO_TCP : printf("\tip6_nxt  : IPPROTO_TCP (%d)\n", ip6->ip6_nxt);
                           break;
        case IPPROTO_UDP : printf("\tip6_nxt  : IPPROTO_UDP (%d)\n", ip6->ip6_nxt);
                           break;
        case IPPROTO_ICMP: printf("\tip6_nxt  : IPPROTO_ICMP (%d)\n", ip6->ip6_nxt);
                           break;
        default :
                           printf("\tip6_nxt  : %d\n", ip6->ip6_nxt);
                           break;
      }
      printf("\tip6_src: %s\n", inet_ntop(AF_INET6, &ip6->ip6_src, addr, sizeof(addr)));
      printf("\tip6_dst: %s\n", inet_ntop(AF_INET6, &ip6->ip6_dst, addr, sizeof(addr)));
      printf("\n");
    }
  }

  return FAKE_CELL;
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


/**
 * @brief Forge TCP packet.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return tree_cell with the forged TCP packet containing IPv6 header.
 */
tree_cell*  forge_tcp_v6_packet(lex_ctxt* lexic)
{
  tree_cell *retc;
  char *data;
  int len;
  u_char *pkt;
  struct ip6_hdr *ip6, *tcp_packet;
  struct tcphdr *tcp;
  int ipsz;

  ip6 = (struct ip6_hdr*)get_str_local_var_by_name(lexic, "ip6");
  if (ip6 == NULL)
  {
    nasl_perror(lexic,"forge_tcp_packet : You must supply the 'ip' argument !");
    return NULL;
  }

  ipsz = get_local_var_size_by_name(lexic, "ip6");

  // Not considering IP Options.
  if(ipsz != 40)
    ipsz = 40;

  data = get_str_local_var_by_name(lexic, "data");
  len = data == NULL ? 0 : get_var_size_by_name(lexic, "data");

  retc = alloc_tree_cell(0, NULL);
  retc->type = CONST_DATA;
  tcp_packet = (struct ip6_hdr*) emalloc(ipsz + sizeof(struct tcphdr) + len);
  retc->x.str_val = (char*) tcp_packet;
  pkt = (u_char*) tcp_packet;

  bcopy(ip6, tcp_packet, ipsz );
  /* Adjust length in ipv6 header */
  tcp_packet->ip6_ctlun.ip6_un1.ip6_un1_plen = FIX(sizeof(struct tcphdr) + len);
  tcp = (struct tcphdr *)((char*)tcp_packet + 40);

  tcp->th_sport = ntohs(get_int_local_var_by_name(lexic, "th_sport", 0));
  tcp->th_dport = ntohs(get_int_local_var_by_name(lexic, "th_dport", 0));
  tcp->th_seq = htonl(get_int_local_var_by_name(lexic, "th_seq", rand()));
  tcp->th_ack = htonl(get_int_local_var_by_name(lexic, "th_ack", 0));
  tcp->th_x2 = get_int_local_var_by_name(lexic, "th_x2", 0);
  tcp->th_off = get_int_local_var_by_name(lexic, "th_off", 5);
  tcp->th_flags = get_int_local_var_by_name(lexic, "th_flags", 0);
  tcp->th_win = htons(get_int_local_var_by_name(lexic, "th_win", 0));
  tcp->th_sum = get_int_local_var_by_name(lexic, "th_sum", 0);
  tcp->th_urp = get_int_local_var_by_name(lexic, "th_urp", 0);

  if(data != NULL)
    bcopy(data, (char*)tcp + sizeof(struct tcphdr), len);

  if(!tcp->th_sum)
  {
    struct v6pseudohdr pseudoheader;
    char * tcpsumdata = emalloc(sizeof(struct v6pseudohdr) + (len % 2 ? len + 1 : len ) );

    bzero(&pseudoheader, 38+sizeof(struct tcphdr));
    memcpy(&pseudoheader.s6addr, &ip6->ip6_src, sizeof(struct in6_addr));
    memcpy(&pseudoheader.d6addr, &ip6->ip6_dst, sizeof(struct in6_addr));

    pseudoheader.protocol=IPPROTO_TCP;
    pseudoheader.length=htons(sizeof(struct tcphdr)+len);
    bcopy((char *) tcp,(char *) &pseudoheader.tcpheader,sizeof(struct tcphdr));
    /* fill tcpsumdata with data to checksum */
    bcopy((char *) &pseudoheader, tcpsumdata ,sizeof(struct v6pseudohdr));
    if( data != NULL ) bcopy((char *) data, tcpsumdata + sizeof(struct v6pseudohdr), len );
    tcp->th_sum = np_in_cksum((unsigned short *)tcpsumdata,38+sizeof(struct tcphdr) + len );
    efree(&tcpsumdata );
  }

  retc->size = ipsz + sizeof(struct tcphdr) + len;
  return retc;
}

/**
 * @brief Get TCP Header element.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return tree_cell with the forged IP packet.
 */
tree_cell * get_tcp_v6_element(lex_ctxt * lexic)
{
  u_char * packet = (u_char*)get_str_local_var_by_name(lexic, "tcp");
  struct ip6_hdr *ip6;
  int ipsz;
  struct tcphdr *tcp;
  char *element;
  int ret;
  tree_cell * retc;

  ipsz = get_local_var_size_by_name(lexic, "tcp");

  if(packet == NULL)
  {
    nasl_perror(lexic, "get_tcp_element : Error ! No valid 'tcp' argument !\n");
    return NULL;
  }

  ip6 = (struct ip6_hdr *) packet;

  /* valid ipv6 header check*/
  if(UNFIX(ip6->ip6_plen) > ipsz)
    return NULL;	/* Invalid packet */

  tcp = (struct tcphdr*)(packet + 40);

  element = get_str_local_var_by_name(lexic, "element");
  if(!element)
  {
    nasl_perror(lexic, "get_tcp_element : Error ! No valid 'element' argument !\n");
    return NULL;
  }

  if(!strcmp(element, "th_sport"))ret = ntohs(tcp->th_sport);
  else if(!strcmp(element, "th_dsport"))ret = ntohs(tcp->th_dport);
  else if(!strcmp(element, "th_seq"))ret = ntohl(tcp->th_seq);
  else if(!strcmp(element, "th_ack"))ret = ntohl(tcp->th_ack);
  else if(!strcmp(element, "th_x2"))ret = tcp->th_x2;
  else if(!strcmp(element, "th_off"))ret = tcp->th_off;
  else if(!strcmp(element, "th_flags"))ret = tcp->th_flags;
  else if(!strcmp(element, "th_win"))ret = ntohs(tcp->th_win);
  else if(!strcmp(element, "th_sum"))ret = tcp->th_sum;
  else if(!strcmp(element, "th_urp"))ret = tcp->th_urp;
  else if(!strcmp(element, "data")){
    retc = alloc_tree_cell(0, NULL);
    retc->type = CONST_DATA;
    retc->size = UNFIX(ip6->ip6_plen) - ntohl(tcp->th_off) * 4;
    retc->x.str_val = emalloc(retc->size);
    bcopy(tcp + ntohl(tcp->th_off) * 4, retc->x.str_val, retc->size);
    return retc;
  }
  else {
    nasl_perror(lexic, "Unknown tcp field %s\n", element);
    return NULL;
  }

  retc = alloc_tree_cell(0, NULL);
  retc->type = CONST_INT;
  retc->x.i_val = ret;
  return retc;
}

/**
 * @brief Set TCP Header element.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return tree_cell with the forged TCP packet and IPv6.
 */
tree_cell * set_tcp_v6_elements(lex_ctxt * lexic)
{
  char *pkt = get_str_local_var_by_name(lexic, "tcp");
  struct ip6_hdr *ip6 = (struct ip6_hdr*) pkt;
  int  pktsz = get_local_var_size_by_name(lexic, "tcp");
  struct tcphdr *tcp;
  tree_cell *retc;
  char *data = get_str_local_var_by_name(lexic, "data");
  int data_len = get_local_var_size_by_name(lexic, "data");
  char *npkt;

  if( pkt == NULL )
  {
    nasl_perror(lexic, "set_tcp_elements : Invalid value for the argument 'tcp'\n");
    return NULL;
  }

  tcp =  (struct tcphdr*)(pkt + 40);

  if(pktsz < UNFIX(ip6->ip6_plen))
    return NULL;

  if(data_len == 0)
  {
    data_len = UNFIX(ip6->ip6_plen) - (tcp->th_off * 4);
    data = (char*)((char*)tcp + tcp->th_off * 4);
  }

  npkt = emalloc(40 + tcp->th_off * 4 + data_len);
  bcopy(pkt, npkt, UNFIX(ip6->ip6_plen) + 40);

  ip6  = (struct ip6_hdr*)(npkt);
  tcp = (struct tcphdr*)(npkt + 40);

  tcp->th_sport = htons(get_int_local_var_by_name(lexic, "th_sport", ntohs(tcp->th_sport)));
  tcp->th_dport = htons(get_int_local_var_by_name(lexic, "th_dport", ntohs(tcp->th_dport)));
  tcp->th_seq   = htonl(get_int_local_var_by_name(lexic, "th_seq", ntohl(tcp->th_seq)));
  tcp->th_ack   = htonl(get_int_local_var_by_name(lexic, "th_ack", ntohl(tcp->th_ack)));
  tcp->th_x2    = get_int_local_var_by_name(lexic, "th_x2", tcp->th_x2);
  tcp->th_off   = get_int_local_var_by_name(lexic, "th_off", tcp->th_off);
  tcp->th_flags = get_int_local_var_by_name(lexic, "th_flags", tcp->th_flags);
  tcp->th_win   = htons(get_int_local_var_by_name(lexic, "th_win", ntohs(tcp->th_win)));
  tcp->th_sum   = get_int_local_var_by_name(lexic, "th_sum", 0);
  tcp->th_urp   = get_int_local_var_by_name(lexic, "th_urp", tcp->th_urp);

  bcopy(data, (char*)tcp + tcp->th_off * 4, data_len);

  if(get_int_local_var_by_name(lexic, "update_ip_len", 1) != 0)
  {
    ip6->ip6_plen = tcp->th_off * 4 + data_len;
  }

  if(tcp->th_sum == 0)
  {
    struct v6pseudohdr pseudoheader;
    char * tcpsumdata = emalloc(sizeof(struct v6pseudohdr) + (data_len % 2 ? data_len + 1 : data_len));

    bzero(&pseudoheader, 38 + sizeof(struct tcphdr));
    memcpy(&pseudoheader.s6addr, &ip6->ip6_src, sizeof(struct in6_addr));
    memcpy(&pseudoheader.d6addr, &ip6->ip6_dst, sizeof(struct in6_addr));

    pseudoheader.protocol = IPPROTO_TCP;
    pseudoheader.length = htons(sizeof(struct tcphdr)+data_len);
    bcopy((char *) tcp,(char *) &pseudoheader.tcpheader,sizeof(struct tcphdr));
    /* fill tcpsumdata with data to checksum */
    bcopy((char *) &pseudoheader, tcpsumdata ,sizeof(struct v6pseudohdr));
    if( data != NULL ) bcopy((char *) data, tcpsumdata + sizeof(struct v6pseudohdr), data_len );
    tcp->th_sum = np_in_cksum((unsigned short *)tcpsumdata,38+sizeof(struct tcphdr) + data_len );
    efree(&tcpsumdata );
  }

  retc = alloc_tree_cell(0, NULL);
  retc->type = CONST_DATA;
  retc->size = 40 + (tcp->th_off * 4) + data_len;
  retc->x.str_val = npkt;
  return retc;
}

/**
 * @brief Print TCP/IPv6 packet.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return Print and return FAKE_CELL.
 */
tree_cell * dump_tcp_v6_packet(lex_ctxt * lexic)
{
  int i = 0;
  u_char * pkt;

  while((pkt = (u_char*)get_str_var_by_num(lexic, i++)) != NULL)
  {
    int a = 0;
    struct ip6_hdr * ip6 = (struct ip6_hdr*)pkt;
    struct tcphdr * tcp = (struct tcphdr *)(pkt + 40);
    int j;
    int limit;
    char * c;

    limit = get_var_size_by_num(lexic, i - 1);

    printf("------\n");
    printf("\tth_sport : %d\n", ntohs(tcp->th_sport));
    printf("\tth_dport : %d\n", ntohs(tcp->th_dport));
    printf("\tth_seq   : %u\n", (unsigned int)ntohl(tcp->th_seq));
    printf("\tth_ack   : %u\n", (unsigned int)ntohl(tcp->th_ack));
    printf("\tth_x2    : %d\n", tcp->th_x2);
    printf("\tth_off   : %d\n",tcp->th_off);
    printf("\tth_flags : ");
    if(tcp->th_flags & TH_FIN){printf("TH_FIN");a++;}
    if(tcp->th_flags & TH_SYN){if(a)printf("|");printf("TH_SYN");a++;}
    if(tcp->th_flags & TH_RST){if(a)printf("|");printf("TH_RST");a++;}
    if(tcp->th_flags & TH_PUSH){if(a)printf("|");printf("TH_PUSH");a++;}
    if(tcp->th_flags & TH_ACK){if(a)printf("|");printf("TH_ACK");a++;}
    if(tcp->th_flags & TH_URG){if(a)printf("|");printf("TH_URG");a++;}
    if(!a)printf("0");
    else printf(" (%d)", tcp->th_flags);
    printf("\n");
    printf("\tth_win   : %d\n", ntohs(tcp->th_win));
    printf("\tth_sum   : 0x%x\n", tcp->th_sum);
    printf("\tth_urp   : %d\n", tcp->th_urp);
    printf("\tData     : ");
    c = (char*)((char*)tcp+sizeof(struct tcphdr));
    if(UNFIX(ip6->ip6_plen)>(sizeof(struct ip6_hdr)+sizeof(struct tcphdr)))
      for(j=0;j<UNFIX(ip6->ip6_plen)-sizeof(struct tcphdr) && j < limit;j++)
        printf("%c", isprint(c[j])?c[j]:'.');
    printf("\n");
    printf("\n");
  }
  return NULL;
}

/**
 * @brief Performs TCP Connect to test if host is alive.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return tree_cell > 0 if host is alive, 0 otherwise.
 */
/*---------------------------------------------------------------------------*/
tree_cell * nasl_tcp_v6_ping(lex_ctxt * lexic)
{
  int port;
  u_char packet[sizeof(struct ip6_hdr) + sizeof(struct tcphdr)];
  int soc;
  struct ip6_hdr * ip = (struct ip6_hdr *)packet;
  struct tcphdr * tcp = (struct tcphdr *)(packet + sizeof(struct ip6_hdr));
  struct arglist *  script_infos = lexic->script_infos;
  struct in6_addr * dst = plug_get_host_ip(script_infos);
  struct in6_addr src;
  struct sockaddr_in6 soca;
  int flag = 0;
  int i = 0;
  int bpf;
  char filter[255];
  u_char * pk = NULL;
  tree_cell * retc;
  int opt = 1;
  struct timeval tv;
  int len;

#define rnd_tcp_port() (rand() % 65535 + 1024)
  int sports[]= { 0,     0,   0,  0,  0, 1023, 0,  0,    0,    0,  0,   0,    0,    0,    0,  0,   0,   0,    0,    0, 53,   0,    0,    20,   0,  25,   0,    0, 0};
  int ports[] = { 139, 135, 445, 80, 22, 515, 23, 21, 6000, 1025, 25, 111, 1028, 9100, 1029, 79, 497, 548, 5000, 1917, 53, 161, 9001, 65535, 443, 113, 993, 8080, 0};
  int num_ports = 0;
  char addr[INET6_ADDRSTRLEN];

  if( dst == NULL || (IN6_IS_ADDR_V4MAPPED(dst) == 1))
    return NULL;

  for(i=0;i < sizeof(sports) / sizeof(int); i ++)
  {
    if ( sports[i] == 0 ) sports[i] = rnd_tcp_port();
  }

  for(i=0; ports[i]; i++)num_ports ++;
  i = 0;

  soc = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
  if(soc < 0)
    return NULL;

#ifdef IP_HDRINCL
  if(setsockopt(soc, IPPROTO_IPV6, IP_HDRINCL, (char*)&opt, sizeof(opt)) < 0)
    perror("setsockopt");
#endif

  port = get_int_local_var_by_name(lexic, "port", -1);
  if(port == -1)
    port = plug_get_host_open_port(script_infos);
  if(v6_islocalhost(dst) > 0 )
    src = *dst;
  else
  {
    bzero(&src, sizeof(src));
    v6_routethrough(dst, &src);
  }

  snprintf(filter, sizeof(filter), "ip6 and src host %s", inet_ntop(AF_INET6, &src, addr, sizeof(addr))); /* RATS: ignore */
  bpf = init_v6_capture_device(*dst, src, filter);

  if(v6_islocalhost(dst) != 0)
    flag++;
  else
  {
    for(i = 0; i < sizeof(sports) / sizeof(int) && ! flag; i ++)
    {
      bzero(packet, sizeof(packet));
      /* IPv6 */
      int version = 0x60, tc = 0, fl = 0;
      ip->ip6_ctlun.ip6_un1.ip6_un1_flow = version | tc | fl;
      ip->ip6_nxt = 0x06,
      ip->ip6_hlim = 0x40,
      ip->ip6_src = src;
      ip->ip6_dst = *dst;

      /* TCP */
      tcp->th_sport = port ? htons(rnd_tcp_port()) : htons(sports[i%num_ports]);  tcp->th_flags = TH_SYN;
      tcp->th_dport = port ? htons(port):htons(ports[i%num_ports]);
      tcp->th_seq = rand();
      tcp->th_ack = 0;  tcp->th_x2  = 0;
      tcp->th_off = 5;  tcp->th_win = 2048;
      tcp->th_urp = 0;  tcp->th_sum = 0;

      bzero(&soca, sizeof(soca));
      soca.sin6_family = AF_INET6;
      soca.sin6_addr = ip->ip6_dst;
      sendto(soc, (const void*)ip, 40, 0, (struct sockaddr_in6 *)&soca, sizeof(struct sockaddr_in6));
      tv.tv_sec = 0;
      tv.tv_usec = 100000;
      if(bpf >= 0 && (pk = bpf_next_tv(bpf, &len, &tv)))flag++;
    }
  }

  retc = alloc_tree_cell(0, NULL);
  retc->type = CONST_INT;
  retc->x.i_val = flag;
  if(bpf >= 0)bpf_close(bpf);
  close(soc);
  return retc;
}

/**
 * @brief Send forged IPv6 Packet.
 *
 * @param[in] lexic Lexical context of NASL interpreter.
 *
 * @return tree_cell with the response to the sent packet.
 */
tree_cell* nasl_send_v6packet(lex_ctxt* lexic)
{
  tree_cell *retc = FAKE_CELL;
  int bpf = -1;
  u_char * answer;
  int answer_sz;
  struct sockaddr_in6 sockaddr;
  char *ip = NULL;
  struct ip6_hdr *sip = NULL;
  int vi = 0, b = 0, len = 0;
  int soc;
  int use_pcap = get_int_local_var_by_name(lexic, "pcap_active", 1);
  int to = get_int_local_var_by_name(lexic, "pcap_timeout", 5);
  char *filter = get_str_local_var_by_name(lexic, "pcap_filter");
  int dfl_len = get_int_local_var_by_name(lexic, "length", -1);
  struct arglist   *script_infos = lexic->script_infos;
  struct in6_addr *dstip = plug_get_host_ip(script_infos);
  int offset = 1;
  char name[INET6_ADDRSTRLEN];

  if( dstip == NULL || (IN6_IS_ADDR_V4MAPPED(dstip) == 1 ))
    return NULL;
  soc = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
  if(soc < 0)
    return NULL;

#ifdef IP_HDRINCL
  if(setsockopt(soc, IPPROTO_IPV6, IP_HDRINCL, (char*)&offset, sizeof(offset)) < 0)
    perror("setsockopt");
#endif
  while ((ip = get_str_var_by_num(lexic, vi)) != NULL)
  {
    int sz = get_var_size_by_num(lexic, vi);
    vi ++;

    if ( sz < sizeof(struct ip6_hdr) )
    {
      nasl_perror(lexic, "send_packet(): packet is too short!\n");
      continue;
    }

    sip = (struct ip6_hdr *)ip;
    if( use_pcap != 0 && bpf < 0)
      bpf = init_v6_capture_device(sip->ip6_dst, sip->ip6_src, filter);

    bzero(&sockaddr, sizeof(struct sockaddr_in6));
    sockaddr.sin6_family = AF_INET6;
    sockaddr.sin6_addr = sip->ip6_dst;
    if (dstip != NULL && !IN6_ARE_ADDR_EQUAL(&sockaddr.sin6_addr, dstip))
    {
      char   txt1[64], txt2[64];
      strncpy(txt1, inet_ntop(AF_INET6, &sockaddr.sin6_addr, name, INET6_ADDRSTRLEN), sizeof(txt1));
      txt1[sizeof(txt1)-1] = '\0';
      strncpy(txt2, inet_ntop(AF_INET6, dstip, name, INET6_ADDRSTRLEN), sizeof(txt2));
      txt2[sizeof(txt2)-1] = '\0';
      nasl_perror(lexic, "send_packet: malicious or buggy script is trying to send packet to %s instead of designated target %s\n", txt1, txt2);
      if(bpf >= 0)bpf_close(bpf);
      close(soc);
      return NULL;
    }

    if(dfl_len > 0 && dfl_len < sz)
      len = dfl_len;
    else
      len = sz;

    b = sendto(soc, (u_char*)ip, len, 0, (struct sockaddr_in6 *)&sockaddr, sizeof(struct sockaddr_in6));
    /* if(b < 0) perror("sendto "); */
    if(b >= 0 && use_pcap != 0 && bpf >= 0)
    {
      if(v6_islocalhost(&sip->ip6_dst))
      {
        answer = (u_char*) capture_next_v6_packet(bpf, to, &answer_sz);
        while(answer != NULL && (!memcmp(answer, (char*)ip, sizeof(struct ip6_hdr))))
        {
          efree(&answer);
          answer = (u_char*)capture_next_v6_packet( bpf, to, &answer_sz);
        }
      }
      else{
        answer = (u_char*)capture_next_v6_packet(bpf, to, &answer_sz);
      }
      if(answer)
      {
        retc = alloc_tree_cell(0, NULL);
        retc->type = CONST_DATA;
        retc->x.str_val = (char*)answer;
        retc->size = answer_sz;
        break;
      }
    }
  }
  if(bpf >= 0)bpf_close(bpf);
  close(soc);
  return retc;
}
