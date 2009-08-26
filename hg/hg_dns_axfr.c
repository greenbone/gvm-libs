/* HostsGatherer
 *
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
 *
 */
 
#include <includes.h>
#include "hosts_gatherer.h"
#include "hg_filter.h"
#include "hg_utils.h"
#include "hg_add_hosts.h"
#include <arpa/inet.h>
#ifdef HAVE_NETINET_IN_H /* (debian) linux wants this - jh */
#include <netinet/in.h>
#endif
#ifdef USE_ARPA_NAMESER_COMPAT_H
#include <arpa/nameser_compat.h>
#else
#include <arpa/nameser.h>
#endif
#include <resolv.h>


#ifndef INT16SZ
#define INT16SZ 2
#endif

#ifndef INT32SZ
#define INT32SZ 4
#endif


#ifndef HFIXEDSZ
#define      HFIXEDSZ 12
#endif

/* The HG_GET16 macro and the hg_get16 function were copied from glibc 2.7
 * (include/arpa/nameser.h (NS_GET16) and resolv/ns_netint.c (ns_get16)) to
 *  avoid using private glibc functions.
 */

# define HG_GET16(s, cp)                \
  do {                                  \
    uint16_t *t_cp = (uint16_t *) (cp); \
    (s) = ntohs (*t_cp);                \
    (cp) += NS_INT16SZ;                 \
} while (0)

typedef union {
	HEADER qb1;
	u_char qb2[PACKETSZ];
} querybuf;

u_int
hg_get16(const u_char *src)
{
	u_int dst;

	HG_GET16(dst, src);
	return (dst);
}

static u_char *
hg_dns_axfr_expand_name(cp, msg, name, namelen)
	u_char *cp, *msg;
	char *name;
        int namelen;
{
	int n;

  if ((n = dn_expand(msg, msg + 512, cp, name, namelen - 2)) < 0)
		return (NULL);
	if (name[0] == '\0') {
		name[0] = '.';
		name[1] = '\0';
	}
	return (cp + n);
}

static char *
hg_dns_axfr_add_host(globals, cp, msg)
	struct hg_globals * globals;
	u_char *cp, *msg;
{
 	int type;
	char name[MAXDNAME];

	if ((cp = (u_char *)hg_dns_axfr_expand_name(cp, msg, name, sizeof(name))) == NULL)
		return (NULL);			/* compression error */
		
	type = hg_get16(cp);
	cp += INT16SZ*3 + INT32SZ;
	if(type == T_A)
	{
	struct in_addr addr;
	bcopy(cp, &addr, sizeof(addr));
	hg_add_host_with_options(globals, name, addr, 0, 32, 0, NULL);
	}
	return(NULL);
}


/*
 * Asks to the nameserver the names of the
 * name servers that are taking care of
 * the domain we are interested in. Returns the
 * length of the answer
 */
static int
 hg_dns_get_nameservers(globals, domain, answer)
  struct hg_globals * globals;
  char 		    * domain;
  querybuf	    * answer;
{
 int msglen;
 querybuf buffer;
 
 msglen = res_mkquery(QUERY, domain, C_IN, T_NS, NULL, 0, NULL, buffer.qb2,
 		      sizeof(buffer));
 if(msglen < 0) return(-1);
 msglen = res_send(buffer.qb2, msglen, answer->qb2, sizeof(*answer));
 if(msglen < 0) return(-1);
 return(msglen);
}

/*
 * Decodes the nameserver reply and put
 * the list of nameservers into a struct
 */
static int
 hg_dns_read_ns_from_answer(domainname, answer, ns, msglen)
  char * domainname;
  querybuf answer;
  struct hg_host ** ns;
  int msglen;
{
 struct hg_host * host;
 int count;
 u_char * cp;
 
 count = ntohs(answer.qb1.ancount) + ntohs(answer.qb1.nscount) +
 	 ntohs(answer.qb1.arcount);
 if(!count||answer.qb1.rcode != NOERROR)return(-1);
 cp = (u_char *)answer.qb2 + 12; 
 if(ntohs(answer.qb1.qdcount) > 0)
      cp += dn_skipname(cp, answer.qb2 + msglen) + QFIXEDSZ;
  
 /*
  * Now adding the nameservers into our host list
  */
  host = malloc(sizeof(struct hg_host));
  bzero(host, sizeof(struct hg_host));
  while(count)
  {
   int type;
   int dlen;
   char domain[256];
   cp += dn_expand(answer.qb2, answer.qb2 + msglen, cp, domain,sizeof(domain));
   type = hg_get16(cp);
   cp += 2 * INT16SZ + INT32SZ;
   dlen = hg_get16(cp);
   cp += INT16SZ;
   if( type == T_NS) /* name server name */
   {
    char name[256];
    if(dn_expand(answer.qb2, answer.qb2 + msglen, cp, name, sizeof(name)) >= 0)
    {
     int ok = 1;
     struct hg_host * t = host;
     if(!strcasecmp(domain, domainname))
     {
      while((t && t->next)&& ok) /* avoid duplicates */
      {
       if(host && host->hostname && !strcasecmp(host->hostname, name))ok = 0;
       t = t->next;
      }	
     
     if(ok)
     {
      int len;
      t = host;
      while(t && t->next)t = t->next;
      t->next = malloc(sizeof(struct hg_host));
      bzero(t->next, sizeof(struct hg_host));
      len = strlen(name);
      t->hostname = malloc(len + 1);
      strncpy(t->hostname, name, len + 1);
     }
    }
   }
  }
  else if (type == T_A) /* name server address */
  {
   struct hg_host * t = host;
   while(t && t->next)
   {
    if(!strcmp(t->hostname, domain)){
     bcopy(cp, &t->addr, sizeof(t->addr));
     t = NULL;
    }
    else t = t->next;
   }
  }
 cp += dlen;
 count --;
 }
 *ns = host;
 return(0);
}
     
/*
 * Checks that we have the IP addresses
 * of all the NS in our list
 *
 */
static void
 hg_dns_fill_ns_addrs(ns)
  struct hg_host * ns;
{
 struct hg_host * t = ns;
 struct in6_addr in6addr;
 
 while(t && t->next)
 {
  hg_resolv(t->hostname, &in6addr, AF_INET);
  if(!t->addr.s_addr)t->addr.s_addr = in6addr.s6_addr32[3];
  t = t->next;
 }
}


static int
 hg_dns_axfr_decode(globals, answer, limit)
 struct hg_globals * globals;
 querybuf *answer;
 u_char * limit;
{
  HEADER * hp = (HEADER *)answer;
  u_char * cp;
  int qdcount, ancount, nscount, arcount;
  if(hp->rcode != NOERROR)return(-1);
  qdcount = ntohs(hp->qdcount);
  ancount = ntohs(hp->ancount);
  nscount = ntohs(hp->nscount);
  arcount = ntohs(hp->arcount);
  
  if(!(qdcount + ancount + nscount + arcount))return(-1);
  cp = (u_char *)answer + HFIXEDSZ;
  while(qdcount--)cp += dn_skipname(cp, limit) + QFIXEDSZ;
  hg_dns_axfr_add_host(globals, cp, answer);
  
 return(0);
}
 
static int
 hg_dns_axfr_query(globals, domain, ns, answer, limit)
struct hg_globals * globals;
char * domain;
struct hg_host * ns;
querybuf * answer;
u_char ** limit;
{
 int soc;
 int msglen;
 querybuf query;
 int len;
 int finished = 0;
 int num;
 u_char * cp, *nmp;
 struct sockaddr_in addr;
 char dname[2][255];
 int soacnt = 0;
 int error_code;

 msglen = res_mkquery(QUERY, domain, C_IN, T_AXFR, NULL, 0, NULL,
 	  	      query.qb2, sizeof(query));
		      
 if(msglen < 0)return(-1);
 bzero(&addr, sizeof(struct sockaddr_in));
 addr.sin_family = AF_INET;
 addr.sin_port   = htons(53);
 addr.sin_addr   = ns->addr;
 soc = socket(AF_INET, SOCK_STREAM, 0);
 if(soc < 0)return(-1);
 if(connect(soc, (struct sockaddr *)&addr, sizeof(addr))<0){
  close(soc);
  return(-1);
  }
 putshort(msglen,(u_char *)&len);
 num = send(soc, (char *)&len, INT16SZ, 0);
 num = send(soc, (char *)&query, msglen, 0);
 if(num < msglen){
  close(soc);
  return(-1);
 }
 
 while(!finished)
 {
 fd_set rd;
 struct timeval tv = {0, 5};
 
 cp = (u_char *)answer;
 FD_ZERO(&rd);
 FD_SET(soc, &rd);
 if(!select(soc+1, &rd, NULL, NULL, &tv))
 {
  close(soc);
  return -1;
 }
 if(recv(soc, (char*)&len, INT16SZ, 0)<0)
 {
  close(soc);
#ifdef DEBUG
   perror("recv in axfr ");
#endif
   return(-1);
  }
 len = ntohs(len);
 error_code = -1;
 if(len>0)
 {
  int num_read;
  int left;
  
  left = len;
  while(left > 0)
  {
   num_read = recv(soc, cp, left, 0);
   if(num_read < 0)
   {
#ifdef DEBUG
	perror("recv in axfr ");
#endif
	close(soc);
	return(-1);
   }
   left -= num_read;
   cp += num_read;
  }
 error_code = answer->qb1.rcode;
 hg_dns_axfr_decode(globals, answer, cp);
 cp = answer->qb2 + HFIXEDSZ;
 if(ntohs(answer->qb1.qdcount) > 0)
    cp+= dn_skipname(cp, answer->qb2 + len) + QFIXEDSZ;
 nmp = cp;
 cp += dn_skipname(cp, (u_char *)answer + len);
 if((hg_get16(cp) == T_SOA)){
  (void)dn_expand(answer->qb2, answer->qb2 + len, nmp,dname[soacnt], 256);
  if(soacnt){if(!strcmp(dname[0], dname[1]))finished = 1;}
  else soacnt++;
 }
}
else finished = 1;
}
 shutdown(soc, 2);
 close(soc);
 *limit = cp;
 return(error_code);
}



/*
 * Our "main" function regarding DNS AXFR
 */	    
void
 hg_dns_axfr_add_hosts(globals, domain)
  struct hg_globals * globals;
  char * domain;
{
 int msglen;
 querybuf answer;
 struct hg_host * ns = NULL;
 u_char * limit;
 if(!domain)return;
 hg_add_domain(globals, domain);
 res_init();
 bzero(&answer, sizeof(answer));
 msglen = hg_dns_get_nameservers(globals, domain, &answer);
 if(msglen < 0)return;
 if(hg_dns_read_ns_from_answer(domain, answer, &ns, msglen)<0)return;
 hg_dns_fill_ns_addrs(ns);
 
 bzero(&answer, sizeof(answer));
#ifdef DEBUG_HIGH
 hg_dump_hosts(ns);
#endif
 hg_dns_axfr_query(globals, domain, ns, &answer, &limit);
 hg_hosts_cleanup(ns);
}
