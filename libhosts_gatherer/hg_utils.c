/* HostsGatherer
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
 
#include <includes.h>
#include "hosts_gatherer.h"

/*
 * 
 * Resolve an hostname
 *
 */
struct in_addr
hg_resolv(hostname)
 char * hostname;
{
 struct in_addr in;
 struct hostent *ent;
   
 if(inet_aton(hostname, &in) != 0)
	 return in;

 in.s_addr = INADDR_NONE;
 ent = gethostbyname(hostname);
 if (ent) memcpy(&(in.s_addr), (char*)(ent->h_addr), ent->h_length);
 return in;
}

/*
 * 
 * Get the FQDN from the IP
 *
 */
int
hg_get_name_from_ip(ip, hostname, sz)
 struct in_addr ip;
 char * hostname; 
 int sz;
{
 struct hostent * he = NULL;
 int i;

 he = gethostbyaddr((char *)&ip, sizeof(long), AF_INET);

 if( he != NULL )
  strncpy(hostname, he->h_name, sz - 1);
 else 
  strncpy(hostname, inet_ntoa(ip), sz - 1);
 
 hostname[sz - 1] = '\0';
 for ( i = 0 ; hostname[i] != '\0' ; i ++ )
 {
  if ( ! isalnum(hostname[i]) && 
         hostname[i] != '.' && 
         hostname[i] != '_' && 
         hostname[i] != '-' ) hostname[i] = '?';
 }
 return 0; /* We never fail */
}

/*
 * input : hostname (ie : www.if.arf.com)
 * returns: if.arf.com
 *
 * If the input is arf.com
 * returns : NULL
 *
 */
char * 
hg_name_to_domain(hostname)
 char * hostname;
{
  unsigned int i = -1, j;
  char * ret;
  int len;
  
  if(inet_addr(hostname)!=INADDR_NONE)return(NULL);
  while(hostname[++i]!='.' && i<strlen(hostname));
  if(hostname[i]!='.')return(NULL);
  j=i;
  while(hostname[++j]!='.' && j<strlen(hostname));
  if(hostname[j]!='.')return(NULL);
  len = strlen(hostname+i+1);
  ret = malloc(len+1);
  strncpy(ret, hostname+i+1, len+1);
  return(ret);
}
  
  
void
hg_host_cleanup(hosts)
 struct hg_host * hosts;
{
  if(hosts->hostname != NULL )free(hosts->hostname);
  if(hosts->domain != NULL )free(hosts->domain);
  free(hosts);
}

void 
hg_hosts_cleanup(hosts)
 struct hg_host * hosts;
{
  while ( hosts != NULL ) 
  {
   struct hg_host * next;
   next = hosts->next;
   hg_host_cleanup(hosts);
   hosts = next;
 }
}
 
