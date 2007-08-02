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
#include  "hg_subnet.h"

/*
 * Returns 1 if the host must be filtered,
 * that is, it must NOT be included in the 
 * list.
 * Returns 0 if it must be included in the list
 */
int 
hg_filter_host(globals, hostname, addr)
 struct hg_globals * globals;
 char * hostname;
 struct in_addr addr;
{
#if DISABLED
 struct hg_host * list = globals->host_list;
 
/* 
 
 int i;

 char * copy;
int len = strlen(hostname);
 copy = malloc(len+1);
 strncpy(copy, hostname, len);
 
  for(i=0;i<len;i++)copy[i]=tolower(copy[i]);

 */
 
 
 while(list->next)
 {
  if(list->use_max)
  {
   if((ntohl(addr.s_addr) >= ntohl(list->min.s_addr))&&
      (ntohl(addr.s_addr) <= ntohl(list->max.s_addr)))
      	{
	/* free(copy); */
	 return 1;
	}
  }
  else if((list->addr.s_addr == addr.s_addr))
    {
     /* free(copy); */
     return(1);
    }
  list = list->next;
 }
 /*free(copy);*/
#endif
 return(0);
}


/*
 * Returns 1 if the subnet must NOT
 * be tested
 */
int
hg_filter_subnet(globals, addr, netmask)
 struct hg_globals * globals;
 struct in_addr addr;
 int    netmask;
{
 struct hg_host * list = globals->tested;
 struct in_addr subnet;
 
 while(list && list->next)
 {
  struct in_addr subnet_2;
  if(list->addr.s_addr)
  {
   if(addr.s_addr != list->addr.s_addr)
   {
    int l_netmask = list->cidr_netmask < netmask ? list->cidr_netmask:netmask;
    subnet   = cidr_get_first_ip(addr, l_netmask);
    subnet_2 = cidr_get_first_ip(list->addr, l_netmask);
    if(subnet.s_addr == subnet_2.s_addr)return(1);
   }
  }
  list = list->next;
 }
 return(0);
}

/*
 * Returns 1 if the domain must NOT
 * be tested
 */
int
hg_filter_domain(globals, domain)
 struct hg_globals * globals;
 char * domain;
{
 struct hg_host * list = globals->tested;
 if(!domain)return(0);
 while(list && list->next)
 {
  if(list->domain)if(!strcmp(list->domain, domain))return(1);
  list = list->next;
 }
 return(0);
}

 
