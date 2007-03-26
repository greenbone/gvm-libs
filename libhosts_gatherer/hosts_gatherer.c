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
#include "hg_add_hosts.h" 
#include "hg_subnet.h"
#include "hg_utils.h"
#include "hg_filter.h"
#include "hg_dns_axfr.h"


int hg_test_syntax(char * hostname, int flags)
{
 struct hg_globals * globals = malloc(sizeof(struct hg_globals));
 int err;
 
 hostname = strdup(hostname);
 bzero(globals, sizeof(struct hg_globals));
 globals->flags = flags;
 globals->host_list = malloc(sizeof(struct hg_host));
 bzero(globals->host_list, sizeof(struct hg_host));
 
 globals->tested = malloc(sizeof(struct hg_host));
 bzero(globals->tested, sizeof(struct hg_host));
 
 globals->input = strdup(hostname);
 globals->marker = globals->input;
 
 globals->distribute = 0;

 
 err = hg_add_comma_delimited_hosts(globals, 0);
 free(hostname);
 hg_cleanup(globals);
 return err;
}



struct hg_globals * 
hg_init(hostname, flags)
 char * hostname;
 int flags;
{
 struct hg_globals * globals = malloc(sizeof(struct hg_globals));

 hostname = strdup(hostname);
 bzero(globals, sizeof(struct hg_globals));
 globals->flags = flags;
 globals->host_list = malloc(sizeof(struct hg_host));
 bzero(globals->host_list, sizeof(struct hg_host));
 
 globals->tested = malloc(sizeof(struct hg_host));
 bzero(globals->tested, sizeof(struct hg_host));
 
 globals->input = strdup(hostname);
 globals->marker = globals->input;
 
 globals->distribute = 0;

 
 hg_add_comma_delimited_hosts(globals, 256);
 free(hostname);
 return(globals);
}


int hg_next_host(globals, ip, hostname, sz)
 struct hg_globals * globals;
 struct in_addr *ip;
 char * hostname;
 int sz;
{
 struct hg_host * host;

 
 if(!globals) return -1;

#ifdef DEBUG_HIGH
 printf("Hosts list : \n");
 hg_dump_hosts(globals->host_list);
#endif

 host = globals->host_list;
 
 while(host->tested && host->next){
        struct hg_host * next = host->next;
        globals->host_list = next;
        hg_host_cleanup(host);
        host = next;
        }
     
 if( globals->flags & HG_DISTRIBUTE )
 {
  struct hg_host * first = host;
  unsigned int i;
  
  
  i = 0;
again:
  host = first;

  while (host != NULL && host->next != NULL )
  {
   if (  host->tested == 0 ){
	 if( globals->distribute == i ) break;
	 }
   i ++;
   host = host->next;
  }
  globals->distribute ++;
    
  if( host == NULL || host->next == NULL ) { 
  			if ( i == 0 ) return -1 ;
  			globals->distribute = 0 ; 
			i = 0; 
			goto again; 
			}
 }
 
 
 if( host != NULL && host->next == NULL )
 {
  if(globals->marker != NULL)
  	{
  	hg_add_comma_delimited_hosts(globals, 0);
	return hg_next_host(globals, ip, hostname, sz);
	}
  else return -1;
 }
				   
  if((globals->flags & HG_DNS_AXFR) && hg_filter_domain(globals, host->domain) == 0 )
        {
     	hg_dns_axfr_add_hosts(globals, host->domain);
	}
	
  
  if(!host->use_max || (host->addr.s_addr == host->max.s_addr))host->tested = 1;
  host->alive = 1;
  
  if(ip)ip->s_addr = host->addr.s_addr;
   
   if(!host->use_max)
   {
   if((globals->flags & HG_REVLOOKUP))
     {
      if(!host->hostname ||
        (inet_addr(host->hostname) != INADDR_NONE)) 
	  return hg_get_name_from_ip(host->addr, hostname, sz);
         else
	  {
          strncpy(hostname, host->hostname, sz - 1);
  	  return 0;
	  }
     }
   else
    {
     if(host->hostname && (inet_addr(host->hostname) == INADDR_NONE))
       strncpy(hostname, host->hostname, sz - 1);
     else 
       strncpy(hostname, inet_ntoa(host->addr), sz - 1);
      return 0;
     }
   }
   else
   {
    if(globals->flags & HG_REVLOOKUP)
      hg_get_name_from_ip(host->addr, hostname, sz);
    else
      strncpy(hostname, inet_ntoa(host->addr), sz - 1);
    
    host->addr.s_addr = htonl(ntohl(host->addr.s_addr) + 1);
    return 0;
   }
}


void hg_cleanup(globals) 
struct hg_globals * globals;
{
 struct hg_host * hosts = globals->host_list;
 struct hg_host * tested = globals->tested;
 free(globals->input);
 free(globals);
 
 hg_hosts_cleanup(hosts);
 hg_hosts_cleanup(tested);
}
   				
