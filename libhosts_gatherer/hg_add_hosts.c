/* Hostloop2 -- the Hostloop Library, version 2.0
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
#include "hg_utils.h"
#include "hg_filter.h"
#include "hg_add_hosts.h"
#include "hg_subnet.h"
/*
 * Add a host of the form
 *
 * 'hostname' or 'xx.xx.xx.xx' or 'hostname/netmask' 
 * or 'xx.xx.xx.xx/netmask'
 * or '[xx|xx-xx].[xx|xx-xx].[xx|xx-xx].[xx|xx-xx]' (by Alex Butcher, Articon-Integralis AG)
 *
 */

#define OCTETRANGE "%3d%*1[-]%3d"
#define OCTET "%3d"
#define DOT "%*1[.]"
#define COMP "%7[0-9-]"  
#define REMINDER "%s"

static int
real_ip(char * s)
{
 int i;
 int n = 0;
 for(i=0;s[i];i++)
 {
  if(s[i] == '.') n ++;
 }
 
 if(n == 3) 
  return 1;
 else 
  return 0;
}

static int
range(data, s, e)
 char * data;
 int * s;
 int * e;
{
 int convs;
 int first, last;
 
 convs=sscanf(data, OCTETRANGE, &first, &last);
 if (convs != 2)
 {
  /* it didn't work out, so we try converting it as
     an OCTET (xxx) */
  convs=sscanf(data, OCTET, &first);
  if (convs != 1)
  {
   /* that didn't work out either, so it's not a range */
   return (-1);
  }
  else
  {
   /* we'll use these as loop ranges later */
   last = first;
  }
 }
 
 if((first < 0) || (first > 255) ||
    (last < 0 ) || (last  > 255))
    	return (-1);
	

 
 if(first > last)
 {
  /* swap the two vars */
  first ^= last;
  last  ^= first;
  first ^= last;
 }
 
 if(s)*s = first;
 if(e)*e = last;
 return 0;
}
 
static int netmask_to_cidr_netmask(struct in_addr nm)
{
 int ret = 32;
 
 nm.s_addr = ntohl(nm.s_addr);
 while(!(nm.s_addr & 1))
 {
  ret--;
  nm.s_addr >>=1;
 }
 return ret;
}

int
hg_add_host(globals, hostname)
 struct hg_globals * globals;
 char * hostname;
{
 int cidr_netmask = 32;
 char * t;
 char * q;
 char * copy;
 struct in_addr ip;
 struct in_addr nm;
 
 int o1first,o1last; /* octet range boundaries */
 int o2first,o2last;
 int o3first,o3last;
 int o4first,o4last;
 int o1,o2,o3,o4; /* octet loop counters */
 int convs; /* number of conversions made by sscanf */
 char rangehost[20]; /* used to store string representation of ip */
  	 	 	 	
 char comp1[8], comp2[8], comp3[8], comp4[8];
 char * reminder;
 int unquote = 0;
 
 *comp1 = *comp2 = *comp3 = *comp4 = '\0';
 
 t = strchr(hostname, '-');
 if(t != NULL)
 {
  struct in_addr ip;
  t[0] = '\0';
  if((inet_aton(hostname, &ip) == 0) || !real_ip(hostname))
  {
   t[0] = '-';
   goto next;
  }
  
  if(real_ip(hostname) && 
     real_ip(&(t[1])))
     {
      struct in_addr start, end;
     
      start = hg_resolv(hostname);
      end = hg_resolv(&(t[1]));
      
      if ( globals->flags & HG_DISTRIBUTE )
        {
         int jump;
         unsigned long diff;
         int i, j;
         
         diff = ntohl(end.s_addr) - ntohl(start.s_addr);
         if ( diff > 255 ) jump = 255;
         else if ( diff > 128 ) jump = 10;
         else jump = 1;
         
        
         
         for ( j = 0 ; j < jump ; j ++ )
         {
         for ( i = j ; i <= diff ; i += jump )
         {
          struct in_addr ia;
          ia.s_addr = htonl(ntohl(start.s_addr) + i);
          if ( ntohl(ia.s_addr) > ntohl(end.s_addr) )break;
         
          hg_add_host_with_options(globals, inet_ntoa(ia), ia, 1, 32, 1, &ia);
         }
        }
       }
      else
        hg_add_host_with_options(globals, inet_ntoa(start), start, 1, 32, 1, &end);
      return 0;
     }
   t[0] = '-';  
 }
 
next:

 reminder = malloc(strlen(hostname));
  	 	 	 					 
 if((hostname[0] == '\'') &&
    (hostname[strlen(hostname) - 1] == '\''))
 {
	 unquote++;
	 goto noranges;
 }
 
 for (t = hostname; *t != '\0'; t ++)
   if (! isdigit(*t) && *t != '-' && *t != '.')
     break;

 if (*t == '\0')
 convs=sscanf(hostname, COMP DOT COMP DOT COMP DOT COMP REMINDER,
 		comp1, comp2, comp3, comp4, reminder);
 else
   convs = 0;

 free(reminder);
 if (convs != 4) goto noranges; /* there are definitely no ranges here, so
                                   skip all this */
 
 /* try to convert components as OCTETRANGE (xxx-xxx) */
 if(range(comp1, &o1first, &o1last) ||
    range(comp2, &o2first, &o2last) ||
    range(comp3, &o3first, &o3last) ||
    range(comp4, &o4first, &o4last))
    	goto noranges;
	
 
 /* generate and add the range */
 for(o1=o1first; o1<=o1last; o1++)
 {
  for(o2=o2first; o2<=o2last; o2++)
  {
   for(o3=o3first; o3<=o3last; o3++)
   {
    for(o4=o4first; o4<=o4last; o4++)
    {
     snprintf(rangehost,17,"%d.%d.%d.%d",o1,o2,o3,o4);
     ip = hg_resolv(rangehost);
     if(ip.s_addr != INADDR_NONE)
     {
     	hg_add_host_with_options(globals, rangehost, ip, 0, 32,0,NULL);
     }
    }
   }
  }
 }
 return 0;
 
noranges:
 if(unquote)
 {
	 copy = malloc(strlen(hostname) - 1);
	 strncpy(copy, &(hostname[1]), strlen(&(hostname[1])) - 1);
 }
 else
 {
 copy = malloc(strlen(hostname)+1);
 strncpy(copy, hostname, strlen(hostname)+1);
 }

 hostname = copy;

 t = strchr(hostname, '/');
 if(t){
  t[0] = '\0';
  if((atoi(t+1) > 32) &&
     inet_aton(t+1, &nm))
  {
   cidr_netmask = netmask_to_cidr_netmask(nm);
  }
  else cidr_netmask = atoi(t+1);
  if((cidr_netmask < 1) || (cidr_netmask > 32))cidr_netmask = 32;
 }
 ip.s_addr = INADDR_NONE;
 q = strchr (hostname, '[');

 if (q != NULL)
 {
  t = strchr (q, ']');

  if (t != NULL)
  {
   t[0] = '\0';
   ip = hg_resolv (&q [1]);
   q[0] = '\0';
  }
 }
 if (ip.s_addr == INADDR_NONE)
 {
  ip = hg_resolv (hostname);
 }
 if(ip.s_addr != INADDR_NONE)
 	{
	if(cidr_netmask == 32)
	{
 	hg_add_host_with_options(globals, hostname, ip, 0, cidr_netmask,0,NULL);
 	}
	else
	{
	 struct in_addr first = cidr_get_first_ip(ip, cidr_netmask);
	 struct in_addr last = cidr_get_last_ip(ip, cidr_netmask);
	 
	 if( (globals->flags & HG_DISTRIBUTE) != 0 && cidr_netmask <= 29 )
	 {
	  struct in_addr c_end;
  	  struct in_addr c_start;
	  int addition;
          
          if ( cidr_netmask <= 21 ) addition = 8;
          else if ( cidr_netmask <= 24 ) addition = 5;
          else addition = 2;
          
	  c_start = first;
  	  c_end   = cidr_get_last_ip(c_start, cidr_netmask + addition);
  	 
  	  for(;;)
	  {
	   int dobreak = 0;
	   
	  
	   if(c_end.s_addr == last.s_addr) dobreak++;
    	   hg_get_name_from_ip(c_start, hostname, sizeof(hostname));
	
           hg_add_host_with_options(globals, strdup(hostname), 
				  c_start, 1, 32, 1,
				  &c_end);	
   	   c_start.s_addr  = htonl(ntohl(c_end.s_addr) + 2);
   	   c_end = cidr_get_last_ip(c_start, cidr_netmask + addition);	
	   c_start.s_addr  = htonl(ntohl(c_start.s_addr) - 1);
	
	  if(dobreak) break;			  
  	 } 
	}
	else hg_add_host_with_options(globals, hostname, first, 1,32,1,&last);
       }
      }
      else {
      	free(copy);
	return -1;
	}
 free(copy);
 return 0;
}
 
 
/*
 * Add hosts of the form :
 *
 * host1/nm,host2/nm,xxx.xxx.xxx.xxx/xxx, ....
 *
 */
int
hg_add_comma_delimited_hosts(globals, limit)
 struct hg_globals * globals;
 int limit;
{
 char * p, *v;
 int n = 0;
 
 p = globals->marker;
 while(p)
 {
   int len;
   if(limit > 0 && n > limit) /* Don't resolve more than 256 host names in a row */
   {
   globals->marker = p;
   return 0;
   } 
  
  while((*p == ' ')&&(p!='\0'))
  	p++;
  
  v = strchr(p+1, ',');
  if( v == NULL )
  	v = strchr(p+1, ';');
  
  if( v != NULL )
  	v[0] = '\0';
	
	
  len = strlen(p);
  while(p[len-1]==' '){
  	p[len-1]='\0';
	len --;
	}
  if(hg_add_host(globals, p) <  0)
  {
   if ( v != NULL )
	globals->marker = v + 1;
   else
	globals->marker = NULL; 
   return -1;
  }
  n ++;
  if(v != NULL)
  	p = v+1;
  else 
  	p = NULL;
 }
 
 globals->marker = NULL;
 return 0;
}

void
hg_add_host_with_options(globals, hostname, ip, alive, netmask, use_max, ip_max)
 struct hg_globals * globals;
 char *  hostname;
 struct in_addr ip;
 int alive;
 int netmask;
 int use_max;
 struct in_addr * ip_max;
{
 char * c_hostname;
 struct hg_host * host;
 int i;

  c_hostname = strdup(hostname);
  for(i=0;i<strlen(hostname);i++)c_hostname[i]=tolower(c_hostname[i]);
  host = globals->host_list;
  while(host->next)host = host->next;
  host->next = malloc(sizeof(struct hg_host));
  bzero(host->next, sizeof(struct hg_host));
 
  host->hostname = c_hostname;
  host->domain = hostname ? hg_name_to_domain(c_hostname):"";
  host->cidr_netmask = netmask;
  if(netmask != 32)printf("Error ! Bad netmask\n");
  host->tested = 0;
  host->alive = alive;
  host->addr = ip;
  host->use_max = use_max?1:0;
  if(ip_max){
  	host->max.s_addr = ip_max->s_addr;
	host->min = cidr_get_first_ip(ip, netmask);
	if(ntohl(host->max.s_addr) < ntohl(host->min.s_addr))
	 {
	 fprintf(stderr, "hg_add_host: error - ip_max < ip_min !\n");
	 host->max.s_addr = host->min.s_addr;
	 }
	}
}
 
void hg_add_domain(globals, domain)
 struct hg_globals * globals;
 char * domain;
{
 struct hg_host * list = globals->tested;
 int len;
 
 while(list && list->next)list = list->next;
 list->next = malloc(sizeof(struct hg_host));
 bzero(list->next, sizeof(struct hg_host));
 len = strlen(domain);
 list->domain = malloc(len + 1);
 strncpy(list->domain, domain, len + 1);
}

void hg_add_subnet(globals, ip, netmask)
 struct hg_globals * globals;
 struct in_addr ip;
 int netmask;
{
 struct hg_host * list = globals->tested; 
 while(list && list->next)list = list->next;
 list->next = malloc(sizeof(struct hg_host));
 bzero(list->next, sizeof(struct hg_host));
 list->addr = ip;
 list->cidr_netmask = netmask;
}
 
