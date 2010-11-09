/*
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

#ifndef HOSTS_GATHERER_H__
#define HOSTS_GATHERER_H__

#include <netinet/in.h>         /* for in_addr */
#include "../misc/arglists.h"

#ifndef INADDR_NONE
#define INADDR_NONE 0xffffffff
#endif


#undef DEBUG
#undef DEBUG_HIGH


/* Flags for hg_hlobals */
#define HG_NFS                1
#define HG_DNS_AXFR           2
#define HG_SUBNET             4
#define HG_PING       	      8
#define HG_REVLOOKUP 	     16 /* Are we allowed to use the DNS ? */
#define HG_REVLOOKUP_AS_PING 32
#define HG_DISTRIBUTE	     64

struct hg_host
{
  char *hostname;       /**< Host name                    */
  char *domain;                 /**< Same pointer as hostname! Don't free it! */
  struct in_addr addr;  /**< Host IP   	        	  */
  struct in6_addr in6addr;      /* Host IP */
  int cidr_netmask;     /**< CIDR-format netmask          */
  /* When given a /N notation, we 
     put this as the upper limit
     of the network */
  struct in_addr min;
  struct in_addr max;
  struct in6_addr min6;
  struct in6_addr max6;
  int use_max:1;                /* use the field above ?        */
  unsigned int tested:1;
  unsigned int alive:1;
  struct hg_host *next;
};

struct hg_globals
{
  struct hg_host *host_list;           /**< List of tested hosts.       */
  struct hg_host *tested;              /**< Tested subnets and domains. */
  int flags;                           /**< Options.		        */
  char *input;                         /**< e.g. hostname               */
  char *marker;
  int counter;
  unsigned int distribute;
};

struct hg_globals *hg_init (char *, int);
int hg_next_host (struct hg_globals *, struct in6_addr *, char *, int);
void hg_cleanup (struct hg_globals *);

int hg_test_syntax (char *hostname, int flags);

#endif
