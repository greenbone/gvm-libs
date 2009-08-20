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

#include <includes.h>
#include "hosts_gatherer.h"

/**
 * @file
 * This simple program compiles when you link it against
 * the following shared libraries :
 *
 *	-lopenvashg
 *	-lpcap
 *	-lopenvas
 *
 * Its purpose is to demonstrate how to use the lib hosts_gatherer
 */

extern int optind;
int main(int argc, char * argv[])
{
 struct hg_globals * globals;
 char m[1024];
 int e;
 int i;
 int flags = 0;
 
  struct in_addr ip;
 while((i=getopt(argc, argv, "dpsnD"))!=-1) /* RATS: ignore */
  switch(i)
  {
  case 'd' : flags |= HG_DNS_AXFR;break;
  case 'p' : flags |= HG_PING;break;
  case 's' : flags |= HG_SUBNET;break;
  case 'n' : flags |= HG_REVLOOKUP;
  case 'D' : flags |= HG_DISTRIBUTE;
  }
 if(!argv[optind])
 { 
  printf("Usage : test -dps hostname/netmask\n-d : DNS axfr\n-p : ping hosts\n\
-s : whole network\n-D: distribute the load\n");
  exit(0);
 }
 if((flags & HG_PING)&&geteuid()){
 	printf("the ping flag will be ignored -- you are not root\n");
	}

 
 if(hg_test_syntax(argv[optind], flags) < 0 )
 {
  printf("BAD SYNTAX\n");
  exit(1);
 }
 globals = hg_init(argv[optind], flags);
 e  = hg_next_host(globals,&ip, m, sizeof(m));
 while(e >= 0)
 {
  printf("%s (%s)\n", m, inet_ntoa(ip));
  e = hg_next_host(globals,&ip, m, sizeof(m));
 }
 hg_cleanup(globals);

 return 0;
}
