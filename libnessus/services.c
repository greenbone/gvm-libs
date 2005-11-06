/* 
 * Copyright (C) 2002 Michel Arboi
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
 * TCP/IP service functions (getservent enhancement)
 */ 

#define EXPORTING
#include <includes.h>
#include <stdarg.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef MAP_FAILED
#define MAP_FAILED ((void*)-1)
#endif

#include "services.h"
#include "libnessus.h"

/* IMPORTANT ! Some options are defined in services.h */

static int
cmp_ns_svc(const void *v1,
	   const void *v2)
{
  const struct nessus_service * p1 = v1;
  const struct nessus_service * p2 = v2;
  
  if(v1 == NULL)
  	return 1;
  else if(v2 == NULL)
  	return -1;
  
  return p1->ns_port - p2->ns_port;
}

ExtFunc const char*
nessus_get_svc_name(int port, const char* proto)
{
  static struct nessus_service		*svc_db_ptr[2] = { NULL, NULL };
  static int				nb_svc[2];

  int			fd = -1, len, idx;
  struct stat		st;
  struct nessus_service	*pns, kns;
  struct servent	*svc;


  if (proto != NULL && strcmp(proto, "udp") == 0)
    idx = 1;
  else
    idx = 0;			/* default to TCP */

  if (svc_db_ptr[idx] == NULL)
    {
      if ((fd = open(idx ? NESSUS_SERVICES_UDP : NESSUS_SERVICES_TCP, O_RDONLY)) >= 0)
	{
	  if (fstat(fd, &st) < 0)
	    perror("fstat");
	  else
	    {
	      len = st.st_size;
	      nb_svc[idx] = len / sizeof(struct nessus_service);
	      if ((svc_db_ptr[idx] = mmap(NULL, len, PROT_READ, MAP_SHARED, fd, 0))== MAP_FAILED )
		{
		perror("mmap");
		svc_db_ptr[idx] = NULL;
		}
	    }
	}
    }

  if (svc_db_ptr[idx] == NULL)
    {
      if (fd > 0)
	close(fd);
    }
  else
    {
      kns.ns_port = port;
      pns = bsearch(&kns, svc_db_ptr[idx], nb_svc[idx], sizeof(kns), cmp_ns_svc);
      if (pns != NULL)
	return pns->ns_name;
#ifdef NESSUS_SVC_READS_ETC_SERVICES
      else
	return "unknown";
#endif
    }

  setservent(1); /* Rewinds /etc/services and keep the file open */
  svc = getservbyport(htons((unsigned short) port), proto);
  if (svc == NULL)
    return "unknown";
  else
    return svc->s_name;
}


ExtFunc unsigned short * get_tcp_svcs(int * num)
{
  struct nessus_service * ns = NULL;
  int len, num_svc;
  unsigned short * ret;
  int fd, i;
  struct stat st;

  if ((fd = open(NESSUS_SERVICES_TCP, O_RDONLY)) >= 0)
	{
	  if (fstat(fd, &st) < 0)
	    perror("fstat");
	  else
	    {
	      len = st.st_size;
	      num_svc = len / sizeof(struct nessus_service);
	      if ((ns = mmap(NULL, len, PROT_READ, MAP_SHARED, fd, 0))== MAP_FAILED ) {
		perror("mmap");
		ns = NULL;
	}
	    }
	}

  if (ns == NULL)
    {
	    struct servent  * ent;
	    int n = 0;
	    ret = emalloc(sizeof(unsigned short) * 65537);
	    endservent();
	    while ( (ent = getservent()) != NULL )
	    {
		    if(strcmp(ent->s_proto, "tcp") == 0 && ntohs(ent->s_port))
		    {
		    ret[n++] = ntohs(ent->s_port);
		    if(n >= 65537)break;
		    }
	    }
	    endservent();

	    if(num != NULL)
		    *num = n;

	    ret = erealloc(ret, sizeof(unsigned short) * (n+1)); 
	    ret[n] = 0;
	    return ret;
    }
  else
    {
	    ret = emalloc(sizeof(unsigned short) * (num_svc + 1));
	    for(i=0;i<num_svc;i++)
	    {
		    ret[i] = ns[i].ns_port;
 	    }
	    if(num != NULL)
		    *num = num_svc;

	    munmap(ns, len);
	    close(fd);
    }
 return ret;
}
