/* Nessuslib -- the Nessus Library
 * Copyright (C) 1998 Renaud Deraison
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
 * Hostname resolver.
 */

#include <string.h>
#include <netdb.h>

#include "resolve.h"

#ifndef INADDR_NONE
#define INADDR_NONE 0xffffffff
#endif


/**
 * @return 0 on success, -1 on failure.
 */
int
host2ip (char * name, struct in_addr * ip)
{
	struct hostent * ent;

	ent = gethostbyname(name);
	if(!ent)
		return -1;
	else if(ip) memcpy(ip, ent->h_addr, ent->h_length);
	return 0; /* success */
}


int nn_resolve(const char *hostname, struct in6_addr *in6addr)
{
  struct addrinfo hints;
  struct addrinfo *ai;
  int    retval;

  *in6addr = in6addr_any;
  /* first check whether it is a numeric host*/
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET6;
  hints.ai_flags = AI_V4MAPPED | AI_ALL;

  retval = getaddrinfo(hostname, NULL, &hints, &ai);
  if(!retval)
  {
    if(ai->ai_family == AF_INET)
    {
      in6addr->s6_addr32[0] = 0;
      in6addr->s6_addr32[1] = 0;
      in6addr->s6_addr32[2] = htonl(0xffff);
      memcpy(&in6addr->s6_addr32[3], &((struct sockaddr_in *)ai->ai_addr)->sin_addr, sizeof(struct in_addr));
    }
    else
    {
      memcpy(in6addr, &((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr, sizeof(struct in6_addr));
    }

    freeaddrinfo(ai);
    return 0;
  }
  return -1;
}
