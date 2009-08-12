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
host2ip(name, ip)
	char * name;
	struct in_addr * ip;
{
	struct hostent * ent;

	ent = gethostbyname(name);
	if(!ent)
		return -1;
	else if(ip) memcpy(ip, ent->h_addr, ent->h_length);
	return 0; /* success */
}


struct in_addr 
nn_resolve(name)
	const char * name;
{
	struct in_addr ret;
	if(host2ip(name, &ret)  < 0)
	{
		ret.s_addr = INADDR_NONE;
	}
	return ret;
}
