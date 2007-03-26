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

#define EXPORTING
#include <includes.h>
#include "resolve.h"

#ifndef __u32
#define __u32 unsigned long
#endif

#ifndef INADDR_NONE
#define INADDR_NONE 0xffffffff
#endif



ExtFunc int
host2ip(name, ip)
	char * name;
	struct in_addr * ip;
{
#undef HAVE_GETHOSTBYNAME_R
#ifdef HAVE_GETHOSTBYNAME_R
        int Errno = 0;
        char * buf = emalloc(4096);
        struct hostent * res = NULL;
        struct hostent * t = NULL;	
	struct hostent * myhostent;
	
	myhostent = emalloc(sizeof(struct hostent));
#undef HAVE_SOLARIS_GETHOSTBYNAME_R
#ifdef HAVE_SOLARIS_GETHOSTBYNAME_R
        gethostbyname_r(name, myhostent, buf, 4096, &Errno);
	 if(Errno){
	  	efree(&myhostent);
		efree(&buf);
		return -1;
		}
#else
         gethostbyname_r(name, myhostent, buf, 4096, &res, &Errno);
         t = myhostent;
         myhostent = res;
#endif /* HAVE_SOLARIS_... */
	memcpy(ip, myhostent->h_addr, myhostent->h_length);
	efree(&myhostent);
	efree(&buf);
	return 0;
#else
	struct hostent * ent;

	ent = gethostbyname(name);
	if(!ent)
		return -1;
	else if(ip) memcpy(ip, ent->h_addr, ent->h_length);
	return 0; /* success */
#endif /* defined(GETHOSTBYNAME_R) */
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
