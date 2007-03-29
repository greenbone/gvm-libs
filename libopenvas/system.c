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
 */

#define EXPORTING
#include <includes.h>
#include "system.h"
#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif








ExtFunc
void * emalloc(size)
 size_t size;
{
    void * ptr;
   
    /*
     * Just for our personal safety, we increase the 
     * size by one
     */
    if((int)size < 0)
    {
	 fprintf(stderr, "[%d] Won't allocate a pointer of size %ld !\n", getpid(), size);
	 exit(1);
    }

    size++;
   
   
    /*
     * If no memory can be allocated, then wait a little.
     * It's very likely that another nessusd child will free
     * the size of memory we need. So we make 10 attempts,
     * and if nothing happens, then we exit
     */
    ptr = malloc(size);
    if(!ptr){
    	int i;
	for(i=0; (i<5) && ptr == NULL ;i++)
	{
	 waitpid(0, NULL, WNOHANG);
 	 usleep(5000);
	 ptr = malloc(size);
	}
	
	if( ptr == NULL )
	{
	 fprintf(stderr, "[%d] Could not allocate a pointer of size %ld !\n", getpid(), size);
	 exit(1);
	}
      }
    bzero(ptr, size);
    return(ptr);
}

ExtFunc char * 
estrdup(str)
 const char * str; 
{
    char * buf;
    int len;
    
    if (!str) return NULL;
    len = strlen(str);

    buf = emalloc(len + 1);
    memcpy(buf, str, len);
    buf[len] = '\0';
    return buf;
}


ExtFunc void 
efree(ptr)
 void * ptr;
{
    char ** p = ptr;
    if(p && *p){
    	free(*p);
    	*p=NULL;
	}
}

ExtFunc void *
erealloc(ptr, size)
 void * ptr;
 size_t size;
{
  void * ret;

  if ( (int)size < 0 )
  {
   fprintf(stderr, "Won't realloc() a pointer of size %ld !\n", size);
   exit (1); 
  }

  ret = realloc(ptr, size);
  if(!ret)
  {
    fprintf(stderr, "Could not realloc() a pointer of size %ld !\n",
		size);
    exit (1);
  }
 return ret;
}



ExtFunc size_t 
estrlen(s,n)
 const char * s; 
 size_t n;
{
    size_t i;
    for(i = 0; (*(s+i) != '\0' && i < n); i++);
    return i;
}



#ifndef HAVE_INET_ATON
/*
 * Coming straight from Fyodor's Nmap
 */
int
inet_aton(cp, addr)
	register const char *cp;
	struct in_addr *addr;
{
	register unsigned int val;	/* changed from u_long --david */
	register int base, n;
	register char c;
	u_int parts[4];
	register u_int *pp = parts;

	c = *cp;
	for (;;) {
		/*
		 * Collect number up to ``.''.
		 * Values are specified as for C:
		 * 0x=hex, 0=octal, isdigit=decimal.
		 */
		if (!isdigit((int)c))
			return (0);
		val = 0; base = 10;
		if (c == '0') {
			c = *++cp;
			if (c == 'x' || c == 'X')
				base = 16, c = *++cp;
			else
				base = 8;
		}
		for (;;) {
			if (isascii((int)c) && isdigit((int)c)) {
				val = (val * base) + (c - '0');
				c = *++cp;
			} else if (base == 16 && isascii((int)c) && isxdigit((int)c)) {
				val = (val << 4) |
					(c + 10 - (islower((int)c) ? 'a' : 'A'));
				c = *++cp;
			} else
				break;
		}
		if (c == '.') {
			/*
			 * Internet format:
			 *	a.b.c.d
			 *	a.b.c	(with c treated as 16 bits)
			 *	a.b	(with b treated as 24 bits)
			 */
			if (pp >= parts + 3)
				return (0);
			*pp++ = val;
			c = *++cp;
		} else
			break;
	}
	/*
	 * Check for trailing characters.
	 */
	if (c != '\0' && (!isascii((int)c) || !isspace((int)c)))
		return (0);
	/*
	 * Concoct the address according to
	 * the number of parts specified.
	 */
	n = pp - parts + 1;
	switch (n) {

	case 0:
		return (0);		/* initial nondigit */

	case 1:				/* a -- 32 bits */
		break;

	case 2:				/* a.b -- 8.24 bits */
		if (val > 0xffffff)
			return (0);
		val |= parts[0] << 24;
		break;

	case 3:				/* a.b.c -- 8.8.16 bits */
		if (val > 0xffff)
			return (0);
		val |= (parts[0] << 24) | (parts[1] << 16);
		break;

	case 4:				/* a.b.c.d -- 8.8.8.8 bits */
		if (val > 0xff)
			return (0);
		val |= (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8);
		break;
	}
	if (addr)
		addr->s_addr = htonl(val);
	return (1);
}
#endif
