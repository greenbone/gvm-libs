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
 * Random generator helper functions
 */ 

#define EXPORTING
#include <includes.h>

#include <stdio.h>
#include <stdlib.h>


/*
 * If the libc does not provide [ls]rand48, we use [s]rand() instead.
 *
 * While rand() is weak in comparison of lrand48, this is not a big
 * issue, as we want moderately random values in our code (meaning
 * that we don't use any of these functions for crypto-related operations)
 *
 */

ExtFunc void
nessus_init_random()
{
  int	fd;			/* Note: we cannot keep this FD open */
  long	x;			/* Do not need to initialise this variable! */
  struct timeval tv;

  if ((fd = open("/dev/urandom", O_RDONLY)) >= 0)
    {
      if (read(fd, &x, sizeof(x)) <= 0)
	perror("/dev/urandom");
      if (close(fd) < 0)
	perror("close");
    }
  else
    {
      if (errno != ENOENT)
	perror("/dev/urandom");
#ifdef EGD_PATH
      if ((fd = open(EGD_PATH, O_RDWR)) >= 0)
	{
	  char	s[sizeof(int) + 1];
	  s[0] = 1; s[1] = sizeof(int);
	  (void) write(fd, s, 2);
	  if (read(fd, s, sizeof(int) + 1) > sizeof(int))
	    x = *(int*) (s+1);
	  close(s);
	}
#endif
    }

  gettimeofday(&tv, NULL);
  x += tv.tv_sec * 3 + tv.tv_usec + getpid() * 7 + getppid();
  srand48(x);
}

#ifndef HAVE_LRAND48

ExtFunc
long lrand48()
{
 return rand();
}

ExtFunc
void srand48(long seed)
{ 
 srand(seed);
}
#endif
