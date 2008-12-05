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

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>


/*
 * If the libc does not provide [ls]rand48, we use [s]rand() instead.
 *
 * While rand() is weak in comparison of lrand48, this is not a big
 * issue, as we want moderately random values in our code (meaning
 * that we don't use any of these functions for crypto-related operations)
 *
 */

void
nessus_init_random()
{
  FILE	*fp;
  long	x = 0;


  if ((fp = fopen("/dev/urandom", "r")) != NULL)
    {
      (void) fread(&x, sizeof(x), 1, fp);
      fclose(fp);
    }
  x += time(NULL) + getpid() + getppid();
  srand48(x); /* RATS: ignore */
}

#ifndef HAVE_LRAND48

long lrand48() /* RATS: ignore */
{
 return rand();
}

void srand48(long seed) /* RATS: ignore */
{ 
 srand(seed); /* RATS: ignore */
}
#endif
