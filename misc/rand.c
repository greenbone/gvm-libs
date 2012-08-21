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
 * Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Random generator helper functions
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <glib.h>


/**
 * @file
 * Random generator helper functions.
 */

void
openvas_init_random ()
{
  FILE *fp;
  long x = 0;


  if ((fp = fopen ("/dev/urandom", "r")) != NULL)
    {
      if (fread (&x, sizeof (x), 1, fp) != 1)
        g_warning ("%s: failed to read from /dev/urandom", __FUNCTION__);
      if (fclose (fp) != 0)
        g_warning ("%s: failed to close /dev/urandom", __FUNCTION__);
    }
  x += time (NULL) + getpid () + getppid ();
  srand48 (x);
}
