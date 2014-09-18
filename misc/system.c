/* OpenVAS
 * $Id$
 * Description: Memory management methods.
 *
 * Authors:
 * Renaud Deraison <deraison@nessus.org> (Original pre-fork development)
 *
 * Copyright:
 * Based on work Copyright (C) 1998 Renaud Deraison
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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/wait.h>
#include <time.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#include <arpa/inet.h>

#include "system_internal.h"
#include "openvas_logging.h"
#include <malloc.h>

/**
 * This method always returns the requested
 * memory size. If anything failed during allocating
 * it, the exit() routine is entered to stop the program.
 */
void *
emalloc (size)
     size_t size;
{
  void *ptr;
  const struct timespec delay = { 0, 5000000 }; /* 5000 mikroseconds = 5000000 nanoseconds */

  /* Just for our personal safety, we increase the size by one */
  if ((int) size < 0)
    {
      log_legacy_write ("[%d] Won't allocate a pointer of size %ld !",
                        getpid (), (long) size);
      exit (1);
    }

  size++;

  /* If no memory can be allocated, then wait a little.
   * It's very likely that another openvas scanner child will free
   * the size of memory we need. So we make 10 attempts,
   * and if nothing happens, then we exit. */
  ptr = malloc (size);
  if (!ptr)
    {
#ifndef _WIN32
      int i;
      for (i = 0; (i < 5) && ptr == NULL; i++)
        {
          waitpid (0, NULL, WNOHANG);
          nanosleep (&delay, NULL);
          ptr = malloc (size);
        }
#endif

      if (ptr == NULL)
        {
          log_legacy_write ("[%d] Could not allocate a pointer of size %ld !",
                            getpid (), (long) size);
          exit (1);
        }
    }
  bzero (ptr, size);
  return (ptr);
}

char *
estrdup (const char *str)
{
  char *buf;
  int len;

  if (!str)
    return NULL;
  len = strlen (str);           /* Flawfinder: ignore. XXX: there is not
                                   much to do about it(?) */

  buf = emalloc (len + 1);
  /* emalloc() is defined to always return sufficient
   * memory, thus return value is not tested. */
  memcpy (buf, str, len);       /* Flawfinder: ignore */
  buf[len] = '\0';
  return buf;
}


void
efree (void *ptr)
{
  char **p = ptr;
  if (p && *p)
    {
      free (*p);
      *p = NULL;
    }
}

void *
erealloc (void *ptr, size_t size)
{
  void *ret;

  if ((int) size < 0)
    {
      log_legacy_write ("Won't realloc() a pointer of size %ld !",
                        (long) size);
      exit (1);
    }

  ret = realloc (ptr, size);
  if (!ret)
    {
      log_legacy_write ("Could not realloc() a pointer of size %ld !",
                        (long) size);
      exit (1);
    }
  return ret;
}

