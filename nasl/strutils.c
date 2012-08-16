/* Nessus Attack Scripting Language
 *
 * Copyright (C) 2002 - 2004 Tenable Network Security
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <ctype.h>              /* for tolower */
#include <string.h>             /* for bcopy */

#include "system.h"             /* for emalloc */

#include "strutils.h"

/**
 * @todo These functions are not necessarily nasl-specific and thus subject to
 *       be moved (e.g. to misc).
 */

char *
nasl_strndup (char *str, int length)
{
  char *ret = emalloc (length + 1);
  bcopy (str, ret, length);
  return ret;
}

/** @todo In parts replacable by g_pattern_match function (when not icase) */
int
str_match (const char *string, const char *pattern, int icase)
{
  while (*pattern != '\0')
    {
      if (*pattern == '?')
        {
          if (*string == '\0')
            return 0;
        }
      else if (*pattern == '*')
        {
          const char *p = string;
          do
            if (str_match (p, pattern + 1, icase))
              return 1;
          while (*p++ != '\0');
          return 0;
        }
      else if ((icase && (tolower (*pattern) != tolower (*string)))
               || (!icase && (*pattern != *string)))
        return 0;
      pattern++;
      string++;
    }
  return *string == '\0';
}



/**
 * @brief Slow replacement for memmem.
 */
void *
nasl_memmem (const void *haystack, size_t hl_len, const void *needle,
             size_t n_len)
{
  char *hs = (char *) haystack;
  char *nd = (char *) needle;
  int i;

  if (hl_len < n_len)
    return NULL;

  for (i = 0; i <= hl_len - n_len; i++)
    {
      if (hs[i] == nd[0])
        {
          int flag = 1;
          int j;
          for (j = 1; j < n_len; j++)
            if (hs[i + j] != nd[j])
              {
                flag = 0;
                break;
              }
          if (flag != 0)
            return (hs + i);
        }
    }
  return (NULL);
}
