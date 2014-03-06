/* openvas-libraries/misc
 * $Id$
 * Description: Implementation of an API to set process title.
 *
 * Authors:
 * Hani Benhabiles <hani.benhabiles@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2014 Greenbone Networks GmbH
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * or, at your option, any later version as published by the Free
 * Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <glib.h>
#include <string.h>
#include <stdio.h>

#include "openvas_proctitle.h"

static int argv_len;
static char **old_argv;
extern char **environ;

/**
 * @brief Initializes the process setting variables.
 *
 * @param[in]   argc    Argc argument from main.
 * @param[in]   argv    Argv argument from main.
 */
void
proctitle_init (int argc, char **argv)
{
  int i = 0;
  char **envp = environ;

  if (argv == NULL)
    return;
  /* Move environ to new memory, to be able to reuse older one. */
  while (envp[i]) i++;
  environ = g_malloc0 (sizeof(char *) * (i + 1));
  for (i = 0; envp[i]; i++)
    environ[i] = g_strdup (envp[i]);
  environ[i] = NULL;

  old_argv = argv;
  if (i > 0)
    argv_len = envp[i-1] + strlen(envp[i-1]) - old_argv[0];
  else
    argv_len = old_argv[argc-1] + strlen(old_argv[argc-1]) - old_argv[0];
}

/**
 * @brief Sets the process' title.
 *
 * @param[in]   new_title   Format string for new process title.
 * @param[in]   args        Format string arguments variable list.
 */
static void
proctitle_set_args (const char *new_title, va_list args)
{
  int i;
  char *formatted;

  if (old_argv == NULL)
    /* Called setproctitle before initproctitle ? */
    return;

  formatted = g_strdup_vprintf (new_title, args);

  i = strlen (formatted);
  if (i > argv_len - 2)
    {
      i = argv_len - 2;
      formatted[i] = '\0';
    }
  bzero (old_argv[0], argv_len);
  strcpy (old_argv[0], formatted);
  old_argv[1] = NULL;
  g_free (formatted);
}

/**
 * @brief Sets the process' title.
 *
 * @param[in]   new_title   Format string for new process title.
 * @param[in]   ...         Arguments for format string.
 */
void
proctitle_set (const char *new_title, ...)
{
  va_list args;

  va_start (args, new_title);
  proctitle_set_args (new_title, args);
  va_end (args);
}
