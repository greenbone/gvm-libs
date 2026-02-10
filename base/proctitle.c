/* SPDX-FileCopyrightText: 2014-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * @brief Implementation of an API to set process title.
 */

#include "proctitle.h"

#include <glib.h> /* for g_free, g_malloc0, g_strdup */
#include <stdio.h>
#include <string.h> /* for strlen, strdup, bzero, strncpy */
#include <sys/param.h>
#include <sys/prctl.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "libgvm base"

/**
 * @brief Access to the executable's name.
 */
extern const char *__progname;
#ifndef __FreeBSD__
extern const char *__progname_full;
#endif
static char **old_argv;
static int old_argc;
extern char **environ;
void *current_environ = NULL;
static int max_prog_name = 0;

/**
 * @brief Initializes the process setting variables.
 *
 * @param[in]   argc    Argc argument from main.
 * @param[in]   argv    Argv argument from main.
 */
void
proctitle_init (int argc, char **argv)
{
  int i;
  char **envp = environ;
#ifndef __FreeBSD__
  char *new_progname, *new_progname_full;
#else
  char *new_progname;
#endif
  old_argc = argc;

  if (argv == NULL)
    return;
  // according to c99 argv is defined as when argc is set it follows program
  // parameter. Since we will override on set_proctitle we know that this
  // memory is modifiable.
  // Everything after that is unsafe and can lead to segmentation faults.
  // Therefore we iterate through argv and append strlen to gather the maximum
  // safe program name.
  for (i = 0; i < argc; i++)
    {
      max_prog_name += strlen (argv[i]) + 1;
    }
  i = 0;

  new_progname = strdup (__progname);
#ifndef __FreeBSD__
  new_progname_full = strdup (__progname_full);
#endif

  /* Move environ to new memory, to be able to reuse older one. */
  while (envp[i])
    i++;
  environ = g_malloc0 (sizeof (char *) * (i + 1));
  g_free (current_environ);
  current_environ = environ;
  for (i = 0; envp[i]; i++)
    environ[i] = g_strdup (envp[i]);
  environ[i] = NULL;

  old_argv = argv;
  /* Seems like these are in the moved environment, so reset them.  Idea from
   * proctitle.cpp in KDE libs.  */
  __progname = new_progname;
#ifndef __FreeBSD__
  __progname_full = new_progname_full;
#endif
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
  char *formatted;
  int tmp;

  if (old_argv == NULL)
    /* Called setproctitle before initproctitle ? */
    return;
  if (max_prog_name == 0)
    // there may no program name set
    return;
  // omit previous additional parameter

  formatted = g_strdup_vprintf (new_title, args);

  tmp = strlen (formatted);
  if (tmp >= max_prog_name)
    {
      formatted[max_prog_name] = '\0';
      tmp = max_prog_name;
    }

  // set display name
  memset (old_argv[0], 0, max_prog_name);
  memcpy (old_argv[0], formatted, tmp);
  g_free (formatted);
  if (old_argc > 1)
    old_argv[1] = NULL;
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
