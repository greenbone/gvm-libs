/* SPDX-FileCopyrightText: 2009-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * @brief PID-file management.
 */

#include "pidfile.h"

#include <errno.h>       /* for errno */
#include <glib.h>        /* for g_free, gchar */
#include <glib/gstdio.h> /* for g_unlink, g_fopen */
#include <libgen.h>      /* for libgen */
#include <stdio.h>       /* for fclose, FILE */
#include <stdlib.h>      /* for atoi */
#include <string.h>      /* for strerror */
#include <unistd.h>      /* for getpid */

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "libgvm base"

/**
 * @brief Create a PID-file.
 *
 * A standard PID file will be created for the
 * given path.
 *
 * @param[in]  pid_file_path The full path of the pid file. E.g.
 * "/tmp/service1.pid"
 *
 * @return 0 for success, anything else indicates an error.
 */
int
pidfile_create (gchar *pid_file_path)
{
  FILE *pidfile;
  gchar *copy, *dir;

  if (pid_file_path == NULL)
    return -1;

  copy = g_strdup (pid_file_path);
  dir = dirname (copy);

  /* Ensure directory exists. */

  if (g_mkdir_with_parents (dir, 0755)) /* "rwxr-xr-x" */
    {
      g_warning ("Failed to create PID file directory %s: %s", dir,
                 strerror (errno));
      g_free (copy);
      return 1;
    }
  g_free (copy);

  /* Create file. */

  pidfile = g_fopen (pid_file_path, "w");

  if (pidfile == NULL)
    {
      g_critical ("%s: failed to open pidfile %s: %s\n", __func__,
                  pid_file_path, strerror (errno));
      return 1;
    }
  else
    {
      g_fprintf (pidfile, "%d\n", getpid ());
      fclose (pidfile);
    }
  return 0;
}

/**
 * @brief Remove PID file.
 *
 * @param[in]  pid_file_path The full path of the pid file. E.g.
 * "/tmp/service1.pid"
 */
void
pidfile_remove (gchar *pid_file_path)
{
  gchar *pidfile_contents;

  if (g_file_get_contents (pid_file_path, &pidfile_contents, NULL, NULL))
    {
      int pid = atoi (pidfile_contents);

      if (pid == getpid ())
        {
          g_unlink (pid_file_path);
        }
      g_free (pidfile_contents);
    }
}
