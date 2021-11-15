/* Copyright (C) 2009-2021 Greenbone Networks GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
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

/**
 * @file
 * @brief PID-file management.
 */

#include "pidfile.h"

#include <errno.h>       /* for errno */
#include <glib.h>        /* for g_free, gchar */
#include <glib/gstdio.h> /* for g_unlink, g_fopen */
#include <stdio.h>       /* for fclose, FILE */
#include <stdlib.h>      /* for atoi */
#include <string.h>      /* for strerror */
#include <unistd.h>      /* for getpid */

/**
 * @brief GLib log domain.
 */
#undef G_LOG_DOMAIN
#define G_LOG_DOMAIN "base pidfile"

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
  FILE *pidfile = g_fopen (pid_file_path, "w");

  if (pidfile == NULL)
    {
      g_critical ("%s: failed to open pidfile: %s\n", __func__,
                  strerror (errno));
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
