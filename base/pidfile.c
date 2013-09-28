/* openvas-libraries/base
 * $Id$
 * Description: PID-file management.
 *
 * Authors:
 * Jan-Oliver Wagner <jan-oliver.wagner@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2009 Greenbone Networks GmbH
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

/**
 * @file pidfile.c
 * @brief PID-file management.
 */

#include <glib.h>
#include <glib/gstdio.h>        /* for g_fopen */

#include <stdio.h>              /* for FILE */
#include <stdlib.h>
#include <string.h>             /* for strerror */
#include <errno.h>              /* for errno */
#include <unistd.h>             /* for getpid */

#include "pidfile.h"

/**
 * @brief GLib log domain.
 */
#undef G_LOG_DOMAIN
#define G_LOG_DOMAIN "base pidfile"

/**
 * @brief Create a PID-file.
 *
 * A standard PID file will be created for the
 * given daemon name.
 *
 * @param[in]  daemon_name The name of the daemon (e.g. "openvasmd")
 *
 * @return 0 for success, anything else indicates an error.
 */
int
pidfile_create (gchar * daemon_name)
{
  gchar *name_pid = g_strconcat (daemon_name, ".pid", NULL);
  gchar *pidfile_name = g_build_filename (OPENVAS_PID_DIR, name_pid, NULL);
  FILE *pidfile = g_fopen (pidfile_name, "w");

  g_free (name_pid);

  if (pidfile == NULL)
    {
      g_critical ("%s: failed to open pidfile: %s\n", __FUNCTION__,
                  strerror (errno));
      return 1;
    }
  else
    {
      g_fprintf (pidfile, "%d\n", getpid ());
      fclose (pidfile);
      g_free (pidfile_name);
    }
  return 0;
}

/**
 * @brief Remove PID file.
 *
 * @param[in]  daemon_name The name of the daemon (e.g. "openvasmd")
 */
void
pidfile_remove (gchar * daemon_name)
{
  gchar *name_pid = g_strconcat (daemon_name, ".pid", NULL);
  gchar *pidfile_name = g_build_filename (OPENVAS_PID_DIR, name_pid, NULL);
  gchar *pidfile_contents;

  g_free (name_pid);

  if (g_file_get_contents (pidfile_name, &pidfile_contents, NULL, NULL))
    {
      int pid = atoi (pidfile_contents);

      if (pid == getpid ())
        {
          g_unlink (pidfile_name);
        }
      g_free (pidfile_contents);
    }

  g_free (pidfile_name);
}
