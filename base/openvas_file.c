/* openvas-libraries/base
 * $Id$
 * Description: File utilities.
 *
 * Authors:
 * Matthew Mundell <matthew.mundell@greenbone.net>
 * Michael Wiegand <michael.wiegand@greenbone.net
 * Felix Wolfsteller <felix.wolfsteller@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2009,2010 Greenbone Networks GmbH
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
 * @file openvas_file.c
 * @brief File utilities.
 */

#include "openvas_file.h"

#include <errno.h>
#include <sys/stat.h>

#include <glib/gstdio.h>        /* for g_remove */

/**
 * @brief Checks whether a file is a directory or not.
 *
 * This is a replacement for the g_file_test functionality which is reported
 * to be unreliable under certain circumstances, for example if this
 * application and glib are compiled with a different libc.
 *
 * Symbolic links are not followed.
 *
 * @param[in]  name  Name of file or directory.
 *
 * @return 1 if parameter is directory, 0 if it is not, -1 if it does not
 *         exist or could not be accessed.
 */
int
openvas_file_check_is_dir (const char *name)
{
  struct stat sb;

  if (g_lstat (name, &sb))
    {
      g_warning ("g_lstat(%s) failed - %s\n", name, g_strerror (errno));
      return -1;
    }

  return (S_ISDIR (sb.st_mode));
}

/**
 * @brief Recursively removes files and directories.
 *
 * This function will recursively call itself to delete a path and any
 * contents of this path.
 *
 * @param[in]  pathname  The name of the file to be deleted from the filesystem.
 *
 * @return 0 if the name was successfully deleted, -1 if an error occurred.
 *         Please note that errno is currently not guaranteed to contain the correct
 *         value if -1 is returned.
 */
int
openvas_file_remove_recurse (const gchar * pathname)
{
  /** @todo Set errno when we return -1 to maintain remove() compatibility. */
  if (openvas_file_check_is_dir (pathname) == 1)
    {
      GError *error = NULL;
      GDir *directory = g_dir_open (pathname, 0, &error);

      if (directory == NULL)
        {
          g_warning ("g_dir_open(%s) failed - %s\n", pathname, error->message);
          g_error_free (error);
          return -1;
        }
      else
        {
          int ret = 0;
          const gchar *entry = NULL;

          while ((entry = g_dir_read_name (directory)) && (ret == 0))
            {
              gchar *entry_path = g_build_filename (pathname, entry, NULL);
              ret = openvas_file_remove_recurse (entry_path);
              g_free (entry_path);
              if (ret != 0)
                {
                  g_warning ("Failed to remove %s from %s!", entry, pathname);
                  g_dir_close (directory);
                  return ret;
                }
            }
          g_dir_close (directory);
        }
    }

  return g_remove (pathname);
}

/**
 * @brief Copies a source file into a destination file.
 *
 * If the destination file does exist already, it will be overwritten.
 *
 * @param[in]  source_file  Source file name.
 * @param[in]  dest_file    Destination file name.
 *
 * @return TRUE if successful, FALSE otherwise.
 */
gboolean
openvas_file_copy (const gchar *source_file, const gchar *dest_file)
{
  gboolean rc;
  GFile *sfile, *dfile;
  GError *error;

#if !GLIB_CHECK_VERSION(2, 35, 0)
  g_type_init ();
#endif
  sfile = g_file_new_for_path (source_file);
  dfile = g_file_new_for_path (dest_file);
  error = NULL;

  rc = g_file_copy (sfile, dfile, G_FILE_COPY_OVERWRITE, NULL, NULL, NULL,
                    &error);
  if (!rc)
    {
      g_warning ("%s: g_file_copy(%s, %s) failed - %s\n", __FUNCTION__,
                 source_file, dest_file, error->message);
      g_error_free (error);
    }

  g_object_unref (sfile);
  g_object_unref (dfile);
  return rc;
}

/**
 * @brief Moves a source file into a destination file.
 *
 * If the destination file does exist already, it will be overwritten.
 *
 * @param[in]  source_file  Source file name.
 * @param[in]  dest_file    Destination file name.
 *
 * @return TRUE if successful, FALSE otherwise.
 */
gboolean
openvas_file_move (const gchar *source_file, const gchar *dest_file)
{
  gboolean rc;
  GFile *sfile, *dfile;
  GError *error;

#if !GLIB_CHECK_VERSION(2, 35, 0)
  g_type_init ();
#endif
  sfile = g_file_new_for_path (source_file);
  dfile = g_file_new_for_path (dest_file);
  error = NULL;

  rc = g_file_move (sfile, dfile, G_FILE_COPY_OVERWRITE, NULL, NULL, NULL,
                    &error);
  if (!rc)
    {
      g_warning ("%s: g_file_move(%s, %s) failed - %s\n", __FUNCTION__,
                 source_file, dest_file, error->message);
      g_error_free (error);
    }

  g_object_unref (sfile);
  g_object_unref (dfile);
  return rc;
}

