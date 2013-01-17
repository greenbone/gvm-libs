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

#include <sys/stat.h>

#include <glib/gstdio.h>        /* for g_remove */

/**
 * @brief Checks whether a file is a directory or not.
 *
 * This is a replacement for the g_file_test functionality which is reported
 * to be unreliable under certain circumstances, for example if this
 * application and glib are compiled with a different libc.
 *
 * @todo FIXME: handle symbolic links
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

  if (stat (name, &sb))
    {
      return -1;
    }
  else
    {
      return (S_ISDIR (sb.st_mode));
    }
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
 * @brief Reads in contents of file, and returns it, base64-encoded.
 *
 * This function does neither log any occuring error, nor does it make it
 * available, it will just return NULL.
 *
 * @param[in]  filename  File to read in.
 *
 * @return NULL if any error occurred, content of file, base64 encoded, freshly
 *        allocated, free with g_free.
 */
gchar *
openvas_file_read_b64_encode (const gchar * filename)
{
  gchar *file_contents = NULL;
  gchar *contents_b64 = NULL;
  GError *error = NULL;
  gsize file_size;

  g_file_get_contents (filename, &file_contents, &file_size, &error);
  if (error)
    {
      g_error_free (error);
      return NULL;
    }

  contents_b64 = g_base64_encode ((guchar *) file_contents, file_size);
  g_free (file_contents);
  return contents_b64;
}

/**
 * @brief Reads contents from a source file into a destination file.
 *
 * The source file is read into memory, so it is inefficient and likely to fail
 * for really big files.
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
  gchar *src_file_content = NULL;
  gsize src_file_size = 0;
  size_t bytes_written = 0;
  FILE *fd = NULL;
  GError *error;

  /* Read file content into memory. */

  error = NULL;
  if (g_file_get_contents (source_file,
                           &src_file_content,
                           &src_file_size,
                           &error)
      == FALSE)
    {
      if (error)
        {
          g_debug ("%s: failed to read %s: %s",
                   __FUNCTION__, source_file, error->message);
          g_error_free (error);
        }
      return FALSE;
    }

  /* Open destination file. */

  fd = fopen (dest_file, "wb");
  if (fd == NULL)
    {
      g_debug ("%s: failed to open %s", __FUNCTION__, dest_file);
      g_free (src_file_content);
      return FALSE;
    }

  /* Write content of src to dst and close it. */

  bytes_written = fwrite (src_file_content, 1, (size_t) src_file_size, fd);
  fclose (fd);

  if (bytes_written != (size_t) src_file_size)
    {
      g_debug ("%s: failed to write to %s"
               " (%zu/%" G_GSIZE_FORMAT ")",
               __FUNCTION__, dest_file, bytes_written, src_file_size);
      g_free (src_file_content);
      return FALSE;
    }
  g_free (src_file_content);

  return TRUE;
}

/**
 * @brief Reads contents from a source file into a destination file
 * @brief and unlinks the source file.
 *
 * The source file is read into memory, so it is inefficient and likely to fail
 * for really big files.
 *
 * If the destination file does exist already, it will be overwritten.
 *
 * @param[in]  source_file  Source file name.
 * @param[in]  dest_file    Destination file name.
 *
 * @return TRUE if successful, FALSE otherwise (displays error but does not
 *         clean up).
 */
gboolean
openvas_file_move (const gchar *source_file, const gchar *dest_file)
{
  /* Copy file (will displays errors itself). */

  if (openvas_file_copy (source_file, dest_file) == FALSE)
    return FALSE;

  /* Remove source file. */

  if (remove (source_file) != 0)
    {
      g_debug ("%s: failed to remove %s", __FUNCTION__, source_file);
      return FALSE;
    }

  return TRUE;
}

/**
 * @brief Recursively removes files and directories.
 *
 * This function will recursively call itself to delete a path and any
 * contents of this path.
 *
 * @param[in]  pathname  Name of file to be deleted from filesystem.
 *
 * @return 0 if the name was successfully deleted, -1 if an error occurred.
 */
int
openvas_file_rmdir_rf (const gchar * pathname)
{
  if (openvas_file_check_is_dir (pathname) == 1)
    {
      GError *error = NULL;
      GDir *directory = g_dir_open (pathname, 0, &error);

      if (directory == NULL)
        {
          if (error)
            {
              g_warning ("g_dir_open(%s) failed - %s\n", pathname, error->message);
              g_error_free (error);
            }
          return -1;
        }
      else
        {
          int ret = 0;
          const gchar *entry = NULL;

          while ((entry = g_dir_read_name (directory)) != NULL && (ret == 0))
            {
              gchar *entry_path = g_build_filename (pathname, entry, NULL);
              ret = openvas_file_rmdir_rf (entry_path);
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


