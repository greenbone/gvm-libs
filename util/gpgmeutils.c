/* gvm-libs/util
 * $Id$
 * Description: GPGME utilities.
 *
 * Authors:
 * Bernhard Herzog <bernhard.herzog@intevation.de>
 * Werner Koch <wk@gnupg.org>
 *
 * Copyright:
 * Copyright (C) 2009,2013 Greenbone Networks GmbH
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
 * @file gpgmeutils.c
 * @brief GPGME utilities.
 */

#include "gpgmeutils.h"

#include <errno.h>     /* for ENOENT, errno */
#include <gpg-error.h> /* for gpg_err_source, gpg_strerror, gpg_error_from_... */
#include <locale.h>    /* for setlocale, LC_MESSAGES, LC_CTYPE */
#include <sys/stat.h>  /* for mkdir */
#include <unistd.h>    /* for access, F_OK */

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "util gpgme"

/**
 * @brief Log function with extra gpg-error style output
 *
 * If \p err is not 0, the appropriate error string is appended to
 * the output.  It takes care to only add the error source string if
 * it makes sense.
 *
 * @todo: Make this a global function.  There is already a copy in the
 *        manager
 *
 * @param level  The GLib style log level
 * @param err    An gpg-error value or 0
 * @param fmt    The printf style format string, followed by its
 *                arguments.
 *
 */
static void
log_gpgme (GLogLevelFlags level, gpg_error_t err, const char *fmt, ...)
{
  va_list arg_ptr;
  char *msg;

  va_start (arg_ptr, fmt);
  msg = g_strdup_vprintf (fmt, arg_ptr);
  va_end (arg_ptr);
  if (err && gpg_err_source (err) != GPG_ERR_SOURCE_ANY
          && gpg_err_source (err))
    g_log (G_LOG_DOMAIN, level, "%s: %s <%s>",
           msg, gpg_strerror (err), gpg_strsource (err));
  else if (err)
    g_log (G_LOG_DOMAIN, level, "%s: %s",
           msg, gpg_strerror (err));
  else
    g_log (G_LOG_DOMAIN, level, "%s",
           msg);
  g_free (msg);
}

/**
 * @brief Returns a new gpgme context.
 *
 * Inits a gpgme context with the custom gpg directory, protocol
 * version etc. Returns the context or NULL if an error occurred.
 * This function also does an gpgme initialization the first time it
 * is called.
 *
 * @param dir  Directory to use for gpg
 *
 * @return The gpgme_ctx_t to the context or NULL if an error occurred.
 */
gpgme_ctx_t
gvm_init_gpgme_ctx_from_dir (const gchar *dir)
{
  static int initialized;
  gpgme_error_t err;
  gpgme_ctx_t ctx;

  /* Initialize GPGME the first time we are called.  This is a
     failsafe mode; it would be better to initialize GPGME early at
     process startup instead of this on-the-fly method; however in
     this non-threaded system; this is an easier way for a library.
     We allow to initialize until a valid gpgme or a gpg backend has
     been found.  */
  if (!initialized)
    {
      gpgme_engine_info_t info;

      if (!gpgme_check_version (NULL))
        {
          g_critical ("gpgme library could not be initialized.");
          return NULL;
        }
      gpgme_set_locale (NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));
#   ifdef LC_MESSAGES
      gpgme_set_locale (NULL, LC_MESSAGES, setlocale (LC_MESSAGES, NULL));
#   endif

#ifndef NDEBUG
      g_message ("Setting GnuPG dir to '%s'", dir);
#endif
      err = 0;
      if (access (dir, F_OK))
        {
          err = gpg_error_from_syserror ();

          if (errno == ENOENT)
            /* directory does not exists. try to create it */
            if (mkdir (dir, 0700) == 0)
              {
#ifndef NDEBUG
                g_message ("Created GnuPG dir '%s'", dir);
#endif
                err = 0;
              }
        }

      if (!err)
        err = gpgme_set_engine_info (GPGME_PROTOCOL_OpenPGP, NULL, dir);

      if (err)
        {
          log_gpgme (G_LOG_LEVEL_WARNING, err, "Setting GnuPG dir failed");
          return NULL;
        }

      /* Show the OpenPGP engine version.  */
      if (!gpgme_get_engine_info (&info))
        {
          while (info && info->protocol != GPGME_PROTOCOL_OpenPGP)
            info = info->next;
        }
      else
        info = NULL;
#ifndef NDEBUG
      g_message ("Using OpenPGP engine version '%s'",
                 info && info->version? info->version: "[?]");
#endif

      /* Everything is fine.  */
      initialized = 1;
    }

  /* Allocate the context.  */
  ctx = NULL;
  err = gpgme_new (&ctx);
  if (err)
    log_gpgme (G_LOG_LEVEL_WARNING, err, "Creating GPGME context failed");

  return ctx;
}
