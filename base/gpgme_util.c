/* openvas-libraries/base
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
 * @file gpgme_util.c
 * @brief GPGME utilities.
 */

#include <assert.h>
#include <ctype.h>
#include <glib.h>
#include <stdlib.h>
#include <locale.h>             /* for LC_CTYPE  */
#include <unistd.h>             /* for F_OK */

#include "gpgme_util.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "base gpgme"

/**
 * @brief Log function with extra gpg-error style output
 *
 * If @ref err is not 0, the appropriate error string is appended to
 * the output.  It takes care to only add the error source string if
 * it makes sense.
 *
 * TODO: Make this a global function.  There is already a copy in the
 *       manager
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
 * @brief Return the name of the writable GnuPG home directory
 *
 * Returns the name of the GnuPG home directory to use when checking
 * GnuPG signatures.  The return value is the value of the environment
 * variable OPENVAS_GPGHOME if it is set.  Otherwise it is the
 * directory openvas/gnupg under the statedir that was set by
 * configure (usually $prefix/var/lib/openvas/gnupg).  The return
 * value must be released with g_free.
 *
 * @return Custom name of the GnuPG home directory for general use.
 */
static char *
determine_gpghome (void)
{
  char *envdir = getenv ("OPENVAS_GPGHOME");

  if (envdir)
    return g_strdup (envdir);
  else
    return g_build_filename (OPENVAS_STATE_DIR, "gnupg", NULL);
}

/**
 * @brief Returns a new gpgme context.
 *
 * Inits a gpgme context with the custom gpghome directory, protocol
 * version etc. Returns the context or NULL if an error occurred.
 * This function also does an gpgme initialization the first time it
 * is called.  It is advisable to call this function as early as
 * possible to notice a bad installation (e.g. an too old gpg version).
 *
 * @return The gpgme_ctx_t to the context or NULL if an error occurred.
 */
gpgme_ctx_t
openvas_init_gpgme_ctx (void)
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
      char *gpghome;
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

      gpghome = determine_gpghome ();
#ifndef NDEBUG
      g_message ("Setting GnuPG homedir to '%s'", gpghome);
#endif
      if (access (gpghome, F_OK))
        err = gpg_error_from_syserror ();
      else
        err = gpgme_set_engine_info (GPGME_PROTOCOL_OpenPGP, NULL, gpghome);
      g_free (gpghome);
      if (err)
        {
          log_gpgme (G_LOG_LEVEL_WARNING, err, "Setting GnuPG homedir failed");
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

/**
 * @brief Return the name of the sysconf GnuPG home directory
 *
 * Returns the name of the GnuPG home directory to use when checking
 * signatures.  It is the directory openvas/gnupg under the sysconfdir
 * that was set by configure (usually $prefix/etc).
 *
 * @return Static name of the Sysconf GnuPG home directory.
 */
static const char *
get_sysconf_gpghome (void)
{
  static char *name;

  if (!name)
    name = g_build_filename (OPENVAS_SYSCONF_DIR, "gnupg", NULL);

  return name;
}

/**
 * @brief Returns a new gpgme context using the sycconf directory.
 *
 * Inits a gpgme context with the systeconf gpghome directory,
 * protocol version etc. Returns the context or NULL if an error
 * occurred.  This function also does an gpgme initialization the
 * first time it is called.  It is advisable to call this function (or
 * openvas_init_gpgme_ctx) as early as possible to notice a bad
 * installation (e.g. an too old gpg version).
 *
 * @return The gpgme_ctx_t to the context or NULL if an error occurred.
 */
gpgme_ctx_t
openvas_init_gpgme_sysconf_ctx (void)
{
  static int info_shown;
  gpg_error_t err;
  gpgme_ctx_t ctx;

  ctx = openvas_init_gpgme_ctx ();
  if (!ctx)
    return NULL;

  if (!info_shown)
    {
      info_shown = 1;
#ifndef NDEBUG
      g_message ("Setting GnuPG sysconf homedir to '%s'",
                 get_sysconf_gpghome());
#endif
    }
  if (access (get_sysconf_gpghome (), F_OK))
    err = gpg_error_from_syserror ();
  else
    err = gpgme_ctx_set_engine_info (ctx, GPGME_PROTOCOL_OpenPGP,
                                     NULL, get_sysconf_gpghome ());
  if (err)
    {
      log_gpgme (G_LOG_LEVEL_WARNING, err,
                 "Setting GnuPG sysconf homedir to '%s' failed",
                 get_sysconf_gpghome());
      gpgme_release (ctx);
      ctx = NULL;
    }

  return ctx;
}
