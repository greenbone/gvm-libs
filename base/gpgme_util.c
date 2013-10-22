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

#include "gpgme_util.h"

#undef G_LOG_DOMAIN
/**
 * @brief GLib log domain.
 */
#define G_LOG_DOMAIN "base gpgme"

/**
 * @brief Return the name of the GnuPG home directory
 *
 * Returns the name of the GnuPG home directory to use when checking
 * GnuPG signatures.  The return value is the value of the environment
 * variable OPENVAS_GPGHOME if it is set.  Otherwise it is the directory
 * openvas/gnupg under the sysconfdir that was set by configure (usually
 * $prefix/etc).  The return value must be released with g_free.
 *
 * @return Custom path of the GnuPG home directory.
 */
static char *
determine_gpghome (void)
{
  /** @todo Use glibs g_build_filename */
  char *default_dir = OPENVAS_SYSCONF_DIR "/gnupg";
  char *envdir = getenv ("OPENVAS_GPGHOME");

  return g_strdup (envdir ? envdir : default_dir);
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
      g_message ("Setting GnuPG homedir to '%s'", gpghome);
      err = gpgme_set_engine_info (GPGME_PROTOCOL_OpenPGP, NULL, gpghome);
      g_free (gpghome);
      if (err)
        {
          g_warning ("Setting GnuPG homedir failed: %s/%s",
                     gpgme_strsource (err), gpgme_strerror (err));

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
      g_message ("Using OpenPGP engine version '%s'",
                 info && info->version? info->version: "[?]");

      /* Everything is fine.  */
      initialized = 1;
    }

  /* Allocate the context.  */
  ctx = NULL;
  err = gpgme_new (&ctx);
  if (err)
    g_warning ("Creating GPGME context failed: %s/%s",
               gpgme_strsource (err), gpgme_strerror (err));

  return ctx;
}
