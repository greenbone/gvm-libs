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
#include <locale.h>    /* for setlocale, LC_MESSAGES, LC_CTYPE */
#include <sys/stat.h>  /* for mkdir */
#include <unistd.h>    /* for access, F_OK */
#include <gpg-error.h> /* for gpg_err_source, gpg_strerror, gpg_error_from... */
#include <string.h>    /* for strlen */
#include <stdlib.h>    /* for mkdtemp */

#include "fileutils.h"

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
 * @param level  The GLib style log level
 * @param err    An gpg-error value or 0
 * @param fmt    The printf style format string, followed by its
 *                arguments.
 *
 */
void
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

/**
 * @brief Import a key or certificate given by a string.
 *
 * @param[in]  ctx      The GPGME context to import the key / certificate into.
 * @param[in]  key_str  Key or certificate string.
 * @param[in]  key_len  Length of key/certificate string or -1 to use strlen.
 * @param[in]  key_type The expected key type.
 * 
 * @return 0 success, 1 invalid key data, 2 unexpected key data, -1 error.
 */
int
gvm_gpg_import_from_string (gpgme_ctx_t ctx,
                            const char *key_str, ssize_t key_len,
                            gpgme_data_type_t key_type)
{
  gpgme_data_t key_data;
  gpgme_error_t err;

  gpgme_data_new_from_mem (&key_data, key_str,
                           (key_len >= 0 ? key_len 
                                         : (ssize_t) strlen(key_str)),
                           0);

  if (gpgme_data_identify (key_data, 0) != key_type)
    {
      int ret;
      gpgme_data_type_t given_key_type = gpgme_data_identify (key_data, 0);
      if (given_key_type == GPGME_DATA_TYPE_INVALID)
        {
          ret = 1;
          g_warning ("%s: key_str is invalid", __FUNCTION__);
        }
      else
        {
          ret = 2;
          g_warning ("%s: key_str is not the expected type: "
                     " expected: %d, got %d", __FUNCTION__,
                     key_type, given_key_type);
        }
      gpgme_data_release (key_data);
      return ret;
    }

  err = gpgme_op_import (ctx, key_data);
  gpgme_data_release (key_data);
  if (err)
    {
      g_warning ("%s: Import failed: %s",
                 __FUNCTION__, gpgme_strerror (err));
      return -1;
    }

  return 0;
}

/**
 * @brief Encrypt a stream for a PGP public key, writing to another stream.
 *
 * The output will use ASCII armor mode and no compression.
 *
 * @param[in]  plain_file       Stream / FILE* providing the plain text.
 * @param[in]  encrypted_file   Stream to write the encrypted text to.
 * @param[in]  public_key_str   String containing the public key.
 * @param[in]  public_key_len   Length of public key or -1 to use strlen.
 */
int
gvm_pgp_pubkey_encrypt_stream (FILE *plain_file, FILE *encrypted_file,
                               const char *public_key_str,
                               ssize_t public_key_len)
{
  char gpg_temp_dir[] = "/tmp/gvmd-gpg-XXXXXX";
  gpgme_ctx_t ctx;
  gpgme_data_t plain_data, encrypted_data;
  gpgme_key_t public_key;
  gpgme_key_t keys[2] = { NULL, NULL };
  gpgme_error_t err;
  gpgme_encrypt_flags_t encrypt_flags;

  // Create temporary GPG home directory, set up context and encryption flags
  if (mkdtemp (gpg_temp_dir) == NULL)
    {
      g_warning ("%s: mkdtemp failed\n", __FUNCTION__);
      return -1;
    }

  gpgme_new (&ctx);
  gpgme_ctx_set_engine_info (ctx, GPGME_PROTOCOL_OpenPGP, NULL, gpg_temp_dir);
  gpgme_set_armor (ctx, 1);
  encrypt_flags = GPGME_ENCRYPT_ALWAYS_TRUST | GPGME_ENCRYPT_NO_COMPRESS;

  // Import public key into context
  err = gvm_gpg_import_from_string (ctx, public_key_str, public_key_len,
                                    GPGME_DATA_TYPE_PGP_KEY);
  if (err)
    {
      g_warning ("%s: Import of public key failed: %s",
                 __FUNCTION__, gpgme_strerror (err));
      gpgme_release (ctx);
      gvm_file_remove_recurse (gpg_temp_dir);
      return -1;
    }

  // Get imported public key
  gpgme_op_keylist_start (ctx, NULL, 0);
  err = gpgme_op_keylist_next (ctx, &public_key);
  if (err)
    {
      g_warning ("%s: Could not get imported public key: %s",
                 __FUNCTION__, gpgme_strerror (err));
      gpgme_release (ctx);
      gvm_file_remove_recurse (gpg_temp_dir);
      return -1;
    }
  keys[0] = public_key;

  // Set up data objects for input and output streams
  gpgme_data_new_from_stream (&plain_data, plain_file);
  gpgme_data_new_from_stream (&encrypted_data, encrypted_file);

  // Encrypt data
  err = gpgme_op_encrypt (ctx, keys, encrypt_flags,
                          plain_data, encrypted_data);

  if (err)
    {
      g_warning ("%s: Encryption failed: %s",
                 __FUNCTION__, gpgme_strerror (err));
      gpgme_data_release (plain_data);
      gpgme_data_release (encrypted_data);
      gpgme_release (ctx);
      gvm_file_remove_recurse (gpg_temp_dir);
      return -1;
    }

  return 0;
}
