/* OpenVAS-Client
 * $Id$
 * Description: SSH Key management.
 *
 * Authors:
 * Matthew Mundell <matt@mundell.ukfsn.org>
 * Michael Wiegand <michael.wiegand@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2009 Greenbone Networks GmbH
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#include "openvas_auth.h"
#include <errno.h>
#include <gcrypt.h>
#include <glib/gstdio.h>

/**
 * @brief Generate a hexadecimal representation of a message digest.
 *
 * @param gcrypt_algorithm The libgcrypt message digest algorithm used to
 * create the digest (e.g. GCRY_MD_MD5; see the enum gcry_md_algos in
 * gcrypt.h).
 * @param digest The binary representation of the digest.
 *
 * @return A pointer to the hexadecimal representation of the message digest
 * or NULL if an unavailable message digest algorithm was selected.
 */
gchar *
digest_hex (int gcrypt_algorithm, const guchar * digest)
{
  gcry_error_t err = gcry_md_test_algo (gcrypt_algorithm);
  if (err != 0)
    {
      g_warning ("Could not select gcrypt algorithm: %s",
                 gcry_strerror (err));
      return NULL;
    }

  gchar *hex = g_malloc0(gcry_md_get_algo_dlen (gcrypt_algorithm) * 2 + 1);
  int i;

  for (i = 0; i < gcry_md_get_algo_dlen (gcrypt_algorithm); i++)
    {
      g_snprintf(hex + i * 2, 3, "%02x", digest[i]);
    }

  return hex;
}

/**
 * @brief Generate a pair of hashes to be used in the OpenVAS "auth/hash" file
 * for the user.
 *
 * The "auth/hash" file consist of two hashes, h_1 and h_2. h_2 (the "seed")
 * is the message digest of (currently) 256 bytes of random data. h_1 is the
 * message digest of h_2 concatenated with the password in plaintext.
 *
 * The current implementation was taken from the openvas-adduser shell script
 * provided with openvas-server.
 *
 * @param gcrypt_algorithm The libgcrypt message digest algorithm used to
 * create the digest (e.g. GCRY_MD_MD5; see the enum gcry_md_algos in
 * gcrypt.h)
 * @param password The password in plaintext.
 *
 * @return A pointer to a gchar containing the two hashes separated by a
 * space or NULL if an unavailable message digest algorithm was selected.
 */
gchar *
get_password_hashes (int gcrypt_algorithm, const gchar * password)
{
  gcry_error_t err = gcry_md_test_algo (gcrypt_algorithm);
  if (err != 0)
    {
      g_warning ("Could not select gcrypt algorithm: %s",
                 gcry_strerror (err));
      return NULL;
    }

  g_assert (password);

  /* RATS:ignore, is sanely used with gcry_create_nonce and gcry_md_hash_buffer */
  unsigned char *nonce_buffer[256];
  guchar *seed = g_malloc0 (gcry_md_get_algo_dlen (gcrypt_algorithm));
  gchar *seed_hex = NULL;
  gchar *seed_pass = NULL;
  guchar *hash = g_malloc0 (gcry_md_get_algo_dlen (gcrypt_algorithm));
  gchar *hash_hex = NULL;
  gchar *hashes_out = NULL;

  gcry_create_nonce (nonce_buffer, 256);
  gcry_md_hash_buffer (GCRY_MD_MD5, seed, nonce_buffer, 256);
  seed_hex = digest_hex (GCRY_MD_MD5, seed);
  seed_pass = g_strconcat (seed_hex, password, NULL);
  gcry_md_hash_buffer (GCRY_MD_MD5, hash, seed_pass, strlen (seed_pass));
  hash_hex = digest_hex (GCRY_MD_MD5, hash);

  hashes_out = g_strjoin (" ", hash_hex, seed_hex, NULL);

  g_free (seed);
  g_free (seed_hex);
  g_free (seed_pass);
  g_free (hash);
  g_free (hash_hex);

  return hashes_out;
}

/**
 * @brief Authenticate a credential pair.
 *
 * @param username Username.
 * @param password Password.
 *
 * @return 0 authentication success, 1 authentication failure, -1 error.
 */
int
openvas_authenticate (const gchar * username, const gchar * password)
{
  int gcrypt_algorithm = GCRY_MD_MD5; // FIX whatever configer used
  int ret;
  gchar* actual;
  gchar* expect;
  GError* error = NULL;
  gchar *seed_pass = NULL;
  guchar *hash = g_malloc0 (gcry_md_get_algo_dlen (gcrypt_algorithm));
  gchar *hash_hex = NULL;
  gchar **seed_hex;
  gchar **split;

  gchar *file_name = g_build_filename (OPENVAS_USERS_DIR,
                                       username,
                                       "auth",
                                       "hash",
                                       NULL);
  g_file_get_contents (file_name, &actual, NULL, &error);
  g_free (file_name);
  if (error)
    {
      g_error_free (error);
      return 1;
    }

  split = g_strsplit_set (g_strchomp (actual), " ", 2);
  seed_hex = split + 1;
  if (*split == NULL || *seed_hex == NULL)
    {
      g_warning ("Failed to split auth contents.");
      g_strfreev (split);
      return -1;
    }

  seed_pass = g_strconcat (*seed_hex, password, NULL);
  gcry_md_hash_buffer (GCRY_MD_MD5, hash, seed_pass, strlen (seed_pass));
  hash_hex = digest_hex (GCRY_MD_MD5, hash);

  expect = g_strjoin (" ", hash_hex, *seed_hex, NULL);

  g_strfreev (split);
  g_free (seed_pass);
  g_free (hash);
  g_free (hash_hex);

  ret = strcmp (expect, actual) ? 1 : 0;
  g_free (expect);
  g_free (actual);
  return ret;
}

/**
 * @brief Check if a user has administrative privileges.
 *
 * The check for administrative privileges is currently done by looking for an
 * "isadmin" file in the user directory.
 *
 * @param username Username.
 *
 * @return 1 user has administrative privileges, 0 user does not have
 * administrative privileges
 */
int
openvas_is_user_admin (const gchar * username)
{
  gchar *file_name = g_build_filename (OPENVAS_USERS_DIR,
                                       username,
                                       "isadmin",
                                       NULL);
  gboolean file_exists = g_file_test (file_name, G_FILE_TEST_EXISTS);

  g_free (file_name);
  return file_exists;
}

/**
 * @brief Set the role of a user.
 *
 * @param username Username.
 * @param role Role.
 *
 * @return 0 success, -1 failure.
 */
int
openvas_set_user_role (const gchar * username, const gchar * role)
{
  int ret = -1;
  gchar *file_name;

  file_name = g_build_filename (OPENVAS_USERS_DIR,
                                username,
                                "isadmin",
                                NULL);

  if (strcmp (role, "User") == 0)
    {
      if (g_remove (file_name))
        {
          if (errno == ENOENT) ret = 0;
        }
      else
        ret = 0;
    }
  else if (strcmp (role, "Admin") == 0
           && g_file_set_contents (file_name, "", 0, NULL))
    {
      g_chmod (file_name, 0600);
      ret = 0;
    }

  g_free (file_name);
  return ret;
}
