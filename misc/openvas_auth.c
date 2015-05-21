/* OpenVAS Libraries
 * $Id$
 * Description: Authentication mechanism(s).
 *
 * Authors:
 * Matthew Mundell <matt@mundell.ukfsn.org>
 * Michael Wiegand <michael.wiegand@greenbone.net>
 * Felix Wolfsteller <felix.wolfsteller@intevation.de>
 *
 * Copyright:
 * Copyright (C) 2009,2010 Greenbone Networks GmbH
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

#ifndef _WIN32
#include "openvas_uuid.h"
#endif

#include "openvas_file.h"
#include "array.h"

#include <errno.h>
#include <gcrypt.h>
#include <glib/gstdio.h>

#ifdef ENABLE_LDAP_AUTH
#include "ldap_connect_auth.h"
#endif /*ENABLE_LDAP_AUTH */

#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "lib  auth"

/**
 * @file misc/openvas_auth.c
 *
 * @brief Authentication mechanisms used by openvas-manager and
 * openvas-administrator.
 *
 * @section authentication_mechanisms Authentication Mechanisms
 *
 * Three authentication mechanisms are supported:
 *  - local file authentication. The classical authentication mechanism to
 *    authenticate against files (in PREFIX/var/lib/openvas/users).
 *  - remote ldap authentication. To authenticate against a remote ldap
 *    directory server.
 *
 * These mechanisms are also used for authorization (role and access management).
 *
 * Also a mixture can be used. To do so, a configuration file
 * (PREFIX/var/lib/openvas/auth.conf) has to be used and the authentication
 * system has to be initialised with a call to \ref openvas_auth_init and can
 * be freed with \ref openvas_auth_tear_down .
 *
 * In addition, there is an authentication mechanism that can be enabled per user
 * and does not do authorization (role and access management).
 *  - 'simple ldap authentication' against remote ldap directory server
 *    (ldap-connect).
 * As an exception, this method ignores any priority settings: If ldap-connect is
 * enabled for a user, it is the only method tried (i.e. the password stored for
 * the file-based authentication cannot be used).
 *
 * The configuration file allows to specify details of a remote ldap-connect
 * authentication and to assign an "order" value to the specified
 * authentication mechanisms. Mechanisms with a lower order will be tried
 * first.
 *
 * @section user_directories User Directories
 *
 * The directory of remotely authenticated users reside under
 * OPENVAS_STATE_DIR/users-remote/[method] , where [method] currently can only
 * be "ldap_connect".
 *
 * A users directory will contain:
 *
 *  - uuid : File containing the users uuid.
 *  - auth/hash : (only for locally authenticated users) hash of the users
 *                password
 */


/**
 * @brief Array of string representations of the supported authentication
 * @brief methods.
 */
/** @warning  Beware to have it in sync with \ref authentication_method. */
static const gchar *authentication_methods[] = { "file",
                                                 "ldap_connect",
                                                 NULL };

/** @brief Flag whether the config file was read. */
static gboolean initialized = FALSE;

/** @brief List of configured authentication methods. */
static GSList *authenticators = NULL;

/**
 * @brief Whether or not an exclusive per-user ldap authentication method is
 * @brief configured.
 */
static gboolean ldap_connect_configured = FALSE;

/** @brief Representation of an abstract authentication mechanism. */
struct authenticator
{
  /** @brief The method of this authenticator. */
  auth_method_t method;
  /** @brief The order. Authenticators with lower order will be tried first. */
  int order;
  /** @brief Optional data to be passed to callback functions. */
  void *data;
};

/** @brief Authenticator type. */
typedef struct authenticator *authenticator_t;


gchar* (*classic_get_hash) (const gchar *) = NULL;

int (*get_ldap_info) (gchar **, gchar **, int *) = NULL;

/**
 * @brief Return whether libraries has been compiled with LDAP support.
 *
 * @return 1 if enabled, else 0.
 */
int
openvas_auth_ldap_enabled ()
{
#ifdef ENABLE_LDAP_AUTH
  return 1;
#else
  return 0;
#endif /* ENABLE_LDAP_AUTH */
}

/**
 * @brief Return name of auth_method_t.
 *
 * Keep in sync with \ref authentication_methods and
 * \ref authentication_method .
 *
 * @param method Auth method.
 *
 * @return Name of auth method.
 */
const gchar *
auth_method_name (auth_method_t method)
{
  if (method >= AUTHENTICATION_METHOD_LAST)
    return "ERROR";
  return authentication_methods[method];
}

/**
 * @brief Implements a (GCompareFunc) to add authenticators to the
 * @brief authenticator list, sorted by the order.
 *
 * One exception is that LDAP_CONNECT always comes first.
 *
 * @param first_auth  First authenticator to be compared.
 * @param second_auth Second authenticator to be compared.
 *
 * @return >0 If the first authenticator should come after the second.
 */
static gint
order_compare (authenticator_t first_auth, authenticator_t second_auth)
{
  if (first_auth->method == AUTHENTICATION_METHOD_LDAP_CONNECT)
    return -1;
  else if (second_auth->method == AUTHENTICATION_METHOD_LDAP_CONNECT)
    return 1;

  return (first_auth->order - second_auth->order);
}


/**
 * @brief Create a fresh authenticator to authenticate against a file.
 *
 * @param order Order of the authenticator.
 *
 * @return A fresh authenticator to authenticate against a file.
 */
static authenticator_t
classic_authenticator_new (int order)
{
  authenticator_t authent = g_malloc0 (sizeof (struct authenticator));
  authent->order = order;
  authent->data = (void *) NULL;
  authent->method = AUTHENTICATION_METHOD_FILE;
  return authent;
}

/**
 * @brief Initializes the list of authentication methods.
 *
 * Parses PREFIX/var/lib/openvas/auth.conf and adds respective authenticators
 * to the authenticators list.
 *
 * Call once before calls to openvas_authenticate, otherwise the
 * authentication method will default to file-system based authentication.
 *
 * The list should be freed with \ref openvas_auth_tear_down once no further
 * authentication trials will be done.
 *
 * A warning will be issued if \ref openvas_auth_init is called a second time
 * without a call to \ref openvas_auth_tear_down in between. In this case,
 * no reconfiguration will take place.
 *
 * @return 0 success, -1 error.
 */
int
openvas_auth_init_funcs (gchar * (*get_hash) (const gchar *),
                         int (*get_ldap_information) (gchar **,
                                                      gchar **,
                                                      int *))
{
  if (initialized == TRUE)
    {
      g_warning ("openvas_auth_init called a second time.");
      return -1;
    }

  classic_get_hash = get_hash;
  get_ldap_info = get_ldap_information;

  /* Init Libgcrypt. */

  /* Version check should be the very first call because it makes sure that
   * important subsystems are intialized.
   * We pass NULL to gcry_check_version to disable the internal version mismatch
   * test. */
  if (!gcry_check_version (NULL))
    {
      g_critical ("%s: libgcrypt version check failed\n", __FUNCTION__);
      return -1;
    }

  /* We don't want to see any warnings, e.g. because we have not yet parsed
   * program options which might be used to suppress such warnings. */
  gcry_control (GCRYCTL_SUSPEND_SECMEM_WARN);

  /* ... If required, other initialization goes here.  Note that the process
   * might still be running with increased privileges and that the secure
   * memory has not been intialized. */

  /* Allocate a pool of 16k secure memory.  This make the secure memory
   * available and also drops privileges where needed. */
  gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);

  /* It is now okay to let Libgcrypt complain when there was/is a problem with
   * the secure memory. */
  gcry_control (GCRYCTL_RESUME_SECMEM_WARN);

  /* ... If required, other initialization goes here. */

  /* Tell Libgcrypt that initialization has completed. */
  gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

  /* Setup "file" auth config. */

  authenticators = g_slist_insert_sorted (authenticators,
                                          classic_authenticator_new (1),
                                          (GCompareFunc) order_compare);

  /* Setup "ldap_connect" auth config. */

#ifdef ENABLE_LDAP_AUTH
  {
    ldap_auth_info_t info;

    info = ldap_auth_info_from_function (get_ldap_info);
    if (info)
      {
        authenticator_t authent = g_malloc0 (sizeof (struct authenticator));
        // TODO: The order is ignored in this case (oder_compare does sort
        //       LDAP_CONNECT differently), make order optional.
        authent->order = 1;
        authent->data = info;
        authent->method = AUTHENTICATION_METHOD_LDAP_CONNECT;
        authenticators =
          g_slist_insert_sorted (authenticators, authent,
                                 (GCompareFunc) order_compare);
        ldap_connect_configured = TRUE;
     }
  }
#endif /* ENABLE_LDAP_AUTH */

  initialized = TRUE;

  return 0;
}

/**
 * @brief Free memory associated to authentication configuration.
 *
 * This will have no effect if openvas_auth_init was not called.
 */
void
openvas_auth_tear_down (void)
{
  /** @todo Close memleak, destroy list and content. */
}

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
      g_warning ("Could not select gcrypt algorithm: %s", gcry_strerror (err));
      return NULL;
    }

  gchar *hex = g_malloc0 (gcry_md_get_algo_dlen (gcrypt_algorithm) * 2 + 1);
  int i;

  for (i = 0; i < gcry_md_get_algo_dlen (gcrypt_algorithm); i++)
    {
      g_snprintf (hex + i * 2, 3, "%02x", digest[i]);
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
get_password_hashes (int digest_algorithm, const gchar * password)
{
  gcry_error_t err = gcry_md_test_algo (digest_algorithm);
  if (err != 0)
    {
      g_warning ("Could not select gcrypt algorithm: %s", gcry_strerror (err));
      return NULL;
    }

  g_assert (password);

  /* RATS:ignore, is sanely used with gcry_create_nonce and gcry_md_hash_buffer */
  unsigned char *nonce_buffer[256];
  guchar *seed = g_malloc0 (gcry_md_get_algo_dlen (digest_algorithm));
  gchar *seed_hex = NULL;
  gchar *seed_pass = NULL;
  guchar *hash = g_malloc0 (gcry_md_get_algo_dlen (digest_algorithm));
  gchar *hash_hex = NULL;
  gchar *hashes_out = NULL;

  gcry_create_nonce (nonce_buffer, 256);
  gcry_md_hash_buffer (digest_algorithm, seed, nonce_buffer, 256);
  seed_hex = digest_hex (digest_algorithm, seed);
  seed_pass = g_strconcat (seed_hex, password, NULL);
  gcry_md_hash_buffer (digest_algorithm, hash, seed_pass, strlen (seed_pass));
  hash_hex = digest_hex (digest_algorithm, hash);

  hashes_out = g_strjoin (" ", hash_hex, seed_hex, NULL);

  g_free (seed);
  g_free (seed_hex);
  g_free (seed_pass);
  g_free (hash);
  g_free (hash_hex);

  return hashes_out;
}

/**
 * @brief Authenticate a credential pair against openvas user file contents.
 *
 * @param username Username.
 * @param password Password.
 * @param data     Ignored.
 *
 * @return 0 authentication success, 1 authentication failure, -1 error.
 */
int
openvas_authenticate_classic (const gchar * username, const gchar * password,
                              void *data)
{
  int gcrypt_algorithm = GCRY_MD_MD5;   // FIX whatever configer used
  int ret;
  gchar *actual, *expect, *seed_pass;
  guchar *hash;
  gchar *hash_hex, **seed_hex, **split;

  if (classic_get_hash == NULL)
    return -1;

  actual = classic_get_hash (username);
  if (actual == NULL)
    return 1;

  split = g_strsplit_set (g_strchomp (actual), " ", 2);
  seed_hex = split + 1;
  if (*split == NULL || *seed_hex == NULL)
    {
      g_warning ("Failed to split auth contents.");
      g_strfreev (split);
      g_free (actual);
      return -1;
    }

  seed_pass = g_strconcat (*seed_hex, password, NULL);
  hash = g_malloc0 (gcry_md_get_algo_dlen (gcrypt_algorithm));
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
