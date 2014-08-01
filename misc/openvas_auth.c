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

#define AUTH_CONF_FILE "openvasmd/auth.conf"

#define GROUP_PREFIX_METHOD "method:"
#define KEY_ORDER "order"

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
  /** @brief Authentication callback function. */
  int (*authenticate) (const gchar * user, const gchar * pass, void *data);
  /** @brief Existence predicate callback function. */
  int (*user_exists) (const gchar * user, void *data);
  /** @brief Optional data to be passed to callback functions. */
  void *data;
};

/** @brief Authenticator type. */
typedef struct authenticator *authenticator_t;


// forward decl.
static int openvas_authenticate_classic (const gchar * usr, const gchar * pas,
                                         void *dat);

static int openvas_user_exists_classic (const gchar *name, void *data);

#ifdef ENABLE_LDAP_AUTH
static int ldap_connect_user_exists (const gchar *name, void *data);
#endif

gchar* (*classic_get_hash) (const gchar *) = NULL;

int (*user_uuid_method) (const char *method) = NULL;

int (*user_set_role) (const gchar *, const gchar *, const gchar *) = NULL;

gchar* (*user_get_uuid) (const gchar *, auth_method_t) = NULL;

int (*user_exists) (const gchar *, auth_method_t) = NULL;

/**
 * @brief Return a auth_method_t from string representation eg. "ldap_connect".
 *
 * Keep in sync with \ref authentication_methods and
 * \ref authentication_method .
 *
 * @param method The string representation of an auth_method_t (e.g. "file").
 *
 * @return Respective auth_method_t, -1 for unknown.
 */
static auth_method_t
auth_method_from_string (const char *method)
{
  if (method == NULL)
    return -1;

  int i = 0;
  for (i = 0; i < AUTHENTICATION_METHOD_LAST; i++)
    if (!strcmp (method, authentication_methods[i]))
      return i;
  return -1;
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
  if ((method < 0) || (method >= AUTHENTICATION_METHOD_LAST))
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
  authent->authenticate = &openvas_authenticate_classic;
  authent->data = (void *) NULL;
  authent->user_exists = &openvas_user_exists_classic;
  authent->method = AUTHENTICATION_METHOD_FILE;
  return authent;
}

/**
 * @brief Add an authenticator.
 *
 * @param key_file GKeyFile to access for getting data.
 * @param group    Groupname within \ref key_file to query.
 */
static void
add_authenticator (GKeyFile * key_file, const gchar * group)
{
  const char *auth_method_str = group + strlen (GROUP_PREFIX_METHOD);
  auth_method_t auth_method = auth_method_from_string (auth_method_str);
  GError *error = NULL;
  int order = g_key_file_get_integer (key_file, group, KEY_ORDER, &error);
  if (error != NULL)
    {
      g_warning ("No order for authentication method %s specified, "
                 "skipping this entry.\n", group);
      g_error_free (error);
      return;
    }
  switch (auth_method)
    {
    case AUTHENTICATION_METHOD_FILE:
      {
        authenticator_t authent = classic_authenticator_new (order);
        authenticators =
          g_slist_insert_sorted (authenticators, authent,
                                 (GCompareFunc) order_compare);
        break;
      }
    case AUTHENTICATION_METHOD_LDAP_CONNECT:
      {
#ifdef ENABLE_LDAP_AUTH
        //int (*authenticate_func) (const gchar* user, const gchar* pass, void* data) = NULL;
        // Use ldap_connect for authentication, but file-based authorization.
        authenticator_t authent = g_malloc0 (sizeof (struct authenticator));
        // TODO: The order is ignored in this case (oder_compare does sort
        //       LDAP_CONNECT differently), make order optional.
        authent->order = order;
        authent->authenticate = &ldap_connect_authenticate;
        authent->user_exists = &ldap_connect_user_exists;
        ldap_auth_info_t info = ldap_auth_info_from_key_file (key_file, group);
        authent->data = info;
        authent->method = AUTHENTICATION_METHOD_LDAP_CONNECT;
        authenticators =
          g_slist_insert_sorted (authenticators, authent,
                                 (GCompareFunc) order_compare);
#else
        g_warning ("LDAP-connect Authentication was configured, but "
                   "openvas-libraries was not build with "
                   "ldap-support. The configuration entry will "
                   "have no effect.");
#endif /* ENABLE_LDAP_AUTH */
        break;
      }
    default:
      g_warning ("Unsupported authentication method: %s.", group);
      break;
    }
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
openvas_auth_init ()
{
  return openvas_auth_init_funcs (NULL, NULL, NULL, NULL);
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
                         int (*set_role) (const gchar *, const gchar *,
                                          const gchar *),
                         int (*user_exists_arg) (const gchar *, auth_method_t),
                         gchar * (*get_uuid) (const gchar *, auth_method_t))
{
  GKeyFile *key_file;
  gchar *config_file;

  if (initialized == TRUE)
    {
      g_warning ("openvas_auth_init called a second time.");
      return -1;
    }

  user_exists = user_exists_arg;
  classic_get_hash = get_hash;
  user_get_uuid = get_uuid;
  user_set_role = set_role;

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

  /* Load auth config. */

  key_file = g_key_file_new ();
  config_file = g_build_filename (OPENVAS_STATE_DIR, AUTH_CONF_FILE, NULL);

  if (!g_file_test (config_file, G_FILE_TEST_EXISTS))
    {
      g_log ("lib auth", G_LOG_LEVEL_INFO,
             "Authentication configuration not found.\n");
      initialized = TRUE;
      return 0;
    }

  g_debug ("loading auth: %s", config_file);

  gboolean loaded =
    g_key_file_load_from_file (key_file, config_file, G_KEY_FILE_NONE, NULL);
  gchar **groups = NULL;
  gchar **group = NULL;
  g_free (config_file);

  if (loaded == FALSE)
    {
      g_key_file_free (key_file);
      initialized = TRUE;
      g_warning ("Authentication configuration could not be loaded.\n");
      return 0;
    }

  groups = g_key_file_get_groups (key_file, NULL);

  group = groups;
  while (*group != NULL)
    {
      if (g_str_has_prefix (*group, GROUP_PREFIX_METHOD))
        {
          /* Add the classic/file based authentication regardless of its
           * "enabled" value. */
          if (!strcmp (*group, "method:file"))
            {
              add_authenticator (key_file, *group);
            }
          else
            {
              // Add other authenticators iff they are enabled.
              gchar *enabled_value =
                g_key_file_get_value (key_file, *group, "enable", NULL);
              if (enabled_value != NULL && !strcmp (enabled_value, "true"))
                {
                  add_authenticator (key_file, *group);
                }
              else
                {
                  g_log ("event auth", G_LOG_LEVEL_DEBUG,
                    "Authentication method configured but not enabled: %s", *group);
                }
              g_free (enabled_value);
              // Remember that we enabled ldap_connect.
              if (!strcmp (*group, "method:ldap_connect"))
                {
                  ldap_connect_configured = TRUE;
                }
            }
        }
      group++;
    }

  g_key_file_free (key_file);
  g_strfreev (groups);
  initialized = TRUE;

  return 0;
}

/**
 * @brief Free memory associated to authentication configuration.
 *
 * This will have no effect if openvas_auth_init was not called.
 */
void
openvas_auth_tear_down ()
{
  /** @todo Close memleak, destroy list and content. */
}

/**
 * @brief Writes the authentication mechanism configuration, merging with
 * @brief defaults and existing configuration.
 *
 * If the passed key-file contains just method:ldap_connect, do not write the
 * defaults of any other group.
 *
 * @param[in] keyfile The KeyFile to merge and write. Can be NULL, in which
 *                    case just the default will be written.
 *
 * @return 0 if file has been written successfully, 1 authdn validation
 *         failed, -1 error.
 */
int
openvas_auth_write_config (GKeyFile * key_file)
{
  GKeyFile *new_conffile = g_key_file_new ();
  GKeyFile *old_conffile = g_key_file_new ();
  gchar **groups = NULL;
  gchar **group = NULL;
  gchar **keys = NULL;
  gchar **key = NULL;
  gchar *file_content = NULL;
  gboolean written = FALSE;
  gchar *file_path = g_build_filename (OPENVAS_STATE_DIR, AUTH_CONF_FILE,
                                       NULL);

  // Instead of clever merging with existing file and the defaults, fill
  // conffile with defaults and overwrite with values from parameter, if any.

  // "Classic authentication" configuration.
  g_key_file_set_comment (new_conffile, NULL, NULL,
                          "This file was automatically generated.", NULL);
  g_key_file_set_value (new_conffile, "method:file", "enable", "true");
  g_key_file_set_value (new_conffile, "method:file", "order", "1");

  // LDAP configuration.
  if (key_file == NULL || g_key_file_has_group
                           (key_file, "method:ldap_connect") == TRUE)
    {
      g_key_file_set_value (new_conffile, "method:ldap_connect", "enable", "false");
      g_key_file_set_value (new_conffile, "method:ldap_connect", "order", "-1");
      g_key_file_set_value (new_conffile, "method:ldap_connect", "ldaphost",
                            "localhost");
      g_key_file_set_value (new_conffile, "method:ldap_connect", "authdn",
                            "authdn=uid=%s,cn=users,o=yourserver,c=yournet");
      g_key_file_set_value (new_conffile, "method:ldap_connect", "allow-plaintext",
                            "false");
    }

  // Old, user-provided configuration, if any.
  /** @todo Preserve comments in file. */
  old_conffile = g_key_file_new ();
  if (g_key_file_load_from_file
      (old_conffile, file_path, G_KEY_FILE_KEEP_COMMENTS, NULL) == TRUE)
    {
      // Old file does exist.
      groups = g_key_file_get_groups (old_conffile, NULL);

      group = groups;
      while (group && *group != NULL)
        {
          keys = g_key_file_get_keys (old_conffile, *group, NULL, NULL);
          key = keys;
          while (*key != NULL)
            {
              gchar *value =
                g_key_file_get_value (old_conffile, *group, *key, NULL);
              g_key_file_set_value (new_conffile, *group, *key, value);
              key++;
            }
          g_strfreev (keys);
          group++;
        }
      g_strfreev (groups);
      g_key_file_free (old_conffile);
    }

  // New, user-provided configuration, if any.
  groups = (key_file) ? g_key_file_get_groups (key_file, NULL) : NULL;

  group = groups;
  while (group && *group != NULL)
    {
      keys = g_key_file_get_keys (key_file, *group, NULL, NULL);
      key = keys;
      while (*key != NULL)
        {
          gchar *value = g_key_file_get_value (key_file, *group, *key, NULL);
          g_key_file_set_value (new_conffile, *group, *key, value);
          key++;
        }
      g_strfreev (keys);
      group++;
    }
  g_strfreev (groups);

#ifdef ENABLE_LDAP_AUTH
  // Validate.
  {
    gchar *authdn;
    authdn = g_key_file_get_value (new_conffile, "method:ldap_connect", "authdn", NULL);
    if (authdn && (ldap_auth_dn_is_good (authdn) == FALSE))
      {
        // Clean up.
        g_key_file_free (new_conffile);
        g_free (file_content);
        g_free (file_path);
        g_free (authdn);

        return 1;
      }
    g_free (authdn);
  }
#endif

  // Write file.
  file_content = g_key_file_to_data (new_conffile, NULL, NULL);
  written = g_file_set_contents (file_path, file_content, -1, NULL);

  // Clean up.
  g_key_file_free (new_conffile);
  g_free (file_content);
  g_free (file_path);

  return (written == TRUE) ? 0 : -1;
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
static int
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

/**
 * @brief Check for existence of ldap_connect file in user auth/methods directory.
 *
 * If ldap_connect authentication is disabled, return FALSE.
 *
 * @param[in] username Username for which to check the existence of file.
 *
 * @return TRUE if the user is allowed to authenticate exclusively with an
 *         configured ldap_connect method, FALSE otherwise.
 */
static gboolean
can_user_ldap_connect (const gchar * username)
{
  // If ldap_connect is not globally enabled, no need to check locally.
  if (ldap_connect_configured == FALSE)
    return FALSE;

  if (user_exists (username, AUTHENTICATION_METHOD_LDAP_CONNECT) == 0)
    return FALSE;

  return TRUE;
}

#ifndef _WIN32
/**
 * @brief Authenticate a credential pair and expose the method used.
 *
 * Uses the configurable authenticators list, if available.
 * Defaults to file-based (openvas users directory) authentication otherwise.
 *
 * @param username Username.
 * @param password Password.
 * @param method[out] Return location for the method that was used to
 *                    authenticate the credential pair.
 *
 * @return 0 authentication success, otherwise the result of the last
 *         authentication trial: 1 authentication failure, -1 error.
 */
int
openvas_authenticate_method (const gchar * username, const gchar * password,
                             auth_method_t * method)
{
  *method = AUTHENTICATION_METHOD_FILE;

  if (initialized == FALSE)
    {
      g_warning ("Call init function first.");
      return -1;
    }

  if (authenticators == NULL)
    return openvas_authenticate_classic (username, password, NULL);

  // Try each authenticator in the list.
  int ret = -1;
  GSList *item = authenticators;
  while (item)
    {
      authenticator_t authent = (authenticator_t) item->data;

      // LDAP_CONNECT is either the only method to try or not tried.
      if (authent->method == AUTHENTICATION_METHOD_LDAP_CONNECT)
        {
          if (can_user_ldap_connect (username) == TRUE)
            {
              *method = AUTHENTICATION_METHOD_LDAP_CONNECT;
              return authent->authenticate (username, password, authent->data);
            }
          else
            {
              item = g_slist_next (item);
              continue;
            }
        }

      ret = authent->authenticate (username, password, authent->data);
      g_debug ("Authentication trial, order %d, method %s -> %d. (w/method)",
               authent->order, authentication_methods[authent->method], ret);

      // Return if successfull
      if (ret == 0)
        {
          *method = authent->method;
          return 0;
        }

      item = g_slist_next (item);
    }

  return ret;
}


/**
 * @brief Return the UUID of a user from the OpenVAS user UUID file.
 *
 * If the user exists, ensure that the user has a UUID (create that file).
 *
 * @param[in]  name   User name.
 *
 * @return UUID of given user if user exists, else NULL.
 */
static gchar *
openvas_user_uuid_method (const char *name, const auth_method_t method)
{
  if (user_get_uuid == NULL)
    return NULL;

  return user_get_uuid (name, method);
}


/**
 * @brief Check whether a local user exists.
 *
 * @param[in]  name   User name.
 * @param[in]  data   Dummy arg.
 *
 * @return 1 yes, 0 no, -1 error.
 */
static int
openvas_user_exists_classic (const gchar *name, void *data)
{
  if (user_exists == NULL)
    return -1;

  return user_exists (name, AUTHENTICATION_METHOD_FILE);
}

#ifdef ENABLE_LDAP_AUTH
/**
 * @brief Check whether a "LDAP connect" user exists in the database.
 *
 * @param[in]  name   User name.
 * @param[in]  data   Dummy arg.
 *
 * @return 1 yes, 0 no, -1 error.
 */
static int
ldap_connect_user_exists (const gchar *name, void *data)
{
  if (user_exists == NULL)
    return -1;

  return user_exists (name, AUTHENTICATION_METHOD_LDAP_CONNECT);
}
#endif

/**
 * @brief Check whether a user exists.
 *
 * @param[in]  name   User name.
 *
 * @return 1 yes, 0 no, -1 error.
 */
int
openvas_user_exists (const char *name)
{
  GSList *item;

  if (initialized == FALSE || authenticators == NULL)
    return openvas_user_exists_classic (name, NULL);

  // Try each authenticator in the list.
  item = authenticators;
  while (item)
    {
      authenticator_t authent;

      authent = (authenticator_t) item->data;
      if (authent->user_exists)
        {
          int ret;
          ret = authent->user_exists (name, authent->data);
          if (ret)
            return ret;
        }
      item = g_slist_next (item);
    }
  return 0;
}

/**
 * @brief Return the UUID of a user from the OpenVAS user UUID file.
 *
 * If the user exists, ensure that the user has a UUID (create that file).
 *
 * @param[in]  name   User name.
 *
 * @return UUID of given user if (locally authenticated) user exists,
 *         else NULL.
 */
gchar *
openvas_user_uuid (const char *name)
{
  GSList *item;

  if (initialized == FALSE || authenticators == NULL)
    return openvas_user_uuid_method (name, AUTHENTICATION_METHOD_FILE);

  // Try each authenticator in the list.
  item = authenticators;
  while (item)
    {
      authenticator_t authent;

      authent = (authenticator_t) item->data;
      if (authent->user_exists)
        {
          int ret;
          ret = authent->user_exists (name, authent->data);
          if (ret == 1)
            return openvas_user_uuid_method (name, authent->method);
          if (ret)
            return NULL;
        }
      item = g_slist_next (item);
    }
  return 0;
}
#endif // not _WIN32
