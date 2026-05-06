/* SPDX-FileCopyrightText: 2026 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "credentialutils.c"

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>
#include <fcntl.h>

Describe (credentialutils);
BeforeEach (credentialutils)
{
}

AfterEach (credentialutils)
{
}

// -------------------- Mock Functions --------------------
static void
collect_auth_data (const char *name, const char *value, void *user_data)
{
  GHashTable *auth_data = (GHashTable *) user_data;
  g_hash_table_insert (auth_data, g_strdup (name), g_strdup (value));
}

Ensure (credentialutils, credentialutils_set_and_retrieve_auth_data)
{
  scan_credential_t *credential;

  credential = scan_credential_new ("up", "generic", "0");

  scan_credential_set_auth_data (credential, "username", "admin");
  scan_credential_set_auth_data (credential, "password", "admin");

  const char *type = scan_credential_get_type (credential);
  assert_that (type, is_equal_to_string ("up"));

  const char *service = scan_credential_get_service (credential);
  assert_that (service, is_equal_to_string ("generic"));

  int port = atoi (scan_credential_get_port (credential));
  assert_that (port, is_equal_to (0));

  const char *username = scan_credential_get_auth_data (credential, "username");
  const char *password = scan_credential_get_auth_data (credential, "password");

  assert_that (username, is_equal_to_string ("admin"));
  assert_that (password, is_equal_to_string ("admin"));

  scan_credential_free (credential);
}

Ensure (credentialutils, credentialutils_set_and_unset_auth_data)
{
  scan_credential_t *credential;

  credential = scan_credential_new ("up", "generic", "0");

  scan_credential_set_auth_data (credential, "username", "admin");
  const char *username = scan_credential_get_auth_data (credential, "username");
  assert_that (username, is_equal_to_string ("admin"));

  scan_credential_set_auth_data (credential, "username", NULL);
  username = scan_credential_get_auth_data (credential, "username");
  assert_that (username, is_null);

  scan_credential_free (credential);
}

Ensure (credentialutils, credentialutils_set_auth_data_rejects_invalid_name)
{
  scan_credential_t *credential;

  credential = scan_credential_new ("up", "generic", "0");

  scan_credential_set_auth_data (credential, "invalid-name", "value");

  const char *value =
    scan_credential_get_auth_data (credential, "invalid-name");
  assert_that (value, is_null);

  scan_credential_free (credential);
}

Ensure (credentialutils, credentialutils_foreach_auth_data)
{
  scan_credential_t *credential;

  credential = scan_credential_new ("up", "generic", "0");

  scan_credential_set_auth_data (credential, "username", "admin1");
  scan_credential_set_auth_data (credential, "password", "admin2");

  GHashTable *collected_auth_data =
    g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

  scan_credential_foreach_auth_data (credential, collect_auth_data,
                                     collected_auth_data);

  const char *username = g_hash_table_lookup (collected_auth_data, "username");
  const char *password = g_hash_table_lookup (collected_auth_data, "password");

  assert_that (username, is_equal_to_string ("admin1"));
  assert_that (password, is_equal_to_string ("admin2"));

  g_hash_table_destroy (collected_auth_data);
  scan_credential_free (credential);
}

/* Test suite. */
int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, credentialutils,
                         credentialutils_set_and_retrieve_auth_data);
  add_test_with_context (suite, credentialutils,
                         credentialutils_set_and_unset_auth_data);
  add_test_with_context (suite, credentialutils,
                         credentialutils_set_auth_data_rejects_invalid_name);
  add_test_with_context (suite, credentialutils,
                         credentialutils_foreach_auth_data);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
