/* SPDX-FileCopyrightText: 2025 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "authutils.c"

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>
#include <glib.h>

Describe (authutils);
BeforeEach (authutils)
{
  // Initialize auth for tests that need gcrypt functionality
  gvm_auth_init ();
}

AfterEach (authutils)
{
}

/* auth_method_name */

Ensure (authutils, auth_method_name_returns_correct_strings)
{
  assert_that (auth_method_name (AUTHENTICATION_METHOD_FILE),
               is_equal_to_string ("file"));
  assert_that (auth_method_name (AUTHENTICATION_METHOD_LDAP_CONNECT),
               is_equal_to_string ("ldap_connect"));
  assert_that (auth_method_name (AUTHENTICATION_METHOD_RADIUS_CONNECT),
               is_equal_to_string ("radius_connect"));
  assert_that (auth_method_name (AUTHENTICATION_METHOD_LAST),
               is_equal_to_string ("ERROR"));
}

/* auth_method_name_valid */

Ensure (authutils, auth_method_name_valid_returns_one_for_valid_names)
{
  assert_that (auth_method_name_valid ("file"), is_equal_to (1));
  assert_that (auth_method_name_valid ("ldap_connect"), is_equal_to (1));
  assert_that (auth_method_name_valid ("radius_connect"), is_equal_to (1));
}

Ensure (authutils, auth_method_name_valid_returns_zero_for_invalid_names)
{
  assert_that (auth_method_name_valid ("invalid_method"), is_equal_to (0));
  assert_that (auth_method_name_valid (NULL), is_equal_to (0));
}

/* gvm_auth_ldap_enabled */

Ensure (authutils, gvm_auth_ldap_enabled_returns_one_when_enabled)
{
#ifdef ENABLE_LDAP_AUTH
  assert_that (gvm_auth_ldap_enabled (), is_equal_to (1));
#else
  assert_that (gvm_auth_ldap_enabled (), is_equal_to (0));
#endif
}

/* gvm_auth_radius_enabled */

Ensure (authutils, gvm_auth_radius_enabled_returns_one_when_enabled)
{
#ifdef ENABLE_RADIUS_AUTH
  assert_that (gvm_auth_radius_enabled (), is_equal_to (1));
#else
  assert_that (gvm_auth_radius_enabled (), is_equal_to (0));
#endif
}

/* digest_hex */

Ensure (authutils, digest_hex_returns_correct_hex_string)
{
  guchar digest[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
  gchar *hex = digest_hex (GCRY_MD_MD5, digest);
  assert_that (hex, is_not_null);
  assert_that (hex, is_equal_to_string ("000102030405060708090a0b0c0d0e0f"));
  g_free (hex);
}

Ensure (authutils, digest_hex_returns_null_for_invalid_algorithm)
{
  guchar digest[] = {0x00, 0x01, 0x02};
  gchar *hex = digest_hex (9999, digest); // Invalid algorithm
  assert_that (hex, is_null);
}

/* get_md5_hash_from_string */

Ensure (authutils, get_md5_hash_from_string_returns_correct_hash)
{
  gchar *hash = get_md5_hash_from_string ("test");
  assert_that (hash, is_not_null);
  // MD5 hash of "test" is "098f6bcd4621d373cade4e832627b4f6"
  assert_that (hash, is_equal_to_string ("098f6bcd4621d373cade4e832627b4f6"));
  g_free (hash);
}

Ensure (authutils, get_md5_hash_from_string_handles_empty_string)
{
  gchar *hash = get_md5_hash_from_string ("");
  assert_that (hash, is_not_null);
  // MD5 hash of "" is "d41d8cd98f00b204e9800998ecf8427e"
  assert_that (hash, is_equal_to_string ("d41d8cd98f00b204e9800998ecf8427e"));
  g_free (hash);
}

/* get_password_hashes */

Ensure (authutils, get_password_hashes_returns_valid_hash_pair)
{
  gchar *hashes = get_password_hashes ("password");
  assert_that (hashes, is_not_null);

  // Should contain two MD5 hashes separated by a space
  gchar **split = g_strsplit (hashes, " ", 2);
  assert_that (split, is_not_null);
  assert_that (split[0], is_not_null);
  assert_that (split[1], is_not_null);
  assert_that (split[2], is_null); // Should only have two elements

  // Both should be 32 characters (MD5 hex representation)
  assert_that (strlen (split[0]), is_equal_to (32));
  assert_that (strlen (split[1]), is_equal_to (32));

  g_strfreev (split);
  g_free (hashes);
}

/* gvm_authenticate_classic */

Ensure (authutils, gvm_authenticate_classic_succeeds_with_correct_password)
{
  // Generate a valid hash for testing
  gchar *hashes = get_password_hashes ("password");
  assert_that (hashes, is_not_null);

  int result = gvm_authenticate_classic ("user", "password", hashes);
  assert_that (result, is_equal_to (0)); // Success

  g_free (hashes);
}

Ensure (authutils, gvm_authenticate_classic_fails_with_incorrect_password)
{
  // Generate a valid hash for testing
  gchar *hashes = get_password_hashes ("password");
  assert_that (hashes, is_not_null);

  int result = gvm_authenticate_classic ("user", "wrongpassword", hashes);
  assert_that (result, is_equal_to (1)); // Failure

  g_free (hashes);
}

Ensure (authutils, gvm_authenticate_classic_fails_with_null_hash)
{
  int result = gvm_authenticate_classic ("user", "password", NULL);
  assert_that (result, is_equal_to (1)); // Failure
}

Ensure (authutils,
        gvm_authenticate_classic_returns_error_for_invalid_hash_format)
{
  int result = gvm_authenticate_classic ("user", "password", "invalid");
  assert_that (result, is_equal_to (-1)); // Error
}

/* gvm_auth_init */

Ensure (authutils, gvm_auth_init_succeeds_on_first_call)
{
  // For this test, we need to reset the initialized flag
  // This is a special case where we test the init function itself
  initialized = FALSE;
  int result = gvm_auth_init ();
  assert_that (result, is_equal_to (0)); // Success
}

Ensure (authutils, gvm_auth_init_fails_on_second_call)
{
  // For this test, we need to reset the initialized flag
  // This is a special case where we test the init function itself
  initialized = FALSE;

  // First call
  gvm_auth_init ();

  // Second call should return error
  int result = gvm_auth_init ();
  assert_that (result, is_equal_to (-1)); // Error
}

/* Test suite. */

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, authutils,
                         auth_method_name_returns_correct_strings);
  add_test_with_context (suite, authutils,
                         auth_method_name_valid_returns_one_for_valid_names);
  add_test_with_context (suite, authutils,
                         auth_method_name_valid_returns_zero_for_invalid_names);
  add_test_with_context (suite, authutils,
                         gvm_auth_ldap_enabled_returns_one_when_enabled);
  add_test_with_context (suite, authutils,
                         gvm_auth_radius_enabled_returns_one_when_enabled);
  add_test_with_context (suite, authutils,
                         digest_hex_returns_correct_hex_string);
  add_test_with_context (suite, authutils,
                         digest_hex_returns_null_for_invalid_algorithm);
  add_test_with_context (suite, authutils,
                         get_md5_hash_from_string_returns_correct_hash);
  add_test_with_context (suite, authutils,
                         get_md5_hash_from_string_handles_empty_string);
  add_test_with_context (suite, authutils,
                         get_password_hashes_returns_valid_hash_pair);
  add_test_with_context (
    suite, authutils, gvm_authenticate_classic_succeeds_with_correct_password);
  add_test_with_context (
    suite, authutils, gvm_authenticate_classic_fails_with_incorrect_password);
  add_test_with_context (suite, authutils,
                         gvm_authenticate_classic_fails_with_null_hash);
  add_test_with_context (
    suite, authutils,
    gvm_authenticate_classic_returns_error_for_invalid_hash_format);
  add_test_with_context (suite, authutils,
                         gvm_auth_init_succeeds_on_first_call);
  add_test_with_context (suite, authutils, gvm_auth_init_fails_on_second_call);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
