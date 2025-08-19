/* SPDX-FileCopyrightText: 2025 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "credentials.c"
#include "strings.h"

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>

Describe (credentials);
BeforeEach (credentials)
{
}
AfterEach (credentials)
{
}

/* free_credentials */

Ensure (credentials, free_credentials_frees_all_fields)
{
  credentials_t credentials;

  credentials.username = g_strdup ("testuser");
  credentials.password = g_strdup ("testpass");
  credentials.uuid = g_strdup ("12345");
  credentials.timezone = g_strdup ("UTC");
  credentials.default_severity = 5.0;
  credentials.severity_class = g_strdup ("nist");
  credentials.dynamic_severity = 1;
  credentials.role = g_strdup ("admin");
  credentials.excerpt_size = 100;

  free_credentials (&credentials);

  assert_that (credentials.username, is_null);
  assert_that (credentials.password, is_null);
  assert_that (credentials.uuid, is_null);
  assert_that (credentials.timezone, is_null);
  assert_that (credentials.role, is_null);
  assert_that (credentials.severity_class, is_null);
}

/* append_to_credentials_username */

Ensure (credentials, append_to_credentials_username_appends_text)
{
  credentials_t credentials;

  credentials.username = NULL;

  append_to_credentials_username (&credentials, "test", 4);

  assert_that (credentials.username, is_equal_to_string ("test"));

  append_to_credentials_username (&credentials, "user", 4);

  assert_that (credentials.username, is_equal_to_string ("testuser"));

  g_free (credentials.username);
}

/* append_to_credentials_password */

Ensure (credentials, append_to_credentials_password_appends_text)
{
  credentials_t credentials;

  credentials.password = NULL;

  append_to_credentials_password (&credentials, "secret", 6);

  assert_that (credentials.password, is_equal_to_string ("secret"));

  append_to_credentials_password (&credentials, "123", 3);

  assert_that (credentials.password, is_equal_to_string ("secret123"));

  g_free (credentials.password);
}

/* Test suite. */

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, credentials, free_credentials_frees_all_fields);
  add_test_with_context (suite, credentials,
                         append_to_credentials_username_appends_text);
  add_test_with_context (suite, credentials,
                         append_to_credentials_password_appends_text);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
