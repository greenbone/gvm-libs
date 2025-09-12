/* SPDX-FileCopyrightText: 2025 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "container_image_scanner.c"

#include <cgreen/assertions.h>
#include <cgreen/cgreen.h>
#include <cgreen/constraint_syntax_helpers.h>
#include <cgreen/internal/c_assertions.h>
#include <cgreen/mocks.h>

Describe (container_image);
BeforeEach (container_image)
{
}

AfterEach (container_image)
{
}

Ensure (container_image, container_image_add_credential_to_scan_json)
{
  container_image_credential_t *credential;
  cJSON *credentials = cJSON_CreateArray ();

  credential = container_image_credential_new ("up", "generic");

  container_image_credential_set_auth_data (credential, "username", "admin");
  container_image_credential_set_auth_data (credential, "password", "admin");

  add_credential_to_scan_json (credential, credentials);

  cJSON *credential_obj = cJSON_GetArrayItem (credentials, 0);
  assert_that (cJSON_IsObject (credential_obj), is_true);

  const char *service =
    cJSON_GetStringValue (cJSON_GetObjectItem (credential_obj, "service"));
  assert_that (service, is_equal_to_string ("generic"));

  cJSON *auth_data = cJSON_GetObjectItem (credential_obj, "up");
  const char *username =
    cJSON_GetStringValue (cJSON_GetObjectItem (auth_data, "username"));
  const char *password =
    cJSON_GetStringValue (cJSON_GetObjectItem (auth_data, "password"));

  assert_that (cJSON_IsObject (auth_data), is_true);
  assert_that (username, is_equal_to_string ("admin"));
  assert_that (password, is_equal_to_string ("admin"));

  container_image_credential_free (credential);
  cJSON_Delete (credentials);
}


/* Test suite. */
int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, container_image, container_image_add_credential_to_scan_json);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
