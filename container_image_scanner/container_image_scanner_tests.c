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

Ensure (container_image, null_free_doesnt_crash)
{
  container_image_target_free (NULL);
  container_image_credential_free (NULL);
}

Ensure (container_image, new_container_image_target_has_hosts)
{
  container_image_target_t *target = container_image_target_new (NULL, NULL, NULL);

  assert_that (target, is_not_equal_to (NULL));
  assert_that (target->scan_id, is_equal_to (NULL));
  assert_that (target->hosts, is_equal_to (NULL));
  assert_that (target->exclude_hosts, is_equal_to (NULL));
  container_image_target_free (target);

  const gchar *scanid = "TEST-SCAN-ID";
  const gchar *hosts = "oci://test/path,oci://test2/path";
  const gchar *exclude_hosts = "oci://exclude/path";
  target = container_image_target_new (scanid, hosts, exclude_hosts);

  assert_that (target, is_not_equal_to (NULL));
  assert_that (target->scan_id, is_equal_to_string (scanid));
  assert_that (target->hosts, is_equal_to_string (hosts));
  assert_that (target->exclude_hosts, is_equal_to_string (exclude_hosts));
  container_image_target_free (target);
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

Ensure (container_image, container_image_credential_set_valid_auth_data)
{
  container_image_credential_t *credential =
    container_image_credential_new ("up", "generic");

  container_image_credential_set_auth_data (credential, "username", "password");
  container_image_credential_set_auth_data (credential, "temp", "test");

  assert_that (g_hash_table_size (credential->auth_data), is_equal_to (2));

  assert_that (g_hash_table_contains (credential->auth_data, "username"),
               is_true);
  assert_that (g_hash_table_contains (credential->auth_data, "temp"), is_true);

  container_image_credential_set_auth_data (credential, "temp", NULL);

  assert_that (g_hash_table_size (credential->auth_data), is_equal_to (1));
  assert_that (g_hash_table_contains (credential->auth_data, "temp"), is_false);

  container_image_credential_free (credential);
}

Ensure (container_image, container_image_credential_set_invalid_auth_data)
{
  container_image_credential_t *credential =
    container_image_credential_new ("up", "generic");

  // NULL values
  container_image_credential_set_auth_data (NULL, NULL, NULL);
  container_image_credential_set_auth_data (NULL, "name", NULL);
  container_image_credential_set_auth_data (NULL, "name", "value");
  container_image_credential_set_auth_data (credential, NULL, NULL);
  container_image_credential_set_auth_data (credential, NULL, "value");

  // Invalid names
  container_image_credential_set_auth_data (credential, "_$", "123");
  container_image_credential_set_auth_data (credential, "\x00", "123");
  container_image_credential_set_auth_data (credential, "\xFF", "123"); //fails
  container_image_credential_set_auth_data (credential, "AlmostValid\x7E",
                                            "123");

  assert_that (g_hash_table_size (credential->auth_data), is_equal_to (0));

  container_image_credential_free (credential);
}

Ensure (container_image, container_image_add_preferences_to_scan_json)
{
  const gchar *key1 = "test1";
  const gchar *value1 = "123";

  const gchar *key2 = "test2";
  const gchar *value2 = "456";

  cJSON *scan_prefs_array = cJSON_CreateArray ();

  add_scan_preferences_to_scan_json ((gpointer) key1, (gpointer) value1,
                                     scan_prefs_array);
  add_scan_preferences_to_scan_json ((gpointer) key2, (gpointer) value2,
                                     scan_prefs_array);

  const cJSON *test1 = cJSON_GetArrayItem (scan_prefs_array, 0);
  const cJSON *test2 = cJSON_GetArrayItem (scan_prefs_array, 1);

  assert_that (cJSON_IsObject (test1), is_true);
  assert_that (cJSON_IsObject (test2), is_true);

  assert_that (cJSON_GetStringValue (cJSON_GetObjectItem (test1, "id")),
               is_equal_to_string (key1));
  assert_that (cJSON_GetStringValue (cJSON_GetObjectItem (test1, "value")),
               is_equal_to_string (value1));

  assert_that (cJSON_GetStringValue (cJSON_GetObjectItem (test2, "id")),
               is_equal_to_string (key2));
  assert_that (cJSON_GetStringValue (cJSON_GetObjectItem (test2, "value")),
               is_equal_to_string (value2));

  cJSON_Delete (scan_prefs_array);
}

Ensure (container_image, container_image_target_add_credentials)
{
  container_image_target_t *target
    = container_image_target_new (NULL, "hosts", NULL);

  container_image_credential_t *credential =
    container_image_credential_new ("test", "generic");

  // Invalid calls, no credentials added
  container_image_target_add_credential (NULL, NULL);
  container_image_target_add_credential (target, NULL);
  container_image_target_add_credential (NULL, credential);

  container_image_credential_free (credential);

  // Add valid credentials
  container_image_target_add_credential (
    target, container_image_credential_new (NULL, NULL));
  container_image_target_add_credential (
    target, container_image_credential_new ("up", "generic"));
  container_image_target_add_credential (
    target, container_image_credential_new ("ssh", NULL));
  container_image_target_add_credential (
    target, container_image_credential_new (NULL, "docker"));

  assert_that (g_slist_length (target->credentials), is_equal_to (4));

  container_image_target_free (target);
}

Ensure (container_image, emit_simple_scan_json)
{
  container_image_target_t *target =
    container_image_target_new ("TEST-ID", "oci://test-host/test-image",
                                "oci://exclude/path");

  container_image_credential_t *credential =
    container_image_credential_new ("up", "generic");
  container_image_credential_set_auth_data (credential, "username", "password");

  container_image_target_add_credential (target, credential);

  GHashTable *preferences = g_hash_table_new (g_str_hash, g_str_equal);
  g_hash_table_insert (preferences, "accept_invalid_certs", "true");

  gchar *json = container_image_build_scan_config_json (target, preferences);

  assert_that (json, is_equal_to_string (
                       "{\n"
                       "\t\"scan_id\":\t\"TEST-ID\",\n"
                       "\t\"target\":\t{\n"
                       "\t\t\"hosts\":\t[\"oci://test-host/test-image\"],\n"
                       "\t\t\"excluded_hosts\":\t[\"oci://exclude/path\"],\n"
                       "\t\t\"credentials\":\t[{\n"
                       "\t\t\t\t\"service\":\t\"generic\",\n"
                       "\t\t\t\t\"up\":\t{\n"
                       "\t\t\t\t\t\"username\":\t\"password\"\n"
                       "\t\t\t\t}\n"
                       "\t\t\t}]\n"
                       "\t},\n"
                       "\t\"scan_preferences\":\t[{\n"
                       "\t\t\t\"id\":\t\"accept_invalid_certs\",\n"
                       "\t\t\t\"value\":\t\"true\"\n"
                       "\t\t}]\n"
                       "}"));

  g_free (json);
  g_hash_table_destroy (preferences);
  container_image_target_free (target);
}

/* Test suite. */
int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, container_image, null_free_doesnt_crash);
  add_test_with_context (suite, container_image,
                         new_container_image_target_has_hosts);
  add_test_with_context (suite, container_image,
                         container_image_add_credential_to_scan_json);
  add_test_with_context (suite, container_image,
                         container_image_credential_set_valid_auth_data);
  add_test_with_context (suite, container_image,
                         container_image_credential_set_invalid_auth_data);
  add_test_with_context (suite, container_image,
                         container_image_add_preferences_to_scan_json);
  add_test_with_context (suite, container_image,
                         container_image_target_add_credentials);
  add_test_with_context (suite, container_image, emit_simple_scan_json);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
