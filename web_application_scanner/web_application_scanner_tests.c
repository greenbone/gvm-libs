/* SPDX-FileCopyrightText: 2025 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "web_application_scanner.c"

#include <cgreen/assertions.h>
#include <cgreen/cgreen.h>
#include <cgreen/constraint_syntax_helpers.h>
#include <cgreen/internal/c_assertions.h>
#include <cgreen/mocks.h>

Describe (web_application_scanner);
BeforeEach (web_application_scanner)
{
}

AfterEach (web_application_scanner)
{
}

Ensure (web_application_scanner, new_web_application_scanner_target_has_urls)
{
  web_scanner_target_t *target = web_scanner_target_new (NULL, NULL, NULL);

  assert_that (target, is_equal_to (NULL));
  web_scanner_target_free (target);

  const gchar *scanid = "TEST-SCAN-ID";
  const gchar *urls = "http://example.com1,http://example.com2";
  const gchar *exclude_urls = "http://exclude.example.com";
  target = web_scanner_target_new (scanid, urls, exclude_urls);

  assert_that (target, is_not_equal_to (NULL));
  assert_that (target->scan_id, is_equal_to_string (scanid));
  assert_that (target->urls, is_equal_to_string (urls));
  assert_that (target->exclude_urls, is_equal_to_string (exclude_urls));
  web_scanner_target_free (target);
}

Ensure (web_application_scanner,
        web_application_scanner_add_credential_to_scan_json)
{
  scan_credential_t *credential;
  cJSON *credentials = cJSON_CreateArray ();

  credential = scan_credential_new ("up", "generic", "123");

  scan_credential_set_auth_data (credential, "username", "admin");
  scan_credential_set_auth_data (credential, "password", "admin");

  add_credential_to_scan_json (credential, credentials);

  cJSON *credential_obj = cJSON_GetArrayItem (credentials, 0);
  assert_that (cJSON_IsObject (credential_obj), is_true);

  const char *service =
    cJSON_GetStringValue (cJSON_GetObjectItem (credential_obj, "service"));
  assert_that (service, is_equal_to_string ("generic"));

  int port =
    cJSON_GetNumberValue (cJSON_GetObjectItem (credential_obj, "port"));
  assert_that (port, is_equal_to (123));

  cJSON *auth_data = cJSON_GetObjectItem (credential_obj, "up");
  const char *username =
    cJSON_GetStringValue (cJSON_GetObjectItem (auth_data, "username"));
  const char *password =
    cJSON_GetStringValue (cJSON_GetObjectItem (auth_data, "password"));

  assert_that (cJSON_IsObject (auth_data), is_true);
  assert_that (username, is_equal_to_string ("admin"));
  assert_that (password, is_equal_to_string ("admin"));
  assert_that (port, is_equal_to (123));

  scan_credential_free (credential);
  cJSON_Delete (credentials);
}

Ensure (web_application_scanner,
        web_application_scanner_add_preferences_to_scan_json)
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

Ensure (web_application_scanner, web_application_scanner_target_add_credentials)
{
  web_scanner_target_t *target = web_scanner_target_new (NULL, "hosts", NULL);

  scan_credential_t *credential = scan_credential_new ("test", "generic", "0");

  // Invalid calls, no credentials added
  web_scanner_target_add_credential (NULL, NULL);
  web_scanner_target_add_credential (target, NULL);
  web_scanner_target_add_credential (NULL, credential);

  scan_credential_free (credential);

  // Add valid credentials
  web_scanner_target_add_credential (target,
                                     scan_credential_new (NULL, NULL, NULL));
  web_scanner_target_add_credential (
    target, scan_credential_new ("up", "generic", "0"));
  web_scanner_target_add_credential (target,
                                     scan_credential_new ("ssh", NULL, NULL));
  web_scanner_target_add_credential (target,
                                     scan_credential_new (NULL, "docker", "0"));

  assert_that (g_slist_length (target->credentials), is_equal_to (4));

  web_scanner_target_free (target);
}

Ensure (web_application_scanner, emit_simple_scan_json)
{
  web_scanner_target_t *target = web_scanner_target_new (
    "TEST-ID", "http://example1.com,http://example2.com",
    "http://exclude.example.com");

  scan_credential_t *credential = scan_credential_new ("up", "generic", NULL);
  scan_credential_set_auth_data (credential, "username", "password");

  web_scanner_target_add_credential (target, credential);

  GHashTable *preferences = g_hash_table_new (g_str_hash, g_str_equal);
  g_hash_table_insert (preferences, "key1", "true");

  gchar *json = web_scanner_build_scan_config_json (target, preferences, NULL);

  assert_that (
    json,
    is_equal_to_string (
      "{\n"
      "\t\"scan_id\":\t\"TEST-ID\",\n"
      "\t\"target\":\t{\n"
      "\t\t\"hosts\":\t[\"http://example1.com\", \"http://example2.com\"],\n"
      "\t\t\"excluded_hosts\":\t[\"http://exclude.example.com\"],\n"
      "\t\t\"credentials\":\t[{\n"
      "\t\t\t\t\"service\":\t\"generic\",\n"
      "\t\t\t\t\"up\":\t{\n"
      "\t\t\t\t\t\"username\":\t\"password\"\n"
      "\t\t\t\t}\n"
      "\t\t\t}]\n"
      "\t},\n"
      "\t\"scan_preferences\":\t[{\n"
      "\t\t\t\"id\":\t\"key1\",\n"
      "\t\t\t\"value\":\t\"true\"\n"
      "\t\t}],\n"
      "\t\"vts\":\t[]\n"
      "}"));

  g_free (json);
  g_hash_table_destroy (preferences);
  web_scanner_target_free (target);
}

/* Test suite. */
int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, web_application_scanner,
                         new_web_application_scanner_target_has_urls);
  add_test_with_context (suite, web_application_scanner,
                         web_application_scanner_add_credential_to_scan_json);
  add_test_with_context (suite, web_application_scanner,
                         web_application_scanner_add_preferences_to_scan_json);
  add_test_with_context (suite, web_application_scanner,
                         web_application_scanner_target_add_credentials);
  add_test_with_context (suite, web_application_scanner, emit_simple_scan_json);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
