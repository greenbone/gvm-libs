/* SPDX-FileCopyrightText: 2019-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "openvasd.c"

#include <cgreen/assertions.h>
#include <cgreen/cgreen.h>
#include <cgreen/constraint_syntax_helpers.h>
#include <cgreen/internal/c_assertions.h>
#include <cgreen/mocks.h>

Describe (openvasd);
BeforeEach (openvasd)
{
}

AfterEach (openvasd)
{
}

Ensure (openvasd, openvasd_add_credential_to_scan_json)
{
  openvasd_credential_t *credential;
  cJSON *credentials = cJSON_CreateArray ();

  credential = openvasd_credential_new ("up", "generic", "0");

  openvasd_credential_set_auth_data (credential, "username", "admin");
  openvasd_credential_set_auth_data (credential, "password", "admin");

  add_credential_to_scan_json (credential, credentials);

  cJSON *credential_obj = cJSON_GetArrayItem (credentials, 0);
  assert_that (cJSON_IsObject (credential_obj), is_true);

  const char *service =
    cJSON_GetStringValue (cJSON_GetObjectItem (credential_obj, "service"));
  assert_that (service, is_equal_to_string ("generic"));

  int port =
    cJSON_GetNumberValue (cJSON_GetObjectItem (credential_obj, "port"));
  assert_that (port, is_equal_to (0));

  cJSON *auth_data = cJSON_GetObjectItem (credential_obj, "up");
  const char *username =
    cJSON_GetStringValue (cJSON_GetObjectItem (auth_data, "username"));
  const char *password =
    cJSON_GetStringValue (cJSON_GetObjectItem (auth_data, "password"));

  assert_that (cJSON_IsObject (auth_data), is_true);
  assert_that (username, is_equal_to_string ("admin"));
  assert_that (password, is_equal_to_string ("admin"));

  openvasd_credential_free (credential);
  cJSON_Delete (credentials);
}

Ensure (openvasd, openvasd_add_port_to_scan_json)
{
  range_t *ports_range;
  cJSON *ports_range_array = cJSON_CreateArray ();

  ports_range = g_malloc0 (sizeof (range_t));

  ports_range->type = PORT_PROTOCOL_TCP;
  ports_range->start = 22;
  ports_range->end = 22;

  add_port_to_scan_json (ports_range, ports_range_array);

  cJSON *ports_obj = cJSON_GetArrayItem (ports_range_array, 0);

  const char *protocol =
    cJSON_GetStringValue (cJSON_GetObjectItem (ports_obj, "protocol"));

  assert_that (cJSON_IsObject (ports_obj), is_true);
  assert_that (protocol, is_equal_to_string ("tcp"));

  cJSON *range_array = cJSON_GetObjectItem (ports_obj, "range");

  assert_that (cJSON_IsArray (range_array), is_true);

  cJSON *range_obj = cJSON_GetArrayItem (range_array, 0);

  assert_that (cJSON_IsObject (range_obj), is_true);

  int start = cJSON_GetNumberValue (cJSON_GetObjectItem (range_obj, "start"));
  int end = cJSON_GetNumberValue (cJSON_GetObjectItem (range_obj, "end"));

  assert_that (start, is_equal_to (22));
  assert_that (end, is_equal_to (22));

  g_free (ports_range);
  cJSON_Delete (ports_range_array);
}

Ensure (openvasd, openvasd_add_vts_to_scan_json)
{
  openvasd_vt_single_t *vt;
  cJSON *vts_array = cJSON_CreateArray ();

  vt = openvasd_vt_single_new ("1.3.6.1.4.1.25623.1.0.877440");

  openvasd_vt_single_add_value (vt, "0", "bar");

  add_vts_to_scan_json (vt, vts_array);

  cJSON *vts_obj = cJSON_GetArrayItem (vts_array, 0);

  assert_that (cJSON_IsObject (vts_obj), is_true);

  const char *oid = cJSON_GetStringValue (cJSON_GetObjectItem (vts_obj, "oid"));

  assert_that (oid, is_equal_to_string ("1.3.6.1.4.1.25623.1.0.877440"));

  cJSON *params_array = cJSON_GetObjectItem (vts_obj, "parameters");

  assert_that (cJSON_IsArray (params_array), is_true);

  cJSON *param_obj = cJSON_GetArrayItem (params_array, 0);

  assert_that (cJSON_IsObject (param_obj), is_true);

  int id = cJSON_GetNumberValue (cJSON_GetObjectItem (param_obj, "id"));

  const char *value =
    cJSON_GetStringValue (cJSON_GetObjectItem (param_obj, "value"));

  assert_that (value, is_equal_to_string ("bar"));
  assert_that (id, is_equal_to (0));

  openvasd_vt_single_free (vt);
  cJSON_Delete (vts_array);
}

/* Test suite. */
int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, openvasd, openvasd_add_credential_to_scan_json);
  add_test_with_context (suite, openvasd, openvasd_add_port_to_scan_json);
  add_test_with_context (suite, openvasd, openvasd_add_vts_to_scan_json);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
