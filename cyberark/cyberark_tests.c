/* SPDX-FileCopyrightText: 2025 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "cyberark.c"

#include <cgreen/assertions.h>
#include <cgreen/cgreen.h>
#include <cgreen/constraint_syntax_helpers.h>
#include <cgreen/internal/c_assertions.h>
#include <cgreen/mocks.h>

Describe (cyberark);
BeforeEach (cyberark)
{
}
AfterEach (cyberark)
{
}

/* cyberark_build_query_string */

Ensure (cyberark, build_query_string_null_connector)
{
  assert_that (cyberark_build_query_string (NULL, "s", "f", "o"), is_null);
}

Ensure (cyberark, build_query_string_missing_app_id)
{
  cyberark_connector_t conn = cyberark_connector_new ();

  assert_that (cyberark_build_query_string (conn, "s", "f", "o"), is_null);
  cyberark_connector_free (conn);
}

Ensure (cyberark, build_query_string_missing_object)
{
  cyberark_connector_t conn = cyberark_connector_new ();

  conn->app_id = g_strdup ("app");
  assert_that (cyberark_build_query_string (conn, "s", "f", NULL), is_null);
  assert_that (cyberark_build_query_string (conn, "s", "f", ""), is_null);
  cyberark_connector_free (conn);
}

Ensure (cyberark, build_query_string_builds)
{
  cyberark_connector_t conn = cyberark_connector_new ();
  const gchar *expected = "?AppID=app&Query=object=o;safe=s;folder=f";
  gchar *query;

  conn->app_id = g_strdup ("app");
  query = cyberark_build_query_string (conn, "s", "f", "o");
  assert_that (query, is_equal_to_string (expected));
  g_free (query);
  cyberark_connector_free (conn);
}

Ensure (cyberark, build_query_string_escapes)
{
  cyberark_connector_t conn = cyberark_connector_new ();
  gchar *query;

  conn->app_id = g_strdup ("my app");
  query = cyberark_build_query_string (conn, NULL, NULL, "o");
  assert_that (query, is_equal_to_string ("?AppID=my%20app&Query=object=o"));
  g_free (query);
  cyberark_connector_free (conn);
}

/* cyberark_connector_builder */

Ensure (cyberark, builder_set_twice_does_not_leak)
{
  cyberark_connector_t conn = cyberark_connector_new ();
  cyberark_error_t rc;

  rc = cyberark_connector_builder (conn, CYBERARK_HOST, "host-1");
  assert_that (rc, is_equal_to (CYBERARK_OK));
  rc = cyberark_connector_builder (conn, CYBERARK_HOST, "host-2");
  assert_that (rc, is_equal_to (CYBERARK_OK));
  cyberark_connector_free (conn);
}

/* parse_cyberark_object */

Ensure (cyberark, parse_object_valid)
{
  cJSON *json = cJSON_Parse ("{\"username\":\"u\",\"content\":\"c\","
                             "\"passwordchangeinprocess\":\"true\"}");
  cyberark_object_t object;

  object = parse_cyberark_object (json);
  assert_that (object, is_not_null);
  assert_that (object->username, is_equal_to_string ("u"));
  assert_that (object->content, is_equal_to_string ("c"));
  assert_that (object->password_change_in_process, is_equal_to (1));
  cyberark_object_free (object);
  cJSON_Delete (json);
}

Ensure (cyberark, parse_object_missing_required_field)
{
  cJSON *json = cJSON_Parse ("{\"username\":\"u\"}");

  assert_that (parse_cyberark_object (json), is_null);
  cJSON_Delete (json);
}

/* parse_cyberark_error */

Ensure (cyberark, parse_error_returns_error_code)
{
  gchar *error = parse_cyberark_error ("{\"ErrorCode\":\"ABC123\"}");

  assert_that (error, is_equal_to_string ("ABC123"));
  g_free (error);
}

Ensure (cyberark, parse_error_invalid_input)
{
  assert_that (parse_cyberark_error ("not json"), is_null);
  assert_that (parse_cyberark_error (NULL), is_null);
}

/* Test suite. */

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, cyberark, build_query_string_null_connector);
  add_test_with_context (suite, cyberark, build_query_string_missing_app_id);
  add_test_with_context (suite, cyberark, build_query_string_missing_object);
  add_test_with_context (suite, cyberark, build_query_string_builds);
  add_test_with_context (suite, cyberark, build_query_string_escapes);
  add_test_with_context (suite, cyberark, builder_set_twice_does_not_leak);
  add_test_with_context (suite, cyberark, parse_object_valid);
  add_test_with_context (suite, cyberark, parse_object_missing_required_field);
  add_test_with_context (suite, cyberark, parse_error_returns_error_code);
  add_test_with_context (suite, cyberark, parse_error_invalid_input);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
