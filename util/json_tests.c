/* SPDX-FileCopyrightText: 2019-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "json.c"

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>
#include <stdio.h>

Describe (json);
BeforeEach (json)
{
}
AfterEach (json)
{
}

/* gvm_json_string_escape */

Ensure (json, can_json_escape_strings)
{
  const char *unescaped_string = "\"'Abc\\\b\f\n\r\t\001Äöü'\"";
  const char *escaped_string_dq = "\\\"'Abc\\\\\\b\\f\\n\\r\\t\\u0001Äöü'\\\"";
  const char *escaped_string_sq = "\"\\'Abc\\\\\\b\\f\\n\\r\\t\\u0001Äöü\\'\"";

  gchar *escaped_string = NULL;
  escaped_string = gvm_json_string_escape (NULL, FALSE);
  assert_that (escaped_string, is_null);

  escaped_string = gvm_json_string_escape (unescaped_string, FALSE);
  assert_that (escaped_string, is_equal_to_string (escaped_string_dq));
  g_free (escaped_string);

  escaped_string = gvm_json_string_escape (unescaped_string, TRUE);
  assert_that (escaped_string, is_equal_to_string (escaped_string_sq));
  g_free (escaped_string);
}

/* gvm_json_obj_double */

Ensure (json, gvm_json_obj_double_gets_value)
{
  cJSON *json;
  double d;

  json = cJSON_Parse ("{ \"eg\": 2.3 }");
  assert_that (json, is_not_null);
  d = gvm_json_obj_double (json, "eg");
  assert_that_double (d, is_equal_to_double (2.3));
}

Ensure (json, gvm_json_obj_double_0_when_missing)
{
  cJSON *json;
  double d;

  json = cJSON_Parse ("{ \"eg\": 2.3 }");
  assert_that (json, is_not_null);
  d = gvm_json_obj_double (json, "err");
  assert_that_double (d, is_equal_to_double (0));
}

/* gvm_json_obj_str */

Ensure (json, gvm_json_obj_str_gets_value)
{
  cJSON *json;
  const gchar *s;

  json = cJSON_Parse ("{ \"eg\": \"abc\" }");
  assert_that (json, is_not_null);
  s = gvm_json_obj_str (json, "eg");
  assert_that (s, is_equal_to_string ("abc"));
  cJSON_Delete (json);
}

Ensure (json, gvm_json_obj_str_null_when_missing)
{
  cJSON *json;
  const gchar *s;

  json = cJSON_Parse ("{ \"eg\": \"abc\" }");
  assert_that (json, is_not_null);
  s = gvm_json_obj_str (json, "err");
  assert_that (s, is_null);
  cJSON_Delete (json);
}

int
main (int argc, char **argv)
{
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, json, can_json_escape_strings);

  add_test_with_context (suite, json, gvm_json_obj_double_gets_value);
  add_test_with_context (suite, json, gvm_json_obj_double_0_when_missing);

  add_test_with_context (suite, json, gvm_json_obj_str_gets_value);
  add_test_with_context (suite, json, gvm_json_obj_str_null_when_missing);

  if (argc > 1)
    return run_single_test (suite, argv[1], create_text_reporter ());
  return run_test_suite (suite, create_text_reporter ());
}
