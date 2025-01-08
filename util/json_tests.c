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

int
main (int argc, char **argv)
{
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, json, can_json_escape_strings);

  if (argc > 1)
    return run_single_test (suite, argv[1], create_text_reporter ());
  return run_test_suite (suite, create_text_reporter ());
}
