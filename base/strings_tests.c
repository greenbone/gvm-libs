/* SPDX-FileCopyrightText: 2025 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "strings.c"

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>

Describe (strings);
BeforeEach (strings)
{
}
AfterEach (strings)
{
}

/* gvm_append_string */

Ensure (strings, gvm_append_string_appends_to_null_string)
{
  gchar *string = NULL;
  gvm_append_string (&string, "test");
  assert_that (string, is_equal_to_string ("test"));
  g_free (string);
}

Ensure (strings, gvm_append_string_appends_to_existing_string)
{
  gchar *string = g_strdup ("test");
  gvm_append_string (&string, "123");
  assert_that (string, is_equal_to_string ("test123"));
  g_free (string);
}

Ensure (strings, gvm_append_string_appends_empty_string)
{
  gchar *string = g_strdup ("test");
  gvm_append_string (&string, "");
  assert_that (string, is_equal_to_string ("test"));
  g_free (string);
}

/* gvm_append_text */

Ensure (strings, gvm_append_text_appends_to_null_string)
{
  gchar *string = NULL;
  gvm_append_text (&string, "test", 4);
  assert_that (string, is_equal_to_string ("test"));
  g_free (string);
}

Ensure (strings, gvm_append_text_appends_to_existing_string)
{
  gchar *string = g_strdup ("test");
  gvm_append_text (&string, "123", 3);
  assert_that (string, is_equal_to_string ("test123"));
  g_free (string);
}

Ensure (strings, gvm_append_text_appends_text_when_size_is_wrong)
{
  gchar *string = g_strdup ("test");
  // Size is supposed to be the length of the string, but it's only used when
  // the first arg is NULL.
  gvm_append_text (&string, "123456", 2);
  assert_that (string, is_equal_to_string ("test123456"));
  g_free (string);
}

Ensure (strings, gvm_append_text_appends_partial_to_null)
{
  gchar *string = NULL;
  gvm_append_text (&string, "123456", 2);
  // This only happens when the first arg is NULL. Size is supposed to be the
  // length of the string.
  assert_that (string, is_equal_to_string ("12"));
  g_free (string);
}

/* gvm_free_string_var */

Ensure (strings, gvm_free_string_var_frees_string)
{
  gchar *string = g_strdup ("test");
  gvm_free_string_var (&string);
  assert_that (string, is_null);
}

Ensure (strings, gvm_free_string_var_frees_null_string)
{
  gchar *string = NULL;
  gvm_free_string_var (&string);
  assert_that (string, is_null);
}

/* gvm_strip_space */

Ensure (strings, gvm_strip_space_strips_leading_spaces)
{
  char string[] = "  test";
  char *end = string + strlen (string);
  char *result = gvm_strip_space (string, end);
  assert_that (result, is_equal_to_string ("test"));
}

Ensure (strings, gvm_strip_space_strips_trailing_spaces)
{
  char string[] = "test  ";
  char *end = string + strlen (string);
  char *result = gvm_strip_space (string, end);
  assert_that (result, is_equal_to_string ("test"));
}

Ensure (strings, gvm_strip_space_strips_both_ends)
{
  char string[] = "  test  ";
  char *end = string + strlen (string);
  char *result = gvm_strip_space (string, end);
  assert_that (result, is_equal_to_string ("test"));
}

Ensure (strings, gvm_strip_space_strips_newlines)
{
  char string[] = "\ntest\n";
  char *end = string + strlen (string);
  char *result = gvm_strip_space (string, end);
  assert_that (result, is_equal_to_string ("test"));
}

Ensure (strings, gvm_strip_space_empty_string)
{
  char string[] = "";
  char *end = string + strlen (string);
  char *result = gvm_strip_space (string, end);
  assert_that (result, is_equal_to_string (""));
}

Ensure (strings, gvm_strip_space_only_spaces)
{
  char string[] = "   ";
  char *end = string + strlen (string);
  char *result = gvm_strip_space (string, end);
  assert_that (result, is_equal_to_string (""));
}

Ensure (strings, gvm_strip_space_no_spaces)
{
  char string[] = "test";
  char *end = string + strlen (string);
  char *result = gvm_strip_space (string, end);
  assert_that (result, is_equal_to_string ("test"));
}

/* Test suite. */

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, strings,
                         gvm_append_string_appends_to_null_string);
  add_test_with_context (suite, strings,
                         gvm_append_string_appends_to_existing_string);
  add_test_with_context (suite, strings,
                         gvm_append_string_appends_empty_string);

  add_test_with_context (suite, strings,
                         gvm_append_text_appends_to_null_string);
  add_test_with_context (suite, strings,
                         gvm_append_text_appends_to_existing_string);
  add_test_with_context (suite, strings,
                         gvm_append_text_appends_text_when_size_is_wrong);
  add_test_with_context (suite, strings,
                         gvm_append_text_appends_partial_to_null);

  add_test_with_context (suite, strings, gvm_free_string_var_frees_string);
  add_test_with_context (suite, strings, gvm_free_string_var_frees_null_string);

  add_test_with_context (suite, strings, gvm_strip_space_strips_leading_spaces);
  add_test_with_context (suite, strings,
                         gvm_strip_space_strips_trailing_spaces);
  add_test_with_context (suite, strings, gvm_strip_space_strips_both_ends);
  add_test_with_context (suite, strings, gvm_strip_space_strips_newlines);
  add_test_with_context (suite, strings, gvm_strip_space_empty_string);
  add_test_with_context (suite, strings, gvm_strip_space_only_spaces);
  add_test_with_context (suite, strings, gvm_strip_space_no_spaces);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
