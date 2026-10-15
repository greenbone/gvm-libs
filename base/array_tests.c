/* SPDX-FileCopyrightText: 2009-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "array.c"

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>

Describe (array);
BeforeEach (array)
{
}
AfterEach (array)
{
}

/* make_array */

Ensure (array, make_array_never_returns_null)
{
  array_t *array;

  array = make_array ();
  assert_that (array, is_not_null);
  array_free (array);
}

/* array_add */

Ensure (array, array_add_appends_in_order)
{
  array_t *array;

  array = make_array ();
  array_add (array, g_strdup ("a"));
  array_add (array, g_strdup ("b"));
  assert_that (array->len, is_equal_to (2));
  assert_that (g_ptr_array_index (array, 0), is_equal_to_string ("a"));
  assert_that (g_ptr_array_index (array, 1), is_equal_to_string ("b"));
  array_free (array);
}

Ensure (array, array_add_null_array_is_noop)
{
  array_add (NULL, (gpointer) "a");
  assert_that (1, is_equal_to (1));
}

/* array_terminate */

Ensure (array, array_terminate_appends_null)
{
  array_t *array;

  array = make_array ();
  array_add (array, g_strdup ("a"));
  array_terminate (array);
  assert_that (array->len, is_equal_to (2));
  assert_that (g_ptr_array_index (array, 1), is_null);
  array_free (array);
}

/* array_reset */

Ensure (array, array_reset_empties_and_keeps_array)
{
  array_t *array;

  array = make_array ();
  array_add (array, g_strdup ("a"));
  array_reset (&array);
  assert_that (array, is_not_null);
  assert_that (array->len, is_equal_to (0));
  array_free (array);
}

/* array_free */

Ensure (array, array_free_null_is_noop)
{
  array_free (NULL);
  assert_that (1, is_equal_to (1));
}

/* Test suite. */

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, array, make_array_never_returns_null);
  add_test_with_context (suite, array, array_add_appends_in_order);
  add_test_with_context (suite, array, array_add_null_array_is_noop);
  add_test_with_context (suite, array, array_terminate_appends_null);
  add_test_with_context (suite, array, array_reset_empties_and_keeps_array);
  add_test_with_context (suite, array, array_free_null_is_noop);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
