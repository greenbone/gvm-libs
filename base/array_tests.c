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
  assert_that (make_array (), is_not_null);
}

/* Test suite. */

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, array, make_array_never_returns_null);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
