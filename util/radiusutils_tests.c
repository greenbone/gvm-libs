/* SPDX-FileCopyrightText: 2019-2025 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "radiusutils.c"

#include <cgreen/assertions.h>
#include <cgreen/cgreen.h>
#include <cgreen/constraint_syntax_helpers.h>
#include <cgreen/internal/c_assertions.h>
#include <cgreen/mocks.h>

Describe (radiusutils);
BeforeEach (radiusutils)
{
}

AfterEach (radiusutils)
{
}

#define HOST "eghost"
#define SECRET "the_secret"

#ifdef ENABLE_RADIUS_AUTH

/* radius_init */

Ensure (radiusutils, radius_init)
{
  rc_handle *rh;

  rh = radius_init (HOST, SECRET);
  assert_that (rh, is_not_null);
}

#else

/* radius_authenticate */

Ensure (radiusutils, radius_authenticate_returns_minus1)
{
  assert_that (radius_authenticate ("h", "s", "u", "p"), is_equal_to (-1));
}

#endif

/* Test suite. */
int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

#ifdef ENABLE_RADIUS_AUTH
  add_test_with_context (suite, radiusutils, radius_init);
#else
  add_test_with_context (suite, radiusutils,
                         radius_authenticate_returns_minus1);
#endif

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
