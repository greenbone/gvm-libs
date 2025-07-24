/* SPDX-FileCopyrightText: 2020-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "ping.c"

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>

Describe (ping);
BeforeEach (ping)
{
}
AfterEach (ping)
{
}

Ensure (ping, dummy_test)
{
  assert_that (0, is_equal_to (0));
}

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, ping, dummy_test);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
