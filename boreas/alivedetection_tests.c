/* SPDX-FileCopyrightText: 2020-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "alivedetection.c"

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>

Describe (alivedetection);
BeforeEach (alivedetection)
{
}
AfterEach (alivedetection)
{
}

Ensure (alivedetection, dummy_test)
{
  assert_that (0, is_equal_to (0));
}

int
main (int argc, char **argv)
{
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, alivedetection, dummy_test);

  if (argc > 1)
    return run_single_test (suite, argv[1], create_text_reporter ());

  return run_test_suite (suite, create_text_reporter ());
}
