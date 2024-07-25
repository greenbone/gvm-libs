/* SPDX-FileCopyrightText: 2019-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "versionutils.c"

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>

Describe (versionutils);
BeforeEach (versionutils)
{
}

AfterEach (versionutils)
{
}

/* parse_entity */

Ensure (versionutils, cmp_versions)
{
  char *version1, *version2;
  int result;

  version1 = "test";
  version2 = "test-1";
  result = cmp_versions (version1, version2);
  assert_that (result, is_less_than (0));
  assert_that (result, is_greater_than (-5));

  version1 = "beta-test-2";
  version2 = "test_1";
  result = cmp_versions (version1, version2);
  assert_that (result, is_greater_than (0));

  version1 = "beta-test-2";
  version2 = "test-2.beta";
  result = cmp_versions (version1, version2);
  assert_that (result, is_equal_to (0));

  version1 = "test-2.beta";
  version2 = "test-2.a";
  result = cmp_versions (version1, version2);
  assert_that (result, is_equal_to (-5));

  version1 = "test-2.beta";
  version2 = "test-2.1";
  result = cmp_versions (version1, version2);
  assert_that (result, is_equal_to (-1));

  version1 = "test-2.release_candidate";
  version2 = "test-2";
  result = cmp_versions (version1, version2);
  assert_that (result, is_equal_to (-1));

  version1 = "test-2.release_candidate2";
  version2 = "test-2.release_candidate1";
  result = cmp_versions (version1, version2);
  assert_that (result, is_greater_than (0));

  version1 = "test-2.release_candidatea";
  version2 = "test-2.release_candidateb";
  result = cmp_versions (version1, version2);
  assert_that (result, is_equal_to (-5));
}

/* Test suite. */
int
main (int argc, char **argv)
{
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, versionutils, cmp_versions);

  if (argc > 1)
    return run_single_test (suite, argv[1], create_text_reporter ());

  return run_test_suite (suite, create_text_reporter ());
}
