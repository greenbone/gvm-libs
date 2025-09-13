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

/* cmp_versions */

Ensure (versionutils, cmp_versions_basic_format_differences)
{
  char *version1, *version2;
  int result;

  version1 = "test";
  version2 = "test-1";
  result = cmp_versions (version1, version2);
  assert_that (result, is_less_than (0));
  assert_that (result, is_greater_than (-5));
}

Ensure (versionutils, cmp_versions_text_vs_numeric_parts)
{
  char *version1, *version2;
  int result;

  version1 = "beta-test-2";
  version2 = "test_1";
  result = cmp_versions (version1, version2);
  assert_that (result, is_greater_than (0));
}

Ensure (versionutils, cmp_versions_equivalent_formats)
{
  char *version1, *version2;
  int result;

  version1 = "beta-test-2";
  version2 = "test-2.beta";
  result = cmp_versions (version1, version2);
  assert_that (result, is_equal_to (0));
}

Ensure (versionutils, cmp_versions_undefined_text_parts)
{
  char *version1, *version2;
  int result;

  version1 = "test-2.beta";
  version2 = "test-2.a";
  result = cmp_versions (version1, version2);
  assert_that (result, is_equal_to (-5));
}

Ensure (versionutils, cmp_versions_text_vs_numeric)
{
  char *version1, *version2;
  int result;

  version1 = "test-2.beta";
  version2 = "test-2.1";
  result = cmp_versions (version1, version2);
  assert_that (result, is_equal_to (-1));
}

Ensure (versionutils, cmp_versions_release_candidate_vs_release)
{
  char *version1, *version2;
  int result;

  version1 = "test-2.release_candidate";
  version2 = "test-2";
  result = cmp_versions (version1, version2);
  assert_that (result, is_equal_to (-1));
}

Ensure (versionutils, cmp_versions_release_candidate_numeric_comparison)
{
  char *version1, *version2;
  int result;

  version1 = "test-2.release_candidate2";
  version2 = "test-2.release_candidate1";
  result = cmp_versions (version1, version2);
  assert_that (result, is_greater_than (0));
}

Ensure (versionutils, cmp_versions_release_candidate_text_comparison)
{
  char *version1, *version2;
  int result;

  version1 = "test-2.release_candidatea";
  version2 = "test-2.release_candidateb";
  result = cmp_versions (version1, version2);
  assert_that (result, is_equal_to (-5));
}

Ensure (versionutils, cmp_versions_date_format)
{
  char *version1, *version2;
  int result;

  version1 = "2024-06-24";
  version2 = "2024-06-23";
  result = cmp_versions (version1, version2);
  assert_that (result, is_greater_than (0));
}

/* Test suite. */

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, versionutils, cmp_versions_basic_format_differences);
  add_test_with_context (suite, versionutils, cmp_versions_text_vs_numeric_parts);
  add_test_with_context (suite, versionutils, cmp_versions_equivalent_formats);
  add_test_with_context (suite, versionutils, cmp_versions_undefined_text_parts);
  add_test_with_context (suite, versionutils, cmp_versions_text_vs_numeric);
  add_test_with_context (suite, versionutils, cmp_versions_release_candidate_vs_release);
  add_test_with_context (suite, versionutils, cmp_versions_release_candidate_numeric_comparison);
  add_test_with_context (suite, versionutils, cmp_versions_release_candidate_text_comparison);
  add_test_with_context (suite, versionutils, cmp_versions_date_format);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
