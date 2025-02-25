/* SPDX-FileCopyrightText: 2019-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "pwpolicy.c"

#include <cgreen/assertions.h>
#include <cgreen/cgreen.h>
#include <cgreen/constraint_syntax_helpers.h>
#include <cgreen/internal/c_assertions.h>
#include <cgreen/mocks.h>

Describe (pwpolicy);
BeforeEach (pwpolicy)
{
}

AfterEach (pwpolicy)
{
}

/* parse_pattern_line */

Ensure (pwpolicy, parse_pattern_line_allows)
{
  char *desc, *error, *line;

  desc = NULL;
  line = g_strdup ("password");
  error = parse_pattern_line (line, "test", 111, &desc, "passw0rd", "name");
  assert_that (error, is_null);
  g_free (desc);
  g_free (line);
}

Ensure (pwpolicy, parse_pattern_line_refuses)
{
  char *desc, *error, *line;

  desc = NULL;
  line = g_strdup ("password");
  error = parse_pattern_line (line, "test", 111, &desc, "password", "name");
  assert_that (error, is_not_null);
  g_free (desc);
  g_free (error);
  g_free (line);
}

Ensure (pwpolicy, parse_pattern_line_comment)
{
  char *desc, *error, *line;

  desc = NULL;
  line = g_strdup ("# password");
  error = parse_pattern_line (line, "test", 111, &desc, "password", "name");
  assert_that (error, is_null);
  g_free (desc);
  g_free (error);
  g_free (line);
}

/* Test suite. */
int
main (int argc, char **argv)
{
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, pwpolicy, parse_pattern_line_allows);
  add_test_with_context (suite, pwpolicy, parse_pattern_line_refuses);
  add_test_with_context (suite, pwpolicy, parse_pattern_line_comment);

  if (argc > 1)
    return run_single_test (suite, argv[1], create_text_reporter ());

  return run_test_suite (suite, create_text_reporter ());
}
