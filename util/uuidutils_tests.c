/* SPDX-FileCopyrightText: 2025 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "uuidutils.c"

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>

static bool
is_between (char value, char lower, char upper)
{
  return value >= lower && value <= upper;
}

Describe (uuidutils);
BeforeEach (uuidutils)
{
}

AfterEach (uuidutils)
{
}

/* gvm_uuid_make */

Ensure (uuidutils, gvm_uuid_make_returns_valid_string)
{
  char *uuid;

  uuid = gvm_uuid_make ();
  assert_that (uuid, is_not_null);
  assert_that (strlen (uuid), is_equal_to (36));
  free (uuid);
}

Ensure (uuidutils, gvm_uuid_make_generates_unique_values)
{
  char *uuid1, *uuid2;

  uuid1 = gvm_uuid_make ();
  uuid2 = gvm_uuid_make ();

  assert_that (uuid1, is_not_null);
  assert_that (uuid2, is_not_null);
  assert_that (uuid1, is_not_equal_to_string (uuid2));

  free (uuid1);
  free (uuid2);
}

Ensure (uuidutils, gvm_uuid_make_generates_valid_format)
{
  char *uuid;
  int i;

  uuid = gvm_uuid_make ();
  assert_that (uuid, is_not_null);

  // Check length
  assert_that (strlen (uuid), is_equal_to (36));

  // Check format: 8-4-4-4-12 hexadecimal characters with 4 hyphens
  for (i = 0; i < 36; i++)
    {
      if (i == 8 || i == 13 || i == 18 || i == 23)
        assert_that (uuid[i], is_equal_to ('-'));
      else
        assert_that (is_between (uuid[i], '0', '9')
                       || is_between (uuid[i], 'a', 'f'),
                     is_true);
    }

  free (uuid);
}

/* Test suite. */

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, uuidutils, gvm_uuid_make_returns_valid_string);
  add_test_with_context (suite, uuidutils,
                         gvm_uuid_make_generates_unique_values);
  add_test_with_context (suite, uuidutils,
                         gvm_uuid_make_generates_valid_format);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
