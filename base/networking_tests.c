/* Copyright (C) 2009-2019 Greenbone Networks GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "networking.c"

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>

Describe (networking);
BeforeEach (networking)
{
}
AfterEach (networking)
{
}

Ensure (networking, validate_port_range)
{
  /* No port range provided. */
  assert_that (validate_port_range (NULL), is_equal_to (1));
  assert_that (validate_port_range (""), is_equal_to (1));

  /* '\0' on end. */
  assert_that (validate_port_range ("\0"), is_equal_to (1));
  assert_that (validate_port_range ("T:1-5,7,9,U:1-3,5,7,9,\\0"),
               is_equal_to (1));

  /* Newline in between range description.*/
  assert_that (validate_port_range ("\nT:1-\n5,7,9,\nU:1-3,5\n,7,9\n"),
               is_equal_to (1));

  /* Port <= 0 or Port > 65535. */
  assert_that (validate_port_range ("0"), is_equal_to (1));
  assert_that (validate_port_range ("-9"), is_equal_to (1));
  assert_that (validate_port_range ("1,0,6,7"), is_equal_to (1));
  assert_that (validate_port_range ("2,-9,4"), is_equal_to (1));
  assert_that (validate_port_range ("90000"), is_equal_to (1));

  /* Illegal Ranges. */
  assert_that (validate_port_range ("T:-"), is_equal_to (1));
  assert_that (validate_port_range ("T:-9"), is_equal_to (1));
  assert_that (validate_port_range ("T:0-"), is_equal_to (1));
  assert_that (validate_port_range ("T:0-9"), is_equal_to (1));
  assert_that (validate_port_range ("T:90000-"), is_equal_to (1));
  assert_that (validate_port_range ("T:90000-90010"), is_equal_to (1));
  assert_that (validate_port_range ("T:9-\\0"), is_equal_to (1));
  assert_that (validate_port_range ("T:9-0"), is_equal_to (1));
  assert_that (validate_port_range ("T:9-90000"), is_equal_to (1));
  assert_that (validate_port_range ("T:100-9"), is_equal_to (1));
  assert_that (validate_port_range ("0-"), is_equal_to (1));
  assert_that (validate_port_range ("0-9"), is_equal_to (1));
  assert_that (validate_port_range ("9-"), is_equal_to (1));
  assert_that (validate_port_range ("9-\\0"), is_equal_to (1));
  assert_that (validate_port_range ("9-8"), is_equal_to (1));
  assert_that (validate_port_range ("90000-90010"), is_equal_to (1));
  assert_that (validate_port_range ("100-9"), is_equal_to (1));
  assert_that (validate_port_range ("T,U"), is_equal_to (1));
  assert_that (validate_port_range ("T  :\n: 1-2,U"), is_equal_to (1));
  assert_that (validate_port_range ("T  :: 1-2,U"), is_equal_to (1));
  assert_that (validate_port_range ("T:2=2"), is_equal_to (1));

  /* Legal single ports.*/
  assert_that (validate_port_range ("6,6,6,6,10,20"), is_equal_to (0));
  assert_that (validate_port_range ("T:7, U:7"), is_equal_to (0));
  assert_that (validate_port_range ("T:7, U:9"), is_equal_to (0));
  assert_that (validate_port_range ("9"), is_equal_to (0));
  assert_that (validate_port_range ("U:,T:"), is_equal_to (0)); /* is ignored */
  assert_that (validate_port_range ("1,2,,,,,,,\n\n\n\n\n\n,,,5"),
               is_equal_to (0));

  /* Example in Documentation. */
  assert_that (validate_port_range ("T:1-5,7,9,U:1-3,5,7,9"), is_equal_to (0));

  /* Treat newlines like commas. */
  assert_that (validate_port_range ("1,2,\n,\n4,6"), is_equal_to (0));
  assert_that (validate_port_range ("T:1-5,7,9,\nU:1-3,5\n,7,9"),
               is_equal_to (0));

  /* Ranges without type specifier. */
  assert_that (validate_port_range ("6-9,7,7,10-20,20"), is_equal_to (0));

  /* Allow whitespace after T/U and anywhere else. */
  assert_that (
    validate_port_range ("   T: 1 -5,  7   ,9, \nU   :1-  3,5  \n,7,9"),
    is_equal_to (0));
  assert_that (validate_port_range (
                 "   T: 1 -5,  7   ,9, \nU :1- 3,5  \n,7,9, T    :  5 -7"),
               is_equal_to (0));
  assert_that (validate_port_range ("   T  : 1"), is_equal_to (0));
}

/* Test suite. */

int
main (int argc, char **argv)
{
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, networking, validate_port_range);

  if (argc > 1)
    return run_single_test (suite, argv[1], create_text_reporter ());

  return run_test_suite (suite, create_text_reporter ());
}
