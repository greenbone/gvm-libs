/* Copyright (C) 2009-2020 Greenbone Networks GmbH
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

#include "cvss.c"

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>
#include <math.h>

Describe (cvss);
BeforeEach (cvss)
{
}
AfterEach (cvss)
{
}

/* get_cvss_score_from_base_metrics */

Ensure (cvss, get_cvss_score_from_base_metrics_null)
{
  assert_that (get_cvss_score_from_base_metrics (NULL), is_equal_to (-1.0));
}

double
nearest (double cvss)
{
  return round(cvss * 10) / 10;
}

Ensure (cvss, get_cvss_score_from_base_metrics_succeeds)
{
  assert_that_double (nearest (get_cvss_score_from_base_metrics ("AV:N/AC:L/Au:N/C:N/I:N/A:C")), is_equal_to_double (7.8));
  assert_that_double (nearest (get_cvss_score_from_base_metrics ("AV:N/AC:L/Au:N/C:N/I:N/A:P")), is_equal_to_double (5.0));
  assert_that_double (nearest (get_cvss_score_from_base_metrics ("AV:N/AC:M/Au:N/C:N/I:N/A:P")), is_equal_to_double (4.3));
  assert_that_double (nearest (get_cvss_score_from_base_metrics ("AV:N/AC:L/Au:N/C:N/I:N/A:N")), is_equal_to_double (0.0));
}

Ensure (cvss, get_cvss_score_from_base_metrics_fails)
{
  assert_that_double (nearest (get_cvss_score_from_base_metrics ("")), is_equal_to_double (-1.0));
  assert_that_double (nearest (get_cvss_score_from_base_metrics ("xxx")), is_equal_to_double (-1.0));
  assert_that_double (nearest (get_cvss_score_from_base_metrics ("//////")), is_equal_to_double (-1.0));
}

/* Test suite. */

int
main (int argc, char **argv)
{
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, cvss, get_cvss_score_from_base_metrics_null);
  add_test_with_context (suite, cvss, get_cvss_score_from_base_metrics_succeeds);
  add_test_with_context (suite, cvss, get_cvss_score_from_base_metrics_fails);

  if (argc > 1)
    return run_single_test (suite, argv[1], create_text_reporter ());

  return run_test_suite (suite, create_text_reporter ());
}
