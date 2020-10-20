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

/* roundup */

Ensure (cvss, roundup_succeeds)
{
  assert_that_double (roundup (0.0), is_equal_to_double (0.0));
  assert_that_double (roundup (1.0), is_equal_to_double (1.0));

  assert_that_double (roundup (1.01), is_equal_to_double (1.1));
  assert_that_double (roundup (0.99), is_equal_to_double (1.0));

  assert_that_double (roundup (1.000001), is_equal_to_double (1.0));
}

/* get_cvss_score_from_base_metrics */

#define CHECK(vector, score)                                               \
  assert_that_double (nearest (get_cvss_score_from_base_metrics (vector)), \
                      is_equal_to_double (score))

Ensure (cvss, get_cvss_score_from_base_metrics_null)
{
  assert_that (get_cvss_score_from_base_metrics (NULL), is_equal_to (-1.0));
}

double
nearest (double cvss)
{
  return round (cvss * 10) / 10;
}

Ensure (cvss, get_cvss_score_from_base_metrics_succeeds)
{
  CHECK ("AV:N/AC:L/Au:N/C:N/I:N/A:C", 7.8);
  CHECK ("AV:N/AC:L/Au:N/C:N/I:N/A:P", 5.0);
  CHECK ("AV:N/AC:M/Au:N/C:N/I:N/A:P", 4.3);
  CHECK ("AV:N/AC:L/Au:N/C:N/I:N/A:N", 0.0);
}

Ensure (cvss, get_cvss_score_from_base_metrics_succeeds_v3)
{
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N", 10.0);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N", 8.2);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N", 5.4);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:N/I:N/A:L", 3.5);
  CHECK ("CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:U/C:N/I:L/A:N", 2.4);

  CHECK ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5);
  CHECK ("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H", 5.5);
  CHECK ("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:L/A:N", 2.5);
}

Ensure (cvss, get_cvss_score_from_base_metrics_fails)
{
  CHECK ("", -1.0);
  CHECK ("xxx", -1.0);
  CHECK ("//////", -1.0);
}

/* Test suite. */

int
main (int argc, char **argv)
{
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, cvss, roundup_succeeds);

  add_test_with_context (suite, cvss, get_cvss_score_from_base_metrics_null);
  add_test_with_context (suite, cvss,
                         get_cvss_score_from_base_metrics_succeeds);
  add_test_with_context (suite, cvss, get_cvss_score_from_base_metrics_fails);
  add_test_with_context (suite, cvss,
                         get_cvss_score_from_base_metrics_succeeds_v3);

  if (argc > 1)
    return run_single_test (suite, argv[1], create_text_reporter ());

  return run_test_suite (suite, create_text_reporter ());
}
