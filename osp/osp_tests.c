/* Copyright (C) 2009-2021 Greenbone Networks GmbH
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

#include "osp.c"

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>

Describe (osp);
BeforeEach (osp)
{
}
AfterEach (osp)
{
}

Ensure (osp, osp_new_target_never_returns_null)
{
  assert_that (osp_target_new (NULL, NULL, NULL, 0, 0, 0), is_not_null);
}

Ensure (osp, osp_new_conn_ret_null)
{
  assert_that (osp_connection_new ("/my/socket", 0, NULL, NULL, NULL), is_null);
}

Ensure (osp, osp_get_vts_no_vts_ret_error)
{
  osp_connection_t *conn = g_malloc0 (sizeof (*conn));
  assert_that (osp_get_vts (conn, NULL), is_equal_to (1));
}

Ensure (osp, osp_get_vts_no_conn_ret_error)
{
  assert_that (osp_get_vts (NULL, NULL), is_equal_to (1));
}
/* Test suite. */

int
main (int argc, char **argv)
{
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, osp, osp_new_target_never_returns_null);
  add_test_with_context (suite, osp, osp_get_vts_no_conn_ret_error);
  add_test_with_context (suite, osp, osp_get_vts_no_vts_ret_error);
  add_test_with_context (suite, osp, osp_new_conn_ret_null);

  if (argc > 1)
    return run_single_test (suite, argv[1], create_text_reporter ());

  return run_test_suite (suite, create_text_reporter ());
}
