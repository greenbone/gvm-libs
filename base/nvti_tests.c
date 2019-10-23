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

#include "nvti.c"

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>

Describe (nvti);
BeforeEach (nvti)
{
}
AfterEach (nvti)
{
}

/* make_nvti */

Ensure (nvti, nvti_new_never_returns_null)
{
  assert_that (nvti_new (), is_not_null);
}

Ensure (nvti, nvtis_add_does_not_use_oid_as_key)
{
  nvtis_t *nvtis;
  nvti_t *nvti;
  gchar *oid;

  nvtis = nvtis_new ();

  nvti = nvti_new ();
  nvti_set_oid (nvti, "1");

  oid = nvti_oid (nvti);

  /* This should not use the pointer nvti->oid as the key, because nvti_set_oid
   * could free nvti->oid. */
  nvtis_add (nvtis, nvti);

  /* Change the first character of the OID. */
  *oid = '2';

  /* To check that the key is not the same pointer as nvti->oid, check
   * that changing the first character of nvti->oid did not affect the key. */
  assert_that (nvtis_lookup (nvtis, "1"), is_not_null);
  assert_that (nvtis_lookup (nvtis, "2"), is_null);
}

/* Test suite. */

int
main (int argc, char **argv)
{
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, nvti, nvti_new_never_returns_null);

  add_test_with_context (suite, nvti, nvtis_add_does_not_use_oid_as_key);

  if (argc > 1)
    return run_single_test (suite, argv[1], create_text_reporter ());

  return run_test_suite (suite, create_text_reporter ());
}
