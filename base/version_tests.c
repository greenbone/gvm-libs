/* SPDX-FileCopyrightText: 2019-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "version.c"

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>

Describe (version);
BeforeEach (version)
{
}
AfterEach (version)
{
}

Ensure (version, gvm_libs_versions_returns_correct_version)
{
  assert_that (strcmp (gvm_libs_version (), GVM_LIBS_VERSION) == 0)
}

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, version,
                         gvm_libs_versions_returns_correct_version);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
