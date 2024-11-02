/* SPDX-FileCopyrightText: 2019-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "cpeutils.c"

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>

Describe (cpeutils);
BeforeEach (cpeutils)
{
}

AfterEach (cpeutils)
{
}

/* parse_entity */

Ensure (cpeutils, uri_cpe_to_cpe_struct)
{
  cpe_struct_t cpe;
  char *uri_cpe;

  uri_cpe = "cpe:/a:microsoft:internet_explorer:8.0.6001:beta";
  cpe_struct_init (&cpe);
  uri_cpe_to_cpe_struct (uri_cpe, &cpe);
  assert_that (cpe.part, is_equal_to_string ("a"));
  assert_that (cpe.vendor, is_equal_to_string ("microsoft"));
  assert_that (cpe.product, is_equal_to_string ("internet_explorer"));
  assert_that (cpe.version, is_equal_to_string ("8\\.0\\.6001"));
  assert_that (cpe.update, is_equal_to_string ("beta"));
  assert_that (cpe.edition, is_equal_to_string ("ANY"));
  assert_that (cpe.language, is_equal_to_string ("ANY"));
  cpe_struct_free (&cpe);

  uri_cpe = "cpe:/a:microsoft:internet_explorer:8.%2a:sp%3f";
  cpe_struct_init (&cpe);
  uri_cpe_to_cpe_struct (uri_cpe, &cpe);
  assert_that (cpe.part, is_equal_to_string ("a"));
  assert_that (cpe.vendor, is_equal_to_string ("microsoft"));
  assert_that (cpe.product, is_equal_to_string ("internet_explorer"));
  assert_that (cpe.version, is_equal_to_string ("8\\.\\*"));
  assert_that (cpe.update, is_equal_to_string ("sp\\?"));
  assert_that (cpe.edition, is_equal_to_string ("ANY"));
  assert_that (cpe.language, is_equal_to_string ("ANY"));
  cpe_struct_free (&cpe);

  uri_cpe = "cpe:/a:hp:insight_diagnostics:7.4.0.1570::~~online~win2003~x64~";
  cpe_struct_init (&cpe);
  uri_cpe_to_cpe_struct (uri_cpe, &cpe);
  assert_that (cpe.part, is_equal_to_string ("a"));
  assert_that (cpe.vendor, is_equal_to_string ("hp"));
  assert_that (cpe.product, is_equal_to_string ("insight_diagnostics"));
  assert_that (cpe.version, is_equal_to_string ("7\\.4\\.0\\.1570"));
  assert_that (cpe.update, is_equal_to_string ("ANY"));
  assert_that (cpe.edition, is_equal_to_string ("ANY"));
  assert_that (cpe.sw_edition, is_equal_to_string ("online"));
  assert_that (cpe.target_sw, is_equal_to_string ("win2003"));
  assert_that (cpe.target_hw, is_equal_to_string ("x64"));
  assert_that (cpe.other, is_equal_to_string ("ANY"));
  assert_that (cpe.language, is_equal_to_string ("ANY"));
  cpe_struct_free (&cpe);

  uri_cpe =
    "cpe:/a:hp:insight_diagnostics:7.4.0.1570::~~online~win2003~x64~other";
  cpe_struct_init (&cpe);
  uri_cpe_to_cpe_struct (uri_cpe, &cpe);
  assert_that (cpe.part, is_equal_to_string ("a"));
  assert_that (cpe.vendor, is_equal_to_string ("hp"));
  assert_that (cpe.product, is_equal_to_string ("insight_diagnostics"));
  assert_that (cpe.version, is_equal_to_string ("7\\.4\\.0\\.1570"));
  assert_that (cpe.update, is_equal_to_string ("ANY"));
  assert_that (cpe.edition, is_equal_to_string ("ANY"));
  assert_that (cpe.sw_edition, is_equal_to_string ("online"));
  assert_that (cpe.target_sw, is_equal_to_string ("win2003"));
  assert_that (cpe.target_hw, is_equal_to_string ("x64"));
  assert_that (cpe.other, is_equal_to_string ("other"));
  assert_that (cpe.language, is_equal_to_string ("ANY"));
  cpe_struct_free (&cpe);

  uri_cpe =
    "cpe:/"
    "a:hp:insight_diagnostics:7.4.0.1570::~~online~win2003~x64~other:english";
  cpe_struct_init (&cpe);
  uri_cpe_to_cpe_struct (uri_cpe, &cpe);
  assert_that (cpe.part, is_equal_to_string ("a"));
  assert_that (cpe.vendor, is_equal_to_string ("hp"));
  assert_that (cpe.product, is_equal_to_string ("insight_diagnostics"));
  assert_that (cpe.version, is_equal_to_string ("7\\.4\\.0\\.1570"));
  assert_that (cpe.update, is_equal_to_string ("ANY"));
  assert_that (cpe.edition, is_equal_to_string ("ANY"));
  assert_that (cpe.sw_edition, is_equal_to_string ("online"));
  assert_that (cpe.target_sw, is_equal_to_string ("win2003"));
  assert_that (cpe.target_hw, is_equal_to_string ("x64"));
  assert_that (cpe.other, is_equal_to_string ("other"));
  assert_that (cpe.language, is_equal_to_string ("english"));
  cpe_struct_free (&cpe);

  uri_cpe = "This is a ~:SIGNAL:~ test.";
  cpe_struct_init (&cpe);
  uri_cpe_to_cpe_struct (uri_cpe, &cpe);
  cpe_struct_free (&cpe);
}

Ensure (cpeutils, fs_cpe_to_cpe_struct)
{
  cpe_struct_t cpe;
  char *fs_cpe;

  fs_cpe = "cpe:2.3:a:microsoft:internet_explorer:8.0.6001:beta:*:*:*:*:*:*";
  cpe_struct_init (&cpe);
  fs_cpe_to_cpe_struct (fs_cpe, &cpe);
  assert_that (cpe.part, is_equal_to_string ("a"));
  assert_that (cpe.vendor, is_equal_to_string ("microsoft"));
  assert_that (cpe.product, is_equal_to_string ("internet_explorer"));
  assert_that (cpe.version, is_equal_to_string ("8\\.0\\.6001"));
  assert_that (cpe.update, is_equal_to_string ("beta"));
  assert_that (cpe.edition, is_equal_to_string ("ANY"));
  assert_that (cpe.language, is_equal_to_string ("ANY"));
  assert_that (cpe.sw_edition, is_equal_to_string ("ANY"));
  assert_that (cpe.target_sw, is_equal_to_string ("ANY"));
  assert_that (cpe.target_hw, is_equal_to_string ("ANY"));
  assert_that (cpe.other, is_equal_to_string ("ANY"));
  cpe_struct_free (&cpe);

  fs_cpe = "This is a ~:SIGNAL:~ test.";
  cpe_struct_init (&cpe);
  fs_cpe_to_cpe_struct (fs_cpe, &cpe);
  cpe_struct_free (&cpe);
}

Ensure (cpeutils, cpe_struct_to_uri_cpe)
{
  cpe_struct_t cpe;
  char *uri_cpe;

  cpe_struct_init (&cpe);
  cpe.part = "a";
  cpe.vendor = "microsoft";
  cpe.product = "internet_explorer";
  cpe.version = "8\\.0\\.6001";
  cpe.update = "beta";
  cpe.edition = "ANY";

  uri_cpe = cpe_struct_to_uri_cpe (&cpe);
  assert_that (uri_cpe, is_equal_to_string (
                          "cpe:/a:microsoft:internet_explorer:8.0.6001:beta"));
  g_free (uri_cpe);
}

Ensure (cpeutils, cpe_struct_to_fs_cpe)
{
  cpe_struct_t cpe;
  char *fs_cpe;

  cpe_struct_init (&cpe);
  cpe.part = "a";
  cpe.vendor = "microsoft";
  cpe.product = "internet_explorer";
  cpe.version = "8\\.0\\.6001";
  cpe.update = "beta";
  cpe.edition = "ANY";

  fs_cpe = cpe_struct_to_fs_cpe (&cpe);
  assert_that (
    fs_cpe,
    is_equal_to_string (
      "cpe:2.3:a:microsoft:internet_explorer:8.0.6001:beta:*:*:*:*:*:*"));
  g_free (fs_cpe);
}

Ensure (cpeutils, uri_cpe_to_fs_cpe)
{
  char *uri_cpe = "cpe:/a:microsoft:internet_explorer:8.0.6001:beta";
  char *fs_cpe = uri_cpe_to_fs_cpe (uri_cpe);
  assert_that (
    fs_cpe,
    is_equal_to_string (
      "cpe:2.3:a:microsoft:internet_explorer:8.0.6001:beta:*:*:*:*:*:*"));
  g_free (fs_cpe);

  uri_cpe = "cpe:/a:hp:insight_diagnostics:7.4.0.1570:-:~~online~win2003~x64~";
  fs_cpe = uri_cpe_to_fs_cpe (uri_cpe);
  assert_that (fs_cpe,
               is_equal_to_string ("cpe:2.3:a:hp:insight_diagnostics:7.4.0."
                                   "1570:-:*:*:online:win2003:x64:*"));
  g_free (fs_cpe);

  uri_cpe = "This is a ~:SIGNAL:~ test.";
  fs_cpe = uri_cpe_to_fs_cpe (uri_cpe);
  g_free (fs_cpe);
}

Ensure (cpeutils, fs_cpe_to_uri_cpe)
{
  char *fs_cpe =
    "cpe:2.3:a:microsoft:internet_explorer:8.0.6001:beta:*:*:*:*:*:*";
  char *uri_cpe = fs_cpe_to_uri_cpe (fs_cpe);
  assert_that (uri_cpe, is_equal_to_string (
                          "cpe:/a:microsoft:internet_explorer:8.0.6001:beta"));
  g_free (uri_cpe);

  fs_cpe =
    "cpe:2.3:a:hp:insight_diagnostics:7.4.0.1570:-:*:*:online:win2003:x64:*";
  uri_cpe = fs_cpe_to_uri_cpe (fs_cpe);
  assert_that (
    uri_cpe,
    is_equal_to_string (
      "cpe:/a:hp:insight_diagnostics:7.4.0.1570:-:~~online~win2003~x64~"));
  g_free (uri_cpe);

  fs_cpe =
    "cpe:2.3:a:hp:insight_diagnostics:7\\:4.0.1570:-:*:*:online:win2003:x64:*";
  uri_cpe = fs_cpe_to_uri_cpe (fs_cpe);
  assert_that (
    uri_cpe,
    is_equal_to_string (
      "cpe:/a:hp:insight_diagnostics:7%3A4.0.1570:-:~~online~win2003~x64~"));
  g_free (uri_cpe);

  fs_cpe =
    "cpe:2.3:a:hp:insight_diagnostics:7.4.0.1570:-:*:*:online:win\\:2003:x64:*";
  uri_cpe = fs_cpe_to_uri_cpe (fs_cpe);
  assert_that (
    uri_cpe,
    is_equal_to_string (
      "cpe:/a:hp:insight_diagnostics:7.4.0.1570:-:~~online~win%3A2003~x64~"));
  g_free (uri_cpe);

  fs_cpe = "cpe:2.3:a:hp:insight_diagnostics:7.4.0.1570:-:*:*:online:win\\:\\:"
           "2003:x64:*";
  uri_cpe = fs_cpe_to_uri_cpe (fs_cpe);
  assert_that (
    uri_cpe,
    is_equal_to_string (
      "cpe:/"
      "a:hp:insight_diagnostics:7.4.0.1570:-:~~online~win%3A%3A2003~x64~"));
  g_free (uri_cpe);

  fs_cpe = "cpe:2.3:a:hp:insight_diagnostics:7.4.0.1570:-:*:*:online:"
           "win2003\\\\:x64:*";
  uri_cpe = fs_cpe_to_uri_cpe (fs_cpe);
  assert_that (
    uri_cpe,
    is_equal_to_string (
      "cpe:/a:hp:insight_diagnostics:7.4.0.1570:-:~~online~win2003%5C~x64~"));
  g_free (uri_cpe);

  fs_cpe = "This is a ~:SIGNAL:~ test.";
  uri_cpe = fs_cpe_to_uri_cpe (fs_cpe);
  g_free (uri_cpe);
}

Ensure (cpeutils, cpe_struct_match)
{
  cpe_struct_t cpe1, cpe2;
  char *fs_cpe1, *fs_cpe2;

  fs_cpe1 = "cpe:2.3:a:microsoft:internet_explorer:8.0.6001:beta:*:*:*:*:*:*";
  cpe_struct_init (&cpe1);
  fs_cpe_to_cpe_struct (fs_cpe1, &cpe1);
  assert_that (cpe_struct_match (&cpe1, &cpe1), is_equal_to (TRUE));

  fs_cpe2 = "cpe:2.3:a:microsoft:internet_explorer:*:beta:*:*:*:*:*:*";
  cpe_struct_init (&cpe2);
  fs_cpe_to_cpe_struct (fs_cpe2, &cpe2);
  assert_that (cpe_struct_match (&cpe2, &cpe1), is_equal_to (TRUE));

  assert_that (cpe_struct_match (&cpe1, &cpe2), is_equal_to (FALSE));

  fs_cpe2 = "cpe:2.3:a:microsoft:internet_explorer:*:-:*:*:*:*:*:*";
  cpe_struct_free (&cpe2);
  cpe_struct_init (&cpe2);
  fs_cpe_to_cpe_struct (fs_cpe2, &cpe2);
  assert_that (cpe_struct_match (&cpe2, &cpe1), is_equal_to (FALSE));

  cpe_struct_free (&cpe1);
  cpe_struct_free (&cpe2);
}

/* Test suite. */
int
main (int argc, char **argv)
{
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, cpeutils, uri_cpe_to_cpe_struct);
  add_test_with_context (suite, cpeutils, fs_cpe_to_cpe_struct);
  add_test_with_context (suite, cpeutils, cpe_struct_to_uri_cpe);
  add_test_with_context (suite, cpeutils, cpe_struct_to_fs_cpe);
  add_test_with_context (suite, cpeutils, uri_cpe_to_fs_cpe);
  add_test_with_context (suite, cpeutils, fs_cpe_to_uri_cpe);
  add_test_with_context (suite, cpeutils, cpe_struct_match);

  if (argc > 1)
    return run_single_test (suite, argv[1], create_text_reporter ());

  return run_test_suite (suite, create_text_reporter ());
}
