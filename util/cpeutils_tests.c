/* SPDX-FileCopyrightText: 2019-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "cpeutils.c"

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>

static cpe_struct_t matching_source, matching_target;

Describe (cpeutils);
BeforeEach (cpeutils)
{
  cpe_struct_init (&matching_source);
  cpe_struct_init (&matching_target);
}

AfterEach (cpeutils)
{
  cpe_struct_free (&matching_source);
  cpe_struct_free (&matching_target);
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

Ensure (cpeutils, uri_cpe_to_uri_product)
{
  const char *uri_cpe;
  gchar *uri_product;

  uri_cpe = "cpe:/a:hp:insight_diagnostics:7.4.0.1570:-:~~online~win2003~x64~";

  uri_product = uri_cpe_to_uri_product (uri_cpe);
  assert_string_equal (uri_product, "cpe:/a:hp:insight_diagnostics");
  g_free (uri_product);
}

Ensure (cpeutils, fs_cpe_to_uri_cpe_accepts_end_star)
{
  char *result;

  result =
    fs_cpe_to_uri_cpe ("cpe:2.3:*:microsoft:foo*:8.0.6001:beta:*:*:*:*:*:*");
  assert_that (result, is_not_null);
  g_free (result);
}

Ensure (cpeutils, add_quoting_rejects_interior_star)
{
  char *result;

  result = add_quoting ("a*b");
  assert_that (result, is_null);
}

Ensure (cpeutils, add_quoting_rejects_interior_question)
{
  char *result;

  result = add_quoting ("a?b");
  assert_that (result, is_null);
}

Ensure (cpeutils, add_quoting_stops_at_trailing_backslash)
{
  char *result;

  result = add_quoting ("bar\\");
  assert_that (result, is_equal_to_string ("bar"));
  g_free (result);
}

Ensure (cpeutils, question_suffix_accepts_one_character_after_dot)
{
  gboolean matches;
  uri_cpe_to_cpe_struct ("cpe:/o:vendor:product:8.%01", &matching_source);
  uri_cpe_to_cpe_struct ("cpe:/o:vendor:product:8.1", &matching_target);

  matches = cpe_struct_match (&matching_source, &matching_target);

  assert_that (matches, is_true);
}

Ensure (cpeutils, question_suffix_rejects_two_characters_after_dot)
{
  gboolean matches;
  uri_cpe_to_cpe_struct ("cpe:/o:vendor:product:8.%01", &matching_source);
  uri_cpe_to_cpe_struct ("cpe:/o:vendor:product:8.12", &matching_target);

  matches = cpe_struct_match (&matching_source, &matching_target);

  assert_that (matches, is_false);
}

Ensure (cpeutils, literal_dotted_version_rejects_additional_character)
{
  gboolean matches;
  uri_cpe_to_cpe_struct ("cpe:/o:vendor:product:8.1", &matching_source);
  uri_cpe_to_cpe_struct ("cpe:/o:vendor:product:8.12", &matching_target);

  matches = cpe_struct_match (&matching_source, &matching_target);

  assert_that (matches, is_false);
}

Ensure (cpeutils, question_suffix_does_not_recount_escaped_prefix_characters)
{
  const struct
  {
    const char *source, *target;
  } cases[] = {
    {"8\\.?", "8\\.12"},   {"8\\-?", "8\\-12"}, {"8\\~?", "8\\~12"},
    {"8\\\\?", "8\\\\12"}, {"8\\??", "8\\?12"},
  };
  enum set_relation results[G_N_ELEMENTS (cases)];

  for (guint i = 0; i < G_N_ELEMENTS (cases); i++)
    results[i] = compare_strings (cases[i].source, cases[i].target);

  for (guint i = 0; i < G_N_ELEMENTS (cases); i++)
    assert_that (results[i], is_equal_to (DISJOINT));
}

Ensure (cpeutils, question_suffix_counts_only_unescaped_suffix_length)
{
  const struct
  {
    const char *target;
    enum set_relation expected;
  } cases[] = {
    {"8\\.1", SUPERSET},     {"8\\.\\-", SUPERSET},
    {"8\\.\\\\", SUPERSET},  {"8\\.\\-\\-", DISJOINT},
    {"8\\.\\\\1", DISJOINT}, {"8\\.\\\\\\\\", DISJOINT},
  };
  enum set_relation results[G_N_ELEMENTS (cases)];

  for (guint i = 0; i < G_N_ELEMENTS (cases); i++)
    results[i] = compare_strings ("8\\.?", cases[i].target);

  for (guint i = 0; i < G_N_ELEMENTS (cases); i++)
    assert_that (results[i], is_equal_to (cases[i].expected));
}

Ensure (cpeutils, leading_wildcards_preserve_question_suffix_length_limit)
{
  const struct
  {
    const char *source, *target;
    enum set_relation expected;
  } cases[] = {
    {"*8\\.?", "abc8\\.1", SUPERSET}, {"*8\\.?", "abc8\\.12", DISJOINT},
    {"?8\\.?", "a8\\.1", SUPERSET},   {"?8\\.?", "a8\\.12", DISJOINT},
    {"?8\\.?", "aa8\\.1", DISJOINT},  {"*8\\.?", "8\\.128\\.1", SUPERSET},
  };
  enum set_relation results[G_N_ELEMENTS (cases)];

  for (guint i = 0; i < G_N_ELEMENTS (cases); i++)
    results[i] = compare_strings (cases[i].source, cases[i].target);

  for (guint i = 0; i < G_N_ELEMENTS (cases); i++)
    assert_that (results[i], is_equal_to (cases[i].expected));
}

Ensure (cpeutils, suffix_wildcards_preserve_existing_length_limits)
{
  const struct
  {
    const char *source, *target;
    enum set_relation expected;
  } cases[] = {
    {"8?", "8", SUPERSET},
    {"8?", "81", SUPERSET},
    {"8?", "812", DISJOINT},
    {"8\\.??", "8\\.12", SUPERSET},
    {"8\\.??", "8\\.123", DISJOINT},
    {"8\\.*", "8\\.123", SUPERSET},
    {"8\\.*", "8\\.\\-\\-", SUPERSET},
    {"8\\.", "8\\.1", DISJOINT},
    {"8\\?", "8\\?1", DISJOINT},
  };
  enum set_relation results[G_N_ELEMENTS (cases)];

  for (guint i = 0; i < G_N_ELEMENTS (cases); i++)
    results[i] = compare_strings (cases[i].source, cases[i].target);

  for (guint i = 0; i < G_N_ELEMENTS (cases); i++)
    assert_that (results[i], is_equal_to (cases[i].expected));
}

/* Test suite. */
int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, cpeutils, uri_cpe_to_cpe_struct);
  add_test_with_context (suite, cpeutils, fs_cpe_to_cpe_struct);
  add_test_with_context (suite, cpeutils, cpe_struct_to_uri_cpe);
  add_test_with_context (suite, cpeutils, cpe_struct_to_fs_cpe);
  add_test_with_context (suite, cpeutils, uri_cpe_to_fs_cpe);
  add_test_with_context (suite, cpeutils, fs_cpe_to_uri_cpe);
  add_test_with_context (suite, cpeutils, cpe_struct_match);
  add_test_with_context (suite, cpeutils, uri_cpe_to_uri_product);
  add_test_with_context (suite, cpeutils, fs_cpe_to_uri_cpe_accepts_end_star);
  add_test_with_context (suite, cpeutils, add_quoting_rejects_interior_star);
  add_test_with_context (suite, cpeutils,
                         add_quoting_rejects_interior_question);
  add_test_with_context (suite, cpeutils,
                         add_quoting_stops_at_trailing_backslash);

  add_test_with_context (suite, cpeutils,
                         question_suffix_accepts_one_character_after_dot);
  add_test_with_context (suite, cpeutils,
                         question_suffix_rejects_two_characters_after_dot);
  add_test_with_context (suite, cpeutils,
                         literal_dotted_version_rejects_additional_character);
  add_test_with_context (
    suite, cpeutils,
    question_suffix_does_not_recount_escaped_prefix_characters);
  add_test_with_context (suite, cpeutils,
                         question_suffix_counts_only_unescaped_suffix_length);
  add_test_with_context (
    suite, cpeutils, leading_wildcards_preserve_question_suffix_length_limit);
  add_test_with_context (suite, cpeutils,
                         suffix_wildcards_preserve_existing_length_limits);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
