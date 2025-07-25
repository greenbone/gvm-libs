/* SPDX-FileCopyrightText: 2009-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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

/* nvti solution_method */

Ensure (nvti, nvti_parse_timestamp)
{
  setenv ("TZ", "utc 0", 1);
  tzset ();

  assert_that (
    parse_nvt_timestamp ("2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018)"),
    is_equal_to (1536311311));
  assert_that_double (
    parse_nvt_timestamp ("2022-05-31 20:54:22 +0100 (Tue, 31 May 2022)"),
    is_equal_to_double (1654026862));
  assert_that_double (parse_nvt_timestamp ("2012-09-23 02:15:34 +0400"),
                      is_equal_to_double (1348352134));
  assert_that_double (parse_nvt_timestamp ("Fri Feb 10 16:09:30 2023 +0100"),
                      is_equal_to_double (1676041770));
}

/* nvti solution_method */

Ensure (nvti, nvti_set_solution_method_correct)
{
  nvti_t *nvti;
  gchar *solution_method;

  nvti = nvti_new ();
  nvti_set_solution_method (nvti, "DebianAPTUpgrade");
  solution_method = nvti_solution_method (nvti);

  assert_that (solution_method, is_equal_to_string ("DebianAPTUpgrade"));

  nvti_free (nvti);
}

/* nvti_get_tag */

Ensure (nvti, nvti_get_tag_gets_correct_value_one_tag)
{
  nvti_t *nvti;
  gchar *tag;

  nvti = nvti_new ();
  nvti_set_tag (nvti, "a=1");
  tag = nvti_get_tag (nvti, "a");

  assert_that (tag, is_equal_to_string ("1"));

  g_free (tag);
  nvti_free (nvti);
}

Ensure (nvti, nvti_get_tag_gets_correct_value_many_tags)
{
  nvti_t *nvti;
  gchar *tag;

  nvti = nvti_new ();
  nvti_set_tag (nvti, "a=1|b=2|c=3");
  tag = nvti_get_tag (nvti, "b");

  assert_that (tag, is_equal_to_string ("2"));

  g_free (tag);
  nvti_free (nvti);
}

Ensure (nvti, nvti_get_tag_handles_empty_tag)
{
  nvti_t *nvti;

  nvti = nvti_new ();

  assert_that (nvti_get_tag (nvti, "b"), is_null);

  nvti_free (nvti);
}

Ensure (nvti, nvti_get_tag_handles_null_nvti)
{
  assert_that (nvti_get_tag (NULL, "example"), is_null);
}

Ensure (nvti, nvti_get_tag_handles_null_name)
{
  nvti_t *nvti;

  nvti = nvti_new ();
  nvti_set_tag (nvti, "example=1");

  assert_that (nvti_get_tag (nvti, NULL), is_null);

  nvti_free (nvti);
}

/* nvtis_add */

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

/* nvti severity vector */

Ensure (nvti, nvti_get_severity_vector_both)
{
  nvti_t *nvti;

  nvti = nvti_new ();
  nvti_set_tag (nvti, "cvss_base_vector=DEF");
  nvti_set_tag (nvti, "severity_vector=ABC");

  assert_that (nvti_severity_vector_from_tag (nvti),
               is_equal_to_string ("ABC"));

  nvti_free (nvti);
}

Ensure (nvti, nvti_get_severity_vector_no_cvss_base)
{
  nvti_t *nvti;

  nvti = nvti_new ();
  nvti_set_tag (nvti, "severity_vector=ABC");

  assert_that (nvti_severity_vector_from_tag (nvti),
               is_equal_to_string ("ABC"));

  nvti_free (nvti);
}

Ensure (nvti, nvti_get_severity_vector_no_severity_vector)
{
  nvti_t *nvti;

  nvti = nvti_new ();
  nvti_set_tag (nvti, "cvss_base_vector=DEF");

  assert_that (nvti_severity_vector_from_tag (nvti),
               is_equal_to_string ("DEF"));

  nvti_free (nvti);
}

/* Test suite. */

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, nvti, nvti_new_never_returns_null);

  add_test_with_context (suite, nvti, nvti_get_tag_gets_correct_value_one_tag);
  add_test_with_context (suite, nvti,
                         nvti_get_tag_gets_correct_value_many_tags);
  add_test_with_context (suite, nvti, nvti_get_tag_handles_empty_tag);
  add_test_with_context (suite, nvti, nvti_get_tag_handles_null_nvti);
  add_test_with_context (suite, nvti, nvti_get_tag_handles_null_name);

  add_test_with_context (suite, nvti, nvti_set_solution_method_correct);

  add_test_with_context (suite, nvti, nvtis_add_does_not_use_oid_as_key);

  add_test_with_context (suite, nvti, nvti_get_severity_vector_both);
  add_test_with_context (suite, nvti,
                         nvti_get_severity_vector_no_severity_vector);
  add_test_with_context (suite, nvti, nvti_get_severity_vector_no_cvss_base);
  add_test_with_context (suite, nvti, nvti_parse_timestamp);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
