/* SPDX-FileCopyrightText: 2025 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "logging_domain.c"

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>
#include <fcntl.h>
#include <glib/gstdio.h>

Describe (logging_domain);

BeforeEach (logging_domain)
{
}

AfterEach (logging_domain)
{
}

Ensure (logging_domain, should_initalize_logging_domain)
{
  gvm_logging_domain_t *log_domain_entry =
    gvm_logging_domain_new (g_strdup ("test"));

  assert_that (log_domain_entry, is_not_null);
  assert_that (gvm_logging_domain_get_log_domain (log_domain_entry),
               is_equal_to_string ("test"));
  assert_that (gvm_logging_domain_get_log_file (log_domain_entry), is_null);
  assert_that (gvm_logging_domain_get_prepend_string (log_domain_entry),
               is_null);
  assert_that (gvm_logging_domain_get_prepend_time_format (log_domain_entry),
               is_null);
  assert_that (gvm_logging_domain_get_default_level (log_domain_entry),
               is_null);
  assert_that (gvm_logging_domain_get_log_channel (log_domain_entry), is_null);
  assert_that (gvm_logging_domain_get_syslog_facility (log_domain_entry),
               is_null);
  assert_that (gvm_logging_domain_get_syslog_ident (log_domain_entry), is_null);
  assert_that (gvm_logging_domain_get_prepend_separator (log_domain_entry),
               is_null);

  gvm_logging_domain_free (log_domain_entry);
}

Ensure (logging_domain, should_allow_setting_properties)
{
  gvm_logging_domain_t *log_domain_entry =
    gvm_logging_domain_new (g_strdup ("test"));

  assert_that (log_domain_entry, is_not_null);
  assert_that (gvm_logging_domain_get_log_domain (log_domain_entry),
               is_equal_to_string ("test"));

  gvm_logging_domain_set_log_file (log_domain_entry, g_strdup ("logfile.log"));
  assert_that (gvm_logging_domain_get_log_file (log_domain_entry),
               is_equal_to_string ("logfile.log"));

  gvm_logging_domain_set_prepend_string (log_domain_entry,
                                         g_strdup ("prepend"));
  assert_that (gvm_logging_domain_get_prepend_string (log_domain_entry),
               is_equal_to_string ("prepend"));

  gvm_logging_domain_set_prepend_time_format (log_domain_entry,
                                              g_strdup ("%Y-%m-%d"));
  assert_that (gvm_logging_domain_get_prepend_time_format (log_domain_entry),
               is_equal_to_string ("%Y-%m-%d"));

  gvm_logging_domain_set_default_level (log_domain_entry, G_LOG_LEVEL_DEBUG);
  assert_that (*gvm_logging_domain_get_default_level (log_domain_entry),
               is_equal_to (G_LOG_LEVEL_DEBUG));

  GIOChannel *log_channel =
    g_io_channel_new_file ("log_channel.log", "w", NULL);
  gvm_logging_domain_set_log_channel (log_domain_entry, log_channel);
  assert_that (gvm_logging_domain_get_log_channel (log_domain_entry),
               is_equal_to (log_channel));

  gvm_logging_domain_set_syslog_facility (log_domain_entry, g_strdup ("user"));
  assert_that (gvm_logging_domain_get_syslog_facility (log_domain_entry),
               is_equal_to_string ("user"));

  gvm_logging_domain_set_syslog_ident (log_domain_entry, g_strdup ("ident"));
  assert_that (gvm_logging_domain_get_syslog_ident (log_domain_entry),
               is_equal_to_string ("ident"));

  gvm_logging_domain_set_prepend_separator (log_domain_entry, g_strdup ("|"));
  assert_that (gvm_logging_domain_get_prepend_separator (log_domain_entry),
               is_equal_to_string ("|"));

  gvm_logging_domain_free (log_domain_entry);
}

static TestSuite *
logging_test_suite ()
{
  TestSuite *suite = create_test_suite ();
  add_test_with_context (suite, logging_domain,
                         should_initalize_logging_domain);
  add_test_with_context (suite, logging_domain,
                         should_allow_setting_properties);
  return suite;
}

int
main (int argc, char **argv)
{
  TestSuite *suite;

  suite = create_test_suite ();
  add_suite (suite, logging_test_suite ());

  if (argc > 1)
    return run_single_test (suite, argv[1], create_text_reporter ());

  return run_test_suite (suite, create_text_reporter ());
}
