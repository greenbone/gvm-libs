/* SPDX-FileCopyrightText: 2025 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "logging.c"

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>
#include <fcntl.h>
#include <glib/gstdio.h>

Describe (logging);

BeforeEach (logging)
{
}

AfterEach (logging)
{
}

Ensure (logging, validate_check_log_file)
{
  gvm_logging_domain_t *log_domain_entry =
    gvm_logging_domain_new (g_strdup ("test"));
  assert_that (check_log_file (log_domain_entry), is_equal_to (0));

  gvm_logging_domain_set_log_file (log_domain_entry, g_strdup (""));
  assert_that (check_log_file (log_domain_entry), is_equal_to (0));

  gvm_logging_domain_set_log_file (log_domain_entry, g_strdup ("syslog"));
  assert_that (check_log_file (log_domain_entry), is_equal_to (0));

  gvm_logging_domain_set_log_file (log_domain_entry,
                                   g_strdup ("some-file.log"));
  assert_that (check_log_file (log_domain_entry), is_equal_to (0));
  assert_that (g_file_test ("some-file.log", G_FILE_TEST_EXISTS),
               is_equal_to (1));
  assert_that (g_remove ("some-file.log"), is_equal_to (0));

  gvm_logging_domain_set_log_file (log_domain_entry,
                                   g_strdup ("some-dir/some-file.log"));
  assert_that (check_log_file (log_domain_entry), is_equal_to (0));
  assert_that (g_file_test ("some-dir/some-file.log", G_FILE_TEST_EXISTS),
               is_equal_to (1));
  assert_that (g_remove ("some-dir/some-file.log"), is_equal_to (0));
  assert_that (g_rmdir ("some-dir"), is_equal_to (0));

  assert_that (g_mkdir_with_parents ("some-dir", 0700), is_equal_to (0));
  assert_that (g_creat ("some-dir/some-file.log", 0400), is_not_equal_to (-1));
  assert_that (check_log_file (log_domain_entry), is_equal_to (-1));
  assert_that (g_chmod ("some-dir/some-file.log", 0700), is_equal_to (0));
  assert_that (g_remove ("some-dir/some-file.log"), is_equal_to (0));
  assert_that (g_rmdir ("some-dir"), is_equal_to (0));

  gvm_logging_domain_free (log_domain_entry);
}

Ensure (logging, should_convert_level_int_from_string)
{
  assert_that (level_int_from_string (NULL), is_equal_to (0));
  assert_that (level_int_from_string (""), is_equal_to (0));

  assert_that (level_int_from_string ("error"),
               is_equal_to (G_LOG_LEVEL_ERROR));
  assert_that (level_int_from_string ("critical"),
               is_equal_to (G_LOG_LEVEL_CRITICAL));
  assert_that (level_int_from_string ("warning"),
               is_equal_to (G_LOG_LEVEL_WARNING));
  assert_that (level_int_from_string ("message"),
               is_equal_to (G_LOG_LEVEL_MESSAGE));
  assert_that (level_int_from_string ("info"), is_equal_to (G_LOG_LEVEL_INFO));
  assert_that (level_int_from_string ("debug"),
               is_equal_to (G_LOG_LEVEL_DEBUG));

  assert_that (level_int_from_string ("4"), is_equal_to (G_LOG_LEVEL_ERROR));
  assert_that (level_int_from_string ("8"), is_equal_to (G_LOG_LEVEL_CRITICAL));
  assert_that (level_int_from_string ("16"), is_equal_to (G_LOG_LEVEL_WARNING));
  assert_that (level_int_from_string ("32"), is_equal_to (G_LOG_LEVEL_MESSAGE));
  assert_that (level_int_from_string ("64"), is_equal_to (G_LOG_LEVEL_INFO));
  assert_that (level_int_from_string ("128"), is_equal_to (G_LOG_LEVEL_DEBUG));
  assert_that (level_int_from_string ("123"), is_equal_to (123));

  assert_that (level_int_from_string ("A"), is_equal_to (0));
}

Ensure (logging, should_convert_facility_int_from_string)
{
  assert_that (facility_int_from_string (NULL), is_equal_to (LOG_LOCAL0));
  assert_that (facility_int_from_string (""), is_equal_to (LOG_LOCAL0));

  assert_that (facility_int_from_string ("auth"), is_equal_to (LOG_AUTH));
  assert_that (facility_int_from_string ("authpriv"),
               is_equal_to (LOG_AUTHPRIV));
  assert_that (facility_int_from_string ("cron"), is_equal_to (LOG_CRON));
  assert_that (facility_int_from_string ("daemon"), is_equal_to (LOG_DAEMON));
  assert_that (facility_int_from_string ("ftp"), is_equal_to (LOG_FTP));
  assert_that (facility_int_from_string ("kern"), is_equal_to (LOG_KERN));
  assert_that (facility_int_from_string ("lpr"), is_equal_to (LOG_LPR));
  assert_that (facility_int_from_string ("mail"), is_equal_to (LOG_MAIL));
  assert_that (facility_int_from_string ("mark"), is_equal_to (INTERNAL_MARK));
  assert_that (facility_int_from_string ("news"), is_equal_to (LOG_NEWS));
  assert_that (facility_int_from_string ("syslog"), is_equal_to (LOG_SYSLOG));
  assert_that (facility_int_from_string ("user"), is_equal_to (LOG_USER));
  assert_that (facility_int_from_string ("uucp"), is_equal_to (LOG_UUCP));
  assert_that (facility_int_from_string ("local0"), is_equal_to (LOG_LOCAL0));
  assert_that (facility_int_from_string ("local1"), is_equal_to (LOG_LOCAL1));
  assert_that (facility_int_from_string ("local2"), is_equal_to (LOG_LOCAL2));
  assert_that (facility_int_from_string ("local3"), is_equal_to (LOG_LOCAL3));
  assert_that (facility_int_from_string ("local4"), is_equal_to (LOG_LOCAL4));
  assert_that (facility_int_from_string ("local5"), is_equal_to (LOG_LOCAL5));
  assert_that (facility_int_from_string ("local6"), is_equal_to (LOG_LOCAL6));
  assert_that (facility_int_from_string ("local7"), is_equal_to (LOG_LOCAL7));

  assert_that (facility_int_from_string (NULL), is_equal_to (LOG_LOCAL0));
  assert_that (facility_int_from_string ("unknown"), is_equal_to (LOG_LOCAL0));
}

Ensure (logging, should_load_log_configuration)
{
  gchar *config_file = "test_log_config.conf";
  GSList *log_config_list;

  /* Create a temporary configuration file */
  FILE *file = fopen (config_file, "w");
  assert_that (file, is_not_null);
  fprintf (file, "[*]\n"
                 "prepend=%%t %%s %%p - \n"
                 "separator=:\n"
                 "prepend_time_format=%%Y-%%m-%%d %%H:%%M:%%S\n"
                 "file=-\n"
                 "level=debug\n"
                 "syslog_facility=local0\n"
                 "syslog_ident=test_ident\n");
  fclose (file);

  /* Load the configuration */
  log_config_list = load_log_configuration (config_file);
  assert_that (log_config_list, is_not_null);

  /* Verify the configuration */
  gvm_logging_domain_t *log_domain_entry =
    (gvm_logging_domain_t *) log_config_list->data;
  assert_that (gvm_logging_domain_get_prepend_string (log_domain_entry),
               is_equal_to_string ("%t %s %p - "));
  assert_that (gvm_logging_domain_get_prepend_separator (log_domain_entry),
               is_equal_to_string (":"));
  assert_that (gvm_logging_domain_get_prepend_time_format (log_domain_entry),
               is_equal_to_string ("%Y-%m-%d %H:%M:%S"));
  assert_that (gvm_logging_domain_get_log_file (log_domain_entry),
               is_equal_to_string ("-"));
  assert_that (*gvm_logging_domain_get_default_level (log_domain_entry),
               is_equal_to (G_LOG_LEVEL_DEBUG));
  assert_that (gvm_logging_domain_get_syslog_facility (log_domain_entry),
               is_equal_to_string ("local0"));
  assert_that (gvm_logging_domain_get_syslog_ident (log_domain_entry),
               is_equal_to_string ("test_ident"));

  /* Clean up */
  free_log_configuration (log_config_list);
  g_remove (config_file);
}

static TestSuite *
logging_test_suite ()
{
  TestSuite *suite = create_test_suite ();
  add_test_with_context (suite, logging, validate_check_log_file);
  add_test_with_context (suite, logging, should_convert_level_int_from_string);
  add_test_with_context (suite, logging,
                         should_convert_facility_int_from_string);
  add_test_with_context (suite, logging, should_load_log_configuration);
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
