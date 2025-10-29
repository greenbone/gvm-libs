/* SPDX-FileCopyrightText: 2025 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "../util/fileutils.h"
#include "pidfile.c"

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>
#include <glib.h>
#include <sys/stat.h>
#include <unistd.h>

Describe (pidfile);
BeforeEach (pidfile)
{
}

AfterEach (pidfile)
{
}

/* pidfile_create */

Ensure (pidfile, pidfile_create_returns_error_for_null_path)
{
  assert_that (pidfile_create (NULL), is_equal_to (-1));
}

Ensure (pidfile, pidfile_create_creates_file_with_correct_pid)
{
  gchar *test_pidfile = "test_pidfile.tmp";
  pid_t current_pid = getpid ();
  gchar *expected_content;
  gchar *actual_content;

  // Remove file if it exists
  g_remove (test_pidfile);

  assert_that (pidfile_create (test_pidfile), is_equal_to (0));

  // Check that file exists
  assert_that (gvm_file_exists (test_pidfile), is_equal_to (1));

  // Check that file contains correct PID
  expected_content = g_strdup_printf ("%d\n", current_pid);
  g_file_get_contents (test_pidfile, &actual_content, NULL, NULL);
  assert_that (actual_content, is_equal_to_string (expected_content));

  g_free (expected_content);
  g_free (actual_content);

  // Clean up
  g_remove (test_pidfile);
}

Ensure (pidfile, pidfile_create_creates_directory_if_needed)
{
  gchar *test_dir = "test_pid_dir";
  gchar *test_pidfile = "test_pid_dir/test_pidfile.tmp";

  // Remove directory if it exists
  g_rmdir (test_dir);

  assert_that (pidfile_create (test_pidfile), is_equal_to (0));

  // Check that directory exists
  assert_that (gvm_file_check_is_dir (test_dir), is_equal_to (1));

  // Check that file exists
  assert_that (gvm_file_exists (test_pidfile), is_equal_to (1));

  // Clean up
  g_remove (test_pidfile);
  g_rmdir (test_dir);
}

Ensure (pidfile, pidfile_create_returns_error_when_cannot_create_file)
{
  gchar *test_pidfile = "/invalid/path/test_pidfile.tmp";

  // This should fail as we can't write to /invalid/path
  assert_that (pidfile_create (test_pidfile), is_not_equal_to (0));
}

/* pidfile_remove */

Ensure (pidfile, pidfile_remove_deletes_file_with_matching_pid)
{
  gchar *test_pidfile = "test_pidfile_remove.tmp";
  pid_t current_pid = getpid ();
  gchar *pid_content;
  FILE *file;

  // Create a pidfile with current PID
  pid_content = g_strdup_printf ("%d\n", current_pid);
  file = fopen (test_pidfile, "w");
  assert_that (file, is_not_null);
  fputs (pid_content, file);
  fclose (file);

  // Verify file exists
  assert_that (gvm_file_exists (test_pidfile), is_equal_to (1));

  // Remove pidfile
  pidfile_remove (test_pidfile);

  // Verify file is deleted
  assert_that (gvm_file_exists (test_pidfile), is_equal_to (0));

  g_free (pid_content);
}

Ensure (pidfile, pidfile_remove_does_not_delete_file_with_different_pid)
{
  gchar *test_pidfile = "test_pidfile_remove_diff.tmp";
  pid_t current_pid = getpid ();
  pid_t different_pid = current_pid + 1;
  gchar *pid_content;
  FILE *file;

  // Create a pidfile with different PID
  pid_content = g_strdup_printf ("%d\n", different_pid);
  file = fopen (test_pidfile, "w");
  assert_that (file, is_not_null);
  fputs (pid_content, file);
  fclose (file);

  // Verify file exists
  assert_that (gvm_file_exists (test_pidfile), is_equal_to (1));

  // Try to remove pidfile (should not delete it)
  pidfile_remove (test_pidfile);

  // Verify file still exists
  assert_that (gvm_file_exists (test_pidfile), is_equal_to (1));

  // Clean up
  g_remove (test_pidfile);
  g_free (pid_content);
}

Ensure (pidfile, pidfile_remove_handles_nonexistent_file)
{
  gchar *test_pidfile = "nonexistent_pidfile.tmp";

  // Ensure file doesn't exist
  g_remove (test_pidfile);

  // Should not crash when trying to remove nonexistent file
  pidfile_remove (test_pidfile);

  // File should still not exist
  assert_that (gvm_file_exists (test_pidfile), is_equal_to (0));
}

/* Test suite. */

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, pidfile,
                         pidfile_create_returns_error_for_null_path);
  add_test_with_context (suite, pidfile,
                         pidfile_create_creates_file_with_correct_pid);
  add_test_with_context (suite, pidfile,
                         pidfile_create_creates_directory_if_needed);
  add_test_with_context (suite, pidfile,
                         pidfile_create_returns_error_when_cannot_create_file);
  add_test_with_context (suite, pidfile,
                         pidfile_remove_deletes_file_with_matching_pid);
  add_test_with_context (
    suite, pidfile, pidfile_remove_does_not_delete_file_with_different_pid);
  add_test_with_context (suite, pidfile,
                         pidfile_remove_handles_nonexistent_file);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
