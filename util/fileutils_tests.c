/* SPDX-FileCopyrightText: 2025 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "fileutils.c"

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>
#include <fcntl.h>
#include <glib.h>
#include <sys/stat.h>
#include <unistd.h>

Describe (fileutils);
BeforeEach (fileutils)
{
}

AfterEach (fileutils)
{
}

/* gvm_file_exists */

Ensure (fileutils, gvm_file_exists_returns_zero_for_nonexistent_file)
{
  assert_that (gvm_file_exists ("nonexistent_file"), is_equal_to (0));
}

Ensure (fileutils, gvm_file_exists_returns_one_for_existing_file)
{
  gchar *test_file = "test_file_exists.tmp";
  FILE *file = fopen (test_file, "w");
  assert_that (file, is_not_null);
  fclose (file);

  assert_that (gvm_file_exists (test_file), is_equal_to (1));

  g_remove (test_file);
}

/* gvm_file_is_executable */

Ensure (fileutils, gvm_file_is_executable_returns_zero_for_nonexistent_file)
{
  assert_that (gvm_file_is_executable ("nonexistent_file"), is_equal_to (0));
}

Ensure (fileutils, gvm_file_is_executable_returns_zero_for_non_executable_file)
{
  gchar *test_file = "test_file_not_executable.tmp";
  FILE *file = fopen (test_file, "w");
  assert_that (file, is_not_null);
  fputs ("test content", file);
  fclose (file);

  assert_that (gvm_file_is_executable (test_file), is_equal_to (0));

  g_remove (test_file);
}

/* gvm_file_is_readable */

Ensure (fileutils, gvm_file_is_readable_returns_zero_for_nonexistent_file)
{
  assert_that (gvm_file_is_readable ("nonexistent_file"), is_equal_to (0));
}

Ensure (fileutils, gvm_file_is_readable_returns_one_for_existing_file)
{
  gchar *test_file = "test_file_readable.tmp";
  FILE *file = fopen (test_file, "w");
  assert_that (file, is_not_null);
  fputs ("test content", file);
  fclose (file);

  assert_that (gvm_file_is_readable (test_file), is_equal_to (1));

  g_remove (test_file);
}

/* gvm_file_check_is_dir */

Ensure (fileutils, gvm_file_check_is_dir_returns_minus_one_for_nonexistent_path)
{
  assert_that (gvm_file_check_is_dir ("nonexistent_dir"), is_equal_to (-1));
}

Ensure (fileutils, gvm_file_check_is_dir_returns_zero_for_file)
{
  gchar *test_file = "test_file_not_dir.tmp";
  FILE *file = fopen (test_file, "w");
  assert_that (file, is_not_null);
  fclose (file);

  assert_that (gvm_file_check_is_dir (test_file), is_equal_to (0));

  g_remove (test_file);
}

Ensure (fileutils, gvm_file_check_is_dir_returns_one_for_directory)
{
  gchar *test_dir = "test_directory";
  assert_that (g_mkdir (test_dir, 0755), is_equal_to (0));

  assert_that (gvm_file_check_is_dir (test_dir), is_equal_to (1));

  g_rmdir (test_dir);
}

/* gvm_file_copy */

Ensure (fileutils, gvm_file_copy_returns_true_and_copies_file)
{
  gchar *source_file = "test_source_copy.tmp";
  gchar *dest_file = "test_dest_copy.tmp";

  FILE *file = fopen (source_file, "w");
  assert_that (file, is_not_null);
  fputs ("test content for copy", file);
  fclose (file);

  gboolean result = gvm_file_copy (source_file, dest_file);
  assert_that (result, is_equal_to (TRUE));

  assert_that (gvm_file_exists (dest_file), is_equal_to (1));

  gchar *content;
  g_file_get_contents (dest_file, &content, NULL, NULL);
  assert_that (content, is_equal_to_string ("test content for copy"));
  g_free (content);

  g_remove (source_file);
  g_remove (dest_file);
}

/* gvm_file_move */

Ensure (fileutils, gvm_file_move_returns_true_and_moves_file)
{
  gchar *source_file = "test_source_move.tmp";
  gchar *dest_file = "test_dest_move.tmp";

  FILE *file = fopen (source_file, "w");
  assert_that (file, is_not_null);
  fputs ("test content for move", file);
  fclose (file);

  gboolean result = gvm_file_move (source_file, dest_file);
  assert_that (result, is_equal_to (TRUE));

  assert_that (gvm_file_exists (source_file), is_equal_to (0));

  assert_that (gvm_file_exists (dest_file), is_equal_to (1));

  gchar *content;
  g_file_get_contents (dest_file, &content, NULL, NULL);
  assert_that (content, is_equal_to_string ("test content for move"));
  g_free (content);

  g_remove (dest_file);
}

/* gvm_file_as_base64 */

Ensure (fileutils, gvm_file_as_base64_returns_correct_base64_for_file)
{
  gchar *test_file = "test_base64.tmp";

  FILE *file = fopen (test_file, "w");
  assert_that (file, is_not_null);
  fputs ("Hello, World!", file);
  fclose (file);

  char *base64_content = gvm_file_as_base64 (test_file);

  assert_that (base64_content, is_not_null);
  assert_that (base64_content, is_equal_to_string ("SGVsbG8sIFdvcmxkIQ=="));

  g_free (base64_content);

  char *nonexistent_base64 = gvm_file_as_base64 ("nonexistent_file");
  assert_that (nonexistent_base64, is_null);

  g_remove (test_file);
}

/* gvm_export_file_name */

Ensure (fileutils, gvm_export_file_name_returns_formatted_string)
{
  gchar *file_name = gvm_export_file_name (
    "%N.%F", "user", "task", "12345678-1234-1234-1234-123456789012",
    "2023-01-01T12:00:00Z", "2023-01-02T12:00:00Z", "Test Task", "XML");

  assert_that (file_name, is_not_null);
  assert_that (file_name, contains_string ("Test_Task"));
  assert_that (file_name, contains_string ("XML"));

  g_free (file_name);

  file_name =
    gvm_export_file_name ("%N.%F", NULL, NULL, NULL, NULL, NULL, NULL, NULL);
  assert_that (file_name, is_not_null);

  g_free (file_name);
}

/* Test suite. */

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, fileutils,
                         gvm_file_exists_returns_zero_for_nonexistent_file);
  add_test_with_context (suite, fileutils,
                         gvm_file_exists_returns_one_for_existing_file);
  add_test_with_context (
    suite, fileutils, gvm_file_is_executable_returns_zero_for_nonexistent_file);
  add_test_with_context (
    suite, fileutils,
    gvm_file_is_executable_returns_zero_for_non_executable_file);
  add_test_with_context (
    suite, fileutils, gvm_file_is_readable_returns_zero_for_nonexistent_file);
  add_test_with_context (suite, fileutils,
                         gvm_file_is_readable_returns_one_for_existing_file);
  add_test_with_context (
    suite, fileutils,
    gvm_file_check_is_dir_returns_minus_one_for_nonexistent_path);
  add_test_with_context (suite, fileutils,
                         gvm_file_check_is_dir_returns_zero_for_file);
  add_test_with_context (suite, fileutils,
                         gvm_file_check_is_dir_returns_one_for_directory);
  add_test_with_context (suite, fileutils,
                         gvm_file_copy_returns_true_and_copies_file);
  add_test_with_context (suite, fileutils,
                         gvm_file_move_returns_true_and_moves_file);
  add_test_with_context (suite, fileutils,
                         gvm_file_as_base64_returns_correct_base64_for_file);
  add_test_with_context (suite, fileutils,
                         gvm_export_file_name_returns_formatted_string);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
