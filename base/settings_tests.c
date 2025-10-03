/* SPDX-FileCopyrightText: 2025 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "settings.c"

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <stdio.h>
#include <unistd.h>

Describe (settings);

BeforeEach (settings)
{
}

AfterEach (settings)
{
}

Ensure (settings, init_settings_iterator_from_file_with_null_params)
{
  settings_iterator_t iterator;
  int ret;

  // Test with NULL filename
  ret = init_settings_iterator_from_file (&iterator, NULL, "group");
  assert_that (ret, is_equal_to (-1));

  // Test with NULL group
  ret = init_settings_iterator_from_file (&iterator, "filename", NULL);
  assert_that (ret, is_equal_to (-1));

  // Test with both NULL
  ret = init_settings_iterator_from_file (&iterator, NULL, NULL);
  assert_that (ret, is_equal_to (-1));
}

Ensure (settings, init_settings_iterator_from_nonexistent_file)
{
  settings_iterator_t iterator;
  int ret;

  ret = init_settings_iterator_from_file (&iterator, "nonexistent.conf", "group");
  assert_that (ret, is_equal_to (-1));
}

Ensure (settings, init_settings_iterator_from_valid_file)
{
  settings_iterator_t iterator;
  int ret;
  gchar *config_file = "test_settings.conf";
  FILE *file;

  // Create a temporary configuration file
  file = fopen (config_file, "w");
  assert_that (file, is_not_null);
  fprintf (file, "key1=value1\nkey2=value2\nkey3=value3\n");
  fclose (file);

  // Initialize iterator from file
  ret = init_settings_iterator_from_file (&iterator, config_file, "Misc");
  assert_that (ret, is_equal_to (0));

  // Clean up
  cleanup_settings_iterator (&iterator);
  g_remove (config_file);
}

Ensure (settings, settings_iterator_operations)
{
  settings_iterator_t iterator;
  int ret;
  gchar *config_file = "test_settings.conf";
  FILE *file;
  const gchar *name;
  const gchar *value;

  // Create a temporary configuration file
  file = fopen (config_file, "w");
  assert_that (file, is_not_null);
  fprintf (file, "key1=value1\nkey2=value2\nkey3=value3\n");
  fclose (file);

  // Initialize iterator from file
  ret = init_settings_iterator_from_file (&iterator, config_file, "Misc");
  assert_that (ret, is_equal_to (0));

  // Test iteration
  assert_that (settings_iterator_next (&iterator), is_true);
  name = settings_iterator_name (&iterator);
  value = settings_iterator_value (&iterator);
  assert_that (name, is_equal_to_string ("key1"));
  assert_that (value, is_equal_to_string ("value1"));

  assert_that (settings_iterator_next (&iterator), is_true);
  name = settings_iterator_name (&iterator);
  value = settings_iterator_value (&iterator);
  assert_that (name, is_equal_to_string ("key2"));
  assert_that (value, is_equal_to_string ("value2"));

  assert_that (settings_iterator_next (&iterator), is_true);
  name = settings_iterator_name (&iterator);
  value = settings_iterator_value (&iterator);
  assert_that (name, is_equal_to_string ("key3"));
  assert_that (value, is_equal_to_string ("value3"));

  // No more items
  assert_that (settings_iterator_next (&iterator), is_false);

  // Clean up
  cleanup_settings_iterator (&iterator);
  g_remove (config_file);
}

Ensure (settings, settings_group_handling)
{
  settings_iterator_t iterator;
  int ret;
  gchar *config_file = "test_group_settings.conf";
  FILE *file;
  const gchar *name;
  const gchar *value;

  // Create a temporary configuration file with multiple groups
  file = fopen (config_file, "w");
  assert_that (file, is_not_null);
  fprintf (file, "[group1]\nkey1=value1\nkey2=value2\n\n[group2]\nkey3=value3\nkey4=value4\n");
  fclose (file);

  // Initialize iterator from file for group1
  ret = init_settings_iterator_from_file (&iterator, config_file, "group1");
  assert_that (ret, is_equal_to (0));

  // Test iteration for group1
  assert_that (settings_iterator_next (&iterator), is_true);
  name = settings_iterator_name (&iterator);
  value = settings_iterator_value (&iterator);
  assert_that (name, is_equal_to_string ("key1"));
  assert_that (value, is_equal_to_string ("value1"));

  assert_that (settings_iterator_next (&iterator), is_true);
  name = settings_iterator_name (&iterator);
  value = settings_iterator_value (&iterator);
  assert_that (name, is_equal_to_string ("key2"));
  assert_that (value, is_equal_to_string ("value2"));

  // No more items in group1
  assert_that (settings_iterator_next (&iterator), is_false);

  // Clean up iterator
  cleanup_settings_iterator (&iterator);

  // Initialize iterator from file for group2
  ret = init_settings_iterator_from_file (&iterator, config_file, "group2");
  assert_that (ret, is_equal_to (0));

  // Test iteration for group2
  assert_that (settings_iterator_next (&iterator), is_true);
  name = settings_iterator_name (&iterator);
  value = settings_iterator_value (&iterator);
  assert_that (name, is_equal_to_string ("key3"));
  assert_that (value, is_equal_to_string ("value3"));

  assert_that (settings_iterator_next (&iterator), is_true);
  name = settings_iterator_name (&iterator);
  value = settings_iterator_value (&iterator);
  assert_that (name, is_equal_to_string ("key4"));
  assert_that (value, is_equal_to_string ("value4"));

  // No more items in group2
  assert_that (settings_iterator_next (&iterator), is_false);

  // Clean up
  cleanup_settings_iterator (&iterator);
  g_remove (config_file);
}

Ensure (settings, settings_cleanup_function)
{
  settings_t settings;
  settings.file_name = g_strdup ("test.conf");
  settings.group_name = g_strdup ("test_group");
  settings.key_file = g_key_file_new ();

  // This should not crash
  settings_cleanup (&settings);
}

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, settings, init_settings_iterator_from_file_with_null_params);
  add_test_with_context (suite, settings, init_settings_iterator_from_nonexistent_file);
  add_test_with_context (suite, settings, init_settings_iterator_from_valid_file);
  add_test_with_context (suite, settings, settings_iterator_operations);
  add_test_with_context (suite, settings, settings_group_handling);
  add_test_with_context (suite, settings, settings_cleanup_function);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
