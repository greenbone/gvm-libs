/* SPDX-FileCopyrightText: 2025 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "prefs.c"

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>
#include <glib.h>
#include <glib/gstdio.h>
#include <stdio.h>
#include <unistd.h>

Describe (prefs);

BeforeEach (prefs)
{
  // Reset preferences before each test
  if (global_prefs)
    g_hash_table_destroy (global_prefs);
  global_prefs = NULL;
}

AfterEach (prefs)
{
  // Clean up after each test
  if (global_prefs)
    g_hash_table_destroy (global_prefs);
  global_prefs = NULL;
}

Ensure (prefs, preferences_get_initializes_prefs)
{
  GHashTable *prefs;

  // First call should initialize the preferences
  prefs = preferences_get ();
  assert_that (prefs, is_not_null);
  assert_that (g_hash_table_size (prefs), is_greater_than (0));
}

Ensure (prefs, prefs_get_returns_null_for_nonexistent_key)
{
  const gchar *value;

  // Get value for a key that doesn't exist
  value = prefs_get ("nonexistent_key");
  assert_that (value, is_null);
}

Ensure (prefs, prefs_get_returns_correct_value)
{
  const gchar *value;

  // Set a preference
  prefs_set ("test_key", "test_value");

  // Get the preference back
  value = prefs_get ("test_key");
  assert_that (value, is_equal_to_string ("test_value"));
}

Ensure (prefs, prefs_get_bool_returns_zero_for_nonexistent_key)
{
  int result;

  // Get boolean value for a key that doesn't exist
  result = prefs_get_bool ("nonexistent_key");
  assert_that (result, is_equal_to (0));
}

Ensure (prefs, prefs_get_bool_returns_one_for_yes_value)
{
  int result;

  // Set a preference to "yes"
  prefs_set ("test_bool_key", "yes");

  // Get boolean value
  result = prefs_get_bool ("test_bool_key");
  assert_that (result, is_equal_to (1));
}

Ensure (prefs, prefs_get_bool_returns_zero_for_non_yes_value)
{
  int result;

  // Set a preference to something other than "yes"
  prefs_set ("test_bool_key", "no");

  // Get boolean value
  result = prefs_get_bool ("test_bool_key");
  assert_that (result, is_equal_to (0));
}

Ensure (prefs, prefs_set_creates_new_preference)
{
  const gchar *value;
  GHashTable *prefs;

  // Get initial preferences
  prefs = preferences_get ();
  int initial_size = g_hash_table_size (prefs);

  // Set a new preference
  prefs_set ("new_key", "new_value");

  // Check that the preference was set
  value = prefs_get ("new_key");
  assert_that (value, is_equal_to_string ("new_value"));

  // Check that the hash table size increased
  assert_that (g_hash_table_size (prefs), is_equal_to (initial_size + 1));
}

Ensure (prefs, prefs_set_overwrites_existing_preference)
{
  const gchar *value;

  // Set a preference
  prefs_set ("overwrite_key", "initial_value");

  // Check initial value
  value = prefs_get ("overwrite_key");
  assert_that (value, is_equal_to_string ("initial_value"));

  // Overwrite the preference
  prefs_set ("overwrite_key", "new_value");

  // Check that the preference was overwritten
  value = prefs_get ("overwrite_key");
  assert_that (value, is_equal_to_string ("new_value"));
}

Ensure (prefs, prefs_config_loads_from_file)
{
  gchar *config_file = "test_prefs.conf";
  FILE *file;
  const gchar *value;

  // Create a temporary configuration file
  file = fopen (config_file, "w");
  assert_that (file, is_not_null);
  fprintf (file, "test_config_key=test_config_value\n");
  fclose (file);

  // Load preferences from file
  prefs_config (config_file);

  // Check that the preference from file was loaded
  value = prefs_get ("test_config_key");
  assert_that (value, is_equal_to_string ("test_config_value"));

  // Check that config_file preference was set
  value = prefs_get ("config_file");
  assert_that (value, is_equal_to_string (config_file));

  // Clean up
  g_remove (config_file);
}

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, prefs, preferences_get_initializes_prefs);
  add_test_with_context (suite, prefs,
                         prefs_get_returns_null_for_nonexistent_key);
  add_test_with_context (suite, prefs, prefs_get_returns_correct_value);
  add_test_with_context (suite, prefs,
                         prefs_get_bool_returns_zero_for_nonexistent_key);
  add_test_with_context (suite, prefs,
                         prefs_get_bool_returns_one_for_yes_value);
  add_test_with_context (suite, prefs,
                         prefs_get_bool_returns_zero_for_non_yes_value);
  add_test_with_context (suite, prefs, prefs_set_creates_new_preference);
  add_test_with_context (suite, prefs,
                         prefs_set_overwrites_existing_preference);
  add_test_with_context (suite, prefs, prefs_config_loads_from_file);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
