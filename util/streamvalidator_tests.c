/* SPDX-FileCopyrightText: 2019-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "streamvalidator.h"

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>

#define VALID_DATA "This should be valid...."
#define TOO_SHORT_DATA "This is too short!"
#define TOO_LONG_DATA "This text is longer than expected!"
#define INVALID_DATA "This shouldn't be valid!"
#define VALID_DATA_HASH \
  "sha256:4ae8f10c9e9551173520b7a675e9caba163007edf04dbbd06022bf61ad3fe4fb"

Describe (streamvalidator);
BeforeEach (streamvalidator)
{
}
AfterEach (streamvalidator)
{
}

Ensure (streamvalidator, accepts_valid_data)
{
  gvm_stream_validator_t validator = NULL;

  assert_equal (
    gvm_stream_validator_new (VALID_DATA_HASH, strlen (VALID_DATA), &validator),
    GVM_STREAM_VALIDATOR_OK);
  assert_equal (
    gvm_stream_validator_write (validator, VALID_DATA, strlen (VALID_DATA)),
    GVM_STREAM_VALIDATOR_OK);
  assert_equal (gvm_stream_validator_end (validator), GVM_STREAM_VALIDATOR_OK);

  gvm_stream_validator_free (validator);
}

Ensure (streamvalidator, accepts_valid_data_after_multiple_writes)
{
  gvm_stream_validator_t validator = NULL;

  assert_equal (
    gvm_stream_validator_new (VALID_DATA_HASH, strlen (VALID_DATA), &validator),
    GVM_STREAM_VALIDATOR_OK);
  assert_equal (gvm_stream_validator_write (validator, VALID_DATA, 5),
                GVM_STREAM_VALIDATOR_OK);
  assert_equal (gvm_stream_validator_write (validator, VALID_DATA + 5, 5),
                GVM_STREAM_VALIDATOR_OK);
  assert_equal (gvm_stream_validator_write (validator, VALID_DATA + 10,
                                            strlen (VALID_DATA) - 10),
                GVM_STREAM_VALIDATOR_OK);
  assert_equal (gvm_stream_validator_end (validator), GVM_STREAM_VALIDATOR_OK);

  gvm_stream_validator_free (validator);
}

Ensure (streamvalidator, accepts_valid_data_after_rewind)
{
  gvm_stream_validator_t validator = NULL;

  assert_equal (
    gvm_stream_validator_new (VALID_DATA_HASH, strlen (VALID_DATA), &validator),
    GVM_STREAM_VALIDATOR_OK);
  assert_equal (gvm_stream_validator_write (validator, TOO_SHORT_DATA,
                                            strlen (TOO_SHORT_DATA)),
                GVM_STREAM_VALIDATOR_OK);
  gvm_stream_validator_rewind (validator);
  assert_equal (
    gvm_stream_validator_write (validator, VALID_DATA, strlen (VALID_DATA)),
    GVM_STREAM_VALIDATOR_OK);
  assert_equal (gvm_stream_validator_end (validator), GVM_STREAM_VALIDATOR_OK);

  gvm_stream_validator_free (validator);
}

Ensure (streamvalidator, rejects_too_long_data)
{
  gvm_stream_validator_t validator = NULL;

  assert_equal (
    gvm_stream_validator_new (VALID_DATA_HASH, strlen (VALID_DATA), &validator),
    GVM_STREAM_VALIDATOR_OK);
  assert_equal (gvm_stream_validator_write (validator, TOO_LONG_DATA,
                                            strlen (TOO_LONG_DATA)),
                GVM_STREAM_VALIDATOR_DATA_TOO_LONG);
  assert_not_equal (gvm_stream_validator_end (validator),
                    GVM_STREAM_VALIDATOR_OK);

  gvm_stream_validator_free (validator);
}

Ensure (streamvalidator, rejects_too_short_data)
{
  gvm_stream_validator_t validator = NULL;

  assert_equal (
    gvm_stream_validator_new (VALID_DATA_HASH, strlen (VALID_DATA), &validator),
    GVM_STREAM_VALIDATOR_OK);
  assert_equal (gvm_stream_validator_write (validator, TOO_SHORT_DATA,
                                            strlen (TOO_SHORT_DATA)),
                GVM_STREAM_VALIDATOR_OK);
  assert_equal (gvm_stream_validator_end (validator),
                GVM_STREAM_VALIDATOR_DATA_TOO_SHORT);

  gvm_stream_validator_free (validator);
}

Ensure (streamvalidator, rejects_hash_mismatch)
{
  gvm_stream_validator_t validator = NULL;

  assert_equal (
    gvm_stream_validator_new (VALID_DATA_HASH, strlen (VALID_DATA), &validator),
    GVM_STREAM_VALIDATOR_OK);
  assert_equal (
    gvm_stream_validator_write (validator, INVALID_DATA, strlen (INVALID_DATA)),
    GVM_STREAM_VALIDATOR_OK);
  assert_equal (gvm_stream_validator_end (validator),
                GVM_STREAM_VALIDATOR_HASH_MISMATCH);

  gvm_stream_validator_free (validator);
}

Ensure (streamvalidator, init_rejects_empty_hash)
{
  gvm_stream_validator_t validator = NULL;

  assert_equal (gvm_stream_validator_new ("", 123, &validator),
                GVM_STREAM_VALIDATOR_INVALID_HASH_SYNTAX);
  assert_equal (validator, NULL);
}

Ensure (streamvalidator, init_rejects_invalid_syntax_hashes)
{
  gvm_stream_validator_t validator = NULL;

  assert_equal (gvm_stream_validator_new ("0123", 123, &validator),
                GVM_STREAM_VALIDATOR_INVALID_HASH_SYNTAX);
  assert_equal (validator, NULL);

  assert_equal (gvm_stream_validator_new ("sha256", 123, &validator),
                GVM_STREAM_VALIDATOR_INVALID_HASH_SYNTAX);
  assert_equal (validator, NULL);
}

Ensure (streamvalidator, init_rejects_invalid_algo_hashes)
{
  gvm_stream_validator_t validator = NULL;

  assert_equal (gvm_stream_validator_new (":0123", 123, &validator),
                GVM_STREAM_VALIDATOR_INVALID_HASH_ALGORITHM);
  assert_equal (validator, NULL);

  assert_equal (gvm_stream_validator_new ("xyz:0123", 123, &validator),
                GVM_STREAM_VALIDATOR_INVALID_HASH_ALGORITHM);
  assert_equal (validator, NULL);
}

Ensure (streamvalidator, init_rejects_invalid_value_hashes)
{
  gvm_stream_validator_t validator = NULL;

  assert_equal (gvm_stream_validator_new ("sha256:", 123, &validator),
                GVM_STREAM_VALIDATOR_INVALID_HASH_VALUE);
  assert_equal (validator, NULL);

  assert_equal (gvm_stream_validator_new ("sha256:xyz", 123, &validator),
                GVM_STREAM_VALIDATOR_INVALID_HASH_VALUE);
  assert_equal (validator, NULL);

  assert_equal (gvm_stream_validator_new ("sha256:123", 123, &validator),
                GVM_STREAM_VALIDATOR_INVALID_HASH_VALUE);
  assert_equal (validator, NULL);

  assert_equal (gvm_stream_validator_new ("sha256:0123ab", 123, &validator),
                GVM_STREAM_VALIDATOR_INVALID_HASH_VALUE);
  assert_equal (validator, NULL);
}

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, streamvalidator, accepts_valid_data);
  add_test_with_context (suite, streamvalidator,
                         accepts_valid_data_after_multiple_writes);
  add_test_with_context (suite, streamvalidator,
                         accepts_valid_data_after_rewind);

  add_test_with_context (suite, streamvalidator, rejects_too_long_data);
  add_test_with_context (suite, streamvalidator, rejects_too_short_data);
  add_test_with_context (suite, streamvalidator, rejects_hash_mismatch);

  add_test_with_context (suite, streamvalidator, init_rejects_empty_hash);
  add_test_with_context (suite, streamvalidator,
                         init_rejects_invalid_syntax_hashes);
  add_test_with_context (suite, streamvalidator,
                         init_rejects_invalid_algo_hashes);
  add_test_with_context (suite, streamvalidator,
                         init_rejects_invalid_value_hashes);
  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
