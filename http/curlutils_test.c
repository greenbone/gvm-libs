/* SPDX-FileCopyrightText: 2019-2025 Greenbone AG
*
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "curlutils.c"
#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>
#include <curl/curl.h>

Describe (curlutils);
BeforeEach(curlutils)
{

}
AfterEach(curlutils)
{

}

Ensure (curlutils, curlutils_add_header_returns_non_null_and_contains_header)
{
  const gchar *test_header = "Content-Type: application/json";
  struct curl_slist *headers = NULL;

  headers = curlutils_add_header(headers, test_header);

  assert_that (headers, is_not_null);
  assert_that (headers->data, is_equal_to_string (test_header));

  curl_slist_free_all (headers);
}

Ensure (curlutils, curlutils_cleanup_headers_does_not_crash_on_null)
{
  curlutils_cleanup_headers (NULL);
  assert_that(true, is_true);
}

Ensure (curlutils, curlutils_remove_handle_does_not_crash_with_null_inputs)
{
  curlutils_remove_handle (NULL, NULL);
  assert_that (true, is_true);
}

Ensure (curlutils, curlutils_multi_init_creates_valid_multi_handle)
{
  curlutils_multi_t *multi = curlutils_multi_init();
  assert_that (multi, is_not_null);
  assert_that (multi->handle, is_not_null);
  assert_that (multi->custom_headers, is_null);

  curlutils_multi_cleanup (multi);
}

Ensure (curlutils, curlutils_cleanup_frees_response_fields)
{
  curlutils_response_t res = {
    .data = g_strdup("mock"),
    .size = 100,
    .http_status = 200,
    .curl_handle = NULL
  };

  curlutils_cleanup (&res);

  assert_that (res.data, is_null);
  assert_that (res.size, is_equal_to (0));
}

Ensure (curlutils, curlutils_response_stream_cleanup_handles_null)
{
  curlutils_response_stream_cleanup (NULL);
  assert_that (true, is_true);
}

int main(int argc, char **argv) {
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, curlutils, curlutils_add_header_returns_non_null_and_contains_header);
  add_test_with_context (suite, curlutils, curlutils_cleanup_headers_does_not_crash_on_null);
  add_test_with_context (suite, curlutils, curlutils_remove_handle_does_not_crash_with_null_inputs);
  add_test_with_context (suite, curlutils, curlutils_multi_init_creates_valid_multi_handle);
  add_test_with_context (suite, curlutils, curlutils_cleanup_frees_response_fields);
  add_test_with_context (suite, curlutils, curlutils_response_stream_cleanup_handles_null);

  if (argc > 1)
    return run_single_test (suite, argv[1], create_text_reporter ());
  return run_test_suite (suite, create_text_reporter ());
}
