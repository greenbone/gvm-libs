/* SPDX-FileCopyrightText: 2019-2025 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "httputils.c"

#include <cgreen/cgreen.h>
#include <curl/curl.h>

Describe (gvm_http);

BeforeEach (gvm_http)
{
}

AfterEach (gvm_http)
{
}

Ensure (gvm_http, add_header_returns_true_and_contains_header)
{
  const gchar *test_header = "Content-Type: application/json";
  gvm_http_headers_t *headers = gvm_http_headers_new ();

  gboolean added = gvm_http_add_header (headers, test_header);

  assert_that (added, is_true);
  assert_that (headers->custom_headers, is_not_null);
  assert_that (headers->custom_headers->data, is_equal_to_string (test_header));

  gvm_http_headers_free (headers);
}

Ensure (gvm_http, cleanup_headers_handles_null_safely)
{
  gvm_http_headers_free (NULL);
  assert_that (true, is_true);
}

Ensure (gvm_http, headers_new_initializes_empty_list)
{
  gvm_http_headers_t *headers = gvm_http_headers_new ();
  assert_that (headers, is_not_null);
  assert_that (headers->custom_headers, is_null);
  gvm_http_headers_free (headers);
}

Ensure (gvm_http, multi_init_returns_valid_object)
{
  gvm_http_multi_t *multi = gvm_http_multi_new ();

  assert_that (multi, is_not_null);
  assert_that (multi->handler, is_not_null);
  assert_that (multi->headers, is_not_null);

  gvm_http_multi_free (multi);
}

Ensure (gvm_http, multi_add_handler_with_null_returns_bad_handle)
{
  gvm_http_multi_result_t result = gvm_http_multi_add_handler (NULL, NULL);
  assert_that (result, is_equal_to (GVM_HTTP_MULTI_BAD_HANDLE));
}

Ensure (gvm_http, multi_perform_with_null_returns_bad_handle)
{
  int running = 0;
  gvm_http_multi_result_t result = gvm_http_multi_perform (NULL, &running);
  assert_that (result, is_equal_to (GVM_HTTP_MULTI_BAD_HANDLE));
}

Ensure (gvm_http, multi_handler_free_does_not_crash_on_null)
{
  gvm_http_multi_handler_free (NULL, NULL);
  assert_that (true, is_true);
}

Ensure (gvm_http, response_free_does_not_crash)
{
  gvm_http_response_t *res = g_malloc0 (sizeof (gvm_http_response_t));
  res->data = g_strdup ("mock");
  res->size = 100;
  res->http_status = 200;

  gvm_http_response_free (res);

  assert_that (true, is_true);
}

Ensure (gvm_http, response_stream_free_handles_null)
{
  gvm_http_response_stream_free (NULL);
  assert_that (true, is_true);
}

Ensure (gvm_http, response_stream_free_handles_valid_stream)
{
  gvm_http_response_stream_t stream = gvm_http_response_stream_new ();
  assert_that (stream, is_not_null);
  gvm_http_response_stream_free (stream);
}

Ensure (gvm_http, response_stream_new_initializes_fields)
{
  gvm_http_response_stream_t stream = gvm_http_response_stream_new ();
  assert_that (stream, is_not_null);
  assert_that (stream->data, is_not_null);
  assert_that (stream->length, is_equal_to (0));
  assert_that (stream->multi_handler, is_not_null);
  gvm_http_response_stream_free (stream);
}

Ensure (gvm_http, http_new_returns_struct_with_valid_handler)
{
  CURL *curl = curl_easy_init ();
  assert_that (curl, is_not_null);

  gvm_http_t *http = gvm_http_t_new (curl);
  assert_that (http, is_not_null);
  assert_that (http->handler, is_equal_to (curl));

  gvm_http_free (http);
}

Ensure (gvm_http, http_new_returns_null_when_passed_null)
{
  gvm_http_t *http = gvm_http_t_new (NULL);
  assert_that (http, is_null);
}

Ensure (gvm_http, http_free_handles_null_safely)
{
  gvm_http_free (NULL);
  assert_that (true, is_true);
}

Ensure (gvm_http, http_free_frees_allocated_struct)
{
  CURL *curl = curl_easy_init ();
  assert_that (curl, is_not_null);

  gvm_http_t *http = gvm_http_t_new (curl);
  assert_that (http, is_not_null);
  assert_that (http->handler, is_equal_to (curl));

  gvm_http_free (http);
  // Cannot assert post-free directly, but reaching here means no crash
  assert_that (true, is_true);
}

Ensure (gvm_http, response_stream_reset_frees_and_resets_data)
{
  gvm_http_response_stream_t stream = gvm_http_response_stream_new ();
  assert_that (stream, is_not_null);

  g_free (stream->data);
  stream->data = g_strdup ("mock response");
  stream->length = strlen (stream->data);

  gvm_http_response_stream_reset (stream);

  assert_that (stream->length, is_equal_to (0));
  assert_that (stream->data, is_not_null);
  assert_that (strlen (stream->data), is_equal_to (0));
  assert_that (stream->data[0], is_equal_to ('\0'));

  gvm_http_response_stream_free (stream);
}

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite = create_test_suite ();

  add_test_with_context (suite, gvm_http,
                         add_header_returns_true_and_contains_header);
  add_test_with_context (suite, gvm_http, cleanup_headers_handles_null_safely);
  add_test_with_context (suite, gvm_http, headers_new_initializes_empty_list);
  add_test_with_context (suite, gvm_http, multi_init_returns_valid_object);
  add_test_with_context (suite, gvm_http,
                         multi_add_handler_with_null_returns_bad_handle);
  add_test_with_context (suite, gvm_http,
                         multi_perform_with_null_returns_bad_handle);
  add_test_with_context (suite, gvm_http,
                         multi_handler_free_does_not_crash_on_null);
  add_test_with_context (suite, gvm_http, response_free_does_not_crash);
  add_test_with_context (suite, gvm_http, response_stream_free_handles_null);
  add_test_with_context (suite, gvm_http,
                         response_stream_free_handles_valid_stream);
  add_test_with_context (suite, gvm_http,
                         response_stream_new_initializes_fields);
  add_test_with_context (suite, gvm_http,
                         http_new_returns_struct_with_valid_handler);
  add_test_with_context (suite, gvm_http,
                         http_new_returns_null_when_passed_null);
  add_test_with_context (suite, gvm_http, http_free_handles_null_safely);
  add_test_with_context (suite, gvm_http, http_free_frees_allocated_struct);
  add_test_with_context (suite, gvm_http,
                         response_stream_reset_frees_and_resets_data);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
