/* SPDX-FileCopyrightText: 2019-2025 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "httputils.c"

#include <cgreen/cgreen.h>
#include <curl/curl.h>

static gboolean post_request_called = FALSE;
static gboolean get_request_called = FALSE;
static gboolean put_request_called = FALSE;
static gboolean patch_request_called = FALSE;
static gboolean delete_request_called = FALSE;
static gboolean head_request_called = FALSE;
static const char *last_postfields = NULL;
static long last_postfieldsize = -1;

/* Mocks */

CURLcode
__wrap_curl_easy_setopt (CURL *handle, CURLoption option, ...);

CURLcode
__wrap_curl_easy_setopt (CURL *handle, CURLoption option, ...)
{
  (void) handle;
  va_list args;
  va_start (args, option);
  switch (option)
    {
    case CURLOPT_HTTPGET:
      if (va_arg (args, long) == 1L)
        get_request_called = TRUE;
      break;
    case CURLOPT_POST:
      if (va_arg (args, long) == 1L)
        post_request_called = TRUE;
      break;
    case CURLOPT_CUSTOMREQUEST:
      {
        const char *method = va_arg (args, const char *);
        if (g_strcmp0 (method, "PUT") == 0)
          put_request_called = TRUE;
        else if (g_strcmp0 (method, "PATCH") == 0)
          patch_request_called = TRUE;
        else if (g_strcmp0 (method, "DELETE") == 0)
          delete_request_called = TRUE;
      }
      break;
    case CURLOPT_NOBODY:
      if (va_arg (args, long) == 1L)
        head_request_called = TRUE;
      break;
    case CURLOPT_POSTFIELDS:
      last_postfields = va_arg (args, const char *);
      break;
    case CURLOPT_POSTFIELDSIZE:
      last_postfieldsize = va_arg (args, long);
      break;
    default:
      (void) option;
      break;
    }
  va_end (args);
  return CURLE_OK;
}

/* Helper functions */

static void
assert_method_and_payload (gvm_http_method_t method, const gchar *payload,
                           gvm_http_method_t expected_method)
{
  gvm_http_response_stream_t s = gvm_http_response_stream_new ();
  gvm_http_t *http = gvm_http_new ("http://example.com", method, payload, NULL,
                                   NULL, NULL, NULL, s);

  assert_that (http, is_not_null);
  assert_that (post_request_called, is_equal_to (expected_method == POST));
  assert_that (get_request_called, is_equal_to (expected_method == GET));
  assert_that (put_request_called, is_equal_to (expected_method == PUT));
  assert_that (patch_request_called, is_equal_to (expected_method == PATCH));
  assert_that (delete_request_called, is_equal_to (expected_method == DELETE));
  assert_that (head_request_called, is_equal_to (expected_method == HEAD));

  if (payload == NULL)
    {
      assert_that (last_postfields, is_null);
      assert_that (last_postfieldsize, is_equal_to (-1));
    }
  else
    {
      assert_that (last_postfields, is_equal_to_string (payload));
      assert_that (last_postfieldsize, is_equal_to ((long) strlen (payload)));
    }

  gvm_http_free (http);
  gvm_http_response_stream_free (s);
}

Describe (gvm_http);

BeforeEach (gvm_http)
{
  post_request_called = FALSE;
  get_request_called = FALSE;
  put_request_called = FALSE;
  patch_request_called = FALSE;
  delete_request_called = FALSE;
  head_request_called = FALSE;
  last_postfields = NULL;
  last_postfieldsize = -1;
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

Ensure (gvm_http, store_response_header_captures_content_disposition)
{
  gvm_http_response_t response = {0};

  gchar header[] = "Content-Disposition: attachment; "
                   "filename=\"support-bundle-agent-123.tar.gz.enc\"\r\n";

  size_t processed =
    store_response_header (header, 1, strlen (header), &response);

  assert_that (processed, is_equal_to (strlen (header)));
  assert_that (response.content_disposition, is_not_null);
  assert_that (
    response.content_disposition,
    is_equal_to_string (
      "attachment; filename=\"support-bundle-agent-123.tar.gz.enc\""));

  g_free (response.content_disposition);
}

Ensure (gvm_http, store_response_header_matches_case_insensitively)
{
  gvm_http_response_t response = {0};

  gchar header[] =
    "content-disposition: attachment; filename=\"bundle.enc\"\r\n";

  store_response_header (header, 1, strlen (header), &response);

  assert_that (response.content_disposition, is_not_null);
  assert_that (response.content_disposition,
               is_equal_to_string ("attachment; filename=\"bundle.enc\""));

  g_free (response.content_disposition);
}

Ensure (gvm_http, store_response_header_trims_value)
{
  gvm_http_response_t response = {0};

  gchar header[] =
    "Content-Disposition:   attachment; filename=\"bundle.enc\"   \r\n";

  store_response_header (header, 1, strlen (header), &response);

  assert_that (response.content_disposition,
               is_equal_to_string ("attachment; filename=\"bundle.enc\""));

  g_free (response.content_disposition);
}

Ensure (gvm_http, post_request_empty_payload_sets_post_method)
{
  assert_method_and_payload (POST, "", POST);
}

Ensure (gvm_http, post_request_null_payload_sets_post_method)
{
  assert_method_and_payload (POST, NULL, POST);
}

Ensure (gvm_http, post_request_nonempty_payload_sets_post_method)
{
  const gchar *payload = "{\"key\": \"value\"}";
  assert_method_and_payload (POST, payload, POST);
}

Ensure (gvm_http, put_request_empty_payload_sets_put_method)
{
  assert_method_and_payload (PUT, "", PUT);
}

Ensure (gvm_http, put_request_null_payload_sets_put_method)
{
  assert_method_and_payload (PUT, NULL, PUT);
}

Ensure (gvm_http, put_request_nonempty_payload_sets_put_method)
{
  const gchar *payload = "{\"key\": \"value\"}";
  assert_method_and_payload (PUT, payload, PUT);
}

Ensure (gvm_http, patch_request_empty_payload_sets_patch_method)
{
  assert_method_and_payload (PATCH, "", PATCH);
}

Ensure (gvm_http, patch_request_null_payload_sets_patch_method)
{
  assert_method_and_payload (PATCH, NULL, PATCH);
}

Ensure (gvm_http, patch_request_nonempty_payload_sets_patch_method)
{
  const gchar *payload = "{\"key\": \"value\"}";
  assert_method_and_payload (PATCH, payload, PATCH);
}

Ensure (gvm_http, get_request_sets_get_method)
{
  assert_method_and_payload (GET, NULL, GET);
}

Ensure (gvm_http, head_request_sets_head_method)
{
  assert_method_and_payload (HEAD, NULL, HEAD);
}

Ensure (gvm_http, delete_request_sets_delete_method)
{
  assert_method_and_payload (DELETE, NULL, DELETE);
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
  add_test_with_context (suite, gvm_http,
                         store_response_header_captures_content_disposition);
  add_test_with_context (suite, gvm_http,
                         store_response_header_matches_case_insensitively);
  add_test_with_context (suite, gvm_http, store_response_header_trims_value);

  add_test_with_context (suite, gvm_http,
                         post_request_empty_payload_sets_post_method);
  add_test_with_context (suite, gvm_http,
                         post_request_null_payload_sets_post_method);
  add_test_with_context (suite, gvm_http,
                         post_request_nonempty_payload_sets_post_method);

  add_test_with_context (suite, gvm_http,
                         put_request_empty_payload_sets_put_method);
  add_test_with_context (suite, gvm_http,
                         put_request_null_payload_sets_put_method);
  add_test_with_context (suite, gvm_http,
                         put_request_nonempty_payload_sets_put_method);

  add_test_with_context (suite, gvm_http,
                         patch_request_empty_payload_sets_patch_method);
  add_test_with_context (suite, gvm_http,
                         patch_request_null_payload_sets_patch_method);
  add_test_with_context (suite, gvm_http,
                         patch_request_nonempty_payload_sets_patch_method);

  add_test_with_context (suite, gvm_http, get_request_sets_get_method);
  add_test_with_context (suite, gvm_http, head_request_sets_head_method);
  add_test_with_context (suite, gvm_http, delete_request_sets_delete_method);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
