/* SPDX-FileCopyrightText: 2026 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "security_intelligence.c"

#include <cgreen/cgreen.h>
#include <string.h>

/* -------------------- Mock State -------------------- */

static GPtrArray *called_headers = NULL;
static gchar *last_sent_url = NULL;
static gchar *last_sent_payload = NULL;
static gchar *last_sent_ca_cert = NULL;
static gchar *last_sent_cert = NULL;
static gchar *last_sent_key = NULL;
static long mock_http_status = 200;
static gchar *mock_response_data = NULL;

/* -------------------- Suite -------------------- */

Describe (security_intelligence);

BeforeEach (security_intelligence)
{
  if (called_headers)
    {
      g_ptr_array_free (called_headers, TRUE);
      called_headers = NULL;
    }

  g_clear_pointer (&last_sent_url, g_free);
  g_clear_pointer (&last_sent_payload, g_free);
  g_clear_pointer (&last_sent_ca_cert, g_free);
  g_clear_pointer (&last_sent_cert, g_free);
  g_clear_pointer (&last_sent_key, g_free);
  g_clear_pointer (&mock_response_data, g_free);

  mock_http_status = 200;
}

AfterEach (security_intelligence)
{
  if (called_headers)
    {
      g_ptr_array_free (called_headers, TRUE);
      called_headers = NULL;
    }

  g_clear_pointer (&last_sent_url, g_free);
  g_clear_pointer (&last_sent_payload, g_free);
  g_clear_pointer (&last_sent_ca_cert, g_free);
  g_clear_pointer (&last_sent_cert, g_free);
  g_clear_pointer (&last_sent_key, g_free);
  g_clear_pointer (&mock_response_data, g_free);
}

/* -------------------- Mock Functions -------------------- */

gvm_http_headers_t *
gvm_http_headers_new (void)
{
  return g_malloc0 (8);
}

void
gvm_http_headers_free (gvm_http_headers_t *headers)
{
  g_free (headers);
}

gboolean
gvm_http_add_header (gvm_http_headers_t *headers, const gchar *header)
{
  (void) headers;

  if (!called_headers)
    called_headers = g_ptr_array_new_with_free_func (g_free);

  g_ptr_array_add (called_headers, g_strdup (header));
  return TRUE;
}

gvm_http_response_t *
gvm_http_request (const gchar *url, gvm_http_method_t method,
                  const gchar *payload, gvm_http_headers_t *headers,
                  const gchar *ca_cert, const gchar *cert, const gchar *key,
                  gvm_http_response_stream_t stream)
{
  (void) headers;
  (void) ca_cert;
  (void) cert;
  (void) key;
  (void) stream;
  (void) method;

  last_sent_url = g_strdup (url);
  last_sent_payload = g_strdup (payload);

  if (!mock_response_data && mock_http_status != 200)
    return NULL;

  gvm_http_response_t *response = g_malloc0 (sizeof (gvm_http_response_t));
  response->http_status = mock_http_status;
  response->data =
    mock_response_data ? g_strdup (mock_response_data) : g_strdup ("{}");
  response->size = strlen (response->data);

  return response;
}

/* -------------------- Helpers -------------------- */

static security_intelligence_connector_t
make_conn (void)
{
  security_intelligence_connector_t conn =
    security_intelligence_connector_new ();
  assert_that (conn, is_not_null);

  conn->protocol = g_strdup ("https");
  conn->host = g_strdup ("localhost");
  conn->port = 8443;
  conn->url = g_strdup ("https://localhost:8443");
  conn->bearer_token = g_strdup ("jwt-token");
  conn->ca_cert = g_strdup ("/tmp/ca.pem");
  conn->cert = g_strdup ("/tmp/cert.pem");
  conn->key = g_strdup ("/tmp/key.pem");

  return conn;
}

static security_intelligence_managed_appliance_t
make_appliance (void)
{
  security_intelligence_managed_appliance_t appliance =
    security_intelligence_managed_appliance_new ();
  assert_that (appliance, is_not_null);

  appliance->appliance_id = g_strdup ("appl-123");
  appliance->ip = g_strdup ("192.168.1.10");
  appliance->https_certificate_fingerprint = g_strdup ("AA:BB:CC");

  return appliance;
}

/* -------------------- Connector Tests -------------------- */

Ensure (security_intelligence, connector_new_returns_zero_initialized_connector)
{
  security_intelligence_connector_t conn =
    security_intelligence_connector_new ();

  assert_that (conn, is_not_null);
  assert_that (conn->ca_cert, is_null);
  assert_that (conn->cert, is_null);
  assert_that (conn->key, is_null);
  assert_that (conn->bearer_token, is_null);
  assert_that (conn->host, is_null);
  assert_that (conn->protocol, is_null);
  assert_that (conn->url, is_null);
  assert_that (conn->port, is_equal_to (0));

  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence, connector_free_handles_null)
{
  security_intelligence_connector_free (NULL);
  assert_that (true, is_true);
}

Ensure (security_intelligence, connector_free_handles_populated_connector)
{
  security_intelligence_connector_t conn =
    security_intelligence_connector_new ();
  assert_that (conn, is_not_null);

  conn->ca_cert = g_strdup ("/tmp/ca.pem");
  conn->cert = g_strdup ("/tmp/cert.pem");
  conn->key = g_strdup ("/tmp/key.pem");
  conn->bearer_token = g_strdup ("token");
  conn->host = g_strdup ("localhost");
  conn->protocol = g_strdup ("https");
  conn->url = g_strdup ("https://localhost:8443");
  conn->port = 8443;

  security_intelligence_connector_free (conn);
  assert_that (true, is_true);
}

Ensure (security_intelligence, connector_builder_sets_all_valid_fields)
{
  security_intelligence_connector_t conn =
    security_intelligence_connector_new ();

  const char *ca_cert = "/path/ca.pem";
  const char *cert = "/path/cert.pem";
  const char *key = "/path/key.pem";
  const char *token = "jwt";
  const char *protocol = "https";
  const char *host = "127.0.0.1";
  const char *url = "https://127.0.0.1:8443";
  int port = 8443;

  assert_that (security_intelligence_connector_builder (
                 conn, SECURITY_INTELLIGENCE_CA_CERT, ca_cert),
               is_equal_to (SECURITY_INTELLIGENCE_OK));
  assert_that (conn->ca_cert, is_equal_to_string (ca_cert));

  assert_that (security_intelligence_connector_builder (
                 conn, SECURITY_INTELLIGENCE_CERT, cert),
               is_equal_to (SECURITY_INTELLIGENCE_OK));
  assert_that (conn->cert, is_equal_to_string (cert));

  assert_that (security_intelligence_connector_builder (
                 conn, SECURITY_INTELLIGENCE_KEY, key),
               is_equal_to (SECURITY_INTELLIGENCE_OK));
  assert_that (conn->key, is_equal_to_string (key));

  assert_that (security_intelligence_connector_builder (
                 conn, SECURITY_INTELLIGENCE_BEARER_TOKEN, token),
               is_equal_to (SECURITY_INTELLIGENCE_OK));
  assert_that (conn->bearer_token, is_equal_to_string (token));

  assert_that (security_intelligence_connector_builder (
                 conn, SECURITY_INTELLIGENCE_PROTOCOL, protocol),
               is_equal_to (SECURITY_INTELLIGENCE_OK));
  assert_that (conn->protocol, is_equal_to_string (protocol));

  assert_that (security_intelligence_connector_builder (
                 conn, SECURITY_INTELLIGENCE_HOST, host),
               is_equal_to (SECURITY_INTELLIGENCE_OK));
  assert_that (conn->host, is_equal_to_string (host));

  assert_that (security_intelligence_connector_builder (
                 conn, SECURITY_INTELLIGENCE_PORT, &port),
               is_equal_to (SECURITY_INTELLIGENCE_OK));
  assert_that (conn->port, is_equal_to (port));

  assert_that (security_intelligence_connector_builder (
                 conn, SECURITY_INTELLIGENCE_URL, url),
               is_equal_to (SECURITY_INTELLIGENCE_OK));
  assert_that (conn->url, is_equal_to_string (url));

  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence, connector_builder_rejects_null_conn)
{
  int port = 8443;

  assert_that (security_intelligence_connector_builder (
                 NULL, SECURITY_INTELLIGENCE_PORT, &port),
               is_equal_to (SECURITY_INTELLIGENCE_INVALID_VALUE));
}

Ensure (security_intelligence, connector_builder_rejects_null_value)
{
  security_intelligence_connector_t conn =
    security_intelligence_connector_new ();

  assert_that (security_intelligence_connector_builder (
                 conn, SECURITY_INTELLIGENCE_HOST, NULL),
               is_equal_to (SECURITY_INTELLIGENCE_INVALID_VALUE));

  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence, connector_builder_accepts_http_protocol)
{
  security_intelligence_connector_t conn =
    security_intelligence_connector_new ();

  assert_that (security_intelligence_connector_builder (
                 conn, SECURITY_INTELLIGENCE_PROTOCOL, "http"),
               is_equal_to (SECURITY_INTELLIGENCE_OK));
  assert_that (conn->protocol, is_equal_to_string ("http"));

  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence, connector_builder_accepts_https_protocol)
{
  security_intelligence_connector_t conn =
    security_intelligence_connector_new ();

  assert_that (security_intelligence_connector_builder (
                 conn, SECURITY_INTELLIGENCE_PROTOCOL, "https"),
               is_equal_to (SECURITY_INTELLIGENCE_OK));
  assert_that (conn->protocol, is_equal_to_string ("https"));

  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence, connector_builder_rejects_invalid_protocol)
{
  security_intelligence_connector_t conn =
    security_intelligence_connector_new ();

  assert_that (security_intelligence_connector_builder (
                 conn, SECURITY_INTELLIGENCE_PROTOCOL, "ftp"),
               is_equal_to (SECURITY_INTELLIGENCE_INVALID_VALUE));
  assert_that (conn->protocol, is_null);

  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence, connector_builder_rejects_invalid_opt)
{
  security_intelligence_connector_t conn =
    security_intelligence_connector_new ();
  const char *value = "x";

  assert_that (security_intelligence_connector_builder (
                 conn, (security_intelligence_connector_opts_t) 999, value),
               is_equal_to (SECURITY_INTELLIGENCE_INVALID_OPT));

  security_intelligence_connector_free (conn);
}

/* ------------- Managed Appliance / Report / Page Allocation -------------- */

Ensure (security_intelligence, managed_appliance_new_allocates_zero_initialized)
{
  security_intelligence_managed_appliance_t appliance =
    security_intelligence_managed_appliance_new ();

  assert_that (appliance, is_not_null);
  assert_that (appliance->appliance_id, is_null);
  assert_that (appliance->ip, is_null);
  assert_that (appliance->https_certificate_fingerprint, is_null);

  security_intelligence_managed_appliance_free (appliance);
}

Ensure (security_intelligence, managed_appliance_free_handles_null)
{
  security_intelligence_managed_appliance_free (NULL);
  assert_that (true, is_true);
}

Ensure (security_intelligence, managed_appliance_free_handles_populated)
{
  security_intelligence_managed_appliance_t appliance =
    security_intelligence_managed_appliance_new ();

  appliance->appliance_id = g_strdup ("id");
  appliance->ip = g_strdup ("10.0.0.1");
  appliance->https_certificate_fingerprint = g_strdup ("FP");

  security_intelligence_managed_appliance_free (appliance);
  assert_that (true, is_true);
}

Ensure (security_intelligence, managed_report_new_allocates_zero_initialized)
{
  security_intelligence_managed_report_t report =
    security_intelligence_managed_report_new ();

  assert_that (report, is_not_null);
  assert_that (report->ref_id, is_null);

  security_intelligence_managed_report_free (report);
}

Ensure (security_intelligence, managed_report_free_handles_null)
{
  security_intelligence_managed_report_free (NULL);
  assert_that (true, is_true);
}

Ensure (security_intelligence, managed_report_free_handles_populated)
{
  security_intelligence_managed_report_t report =
    security_intelligence_managed_report_new ();
  report->ref_id = g_strdup ("report-1");

  security_intelligence_managed_report_free (report);
  assert_that (true, is_true);
}

Ensure (security_intelligence, managed_report_list_new_allocates_valid_list)
{
  security_intelligence_managed_report_list_t list =
    security_intelligence_managed_report_list_new (2);

  assert_that (list, is_not_null);
  assert_that (list->count, is_equal_to (2));
  assert_that (list->reports, is_not_null);
  assert_that (list->reports[0], is_null);
  assert_that (list->reports[1], is_null);

  security_intelligence_managed_report_list_free (list);
}

Ensure (security_intelligence, managed_report_list_new_rejects_negative_count)
{
  security_intelligence_managed_report_list_t list =
    security_intelligence_managed_report_list_new (-1);

  assert_that (list, is_null);
}

Ensure (security_intelligence, managed_report_list_free_handles_null)
{
  security_intelligence_managed_report_list_free (NULL);
  assert_that (true, is_true);
}

Ensure (security_intelligence, managed_report_list_free_handles_populated_list)
{
  security_intelligence_managed_report_list_t list =
    security_intelligence_managed_report_list_new (2);

  list->reports[0] = security_intelligence_managed_report_new ();
  list->reports[0]->ref_id = g_strdup ("r1");

  list->reports[1] = security_intelligence_managed_report_new ();
  list->reports[1]->ref_id = g_strdup ("r2");

  security_intelligence_managed_report_list_free (list);
  assert_that (true, is_true);
}

Ensure (security_intelligence,
        managed_report_page_new_allocates_zero_initialized)
{
  security_intelligence_managed_report_page_t page =
    security_intelligence_managed_report_page_new ();

  assert_that (page, is_not_null);

  security_intelligence_managed_report_page_free (page);
}

Ensure (security_intelligence, managed_report_page_free_handles_null)
{
  security_intelligence_managed_report_page_free (NULL);
  assert_that (true, is_true);
}

Ensure (security_intelligence,
        managed_report_page_list_new_allocates_valid_list)
{
  security_intelligence_managed_report_page_list_t list =
    security_intelligence_managed_report_page_list_new (3);

  assert_that (list, is_not_null);
  assert_that (list->count, is_equal_to (3));
  assert_that (list->pages, is_not_null);
  assert_that (list->pages[0], is_null);
  assert_that (list->pages[1], is_null);
  assert_that (list->pages[2], is_null);

  security_intelligence_managed_report_page_list_free (list);
}

Ensure (security_intelligence, managed_report_page_list_new_rejects_negative)
{
  security_intelligence_managed_report_page_list_t list =
    security_intelligence_managed_report_page_list_new (-5);

  assert_that (list, is_null);
}

Ensure (security_intelligence, managed_report_page_list_free_handles_null)
{
  security_intelligence_managed_report_page_list_free (NULL);
  assert_that (true, is_true);
}

Ensure (security_intelligence, managed_report_page_list_free_handles_populated)
{
  security_intelligence_managed_report_page_list_t list =
    security_intelligence_managed_report_page_list_new (2);

  list->pages[0] = security_intelligence_managed_report_page_new ();
  list->pages[1] = security_intelligence_managed_report_page_new ();

  security_intelligence_managed_report_page_list_free (list);
  assert_that (true, is_true);
}

/* -------------------- Status Conversion -------------------- */

Ensure (security_intelligence, upload_status_to_string_started)
{
  assert_that (security_intelligence_report_upload_status_to_string (
                 SECURITY_INTELLIGENCE_REPORT_UPLOAD_STATUS_STARTED),
               is_equal_to_string ("upload_started"));
}

Ensure (security_intelligence, upload_status_to_string_completed)
{
  assert_that (security_intelligence_report_upload_status_to_string (
                 SECURITY_INTELLIGENCE_REPORT_UPLOAD_STATUS_COMPLETED),
               is_equal_to_string ("upload_completed"));
}

Ensure (security_intelligence, upload_status_to_string_unknown_default)
{
  assert_that (security_intelligence_report_upload_status_to_string (
                 SECURITY_INTELLIGENCE_REPORT_UPLOAD_STATUS_UNKNOWN),
               is_equal_to_string ("unknown"));
}

Ensure (security_intelligence, upload_status_from_string_started)
{
  assert_that (
    security_intelligence_report_upload_status_from_string ("upload_started"),
    is_equal_to (SECURITY_INTELLIGENCE_REPORT_UPLOAD_STATUS_STARTED));
}

Ensure (security_intelligence, upload_status_from_string_completed)
{
  assert_that (
    security_intelligence_report_upload_status_from_string ("upload_completed"),
    is_equal_to (SECURITY_INTELLIGENCE_REPORT_UPLOAD_STATUS_COMPLETED));
}

Ensure (security_intelligence, upload_status_from_string_unknown_for_null)
{
  assert_that (
    security_intelligence_report_upload_status_from_string (NULL),
    is_equal_to (SECURITY_INTELLIGENCE_REPORT_UPLOAD_STATUS_UNKNOWN));
}

Ensure (security_intelligence, upload_status_from_string_unknown_for_invalid)
{
  assert_that (
    security_intelligence_report_upload_status_from_string ("other"),
    is_equal_to (SECURITY_INTELLIGENCE_REPORT_UPLOAD_STATUS_UNKNOWN));
}

/* -------------------- Header / Request Helpers -------------------- */

Ensure (security_intelligence, init_custom_header_adds_auth_and_content_type)
{
  gvm_http_headers_t *headers =
    init_custom_header ("jwt-token", CONTENT_TYPE_JSON);

  assert_that (headers, is_not_null);
  assert_that (called_headers, is_not_null);
  assert_that ((int) called_headers->len, is_equal_to (2));

  assert_that ((const gchar *) g_ptr_array_index (called_headers, 0),
               is_equal_to_string ("Authorization: Bearer jwt-token"));
  assert_that ((const gchar *) g_ptr_array_index (called_headers, 1),
               is_equal_to_string ("Content-Type: application/json"));

  gvm_http_headers_free (headers);
}

Ensure (security_intelligence,
        init_custom_header_adds_only_auth_when_no_content)
{
  gvm_http_headers_t *headers = init_custom_header ("jwt-token", NULL);

  assert_that (headers, is_not_null);
  assert_that (called_headers, is_not_null);
  assert_that ((int) called_headers->len, is_equal_to (1));
  assert_that ((const gchar *) g_ptr_array_index (called_headers, 0),
               is_equal_to_string ("Authorization: Bearer jwt-token"));

  gvm_http_headers_free (headers);
}

Ensure (security_intelligence,
        init_custom_header_adds_only_content_type_when_no_token)
{
  gvm_http_headers_t *headers = init_custom_header (NULL, CONTENT_TYPE_XML);

  assert_that (headers, is_not_null);
  assert_that (called_headers, is_not_null);
  assert_that ((int) called_headers->len, is_equal_to (1));
  assert_that ((const gchar *) g_ptr_array_index (called_headers, 0),
               is_equal_to_string ("Content-Type: application/xml"));

  gvm_http_headers_free (headers);
}

Ensure (security_intelligence, init_custom_header_with_no_token_and_no_content)
{
  gvm_http_headers_t *headers = init_custom_header (NULL, NULL);

  assert_that (headers, is_not_null);
  assert_that (called_headers, is_null);

  gvm_http_headers_free (headers);
}

Ensure (security_intelligence, send_request_returns_null_if_conn_null)
{
  gvm_http_response_t *resp = security_intelligence_send_request (
    NULL, GET, "/x", NULL, CONTENT_TYPE_JSON);

  assert_that (resp, is_null);
}

Ensure (security_intelligence, send_request_returns_null_if_protocol_missing)
{
  security_intelligence_connector_t conn =
    security_intelligence_connector_new ();
  conn->host = g_strdup ("localhost");
  conn->port = 8443;

  gvm_http_response_t *resp = security_intelligence_send_request (
    conn, GET, "/x", NULL, CONTENT_TYPE_JSON);

  assert_that (resp, is_null);

  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence, send_request_returns_null_if_host_missing)
{
  security_intelligence_connector_t conn =
    security_intelligence_connector_new ();
  conn->protocol = g_strdup ("https");
  conn->port = 8443;

  gvm_http_response_t *resp = security_intelligence_send_request (
    conn, GET, "/x", NULL, CONTENT_TYPE_JSON);

  assert_that (resp, is_null);

  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence,
        send_request_builds_url_from_protocol_host_port_and_path)
{
  security_intelligence_connector_t conn = make_conn ();

  gvm_http_response_t *resp = security_intelligence_send_request (
    conn, POST, "/api/test", "{\"a\":1}", CONTENT_TYPE_JSON);

  assert_that (resp, is_not_null);
  assert_that (last_sent_url,
               is_equal_to_string ("https://localhost:8443/api/test"));
  assert_that (last_sent_payload, is_equal_to_string ("{\"a\":1}"));

  gvm_http_response_free (resp);
  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence, send_request_uses_prebuilt_base_url_when_present)
{
  security_intelligence_connector_t conn = make_conn ();
  g_free (conn->url);
  conn->url = g_strdup ("https://example.test/base");

  gvm_http_response_t *resp = security_intelligence_send_request (
    conn, GET, "/resource", NULL, CONTENT_TYPE_JSON);

  assert_that (resp, is_not_null);
  assert_that (last_sent_url,
               is_equal_to_string ("https://example.test/base/resource"));

  gvm_http_response_free (resp);
  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence,
        send_request_returns_null_when_http_request_fails)
{
  security_intelligence_connector_t conn = make_conn ();

  mock_http_status = 500;
  g_clear_pointer (&mock_response_data, g_free);

  gvm_http_response_t *resp = security_intelligence_send_request (
    conn, GET, "/x", NULL, CONTENT_TYPE_JSON);

  assert_that (resp, is_null);

  security_intelligence_connector_free (conn);
}

/* -------------------- Error Helpers -------------------- */

Ensure (security_intelligence, ensure_error_array_initializes_array)
{
  GPtrArray *errs = NULL;

  ensure_error_array (&errs);

  assert_that (errs, is_not_null);
  assert_that ((int) errs->len, is_equal_to (0));

  g_ptr_array_free (errs, TRUE);
}

Ensure (security_intelligence, ensure_error_array_noop_when_already_exists)
{
  GPtrArray *errs = g_ptr_array_new_with_free_func (g_free);
  g_ptr_array_add (errs, g_strdup ("existing"));

  ensure_error_array (&errs);

  assert_that ((int) errs->len, is_equal_to (1));
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               is_equal_to_string ("existing"));

  g_ptr_array_free (errs, TRUE);
}

Ensure (security_intelligence, ensure_error_array_handles_null_parameter)
{
  ensure_error_array (NULL);
  assert_that (true, is_true);
}

Ensure (security_intelligence, push_error_initializes_and_adds_message)
{
  GPtrArray *errs = NULL;

  push_error (&errs, "error-1");

  assert_that (errs, is_not_null);
  assert_that ((int) errs->len, is_equal_to (1));
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               is_equal_to_string ("error-1"));

  g_ptr_array_free (errs, TRUE);
}

Ensure (security_intelligence, push_error_appends_to_existing_array)
{
  GPtrArray *errs = g_ptr_array_new_with_free_func (g_free);
  g_ptr_array_add (errs, g_strdup ("existing"));

  push_error (&errs, "next");

  assert_that ((int) errs->len, is_equal_to (2));
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               is_equal_to_string ("existing"));
  assert_that ((const gchar *) g_ptr_array_index (errs, 1),
               is_equal_to_string ("next"));

  g_ptr_array_free (errs, TRUE);
}

Ensure (security_intelligence, push_error_ignores_null_or_empty_message)
{
  GPtrArray *errs = NULL;

  push_error (&errs, NULL);
  assert_that (errs, is_null);

  push_error (&errs, "");
  assert_that (errs, is_null);
}

Ensure (security_intelligence, push_error_handles_null_errors_parameter)
{
  push_error (NULL, "ignored");
  assert_that (true, is_true);
}

Ensure (security_intelligence, push_error_printf_adds_formatted_message)
{
  GPtrArray *errs = NULL;

  push_error_printf (&errs, "field %d: %s", 7, "invalid");

  assert_that (errs, is_not_null);
  assert_that ((int) errs->len, is_equal_to (1));
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               is_equal_to_string ("field 7: invalid"));

  g_ptr_array_free (errs, TRUE);
}

Ensure (security_intelligence, push_error_printf_ignores_null_format)
{
  GPtrArray *errs = NULL;

  push_error_printf (&errs, NULL);

  assert_that (errs, is_null);
}

Ensure (security_intelligence, error_field_or_unknown_returns_key_when_present)
{
  assert_that (error_field_or_unknown ("field-x"),
               is_equal_to_string ("field-x"));
}

Ensure (security_intelligence, error_field_or_unknown_returns_unknown_for_null)
{
  assert_that (error_field_or_unknown (NULL), is_equal_to_string ("unknown"));
}

Ensure (security_intelligence, error_field_or_unknown_returns_unknown_for_empty)
{
  assert_that (error_field_or_unknown (""), is_equal_to_string ("unknown"));
}

/* -------------------- Error Response JSON Parsing -------------------- */

Ensure (security_intelligence,
        parse_error_response_handles_null_errors_parameter)
{
  parse_error_response_json_into_array ("{}", 400, NULL);
  assert_that (true, is_true);
}

Ensure (security_intelligence, parse_error_response_empty_body_adds_fallback)
{
  GPtrArray *errs = NULL;

  parse_error_response_json_into_array (NULL, 400, &errs);

  assert_that (errs, is_not_null);
  assert_that ((int) errs->len, is_equal_to (1));
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               is_equal_to_string ("Request failed (400)."));

  g_ptr_array_free (errs, TRUE);
}

Ensure (security_intelligence, parse_error_response_invalid_json_adds_message)
{
  GPtrArray *errs = NULL;

  parse_error_response_json_into_array ("not-json", 422, &errs);

  assert_that (errs, is_not_null);
  assert_that ((int) errs->len, is_equal_to (1));
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               contains_string ("invalid JSON error response"));

  g_ptr_array_free (errs, TRUE);
}

Ensure (security_intelligence,
        parse_error_response_collects_title_details_fields)
{
  const char *json = "{"
                     "  \"title\":\"Validation failed\","
                     "  \"details\":\"Input is invalid\","
                     "  \"errors\": {"
                     "    \"ip\":\"must be IPv4\","
                     "    \"fingerprint\":\"required\""
                     "  }"
                     "}";

  GPtrArray *errs = NULL;

  parse_error_response_json_into_array (json, 400, &errs);

  assert_that (errs, is_not_null);
  assert_that ((int) errs->len, is_equal_to (4));
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               is_equal_to_string ("Validation failed"));
  assert_that ((const gchar *) g_ptr_array_index (errs, 1),
               is_equal_to_string ("Input is invalid"));
  assert_that ((const gchar *) g_ptr_array_index (errs, 2),
               is_equal_to_string ("ip: must be IPv4"));
  assert_that ((const gchar *) g_ptr_array_index (errs, 3),
               is_equal_to_string ("fingerprint: required"));

  g_ptr_array_free (errs, TRUE);
}

Ensure (security_intelligence,
        parse_error_response_supports_array_field_values_defensively)
{
  const char *json = "{"
                     "  \"errors\": {"
                     "    \"ip\": [\"bad format\", \"not routable\"]"
                     "  }"
                     "}";

  GPtrArray *errs = NULL;

  parse_error_response_json_into_array (json, 400, &errs);

  assert_that (errs, is_not_null);
  assert_that ((int) errs->len, is_equal_to (2));
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               is_equal_to_string ("ip: bad format"));
  assert_that ((const gchar *) g_ptr_array_index (errs, 1),
               is_equal_to_string ("ip: not routable"));

  g_ptr_array_free (errs, TRUE);
}

Ensure (security_intelligence,
        parse_error_response_supports_nested_object_defensively)
{
  const char *json = "{"
                     "  \"errors\": {"
                     "    \"meta\": {\"reason\":\"bad\"}"
                     "  }"
                     "}";

  GPtrArray *errs = NULL;

  parse_error_response_json_into_array (json, 400, &errs);

  assert_that (errs, is_not_null);
  assert_that ((int) errs->len, is_equal_to (1));
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               contains_string ("meta: {\"reason\":\"bad\"}"));

  g_ptr_array_free (errs, TRUE);
}

Ensure (security_intelligence, parse_error_response_falls_back_to_type)
{
  const char *json = "{ \"type\":\"validation_error\" }";
  GPtrArray *errs = NULL;

  parse_error_response_json_into_array (json, 400, &errs);

  assert_that (errs, is_not_null);
  assert_that ((int) errs->len, is_equal_to (1));
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               is_equal_to_string ("Request failed (400): validation_error"));

  g_ptr_array_free (errs, TRUE);
}

Ensure (security_intelligence, parse_error_response_falls_back_when_no_details)
{
  const char *json = "{ \"errors\": {} }";
  GPtrArray *errs = NULL;

  parse_error_response_json_into_array (json, 500, &errs);

  assert_that (errs, is_not_null);
  assert_that ((int) errs->len, is_equal_to (1));
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               contains_string ("no detailed error was provided"));

  g_ptr_array_free (errs, TRUE);
}

/* -------------------- Managed Appliance Parsing -------------------- */

Ensure (security_intelligence, parse_managed_appliance_parses_valid_object)
{
  const char *json = "{"
                     "  \"applianceId\":\"appl-1\","
                     "  \"ip\":\"10.10.10.10\","
                     "  \"httpsCertificateFingerprint\":\"FF:EE:DD\""
                     "}";

  cJSON *obj = cJSON_Parse (json);
  security_intelligence_managed_appliance_t appliance = NULL;

  security_intelligence_managed_appliance_t parsed =
    security_intelligence_parse_managed_appliance (obj, &appliance);

  assert_that (parsed, is_not_null);
  assert_that (appliance, is_not_null);
  assert_that (appliance->appliance_id, is_equal_to_string ("appl-1"));
  assert_that (appliance->ip, is_equal_to_string ("10.10.10.10"));
  assert_that (appliance->https_certificate_fingerprint,
               is_equal_to_string ("FF:EE:DD"));

  security_intelligence_managed_appliance_free (appliance);
  cJSON_Delete (obj);
}

Ensure (security_intelligence, parse_managed_appliance_returns_null_on_null_out)
{
  const char *json = "{"
                     "  \"applianceId\":\"appl-1\","
                     "  \"ip\":\"10.10.10.10\","
                     "  \"httpsCertificateFingerprint\":\"FF:EE:DD\""
                     "}";

  cJSON *obj = cJSON_Parse (json);

  assert_that (security_intelligence_parse_managed_appliance (obj, NULL),
               is_null);

  cJSON_Delete (obj);
}

Ensure (security_intelligence,
        parse_managed_appliance_returns_null_on_null_item)
{
  security_intelligence_managed_appliance_t appliance = NULL;

  assert_that (security_intelligence_parse_managed_appliance (NULL, &appliance),
               is_null);
  assert_that (appliance, is_null);
}

Ensure (security_intelligence,
        parse_managed_appliance_returns_null_on_non_object)
{
  cJSON *arr = cJSON_CreateArray ();
  security_intelligence_managed_appliance_t appliance = NULL;

  assert_that (security_intelligence_parse_managed_appliance (arr, &appliance),
               is_null);
  assert_that (appliance, is_null);

  cJSON_Delete (arr);
}

Ensure (security_intelligence,
        parse_managed_appliance_returns_null_when_appliance_id_missing)
{
  const char *json = "{"
                     "  \"ip\":\"10.10.10.10\","
                     "  \"httpsCertificateFingerprint\":\"FF:EE:DD\""
                     "}";

  cJSON *obj = cJSON_Parse (json);
  security_intelligence_managed_appliance_t appliance = NULL;

  assert_that (security_intelligence_parse_managed_appliance (obj, &appliance),
               is_null);
  assert_that (appliance, is_null);

  cJSON_Delete (obj);
}

Ensure (security_intelligence,
        parse_managed_appliance_returns_null_when_ip_missing)
{
  const char *json = "{"
                     "  \"applianceId\":\"appl-1\","
                     "  \"httpsCertificateFingerprint\":\"FF:EE:DD\""
                     "}";

  cJSON *obj = cJSON_Parse (json);
  security_intelligence_managed_appliance_t appliance = NULL;

  assert_that (security_intelligence_parse_managed_appliance (obj, &appliance),
               is_null);
  assert_that (appliance, is_null);

  cJSON_Delete (obj);
}

Ensure (security_intelligence,
        parse_managed_appliance_returns_null_when_fingerprint_missing)
{
  const char *json = "{"
                     "  \"applianceId\":\"appl-1\","
                     "  \"ip\":\"10.10.10.10\""
                     "}";

  cJSON *obj = cJSON_Parse (json);
  security_intelligence_managed_appliance_t appliance = NULL;

  assert_that (security_intelligence_parse_managed_appliance (obj, &appliance),
               is_null);
  assert_that (appliance, is_null);

  cJSON_Delete (obj);
}

/* -------------------- Managed Report Parsing -------------------- */

Ensure (security_intelligence, parse_managed_report_returns_null_on_null_input)
{
  security_intelligence_managed_report_t report =
    security_intelligence_parse_managed_report (NULL);

  assert_that (report, is_null);
}

Ensure (security_intelligence, parse_managed_report_returns_null_on_non_object)
{
  cJSON *arr = cJSON_CreateArray ();

  security_intelligence_managed_report_t report =
    security_intelligence_parse_managed_report (arr);

  assert_that (report, is_null);

  cJSON_Delete (arr);
}

Ensure (security_intelligence,
        parse_managed_report_returns_null_when_refid_missing)
{
  const char *json = "{"
                     "  \"uploadStatus\":\"upload_started\""
                     "}";

  cJSON *obj = cJSON_Parse (json);
  security_intelligence_managed_report_t report =
    security_intelligence_parse_managed_report (obj);

  assert_that (report, is_null);

  cJSON_Delete (obj);
}

Ensure (security_intelligence,
        parse_managed_report_returns_null_when_refid_empty)
{
  const char *json = "{"
                     "  \"refId\":\"\","
                     "  \"uploadStatus\":\"upload_started\""
                     "}";

  cJSON *obj = cJSON_Parse (json);
  security_intelligence_managed_report_t report =
    security_intelligence_parse_managed_report (obj);

  assert_that (report, is_null);

  cJSON_Delete (obj);
}

Ensure (security_intelligence,
        parse_managed_report_parses_valid_report_with_started_status)
{
  const char *json = "{"
                     "  \"refId\":\"report-123\","
                     "  \"uploadStatus\":\"upload_started\""
                     "}";

  cJSON *obj = cJSON_Parse (json);
  security_intelligence_managed_report_t report =
    security_intelligence_parse_managed_report (obj);

  assert_that (report, is_not_null);
  assert_that (report->ref_id, is_equal_to_string ("report-123"));
  assert_that (
    report->upload_status,
    is_equal_to (SECURITY_INTELLIGENCE_REPORT_UPLOAD_STATUS_STARTED));

  security_intelligence_managed_report_free (report);
  cJSON_Delete (obj);
}

Ensure (security_intelligence,
        parse_managed_report_parses_valid_report_with_completed_status)
{
  const char *json = "{"
                     "  \"refId\":\"report-456\","
                     "  \"uploadStatus\":\"upload_completed\""
                     "}";

  cJSON *obj = cJSON_Parse (json);
  security_intelligence_managed_report_t report =
    security_intelligence_parse_managed_report (obj);

  assert_that (report, is_not_null);
  assert_that (report->ref_id, is_equal_to_string ("report-456"));
  assert_that (
    report->upload_status,
    is_equal_to (SECURITY_INTELLIGENCE_REPORT_UPLOAD_STATUS_COMPLETED));

  security_intelligence_managed_report_free (report);
  cJSON_Delete (obj);
}

Ensure (security_intelligence,
        parse_managed_report_defaults_to_unknown_when_status_missing)
{
  const char *json = "{"
                     "  \"refId\":\"report-789\""
                     "}";

  cJSON *obj = cJSON_Parse (json);
  security_intelligence_managed_report_t report =
    security_intelligence_parse_managed_report (obj);

  assert_that (report, is_not_null);
  assert_that (report->ref_id, is_equal_to_string ("report-789"));
  assert_that (
    report->upload_status,
    is_equal_to (SECURITY_INTELLIGENCE_REPORT_UPLOAD_STATUS_UNKNOWN));

  security_intelligence_managed_report_free (report);
  cJSON_Delete (obj);
}

Ensure (security_intelligence,
        parse_managed_report_defaults_to_unknown_when_status_invalid)
{
  const char *json = "{"
                     "  \"refId\":\"report-999\","
                     "  \"uploadStatus\":\"something_else\""
                     "}";

  cJSON *obj = cJSON_Parse (json);
  security_intelligence_managed_report_t report =
    security_intelligence_parse_managed_report (obj);

  assert_that (report, is_not_null);
  assert_that (report->ref_id, is_equal_to_string ("report-999"));
  assert_that (
    report->upload_status,
    is_equal_to (SECURITY_INTELLIGENCE_REPORT_UPLOAD_STATUS_UNKNOWN));

  security_intelligence_managed_report_free (report);
  cJSON_Delete (obj);
}

Ensure (security_intelligence,
        parse_managed_report_defaults_to_unknown_when_status_empty)
{
  const char *json = "{"
                     "  \"refId\":\"report-abc\","
                     "  \"uploadStatus\":\"\""
                     "}";

  cJSON *obj = cJSON_Parse (json);
  security_intelligence_managed_report_t report =
    security_intelligence_parse_managed_report (obj);

  assert_that (report, is_not_null);
  assert_that (report->ref_id, is_equal_to_string ("report-abc"));
  assert_that (
    report->upload_status,
    is_equal_to (SECURITY_INTELLIGENCE_REPORT_UPLOAD_STATUS_UNKNOWN));

  security_intelligence_managed_report_free (report);
  cJSON_Delete (obj);
}

/* -------------------- Payload Builders -------------------- */

Ensure (security_intelligence,
        build_create_managed_appliance_payload_returns_null_for_null_input)
{
  gchar *payload =
    security_intelligence_build_create_managed_appliance_payload (NULL);

  assert_that (payload, is_null);
}

Ensure (security_intelligence,
        build_create_managed_appliance_payload_requires_ip)
{
  security_intelligence_managed_appliance_t appliance =
    security_intelligence_managed_appliance_new ();
  appliance->https_certificate_fingerprint = g_strdup ("FP");

  gchar *payload =
    security_intelligence_build_create_managed_appliance_payload (appliance);

  assert_that (payload, is_null);

  security_intelligence_managed_appliance_free (appliance);
}

Ensure (security_intelligence,
        build_create_managed_appliance_payload_requires_fingerprint)
{
  security_intelligence_managed_appliance_t appliance =
    security_intelligence_managed_appliance_new ();
  appliance->ip = g_strdup ("10.0.0.1");

  gchar *payload =
    security_intelligence_build_create_managed_appliance_payload (appliance);

  assert_that (payload, is_null);

  security_intelligence_managed_appliance_free (appliance);
}

Ensure (security_intelligence,
        build_create_managed_appliance_payload_builds_expected_json)
{
  security_intelligence_managed_appliance_t appliance = make_appliance ();

  gchar *payload =
    security_intelligence_build_create_managed_appliance_payload (appliance);

  assert_that (payload, is_not_null);
  assert_that (payload, contains_string ("\"ip\":\"192.168.1.10\""));
  assert_that (
    payload, contains_string ("\"httpsCertificateFingerprint\":\"AA:BB:CC\""));
  assert_that (payload, does_not_contain_string ("applianceId"));

  cJSON_free (payload);
  security_intelligence_managed_appliance_free (appliance);
}

Ensure (security_intelligence,
        build_create_report_payload_returns_null_for_null_or_empty)
{
  assert_that (security_intelligence_build_create_report_payload (NULL),
               is_null);
  assert_that (security_intelligence_build_create_report_payload (""), is_null);
}

Ensure (security_intelligence, build_create_report_payload_builds_json)
{
  gchar *payload =
    security_intelligence_build_create_report_payload ("report-uuid");

  assert_that (payload, is_not_null);
  assert_that (payload, is_equal_to_string ("{\"refId\":\"report-uuid\"}"));

  cJSON_free (payload);
}

Ensure (security_intelligence,
        build_update_report_status_payload_returns_null_for_unknown)
{
  gchar *payload = security_intelligence_build_update_report_status_payload (
    SECURITY_INTELLIGENCE_REPORT_UPLOAD_STATUS_UNKNOWN);

  assert_that (payload, is_null);
}

Ensure (security_intelligence,
        build_update_report_status_payload_builds_started_json)
{
  gchar *payload = security_intelligence_build_update_report_status_payload (
    SECURITY_INTELLIGENCE_REPORT_UPLOAD_STATUS_STARTED);

  assert_that (payload, is_not_null);
  assert_that (payload, is_equal_to_string ("{\"status\":\"upload_started\"}"));

  cJSON_free (payload);
}

Ensure (security_intelligence,
        build_update_report_status_payload_builds_completed_json)
{
  gchar *payload = security_intelligence_build_update_report_status_payload (
    SECURITY_INTELLIGENCE_REPORT_UPLOAD_STATUS_COMPLETED);

  assert_that (payload, is_not_null);
  assert_that (payload,
               is_equal_to_string ("{\"status\":\"upload_completed\"}"));

  cJSON_free (payload);
}

/* -------------------- create_managed_appliance -------------------- */

Ensure (security_intelligence,
        create_managed_appliance_fails_for_null_arguments)
{
  security_intelligence_connector_t conn = make_conn ();
  security_intelligence_managed_appliance_t appliance = make_appliance ();
  security_intelligence_managed_appliance_t created = NULL;
  GPtrArray *errs = NULL;

  int rc = security_intelligence_create_managed_appliance (NULL, appliance,
                                                           &created, &errs);
  assert_that (rc, is_equal_to (SECURITY_INTELLIGENCE_RESP_ERR));
  assert_that (created, is_null);
  assert_that (errs, is_not_null);
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               is_equal_to_string ("Invalid connection or appliance."));

  g_ptr_array_free (errs, TRUE);
  errs = NULL;

  rc = security_intelligence_create_managed_appliance (conn, NULL, &created,
                                                       &errs);
  assert_that (rc, is_equal_to (SECURITY_INTELLIGENCE_RESP_ERR));
  assert_that (created, is_null);
  assert_that (errs, is_not_null);
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               is_equal_to_string ("Invalid connection or appliance."));

  g_ptr_array_free (errs, TRUE);
  errs = NULL;

  rc = security_intelligence_create_managed_appliance (conn, appliance, NULL,
                                                       &errs);
  assert_that (rc, is_equal_to (SECURITY_INTELLIGENCE_RESP_ERR));
  assert_that (errs, is_not_null);
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               is_equal_to_string ("Invalid connection or appliance."));

  g_ptr_array_free (errs, TRUE);
  security_intelligence_managed_appliance_free (appliance);
  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence,
        create_managed_appliance_sets_created_to_null_before_processing)
{
  security_intelligence_connector_t conn = make_conn ();
  security_intelligence_managed_appliance_t appliance = make_appliance ();
  security_intelligence_managed_appliance_t created =
    security_intelligence_managed_appliance_new ();
  security_intelligence_managed_appliance_t old_created = created;
  created->appliance_id = g_strdup ("old");

  GPtrArray *errs = NULL;

  appliance->appliance_id[0] = '\0';

  int rc = security_intelligence_create_managed_appliance (conn, appliance,
                                                           &created, &errs);

  assert_that (rc, is_equal_to (SECURITY_INTELLIGENCE_RESP_ERR));
  assert_that (created, is_null);
  assert_that (errs, is_not_null);

  g_ptr_array_free (errs, TRUE);
  security_intelligence_managed_appliance_free (appliance);
  security_intelligence_managed_appliance_free (old_created);
  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence,
        create_managed_appliance_fails_when_appliance_id_missing)
{
  security_intelligence_connector_t conn = make_conn ();
  security_intelligence_managed_appliance_t appliance = make_appliance ();
  security_intelligence_managed_appliance_t created = NULL;
  GPtrArray *errs = NULL;

  g_free (appliance->appliance_id);
  appliance->appliance_id = NULL;

  int rc = security_intelligence_create_managed_appliance (conn, appliance,
                                                           &created, &errs);

  assert_that (rc, is_equal_to (SECURITY_INTELLIGENCE_RESP_ERR));
  assert_that (created, is_null);
  assert_that (errs, is_not_null);
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               is_equal_to_string ("Invalid appliance id."));

  g_ptr_array_free (errs, TRUE);
  security_intelligence_managed_appliance_free (appliance);
  security_intelligence_managed_appliance_free (created);
  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence,
        create_managed_appliance_fails_when_payload_build_fails)
{
  security_intelligence_connector_t conn = make_conn ();
  security_intelligence_managed_appliance_t appliance = make_appliance ();
  security_intelligence_managed_appliance_t created = NULL;
  GPtrArray *errs = NULL;

  g_free (appliance->ip);
  appliance->ip = NULL;

  int rc = security_intelligence_create_managed_appliance (conn, appliance,
                                                           &created, &errs);

  assert_that (rc, is_equal_to (SECURITY_INTELLIGENCE_RESP_ERR));
  assert_that (created, is_null);
  assert_that (errs, is_not_null);
  assert_that (
    (const gchar *) g_ptr_array_index (errs, 0),
    is_equal_to_string ("Failed to build managed appliance payload."));

  g_ptr_array_free (errs, TRUE);
  security_intelligence_managed_appliance_free (appliance);
  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence,
        create_managed_appliance_fails_when_no_http_response)
{
  security_intelligence_connector_t conn = make_conn ();
  security_intelligence_managed_appliance_t appliance = make_appliance ();
  security_intelligence_managed_appliance_t created = NULL;
  GPtrArray *errs = NULL;

  mock_http_status = 500;
  g_clear_pointer (&mock_response_data, g_free);

  int rc = security_intelligence_create_managed_appliance (conn, appliance,
                                                           &created, &errs);

  assert_that (rc, is_equal_to (SECURITY_INTELLIGENCE_RESP_ERR));
  assert_that (created, is_null);
  assert_that (errs, is_not_null);
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               is_equal_to_string ("Failed to get response."));

  g_ptr_array_free (errs, TRUE);
  security_intelligence_managed_appliance_free (appliance);
  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence,
        create_managed_appliance_fails_on_non_2xx_and_parses_error_response)
{
  security_intelligence_connector_t conn = make_conn ();
  security_intelligence_managed_appliance_t appliance = make_appliance ();
  security_intelligence_managed_appliance_t created = NULL;
  GPtrArray *errs = NULL;

  mock_http_status = 400;
  mock_response_data = g_strdup ("{"
                                 "  \"title\":\"Validation failed\","
                                 "  \"details\":\"Bad request body\","
                                 "  \"errors\": {"
                                 "    \"ip\":\"must be IPv4\""
                                 "  }"
                                 "}");

  int rc = security_intelligence_create_managed_appliance (conn, appliance,
                                                           &created, &errs);

  assert_that (rc, is_equal_to (SECURITY_INTELLIGENCE_RESP_ERR));
  assert_that (created, is_null);
  assert_that (errs, is_not_null);
  assert_that ((int) errs->len, is_equal_to (3));
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               is_equal_to_string ("Validation failed"));
  assert_that ((const gchar *) g_ptr_array_index (errs, 1),
               is_equal_to_string ("Bad request body"));
  assert_that ((const gchar *) g_ptr_array_index (errs, 2),
               is_equal_to_string ("ip: must be IPv4"));

  g_ptr_array_free (errs, TRUE);
  security_intelligence_managed_appliance_free (appliance);
  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence,
        create_managed_appliance_fails_when_success_body_is_invalid_json)
{
  security_intelligence_connector_t conn = make_conn ();
  security_intelligence_managed_appliance_t appliance = make_appliance ();
  security_intelligence_managed_appliance_t created = NULL;
  GPtrArray *errs = NULL;

  mock_http_status = 200;
  mock_response_data = g_strdup ("not-json");

  int rc = security_intelligence_create_managed_appliance (conn, appliance,
                                                           &created, &errs);

  assert_that (rc, is_equal_to (SECURITY_INTELLIGENCE_RESP_ERR));
  assert_that (created, is_null);
  assert_that (errs, is_not_null);
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               is_equal_to_string ("Failed to parse JSON response."));

  g_ptr_array_free (errs, TRUE);
  security_intelligence_managed_appliance_free (appliance);
  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence,
        create_managed_appliance_fails_when_success_body_is_missing_fields)
{
  security_intelligence_connector_t conn = make_conn ();
  security_intelligence_managed_appliance_t appliance = make_appliance ();
  security_intelligence_managed_appliance_t created = NULL;
  GPtrArray *errs = NULL;

  mock_http_status = 200;
  mock_response_data = g_strdup ("{"
                                 "  \"applianceId\":\"appl-123\","
                                 "  \"ip\":\"192.168.1.10\""
                                 "}");

  int rc = security_intelligence_create_managed_appliance (conn, appliance,
                                                           &created, &errs);

  assert_that (rc, is_equal_to (SECURITY_INTELLIGENCE_RESP_ERR));
  assert_that (created, is_null);
  assert_that (errs, is_not_null);
  assert_that (
    (const gchar *) g_ptr_array_index (errs, 0),
    is_equal_to_string ("Failed to parse managed appliance response."));

  g_ptr_array_free (errs, TRUE);
  security_intelligence_managed_appliance_free (appliance);
  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence,
        create_managed_appliance_success_returns_created_object_and_sends_put)
{
  security_intelligence_connector_t conn = make_conn ();
  security_intelligence_managed_appliance_t appliance = make_appliance ();
  security_intelligence_managed_appliance_t created = NULL;
  GPtrArray *errs = NULL;

  mock_http_status = 201;
  mock_response_data =
    g_strdup ("{"
              "  \"applianceId\":\"appl-123\","
              "  \"ip\":\"192.168.1.10\","
              "  \"httpsCertificateFingerprint\":\"AA:BB:CC\""
              "}");

  int rc = security_intelligence_create_managed_appliance (conn, appliance,
                                                           &created, &errs);

  assert_that (rc, is_equal_to (SECURITY_INTELLIGENCE_RESP_OK));
  assert_that (errs, is_null);
  assert_that (created, is_not_null);

  assert_that (last_sent_url, is_equal_to_string (
                                "https://localhost:8443/api/asset-management/"
                                "managed-appliances/appl-123"));
  assert_that (last_sent_payload, contains_string ("\"ip\":\"192.168.1.10\""));
  assert_that (
    last_sent_payload,
    contains_string ("\"httpsCertificateFingerprint\":\"AA:BB:CC\""));

  assert_that (created->appliance_id, is_equal_to_string ("appl-123"));
  assert_that (created->ip, is_equal_to_string ("192.168.1.10"));
  assert_that (created->https_certificate_fingerprint,
               is_equal_to_string ("AA:BB:CC"));

  security_intelligence_managed_appliance_free (created);
  security_intelligence_managed_appliance_free (appliance);
  security_intelligence_connector_free (conn);
}

/* -------------------- delete_managed_appliance -------------------- */

Ensure (security_intelligence,
        delete_managed_appliance_fails_for_null_arguments)
{
  security_intelligence_connector_t conn = make_conn ();
  const gchar *appliance_id = "appliance-id";

  int rc = security_intelligence_delete_managed_appliance (NULL, appliance_id);
  assert_that (rc, is_equal_to (SECURITY_INTELLIGENCE_RESP_ERR));

  rc = security_intelligence_delete_managed_appliance (conn, NULL);
  assert_that (rc, is_equal_to (SECURITY_INTELLIGENCE_RESP_ERR));

  rc = security_intelligence_delete_managed_appliance (conn, "");
  assert_that (rc, is_equal_to (SECURITY_INTELLIGENCE_RESP_ERR));

  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence,
        delete_managed_appliance_fails_with_response_status)
{
  security_intelligence_connector_t conn = make_conn ();
  const gchar *appliance_id = "appliance-id";

  mock_http_status = 400;
  g_clear_pointer (&mock_response_data, g_free);
  mock_response_data = g_strdup ("{}");

  int rc = security_intelligence_delete_managed_appliance (conn, appliance_id);

  assert_that (rc, is_equal_to (SECURITY_INTELLIGENCE_RESP_ERR));
  assert_that (last_sent_url, is_equal_to_string (
                                "https://localhost:8443/api/asset-management/"
                                "managed-appliances/appliance-id"));
  assert_that (last_sent_payload, is_null);

  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence,
        delete_managed_appliance_fails_when_no_http_response)
{
  security_intelligence_connector_t conn = make_conn ();
  const gchar *appliance_id = "appliance-id";

  mock_http_status = 500;
  g_clear_pointer (&mock_response_data, g_free);

  int rc = security_intelligence_delete_managed_appliance (conn, appliance_id);

  assert_that (rc, is_equal_to (SECURITY_INTELLIGENCE_RESP_ERR));
  assert_that (last_sent_url, is_equal_to_string (
                                "https://localhost:8443/api/asset-management/"
                                "managed-appliances/appliance-id"));
  assert_that (last_sent_payload, is_null);

  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence,
        delete_managed_appliance_success_returns_ok_on_200)
{
  security_intelligence_connector_t conn = make_conn ();
  const gchar *appliance_id = "appliance-id";

  mock_http_status = 200;
  g_clear_pointer (&mock_response_data, g_free);
  mock_response_data = g_strdup ("{}");

  int rc = security_intelligence_delete_managed_appliance (conn, appliance_id);

  assert_that (rc, is_equal_to (SECURITY_INTELLIGENCE_RESP_OK));
  assert_that (last_sent_url, is_equal_to_string (
                                "https://localhost:8443/api/asset-management/"
                                "managed-appliances/appliance-id"));
  assert_that (last_sent_payload, is_null);

  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence,
        delete_managed_appliance_success_returns_ok_on_204)
{
  security_intelligence_connector_t conn = make_conn ();
  const gchar *appliance_id = "appliance-id";

  mock_http_status = 204;
  g_clear_pointer (&mock_response_data, g_free);
  mock_response_data = g_strdup ("");

  int rc = security_intelligence_delete_managed_appliance (conn, appliance_id);

  assert_that (rc, is_equal_to (SECURITY_INTELLIGENCE_RESP_OK));
  assert_that (last_sent_url, is_equal_to_string (
                                "https://localhost:8443/api/asset-management/"
                                "managed-appliances/appliance-id"));
  assert_that (last_sent_payload, is_null);

  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence,
        delete_managed_appliance_uses_prebuilt_base_url_when_present)
{
  security_intelligence_connector_t conn = make_conn ();
  const gchar *appliance_id = "appliance-id";

  g_free (conn->url);
  conn->url = g_strdup ("https://example.test/base");

  mock_http_status = 200;
  g_clear_pointer (&mock_response_data, g_free);
  mock_response_data = g_strdup ("{}");

  int rc = security_intelligence_delete_managed_appliance (conn, appliance_id);

  assert_that (rc, is_equal_to (SECURITY_INTELLIGENCE_RESP_OK));
  assert_that (
    last_sent_url,
    is_equal_to_string ("https://example.test/base/api/asset-management/"
                        "managed-appliances/appliance-id"));
  assert_that (last_sent_payload, is_null);

  security_intelligence_connector_free (conn);
}

/* -------------------- list_managed_reports -------------------- */

Ensure (security_intelligence, list_reports_returns_null_on_null_conn)
{
  security_intelligence_managed_report_list_t reports =
    security_intelligence_list_reports (NULL);

  assert_that (reports, is_null);
}

Ensure (security_intelligence, list_reports_returns_null_when_no_http_response)
{
  security_intelligence_connector_t conn = make_conn ();

  mock_http_status = 500;
  g_clear_pointer (&mock_response_data, g_free);

  security_intelligence_managed_report_list_t reports =
    security_intelligence_list_reports (conn);

  assert_that (reports, is_null);
  assert_that (last_sent_url, is_equal_to_string (
                                "https://localhost:8443/api/asset-management/"
                                "managed-appliances/reports"));
  assert_that (last_sent_payload, is_null);

  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence, list_reports_returns_null_on_non_2xx_status)
{
  security_intelligence_connector_t conn = make_conn ();

  mock_http_status = 403;
  g_clear_pointer (&mock_response_data, g_free);
  mock_response_data = g_strdup ("[]");

  security_intelligence_managed_report_list_t reports =
    security_intelligence_list_reports (conn);

  assert_that (reports, is_null);
  assert_that (last_sent_url, is_equal_to_string (
                                "https://localhost:8443/api/asset-management/"
                                "managed-appliances/reports"));
  assert_that (last_sent_payload, is_null);

  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence, list_reports_returns_null_on_invalid_json)
{
  security_intelligence_connector_t conn = make_conn ();

  mock_http_status = 200;
  g_clear_pointer (&mock_response_data, g_free);
  mock_response_data = g_strdup ("not-json");

  security_intelligence_managed_report_list_t reports =
    security_intelligence_list_reports (conn);

  assert_that (reports, is_null);
  assert_that (last_sent_url, is_equal_to_string (
                                "https://localhost:8443/api/asset-management/"
                                "managed-appliances/reports"));

  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence, list_reports_returns_null_when_root_is_not_array)
{
  security_intelligence_connector_t conn = make_conn ();

  mock_http_status = 200;
  g_clear_pointer (&mock_response_data, g_free);
  mock_response_data = g_strdup ("{\"reports\": []}");

  security_intelligence_managed_report_list_t reports =
    security_intelligence_list_reports (conn);

  assert_that (reports, is_null);

  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence, list_reports_returns_empty_list_for_empty_array)
{
  security_intelligence_connector_t conn = make_conn ();

  mock_http_status = 200;
  g_clear_pointer (&mock_response_data, g_free);
  mock_response_data = g_strdup ("[]");

  security_intelligence_managed_report_list_t reports =
    security_intelligence_list_reports (conn);

  assert_that (reports, is_not_null);
  assert_that (reports->count, is_equal_to (0));
  assert_that (reports->reports, is_not_null);

  security_intelligence_managed_report_list_free (reports);
  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence, list_reports_parses_valid_reports)
{
  security_intelligence_connector_t conn = make_conn ();

  mock_http_status = 200;
  g_clear_pointer (&mock_response_data, g_free);
  mock_response_data =
    g_strdup ("["
              "  {\"refId\":\"r1\",\"uploadStatus\":\"upload_started\"},"
              "  {\"refId\":\"r2\",\"uploadStatus\":\"upload_completed\"}"
              "]");

  security_intelligence_managed_report_list_t reports =
    security_intelligence_list_reports (conn);

  assert_that (reports, is_not_null);
  assert_that (reports->count, is_equal_to (2));
  assert_that (reports->reports[0], is_not_null);
  assert_that (reports->reports[1], is_not_null);

  assert_that (reports->reports[0]->ref_id, is_equal_to_string ("r1"));
  assert_that (
    reports->reports[0]->upload_status,
    is_equal_to (SECURITY_INTELLIGENCE_REPORT_UPLOAD_STATUS_STARTED));

  assert_that (reports->reports[1]->ref_id, is_equal_to_string ("r2"));
  assert_that (
    reports->reports[1]->upload_status,
    is_equal_to (SECURITY_INTELLIGENCE_REPORT_UPLOAD_STATUS_COMPLETED));

  security_intelligence_managed_report_list_free (reports);
  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence,
        list_reports_filters_invalid_items_and_keeps_order)
{
  security_intelligence_connector_t conn = make_conn ();

  mock_http_status = 200;
  g_clear_pointer (&mock_response_data, g_free);
  mock_response_data =
    g_strdup ("["
              "  {\"refId\":\"r1\",\"uploadStatus\":\"upload_started\"},"
              "  {\"uploadStatus\":\"upload_completed\"},"
              "  {\"refId\":\"\"},"
              "  {\"refId\":\"r2\",\"uploadStatus\":\"upload_completed\"},"
              "  42,"
              "  null,"
              "  {\"refId\":\"r3\",\"uploadStatus\":\"something_else\"}"
              "]");

  security_intelligence_managed_report_list_t reports =
    security_intelligence_list_reports (conn);

  assert_that (reports, is_not_null);
  assert_that (reports->count, is_equal_to (3));

  assert_that (reports->reports[0], is_not_null);
  assert_that (reports->reports[1], is_not_null);
  assert_that (reports->reports[2], is_not_null);

  assert_that (reports->reports[0]->ref_id, is_equal_to_string ("r1"));
  assert_that (
    reports->reports[0]->upload_status,
    is_equal_to (SECURITY_INTELLIGENCE_REPORT_UPLOAD_STATUS_STARTED));

  assert_that (reports->reports[1]->ref_id, is_equal_to_string ("r2"));
  assert_that (
    reports->reports[1]->upload_status,
    is_equal_to (SECURITY_INTELLIGENCE_REPORT_UPLOAD_STATUS_COMPLETED));

  assert_that (reports->reports[2]->ref_id, is_equal_to_string ("r3"));
  assert_that (
    reports->reports[2]->upload_status,
    is_equal_to (SECURITY_INTELLIGENCE_REPORT_UPLOAD_STATUS_UNKNOWN));

  security_intelligence_managed_report_list_free (reports);
  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence,
        list_reports_all_invalid_items_returns_empty_list)
{
  security_intelligence_connector_t conn = make_conn ();

  mock_http_status = 200;
  g_clear_pointer (&mock_response_data, g_free);
  mock_response_data = g_strdup ("["
                                 "  {},"
                                 "  {\"refId\":\"\"},"
                                 "  null,"
                                 "  [],"
                                 "  7"
                                 "]");

  security_intelligence_managed_report_list_t reports =
    security_intelligence_list_reports (conn);

  assert_that (reports, is_not_null);
  assert_that (reports->count, is_equal_to (0));
  assert_that (reports->reports, is_not_null);

  security_intelligence_managed_report_list_free (reports);
  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence, list_reports_uses_prebuilt_base_url_when_present)
{
  security_intelligence_connector_t conn = make_conn ();

  g_free (conn->url);
  conn->url = g_strdup ("https://example.test/base");

  mock_http_status = 200;
  g_clear_pointer (&mock_response_data, g_free);
  mock_response_data = g_strdup ("[]");

  security_intelligence_managed_report_list_t reports =
    security_intelligence_list_reports (conn);

  assert_that (reports, is_not_null);
  assert_that (reports->count, is_equal_to (0));
  assert_that (last_sent_url, is_equal_to_string (
                                "https://example.test/base/api/"
                                "asset-management/managed-appliances/reports"));
  assert_that (last_sent_payload, is_null);

  security_intelligence_managed_report_list_free (reports);
  security_intelligence_connector_free (conn);
}

/* -------------------- get_managed_reports -------------------- */

Ensure (security_intelligence, get_report_returns_null_on_null_conn)
{
  GPtrArray *errs = NULL;

  security_intelligence_managed_report_t report =
    security_intelligence_get_report (NULL, "report-id", &errs);

  assert_that (report, is_null);
  assert_that (errs, is_null);
}

Ensure (security_intelligence, get_report_returns_null_on_null_report_id)
{
  security_intelligence_connector_t conn = make_conn ();
  GPtrArray *errs = NULL;

  security_intelligence_managed_report_t report =
    security_intelligence_get_report (conn, NULL, &errs);

  assert_that (report, is_null);
  assert_that (errs, is_null);

  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence, get_report_returns_null_on_empty_report_id)
{
  security_intelligence_connector_t conn = make_conn ();
  GPtrArray *errs = NULL;

  security_intelligence_managed_report_t report =
    security_intelligence_get_report (conn, "", &errs);

  assert_that (report, is_null);
  assert_that (errs, is_null);

  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence, get_report_returns_null_when_no_http_response)
{
  security_intelligence_connector_t conn = make_conn ();
  GPtrArray *errs = NULL;

  mock_http_status = 500;
  g_clear_pointer (&mock_response_data, g_free);

  security_intelligence_managed_report_t report =
    security_intelligence_get_report (conn, "report-id", &errs);

  assert_that (report, is_null);
  assert_that (errs, is_null);
  assert_that (last_sent_url, is_equal_to_string (
                                "https://localhost:8443/api/asset-management/"
                                "managed-appliances/reports/report-id"));
  assert_that (last_sent_payload, is_null);

  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence, get_report_non_2xx_populates_errors_from_json)
{
  security_intelligence_connector_t conn = make_conn ();
  GPtrArray *errs = NULL;

  mock_http_status = 404;
  g_clear_pointer (&mock_response_data, g_free);
  mock_response_data = g_strdup ("{"
                                 "  \"title\":\"Not found\","
                                 "  \"details\":\"Report does not exist\","
                                 "  \"errors\": {"
                                 "    \"reportId\":\"unknown id\""
                                 "  }"
                                 "}");

  security_intelligence_managed_report_t report =
    security_intelligence_get_report (conn, "report-id", &errs);

  assert_that (report, is_null);
  assert_that (errs, is_not_null);
  assert_that ((int) errs->len, is_equal_to (3));
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               is_equal_to_string ("Not found"));
  assert_that ((const gchar *) g_ptr_array_index (errs, 1),
               is_equal_to_string ("Report does not exist"));
  assert_that ((const gchar *) g_ptr_array_index (errs, 2),
               is_equal_to_string ("reportId: unknown id"));

  g_ptr_array_free (errs, TRUE);
  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence,
        get_report_non_2xx_invalid_json_adds_fallback_error)
{
  security_intelligence_connector_t conn = make_conn ();
  GPtrArray *errs = NULL;

  mock_http_status = 400;
  g_clear_pointer (&mock_response_data, g_free);
  mock_response_data = g_strdup ("not-json");

  security_intelligence_managed_report_t report =
    security_intelligence_get_report (conn, "report-id", &errs);

  assert_that (report, is_null);
  assert_that (errs, is_not_null);
  assert_that ((int) errs->len, is_equal_to (1));
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               contains_string ("invalid JSON error response"));

  g_ptr_array_free (errs, TRUE);
  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence, get_report_success_invalid_json_adds_parse_error)
{
  security_intelligence_connector_t conn = make_conn ();
  GPtrArray *errs = NULL;

  mock_http_status = 200;
  g_clear_pointer (&mock_response_data, g_free);
  mock_response_data = g_strdup ("not-json");

  security_intelligence_managed_report_t report =
    security_intelligence_get_report (conn, "report-id", &errs);

  assert_that (report, is_null);
  assert_that (errs, is_not_null);
  assert_that ((int) errs->len, is_equal_to (1));
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               is_equal_to_string ("Failed to parse JSON response."));

  g_ptr_array_free (errs, TRUE);
  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence,
        get_report_success_with_invalid_report_object_returns_null)
{
  security_intelligence_connector_t conn = make_conn ();
  GPtrArray *errs = NULL;

  mock_http_status = 200;
  g_clear_pointer (&mock_response_data, g_free);
  mock_response_data = g_strdup ("{"
                                 "  \"uploadStatus\":\"upload_started\""
                                 "}");

  security_intelligence_managed_report_t report =
    security_intelligence_get_report (conn, "report-id", &errs);

  assert_that (report, is_null);
  assert_that (errs, is_not_null);
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               is_equal_to_string ("Failed to parse managed report response."));

  g_ptr_array_free (errs, TRUE);
  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence,
        get_report_success_parses_report_with_started_status)
{
  security_intelligence_connector_t conn = make_conn ();
  GPtrArray *errs = NULL;

  mock_http_status = 200;
  g_clear_pointer (&mock_response_data, g_free);
  mock_response_data = g_strdup ("{"
                                 "  \"refId\":\"report-id\","
                                 "  \"uploadStatus\":\"upload_started\""
                                 "}");

  security_intelligence_managed_report_t report =
    security_intelligence_get_report (conn, "report-id", &errs);

  assert_that (report, is_not_null);
  assert_that (errs, is_null);
  assert_that (report->ref_id, is_equal_to_string ("report-id"));
  assert_that (
    report->upload_status,
    is_equal_to (SECURITY_INTELLIGENCE_REPORT_UPLOAD_STATUS_STARTED));
  assert_that (last_sent_url, is_equal_to_string (
                                "https://localhost:8443/api/asset-management/"
                                "managed-appliances/reports/report-id"));
  assert_that (last_sent_payload, is_null);

  security_intelligence_managed_report_free (report);
  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence,
        get_report_success_parses_report_with_completed_status)
{
  security_intelligence_connector_t conn = make_conn ();
  GPtrArray *errs = NULL;

  mock_http_status = 200;
  g_clear_pointer (&mock_response_data, g_free);
  mock_response_data = g_strdup ("{"
                                 "  \"refId\":\"report-id\","
                                 "  \"uploadStatus\":\"upload_completed\""
                                 "}");

  security_intelligence_managed_report_t report =
    security_intelligence_get_report (conn, "report-id", &errs);

  assert_that (report, is_not_null);
  assert_that (errs, is_null);
  assert_that (report->ref_id, is_equal_to_string ("report-id"));
  assert_that (
    report->upload_status,
    is_equal_to (SECURITY_INTELLIGENCE_REPORT_UPLOAD_STATUS_COMPLETED));

  security_intelligence_managed_report_free (report);
  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence,
        get_report_success_defaults_status_to_unknown_when_missing)
{
  security_intelligence_connector_t conn = make_conn ();
  GPtrArray *errs = NULL;

  mock_http_status = 200;
  g_clear_pointer (&mock_response_data, g_free);
  mock_response_data = g_strdup ("{"
                                 "  \"refId\":\"report-id\""
                                 "}");

  security_intelligence_managed_report_t report =
    security_intelligence_get_report (conn, "report-id", &errs);

  assert_that (report, is_not_null);
  assert_that (errs, is_null);
  assert_that (report->ref_id, is_equal_to_string ("report-id"));
  assert_that (
    report->upload_status,
    is_equal_to (SECURITY_INTELLIGENCE_REPORT_UPLOAD_STATUS_UNKNOWN));

  security_intelligence_managed_report_free (report);
  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence,
        get_report_success_defaults_status_to_unknown_when_invalid)
{
  security_intelligence_connector_t conn = make_conn ();
  GPtrArray *errs = NULL;

  mock_http_status = 200;
  g_clear_pointer (&mock_response_data, g_free);
  mock_response_data = g_strdup ("{"
                                 "  \"refId\":\"report-id\","
                                 "  \"uploadStatus\":\"weird_status\""
                                 "}");

  security_intelligence_managed_report_t report =
    security_intelligence_get_report (conn, "report-id", &errs);

  assert_that (report, is_not_null);
  assert_that (errs, is_null);
  assert_that (report->ref_id, is_equal_to_string ("report-id"));
  assert_that (
    report->upload_status,
    is_equal_to (SECURITY_INTELLIGENCE_REPORT_UPLOAD_STATUS_UNKNOWN));

  security_intelligence_managed_report_free (report);
  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence, get_report_uses_prebuilt_base_url_when_present)
{
  security_intelligence_connector_t conn = make_conn ();
  GPtrArray *errs = NULL;

  g_free (conn->url);
  conn->url = g_strdup ("https://example.test/base");

  mock_http_status = 200;
  g_clear_pointer (&mock_response_data, g_free);
  mock_response_data = g_strdup ("{"
                                 "  \"refId\":\"report-id\","
                                 "  \"uploadStatus\":\"upload_started\""
                                 "}");

  security_intelligence_managed_report_t report =
    security_intelligence_get_report (conn, "report-id", &errs);

  assert_that (report, is_not_null);
  assert_that (
    last_sent_url,
    is_equal_to_string ("https://example.test/base/api/asset-management/"
                        "managed-appliances/reports/report-id"));
  assert_that (last_sent_payload, is_null);

  security_intelligence_managed_report_free (report);
  security_intelligence_connector_free (conn);
}

/* -------------------- create_managed_reports -------------------- */

Ensure (security_intelligence, create_report_fails_for_null_arguments)
{
  security_intelligence_connector_t conn = make_conn ();
  security_intelligence_managed_report_t created = NULL;
  GPtrArray *errs = NULL;

  int rc =
    security_intelligence_create_report (NULL, "report-id", &created, &errs);
  assert_that (rc, is_equal_to (SECURITY_INTELLIGENCE_RESP_ERR));
  assert_that (created, is_null);
  assert_that (errs, is_null);

  rc = security_intelligence_create_report (conn, NULL, &created, &errs);
  assert_that (rc, is_equal_to (SECURITY_INTELLIGENCE_RESP_ERR));
  assert_that (created, is_null);
  assert_that (errs, is_null);

  rc = security_intelligence_create_report (conn, "", &created, &errs);
  assert_that (rc, is_equal_to (SECURITY_INTELLIGENCE_RESP_ERR));
  assert_that (created, is_null);
  assert_that (errs, is_null);

  rc = security_intelligence_create_report (conn, "report-id", NULL, &errs);
  assert_that (rc, is_equal_to (SECURITY_INTELLIGENCE_RESP_ERR));
  assert_that (errs, is_null);

  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence, create_report_sets_created_to_null_on_entry)
{
  security_intelligence_connector_t conn = make_conn ();
  security_intelligence_managed_report_t created =
    security_intelligence_managed_report_new ();
  security_intelligence_managed_report_t old_created = created;
  GPtrArray *errs = NULL;

  created->ref_id = g_strdup ("old-value");

  int rc = security_intelligence_create_report (conn, NULL, &created, &errs);

  assert_that (rc, is_equal_to (SECURITY_INTELLIGENCE_RESP_ERR));
  assert_that (created, is_null);

  security_intelligence_connector_free (conn);
  security_intelligence_managed_report_free (old_created);
}

Ensure (security_intelligence, create_report_fails_when_no_http_response)
{
  security_intelligence_connector_t conn = make_conn ();
  security_intelligence_managed_report_t created = NULL;
  GPtrArray *errs = NULL;

  mock_http_status = 500;
  g_clear_pointer (&mock_response_data, g_free);

  int rc =
    security_intelligence_create_report (conn, "report-id", &created, &errs);

  assert_that (rc, is_equal_to (SECURITY_INTELLIGENCE_RESP_ERR));
  assert_that (created, is_null);
  assert_that (errs, is_not_null);
  assert_that ((int) errs->len, is_equal_to (1));
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               is_equal_to_string ("Failed to get JSON response."));

  assert_that (last_sent_url, is_equal_to_string (
                                "https://localhost:8443/api/asset-management/"
                                "managed-appliances/reports"));
  assert_that (last_sent_payload,
               is_equal_to_string ("{\"refId\":\"report-id\"}"));

  g_ptr_array_free (errs, TRUE);
  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence, create_report_non_2xx_populates_errors_from_json)
{
  security_intelligence_connector_t conn = make_conn ();
  security_intelligence_managed_report_t created = NULL;
  GPtrArray *errs = NULL;

  mock_http_status = 400;
  g_clear_pointer (&mock_response_data, g_free);
  mock_response_data = g_strdup ("{"
                                 "  \"title\":\"Validation failed\","
                                 "  \"details\":\"Bad request body\","
                                 "  \"errors\": {"
                                 "    \"refId\":\"already exists\""
                                 "  }"
                                 "}");

  int rc =
    security_intelligence_create_report (conn, "report-id", &created, &errs);

  assert_that (rc, is_equal_to (SECURITY_INTELLIGENCE_RESP_ERR));
  assert_that (created, is_null);
  assert_that (errs, is_not_null);
  assert_that ((int) errs->len, is_equal_to (3));
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               is_equal_to_string ("Validation failed"));
  assert_that ((const gchar *) g_ptr_array_index (errs, 1),
               is_equal_to_string ("Bad request body"));
  assert_that ((const gchar *) g_ptr_array_index (errs, 2),
               is_equal_to_string ("refId: already exists"));

  g_ptr_array_free (errs, TRUE);
  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence,
        create_report_non_2xx_invalid_json_populates_fallback_error)
{
  security_intelligence_connector_t conn = make_conn ();
  security_intelligence_managed_report_t created = NULL;
  GPtrArray *errs = NULL;

  mock_http_status = 422;
  g_clear_pointer (&mock_response_data, g_free);
  mock_response_data = g_strdup ("not-json");

  int rc =
    security_intelligence_create_report (conn, "report-id", &created, &errs);

  assert_that (rc, is_equal_to (SECURITY_INTELLIGENCE_RESP_ERR));
  assert_that (created, is_null);
  assert_that (errs, is_not_null);
  assert_that ((int) errs->len, is_equal_to (1));
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               contains_string ("invalid JSON error response"));

  g_ptr_array_free (errs, TRUE);
  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence, create_report_fails_on_invalid_success_json)
{
  security_intelligence_connector_t conn = make_conn ();
  security_intelligence_managed_report_t created = NULL;
  GPtrArray *errs = NULL;

  mock_http_status = 201;
  g_clear_pointer (&mock_response_data, g_free);
  mock_response_data = g_strdup ("not-json");

  int rc =
    security_intelligence_create_report (conn, "report-id", &created, &errs);

  assert_that (rc, is_equal_to (SECURITY_INTELLIGENCE_RESP_ERR));
  assert_that (created, is_null);
  assert_that (errs, is_not_null);
  assert_that ((int) errs->len, is_equal_to (1));
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               is_equal_to_string ("Failed to parse JSON response."));

  g_ptr_array_free (errs, TRUE);
  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence,
        create_report_fails_when_success_json_is_not_valid_report)
{
  security_intelligence_connector_t conn = make_conn ();
  security_intelligence_managed_report_t created = NULL;
  GPtrArray *errs = NULL;

  mock_http_status = 200;
  g_clear_pointer (&mock_response_data, g_free);
  mock_response_data = g_strdup ("{"
                                 "  \"uploadStatus\":\"upload_started\""
                                 "}");

  int rc =
    security_intelligence_create_report (conn, "report-id", &created, &errs);

  assert_that (rc, is_equal_to (SECURITY_INTELLIGENCE_RESP_ERR));
  assert_that (created, is_null);
  assert_that (errs, is_not_null);
  assert_that ((int) errs->len, is_equal_to (1));
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               is_equal_to_string ("Failed to parse managed report response."));

  g_ptr_array_free (errs, TRUE);
  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence,
        create_report_success_returns_created_report_started_status)
{
  security_intelligence_connector_t conn = make_conn ();
  security_intelligence_managed_report_t created = NULL;
  GPtrArray *errs = NULL;

  mock_http_status = 201;
  g_clear_pointer (&mock_response_data, g_free);
  mock_response_data = g_strdup ("{"
                                 "  \"refId\":\"report-id\","
                                 "  \"uploadStatus\":\"upload_started\""
                                 "}");

  int rc =
    security_intelligence_create_report (conn, "report-id", &created, &errs);

  assert_that (rc, is_equal_to (SECURITY_INTELLIGENCE_RESP_OK));
  assert_that (errs, is_null);
  assert_that (created, is_not_null);
  assert_that (created->ref_id, is_equal_to_string ("report-id"));
  assert_that (
    created->upload_status,
    is_equal_to (SECURITY_INTELLIGENCE_REPORT_UPLOAD_STATUS_STARTED));

  assert_that (last_sent_url, is_equal_to_string (
                                "https://localhost:8443/api/asset-management/"
                                "managed-appliances/reports"));
  assert_that (last_sent_payload,
               is_equal_to_string ("{\"refId\":\"report-id\"}"));

  security_intelligence_managed_report_free (created);
  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence,
        create_report_success_returns_created_report_completed_status)
{
  security_intelligence_connector_t conn = make_conn ();
  security_intelligence_managed_report_t created = NULL;
  GPtrArray *errs = NULL;

  mock_http_status = 200;
  g_clear_pointer (&mock_response_data, g_free);
  mock_response_data = g_strdup ("{"
                                 "  \"refId\":\"report-id\","
                                 "  \"uploadStatus\":\"upload_completed\""
                                 "}");

  int rc =
    security_intelligence_create_report (conn, "report-id", &created, &errs);

  assert_that (rc, is_equal_to (SECURITY_INTELLIGENCE_RESP_OK));
  assert_that (errs, is_null);
  assert_that (created, is_not_null);
  assert_that (created->ref_id, is_equal_to_string ("report-id"));
  assert_that (
    created->upload_status,
    is_equal_to (SECURITY_INTELLIGENCE_REPORT_UPLOAD_STATUS_COMPLETED));

  security_intelligence_managed_report_free (created);
  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence,
        create_report_success_defaults_unknown_status_when_missing)
{
  security_intelligence_connector_t conn = make_conn ();
  security_intelligence_managed_report_t created = NULL;
  GPtrArray *errs = NULL;

  mock_http_status = 200;
  g_clear_pointer (&mock_response_data, g_free);
  mock_response_data = g_strdup ("{"
                                 "  \"refId\":\"report-id\""
                                 "}");

  int rc =
    security_intelligence_create_report (conn, "report-id", &created, &errs);

  assert_that (rc, is_equal_to (SECURITY_INTELLIGENCE_RESP_OK));
  assert_that (errs, is_null);
  assert_that (created, is_not_null);
  assert_that (created->ref_id, is_equal_to_string ("report-id"));
  assert_that (
    created->upload_status,
    is_equal_to (SECURITY_INTELLIGENCE_REPORT_UPLOAD_STATUS_UNKNOWN));

  security_intelligence_managed_report_free (created);
  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence,
        create_report_uses_prebuilt_base_url_when_present)
{
  security_intelligence_connector_t conn = make_conn ();
  security_intelligence_managed_report_t created = NULL;
  GPtrArray *errs = NULL;

  g_free (conn->url);
  conn->url = g_strdup ("https://example.test/base");

  mock_http_status = 200;
  g_clear_pointer (&mock_response_data, g_free);
  mock_response_data = g_strdup ("{"
                                 "  \"refId\":\"report-id\","
                                 "  \"uploadStatus\":\"upload_started\""
                                 "}");

  int rc =
    security_intelligence_create_report (conn, "report-id", &created, &errs);

  assert_that (rc, is_equal_to (SECURITY_INTELLIGENCE_RESP_OK));
  assert_that (created, is_not_null);
  assert_that (last_sent_url, is_equal_to_string (
                                "https://example.test/base/api/"
                                "asset-management/managed-appliances/reports"));
  assert_that (last_sent_payload,
               is_equal_to_string ("{\"refId\":\"report-id\"}"));

  security_intelligence_managed_report_free (created);
  security_intelligence_connector_free (conn);
}

/* -------------------- add_report_page -------------------- */

Ensure (security_intelligence, add_report_page_fails_with_null_conn)
{
  const guint8 xml[] = "<page>ok</page>";
  GPtrArray *errs = NULL;

  int rc = security_intelligence_add_report_page (
    NULL, "report-id", 0, xml, strlen ((const char *) xml), &errs);

  assert_that (rc, is_equal_to (SECURITY_INTELLIGENCE_RESP_ERR));
  assert_that (errs, is_not_null);
  assert_that ((int) errs->len, is_equal_to (1));
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               is_equal_to_string ("Invalid connector."));

  g_ptr_array_free (errs, TRUE);
}

Ensure (security_intelligence, add_report_page_fails_with_null_report_id)
{
  security_intelligence_connector_t conn = make_conn ();
  const guint8 xml[] = "<page>ok</page>";
  GPtrArray *errs = NULL;

  int rc = security_intelligence_add_report_page (
    conn, NULL, 0, xml, strlen ((const char *) xml), &errs);

  assert_that (rc, is_equal_to (SECURITY_INTELLIGENCE_RESP_ERR));
  assert_that (errs, is_not_null);
  assert_that ((int) errs->len, is_equal_to (1));
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               is_equal_to_string ("Invalid report id."));

  g_ptr_array_free (errs, TRUE);
  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence, add_report_page_fails_with_empty_report_id)
{
  security_intelligence_connector_t conn = make_conn ();
  const guint8 xml[] = "<page>ok</page>";
  GPtrArray *errs = NULL;

  int rc = security_intelligence_add_report_page (
    conn, "", 0, xml, strlen ((const char *) xml), &errs);

  assert_that (rc, is_equal_to (SECURITY_INTELLIGENCE_RESP_ERR));
  assert_that (errs, is_not_null);
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               is_equal_to_string ("Invalid report id."));

  g_ptr_array_free (errs, TRUE);
  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence, add_report_page_fails_with_negative_index)
{
  security_intelligence_connector_t conn = make_conn ();
  const guint8 xml[] = "<page>ok</page>";
  GPtrArray *errs = NULL;

  int rc = security_intelligence_add_report_page (
    conn, "report-id", -1, xml, strlen ((const char *) xml), &errs);

  assert_that (rc, is_equal_to (SECURITY_INTELLIGENCE_RESP_ERR));
  assert_that (errs, is_not_null);
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               is_equal_to_string ("Invalid page index."));

  g_ptr_array_free (errs, TRUE);
  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence, add_report_page_fails_with_null_xml)
{
  security_intelligence_connector_t conn = make_conn ();
  GPtrArray *errs = NULL;

  int rc = security_intelligence_add_report_page (conn, "report-id", 0, NULL,
                                                  10, &errs);

  assert_that (rc, is_equal_to (SECURITY_INTELLIGENCE_RESP_ERR));
  assert_that (errs, is_not_null);
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               is_equal_to_string ("Missing XML payload."));

  g_ptr_array_free (errs, TRUE);
  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence, add_report_page_fails_with_zero_xml_len)
{
  security_intelligence_connector_t conn = make_conn ();
  const guint8 xml[] = "<page>ok</page>";
  GPtrArray *errs = NULL;

  int rc =
    security_intelligence_add_report_page (conn, "report-id", 0, xml, 0, &errs);

  assert_that (rc, is_equal_to (SECURITY_INTELLIGENCE_RESP_ERR));
  assert_that (errs, is_not_null);
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               is_equal_to_string ("Missing XML payload."));

  g_ptr_array_free (errs, TRUE);
  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence, add_report_page_fails_when_no_http_response)
{
  security_intelligence_connector_t conn = make_conn ();
  const guint8 xml[] = "<page>ok</page>";
  GPtrArray *errs = NULL;

  mock_http_status = 500;
  g_clear_pointer (&mock_response_data, g_free);

  int rc = security_intelligence_add_report_page (
    conn, "report-id", 2, xml, strlen ((const char *) xml), &errs);

  assert_that (rc, is_equal_to (SECURITY_INTELLIGENCE_RESP_ERR));
  assert_that (errs, is_not_null);
  assert_that ((int) errs->len, is_equal_to (1));
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               is_equal_to_string ("Failed to get response."));

  assert_that (
    last_sent_url,
    is_equal_to_string ("https://localhost:8443/api/asset-management/"
                        "managed-appliances/reports/report-id/pages/2"));
  assert_that (last_sent_payload, is_equal_to_string ("<page>ok</page>"));

  g_ptr_array_free (errs, TRUE);
  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence,
        add_report_page_non_204_populates_errors_from_json)
{
  security_intelligence_connector_t conn = make_conn ();
  const guint8 xml[] = "<page>bad</page>";
  GPtrArray *errs = NULL;

  mock_http_status = 400;
  g_clear_pointer (&mock_response_data, g_free);
  mock_response_data = g_strdup ("{"
                                 "  \"title\":\"Validation failed\","
                                 "  \"details\":\"XML page rejected\","
                                 "  \"errors\": {"
                                 "    \"page\":\"invalid structure\""
                                 "  }"
                                 "}");

  int rc = security_intelligence_add_report_page (
    conn, "report-id", 5, xml, strlen ((const char *) xml), &errs);

  assert_that (rc, is_equal_to (SECURITY_INTELLIGENCE_RESP_ERR));
  assert_that (errs, is_not_null);
  assert_that ((int) errs->len, is_equal_to (3));
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               is_equal_to_string ("Validation failed"));
  assert_that ((const gchar *) g_ptr_array_index (errs, 1),
               is_equal_to_string ("XML page rejected"));
  assert_that ((const gchar *) g_ptr_array_index (errs, 2),
               is_equal_to_string ("page: invalid structure"));

  assert_that (
    last_sent_url,
    is_equal_to_string ("https://localhost:8443/api/asset-management/"
                        "managed-appliances/reports/report-id/pages/5"));
  assert_that (last_sent_payload, is_equal_to_string ("<page>bad</page>"));

  g_ptr_array_free (errs, TRUE);
  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence,
        add_report_page_non_204_invalid_json_error_adds_fallback)
{
  security_intelligence_connector_t conn = make_conn ();
  const guint8 xml[] = "<page>bad</page>";
  GPtrArray *errs = NULL;

  mock_http_status = 422;
  g_clear_pointer (&mock_response_data, g_free);
  mock_response_data = g_strdup ("not-json");

  int rc = security_intelligence_add_report_page (
    conn, "report-id", 1, xml, strlen ((const char *) xml), &errs);

  assert_that (rc, is_equal_to (SECURITY_INTELLIGENCE_RESP_ERR));
  assert_that (errs, is_not_null);
  assert_that ((int) errs->len, is_equal_to (1));
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               contains_string ("invalid JSON error response"));

  g_ptr_array_free (errs, TRUE);
  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence, add_report_page_success_returns_ok_on_204)
{
  security_intelligence_connector_t conn = make_conn ();
  const guint8 xml[] = "<report><page index=\"0\"/></report>";
  GPtrArray *errs = NULL;

  mock_http_status = 204;
  g_clear_pointer (&mock_response_data, g_free);
  mock_response_data = g_strdup ("");

  int rc = security_intelligence_add_report_page (
    conn, "report-id", 0, xml, strlen ((const char *) xml), &errs);

  assert_that (rc, is_equal_to (SECURITY_INTELLIGENCE_RESP_OK));
  assert_that (errs, is_null);

  assert_that (
    last_sent_url,
    is_equal_to_string ("https://localhost:8443/api/asset-management/"
                        "managed-appliances/reports/report-id/pages/0"));
  assert_that (last_sent_payload,
               is_equal_to_string ("<report><page index=\"0\"/></report>"));

  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence,
        add_report_page_uses_prebuilt_base_url_when_present)
{
  security_intelligence_connector_t conn = make_conn ();
  const guint8 xml[] = "<page>ok</page>";
  GPtrArray *errs = NULL;

  g_free (conn->url);
  conn->url = g_strdup ("https://example.test/base");

  mock_http_status = 204;
  g_clear_pointer (&mock_response_data, g_free);
  mock_response_data = g_strdup ("");

  int rc = security_intelligence_add_report_page (
    conn, "report-id", 7, xml, strlen ((const char *) xml), &errs);

  assert_that (rc, is_equal_to (SECURITY_INTELLIGENCE_RESP_OK));
  assert_that (
    last_sent_url,
    is_equal_to_string ("https://example.test/base/api/asset-management/"
                        "managed-appliances/reports/report-id/pages/7"));
  assert_that (last_sent_payload, is_equal_to_string ("<page>ok</page>"));

  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence,
        add_report_page_respects_xml_len_for_payload_copy)
{
  security_intelligence_connector_t conn = make_conn ();
  GPtrArray *errs = NULL;

  const guint8 xml[] = "<page>ok</page>TRAILING";
  gsize xml_len = strlen ("<page>ok</page>");

  mock_http_status = 204;
  g_clear_pointer (&mock_response_data, g_free);
  mock_response_data = g_strdup ("");

  int rc = security_intelligence_add_report_page (conn, "report-id", 3, xml,
                                                  xml_len, &errs);

  assert_that (rc, is_equal_to (SECURITY_INTELLIGENCE_RESP_OK));
  assert_that (last_sent_payload, is_equal_to_string ("<page>ok</page>"));

  security_intelligence_connector_free (conn);
}

/* -------------------- update_report_status -------------------- */

Ensure (security_intelligence, update_report_status_fails_with_null_conn)
{
  GPtrArray *errs = NULL;

  int rc = security_intelligence_update_report_status (
    NULL, "report-id", SECURITY_INTELLIGENCE_REPORT_UPLOAD_STATUS_STARTED,
    &errs);

  assert_that (rc, is_equal_to (SECURITY_INTELLIGENCE_RESP_ERR));
  assert_that (errs, is_not_null);
  assert_that ((int) errs->len, is_equal_to (1));
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               is_equal_to_string ("Invalid connector."));

  g_ptr_array_free (errs, TRUE);
}

Ensure (security_intelligence, update_report_status_fails_with_null_report_id)
{
  security_intelligence_connector_t conn = make_conn ();
  GPtrArray *errs = NULL;

  int rc = security_intelligence_update_report_status (
    conn, NULL, SECURITY_INTELLIGENCE_REPORT_UPLOAD_STATUS_STARTED, &errs);

  assert_that (rc, is_equal_to (SECURITY_INTELLIGENCE_RESP_ERR));
  assert_that (errs, is_not_null);
  assert_that ((int) errs->len, is_equal_to (1));
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               is_equal_to_string ("Invalid report id."));

  g_ptr_array_free (errs, TRUE);
  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence, update_report_status_fails_with_empty_report_id)
{
  security_intelligence_connector_t conn = make_conn ();
  GPtrArray *errs = NULL;

  int rc = security_intelligence_update_report_status (
    conn, "", SECURITY_INTELLIGENCE_REPORT_UPLOAD_STATUS_STARTED, &errs);

  assert_that (rc, is_equal_to (SECURITY_INTELLIGENCE_RESP_ERR));
  assert_that (errs, is_not_null);
  assert_that ((int) errs->len, is_equal_to (1));
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               is_equal_to_string ("Invalid report id."));

  g_ptr_array_free (errs, TRUE);
  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence,
        update_report_status_fails_when_payload_build_fails_for_unknown_status)
{
  security_intelligence_connector_t conn = make_conn ();
  GPtrArray *errs = NULL;

  int rc = security_intelligence_update_report_status (
    conn, "report-id", SECURITY_INTELLIGENCE_REPORT_UPLOAD_STATUS_UNKNOWN,
    &errs);

  assert_that (rc, is_equal_to (SECURITY_INTELLIGENCE_RESP_ERR));
  assert_that (errs, is_not_null);
  assert_that ((int) errs->len, is_equal_to (1));
  assert_that (
    (const gchar *) g_ptr_array_index (errs, 0),
    is_equal_to_string ("Failed to build update report status payload."));

  g_ptr_array_free (errs, TRUE);
  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence, update_report_status_fails_when_no_http_response)
{
  security_intelligence_connector_t conn = make_conn ();
  GPtrArray *errs = NULL;

  mock_http_status = 500;
  g_clear_pointer (&mock_response_data, g_free);

  int rc = security_intelligence_update_report_status (
    conn, "report-id", SECURITY_INTELLIGENCE_REPORT_UPLOAD_STATUS_STARTED,
    &errs);

  assert_that (rc, is_equal_to (SECURITY_INTELLIGENCE_RESP_ERR));
  assert_that (errs, is_not_null);
  assert_that ((int) errs->len, is_equal_to (1));
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               is_equal_to_string ("Failed to get response."));

  assert_that (last_sent_url, is_equal_to_string (
                                "https://localhost:8443/api/asset-management/"
                                "managed-appliances/reports/report-id"));
  assert_that (last_sent_payload,
               is_equal_to_string ("{\"status\":\"upload_started\"}"));

  g_ptr_array_free (errs, TRUE);
  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence,
        update_report_status_non_2xx_populates_errors_from_json)
{
  security_intelligence_connector_t conn = make_conn ();
  GPtrArray *errs = NULL;

  mock_http_status = 400;
  g_clear_pointer (&mock_response_data, g_free);
  mock_response_data =
    g_strdup ("{"
              "  \"title\":\"Validation failed\","
              "  \"details\":\"Status transition not allowed\","
              "  \"errors\": {"
              "    \"status\":\"invalid current state\""
              "  }"
              "}");

  int rc = security_intelligence_update_report_status (
    conn, "report-id", SECURITY_INTELLIGENCE_REPORT_UPLOAD_STATUS_COMPLETED,
    &errs);

  assert_that (rc, is_equal_to (SECURITY_INTELLIGENCE_RESP_ERR));
  assert_that (errs, is_not_null);
  assert_that ((int) errs->len, is_equal_to (3));
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               is_equal_to_string ("Validation failed"));
  assert_that ((const gchar *) g_ptr_array_index (errs, 1),
               is_equal_to_string ("Status transition not allowed"));
  assert_that ((const gchar *) g_ptr_array_index (errs, 2),
               is_equal_to_string ("status: invalid current state"));

  assert_that (last_sent_url, is_equal_to_string (
                                "https://localhost:8443/api/asset-management/"
                                "managed-appliances/reports/report-id"));
  assert_that (last_sent_payload,
               is_equal_to_string ("{\"status\":\"upload_completed\"}"));

  g_ptr_array_free (errs, TRUE);
  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence,
        update_report_status_non_2xx_invalid_json_adds_fallback_error)
{
  security_intelligence_connector_t conn = make_conn ();
  GPtrArray *errs = NULL;

  mock_http_status = 422;
  g_clear_pointer (&mock_response_data, g_free);
  mock_response_data = g_strdup ("not-json");

  int rc = security_intelligence_update_report_status (
    conn, "report-id", SECURITY_INTELLIGENCE_REPORT_UPLOAD_STATUS_STARTED,
    &errs);

  assert_that (rc, is_equal_to (SECURITY_INTELLIGENCE_RESP_ERR));
  assert_that (errs, is_not_null);
  assert_that ((int) errs->len, is_equal_to (1));
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               contains_string ("invalid JSON error response"));

  g_ptr_array_free (errs, TRUE);
  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence,
        update_report_status_success_returns_ok_for_started_status)
{
  security_intelligence_connector_t conn = make_conn ();
  GPtrArray *errs = NULL;

  mock_http_status = 200;
  g_clear_pointer (&mock_response_data, g_free);
  mock_response_data = g_strdup ("{}");

  int rc = security_intelligence_update_report_status (
    conn, "report-id", SECURITY_INTELLIGENCE_REPORT_UPLOAD_STATUS_STARTED,
    &errs);

  assert_that (rc, is_equal_to (SECURITY_INTELLIGENCE_RESP_OK));
  assert_that (errs, is_null);

  assert_that (last_sent_url, is_equal_to_string (
                                "https://localhost:8443/api/asset-management/"
                                "managed-appliances/reports/report-id"));
  assert_that (last_sent_payload,
               is_equal_to_string ("{\"status\":\"upload_started\"}"));

  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence,
        update_report_status_success_returns_ok_for_completed_status)
{
  security_intelligence_connector_t conn = make_conn ();
  GPtrArray *errs = NULL;

  mock_http_status = 204;
  g_clear_pointer (&mock_response_data, g_free);
  mock_response_data = g_strdup ("");

  int rc = security_intelligence_update_report_status (
    conn, "report-id", SECURITY_INTELLIGENCE_REPORT_UPLOAD_STATUS_COMPLETED,
    &errs);

  assert_that (rc, is_equal_to (SECURITY_INTELLIGENCE_RESP_OK));
  assert_that (errs, is_null);

  assert_that (last_sent_url, is_equal_to_string (
                                "https://localhost:8443/api/asset-management/"
                                "managed-appliances/reports/report-id"));
  assert_that (last_sent_payload,
               is_equal_to_string ("{\"status\":\"upload_completed\"}"));

  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence,
        update_report_status_uses_prebuilt_base_url_when_present)
{
  security_intelligence_connector_t conn = make_conn ();
  GPtrArray *errs = NULL;

  g_free (conn->url);
  conn->url = g_strdup ("https://example.test/base");

  mock_http_status = 200;
  g_clear_pointer (&mock_response_data, g_free);
  mock_response_data = g_strdup ("{}");

  int rc = security_intelligence_update_report_status (
    conn, "report-id", SECURITY_INTELLIGENCE_REPORT_UPLOAD_STATUS_STARTED,
    &errs);

  assert_that (rc, is_equal_to (SECURITY_INTELLIGENCE_RESP_OK));
  assert_that (
    last_sent_url,
    is_equal_to_string ("https://example.test/base/api/asset-management/"
                        "managed-appliances/reports/report-id"));
  assert_that (last_sent_payload,
               is_equal_to_string ("{\"status\":\"upload_started\"}"));

  security_intelligence_connector_free (conn);
}

/* -------------------- get_report_pages -------------------- */

Ensure (security_intelligence, get_report_pages_fails_with_null_conn)
{
  GPtrArray *errs = NULL;

  security_intelligence_managed_report_page_list_t pages =
    security_intelligence_get_report_pages (NULL, "report-id", &errs);

  assert_that (pages, is_null);
  assert_that (errs, is_not_null);
  assert_that ((int) errs->len, is_equal_to (1));
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               is_equal_to_string ("Invalid connector."));

  g_ptr_array_free (errs, TRUE);
}

Ensure (security_intelligence, get_report_pages_fails_with_null_report_id)
{
  security_intelligence_connector_t conn = make_conn ();
  GPtrArray *errs = NULL;

  security_intelligence_managed_report_page_list_t pages =
    security_intelligence_get_report_pages (conn, NULL, &errs);

  assert_that (pages, is_null);
  assert_that (errs, is_not_null);
  assert_that ((int) errs->len, is_equal_to (1));
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               is_equal_to_string ("Invalid report id."));

  g_ptr_array_free (errs, TRUE);
  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence, get_report_pages_fails_with_empty_report_id)
{
  security_intelligence_connector_t conn = make_conn ();
  GPtrArray *errs = NULL;

  security_intelligence_managed_report_page_list_t pages =
    security_intelligence_get_report_pages (conn, "", &errs);

  assert_that (pages, is_null);
  assert_that (errs, is_not_null);
  assert_that ((int) errs->len, is_equal_to (1));
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               is_equal_to_string ("Invalid report id."));

  g_ptr_array_free (errs, TRUE);
  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence, get_report_pages_fails_when_no_http_response)
{
  security_intelligence_connector_t conn = make_conn ();
  GPtrArray *errs = NULL;

  mock_http_status = 500;
  g_clear_pointer (&mock_response_data, g_free);

  security_intelligence_managed_report_page_list_t pages =
    security_intelligence_get_report_pages (conn, "report-id", &errs);

  assert_that (pages, is_null);
  assert_that (errs, is_not_null);
  assert_that ((int) errs->len, is_equal_to (1));
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               is_equal_to_string ("Failed to get response."));
  assert_that (last_sent_url, is_equal_to_string (
                                "https://localhost:8443/api/asset-management/"
                                "managed-appliances/reports/report-id/pages"));
  assert_that (last_sent_payload, is_null);

  g_ptr_array_free (errs, TRUE);
  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence,
        get_report_pages_non_2xx_populates_errors_from_json)
{
  security_intelligence_connector_t conn = make_conn ();
  GPtrArray *errs = NULL;

  mock_http_status = 404;
  g_clear_pointer (&mock_response_data, g_free);
  mock_response_data = g_strdup ("{"
                                 "  \"title\":\"Not found\","
                                 "  \"details\":\"Pages do not exist\","
                                 "  \"errors\": {"
                                 "    \"reportId\":\"unknown report\""
                                 "  }"
                                 "}");

  security_intelligence_managed_report_page_list_t pages =
    security_intelligence_get_report_pages (conn, "report-id", &errs);

  assert_that (pages, is_null);
  assert_that (errs, is_not_null);
  assert_that ((int) errs->len, is_equal_to (3));
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               is_equal_to_string ("Not found"));
  assert_that ((const gchar *) g_ptr_array_index (errs, 1),
               is_equal_to_string ("Pages do not exist"));
  assert_that ((const gchar *) g_ptr_array_index (errs, 2),
               is_equal_to_string ("reportId: unknown report"));

  g_ptr_array_free (errs, TRUE);
  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence,
        get_report_pages_non_2xx_invalid_json_adds_fallback_error)
{
  security_intelligence_connector_t conn = make_conn ();
  GPtrArray *errs = NULL;

  mock_http_status = 400;
  g_clear_pointer (&mock_response_data, g_free);
  mock_response_data = g_strdup ("not-json");

  security_intelligence_managed_report_page_list_t pages =
    security_intelligence_get_report_pages (conn, "report-id", &errs);

  assert_that (pages, is_null);
  assert_that (errs, is_not_null);
  assert_that ((int) errs->len, is_equal_to (1));
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               contains_string ("invalid JSON error response"));

  g_ptr_array_free (errs, TRUE);
  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence, get_report_pages_fails_on_invalid_json)
{
  security_intelligence_connector_t conn = make_conn ();
  GPtrArray *errs = NULL;

  mock_http_status = 200;
  g_clear_pointer (&mock_response_data, g_free);
  mock_response_data = g_strdup ("not-json");

  security_intelligence_managed_report_page_list_t pages =
    security_intelligence_get_report_pages (conn, "report-id", &errs);

  assert_that (pages, is_null);
  assert_that (errs, is_not_null);
  assert_that ((int) errs->len, is_equal_to (1));
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               is_equal_to_string ("Failed to parse response."));

  g_ptr_array_free (errs, TRUE);
  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence, get_report_pages_fails_when_root_not_array)
{
  security_intelligence_connector_t conn = make_conn ();
  GPtrArray *errs = NULL;

  mock_http_status = 200;
  g_clear_pointer (&mock_response_data, g_free);
  mock_response_data = g_strdup ("{\"pages\":[]}");

  security_intelligence_managed_report_page_list_t pages =
    security_intelligence_get_report_pages (conn, "report-id", &errs);

  assert_that (pages, is_null);
  assert_that (errs, is_not_null);
  assert_that ((int) errs->len, is_equal_to (1));
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               is_equal_to_string ("Failed to parse response."));

  g_ptr_array_free (errs, TRUE);
  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence,
        get_report_pages_returns_empty_list_for_empty_array)
{
  security_intelligence_connector_t conn = make_conn ();
  GPtrArray *errs = NULL;

  mock_http_status = 200;
  g_clear_pointer (&mock_response_data, g_free);
  mock_response_data = g_strdup ("[]");

  security_intelligence_managed_report_page_list_t pages =
    security_intelligence_get_report_pages (conn, "report-id", &errs);

  assert_that (pages, is_not_null);
  assert_that (errs, is_null);
  assert_that (pages->count, is_equal_to (0));
  assert_that (pages->pages, is_not_null);

  security_intelligence_managed_report_page_list_free (pages);
  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence, get_report_pages_parses_valid_page_objects)
{
  security_intelligence_connector_t conn = make_conn ();
  GPtrArray *errs = NULL;

  mock_http_status = 200;
  g_clear_pointer (&mock_response_data, g_free);
  mock_response_data = g_strdup ("["
                                 "  {\"index\":0},"
                                 "  {\"index\":1},"
                                 "  {\"index\":5}"
                                 "]");

  security_intelligence_managed_report_page_list_t pages =
    security_intelligence_get_report_pages (conn, "report-id", &errs);

  assert_that (pages, is_not_null);
  assert_that (errs, is_null);
  assert_that (pages->count, is_equal_to (3));

  assert_that (pages->pages[0], is_not_null);
  assert_that (pages->pages[1], is_not_null);
  assert_that (pages->pages[2], is_not_null);

  assert_that (pages->pages[0]->index, is_equal_to (0));
  assert_that (pages->pages[1]->index, is_equal_to (1));
  assert_that (pages->pages[2]->index, is_equal_to (5));

  security_intelligence_managed_report_page_list_free (pages);
  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence,
        get_report_pages_filters_non_object_items_and_keeps_order)
{
  security_intelligence_connector_t conn = make_conn ();
  GPtrArray *errs = NULL;

  mock_http_status = 200;
  g_clear_pointer (&mock_response_data, g_free);
  mock_response_data = g_strdup ("["
                                 "  {\"index\":2},"
                                 "  42,"
                                 "  null,"
                                 "  [],"
                                 "  {\"index\":7},"
                                 "  \"text\","
                                 "  {\"index\":9}"
                                 "]");

  security_intelligence_managed_report_page_list_t pages =
    security_intelligence_get_report_pages (conn, "report-id", &errs);

  assert_that (pages, is_not_null);
  assert_that (errs, is_null);
  assert_that (pages->count, is_equal_to (3));

  assert_that (pages->pages[0]->index, is_equal_to (2));
  assert_that (pages->pages[1]->index, is_equal_to (7));
  assert_that (pages->pages[2]->index, is_equal_to (9));

  security_intelligence_managed_report_page_list_free (pages);
  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence,
        get_report_pages_missing_index_defaults_to_zero_via_helper)
{
  security_intelligence_connector_t conn = make_conn ();
  GPtrArray *errs = NULL;

  mock_http_status = 200;
  g_clear_pointer (&mock_response_data, g_free);
  mock_response_data = g_strdup ("["
                                 "  {},"
                                 "  {\"index\":3}"
                                 "]");

  security_intelligence_managed_report_page_list_t pages =
    security_intelligence_get_report_pages (conn, "report-id", &errs);

  assert_that (pages, is_not_null);
  assert_that (errs, is_null);
  assert_that (pages->count, is_equal_to (2));
  assert_that (pages->pages[0]->index, is_equal_to (0));
  assert_that (pages->pages[1]->index, is_equal_to (3));

  security_intelligence_managed_report_page_list_free (pages);
  security_intelligence_connector_free (conn);
}

Ensure (security_intelligence,
        get_report_pages_uses_prebuilt_base_url_when_present)
{
  security_intelligence_connector_t conn = make_conn ();
  GPtrArray *errs = NULL;

  g_free (conn->url);
  conn->url = g_strdup ("https://example.test/base");

  mock_http_status = 200;
  g_clear_pointer (&mock_response_data, g_free);
  mock_response_data = g_strdup ("[]");

  security_intelligence_managed_report_page_list_t pages =
    security_intelligence_get_report_pages (conn, "report-id", &errs);

  assert_that (pages, is_not_null);
  assert_that (errs, is_null);
  assert_that (
    last_sent_url,
    is_equal_to_string ("https://example.test/base/api/asset-management/"
                        "managed-appliances/reports/report-id/pages"));
  assert_that (last_sent_payload, is_null);

  security_intelligence_managed_report_page_list_free (pages);
  security_intelligence_connector_free (conn);
}

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite = create_test_suite ();

  add_test_with_context (suite, security_intelligence,
                         connector_new_returns_zero_initialized_connector);
  add_test_with_context (suite, security_intelligence,
                         connector_free_handles_null);
  add_test_with_context (suite, security_intelligence,
                         connector_free_handles_populated_connector);
  add_test_with_context (suite, security_intelligence,
                         connector_builder_sets_all_valid_fields);
  add_test_with_context (suite, security_intelligence,
                         connector_builder_rejects_null_conn);
  add_test_with_context (suite, security_intelligence,
                         connector_builder_rejects_null_value);
  add_test_with_context (suite, security_intelligence,
                         connector_builder_accepts_http_protocol);
  add_test_with_context (suite, security_intelligence,
                         connector_builder_accepts_https_protocol);
  add_test_with_context (suite, security_intelligence,
                         connector_builder_rejects_invalid_protocol);
  add_test_with_context (suite, security_intelligence,
                         connector_builder_rejects_invalid_opt);

  add_test_with_context (suite, security_intelligence,
                         managed_appliance_new_allocates_zero_initialized);
  add_test_with_context (suite, security_intelligence,
                         managed_appliance_free_handles_null);
  add_test_with_context (suite, security_intelligence,
                         managed_appliance_free_handles_populated);
  add_test_with_context (suite, security_intelligence,
                         managed_report_new_allocates_zero_initialized);
  add_test_with_context (suite, security_intelligence,
                         managed_report_free_handles_null);
  add_test_with_context (suite, security_intelligence,
                         managed_report_free_handles_populated);
  add_test_with_context (suite, security_intelligence,
                         managed_report_list_new_allocates_valid_list);
  add_test_with_context (suite, security_intelligence,
                         managed_report_list_new_rejects_negative_count);
  add_test_with_context (suite, security_intelligence,
                         managed_report_list_free_handles_null);
  add_test_with_context (suite, security_intelligence,
                         managed_report_list_free_handles_populated_list);
  add_test_with_context (suite, security_intelligence,
                         managed_report_page_new_allocates_zero_initialized);
  add_test_with_context (suite, security_intelligence,
                         managed_report_page_free_handles_null);
  add_test_with_context (suite, security_intelligence,
                         managed_report_page_list_new_allocates_valid_list);
  add_test_with_context (suite, security_intelligence,
                         managed_report_page_list_new_rejects_negative);
  add_test_with_context (suite, security_intelligence,
                         managed_report_page_list_free_handles_null);
  add_test_with_context (suite, security_intelligence,
                         managed_report_page_list_free_handles_populated);

  add_test_with_context (suite, security_intelligence,
                         upload_status_to_string_started);
  add_test_with_context (suite, security_intelligence,
                         upload_status_to_string_completed);
  add_test_with_context (suite, security_intelligence,
                         upload_status_to_string_unknown_default);
  add_test_with_context (suite, security_intelligence,
                         upload_status_from_string_started);
  add_test_with_context (suite, security_intelligence,
                         upload_status_from_string_completed);
  add_test_with_context (suite, security_intelligence,
                         upload_status_from_string_unknown_for_null);
  add_test_with_context (suite, security_intelligence,
                         upload_status_from_string_unknown_for_invalid);

  add_test_with_context (suite, security_intelligence,
                         init_custom_header_adds_auth_and_content_type);
  add_test_with_context (suite, security_intelligence,
                         init_custom_header_adds_only_auth_when_no_content);
  add_test_with_context (
    suite, security_intelligence,
    init_custom_header_adds_only_content_type_when_no_token);
  add_test_with_context (suite, security_intelligence,
                         init_custom_header_with_no_token_and_no_content);
  add_test_with_context (suite, security_intelligence,
                         send_request_returns_null_if_conn_null);
  add_test_with_context (suite, security_intelligence,
                         send_request_returns_null_if_protocol_missing);
  add_test_with_context (suite, security_intelligence,
                         send_request_returns_null_if_host_missing);
  add_test_with_context (
    suite, security_intelligence,
    send_request_builds_url_from_protocol_host_port_and_path);
  add_test_with_context (suite, security_intelligence,
                         send_request_uses_prebuilt_base_url_when_present);
  add_test_with_context (suite, security_intelligence,
                         send_request_returns_null_when_http_request_fails);

  add_test_with_context (suite, security_intelligence,
                         ensure_error_array_initializes_array);
  add_test_with_context (suite, security_intelligence,
                         ensure_error_array_noop_when_already_exists);
  add_test_with_context (suite, security_intelligence,
                         ensure_error_array_handles_null_parameter);
  add_test_with_context (suite, security_intelligence,
                         push_error_initializes_and_adds_message);
  add_test_with_context (suite, security_intelligence,
                         push_error_appends_to_existing_array);
  add_test_with_context (suite, security_intelligence,
                         push_error_ignores_null_or_empty_message);
  add_test_with_context (suite, security_intelligence,
                         push_error_handles_null_errors_parameter);
  add_test_with_context (suite, security_intelligence,
                         push_error_printf_adds_formatted_message);
  add_test_with_context (suite, security_intelligence,
                         push_error_printf_ignores_null_format);
  add_test_with_context (suite, security_intelligence,
                         error_field_or_unknown_returns_key_when_present);
  add_test_with_context (suite, security_intelligence,
                         error_field_or_unknown_returns_unknown_for_null);
  add_test_with_context (suite, security_intelligence,
                         error_field_or_unknown_returns_unknown_for_empty);

  add_test_with_context (suite, security_intelligence,
                         parse_error_response_handles_null_errors_parameter);
  add_test_with_context (suite, security_intelligence,
                         parse_error_response_empty_body_adds_fallback);
  add_test_with_context (suite, security_intelligence,
                         parse_error_response_invalid_json_adds_message);
  add_test_with_context (suite, security_intelligence,
                         parse_error_response_collects_title_details_fields);
  add_test_with_context (
    suite, security_intelligence,
    parse_error_response_supports_array_field_values_defensively);
  add_test_with_context (
    suite, security_intelligence,
    parse_error_response_supports_nested_object_defensively);
  add_test_with_context (suite, security_intelligence,
                         parse_error_response_falls_back_to_type);
  add_test_with_context (suite, security_intelligence,
                         parse_error_response_falls_back_when_no_details);

  add_test_with_context (suite, security_intelligence,
                         parse_managed_report_returns_null_on_null_input);
  add_test_with_context (suite, security_intelligence,
                         parse_managed_report_returns_null_on_non_object);
  add_test_with_context (suite, security_intelligence,
                         parse_managed_report_returns_null_when_refid_missing);
  add_test_with_context (suite, security_intelligence,
                         parse_managed_report_returns_null_when_refid_empty);

  add_test_with_context (
    suite, security_intelligence,
    parse_managed_report_parses_valid_report_with_started_status);
  add_test_with_context (
    suite, security_intelligence,
    parse_managed_report_parses_valid_report_with_completed_status);
  add_test_with_context (
    suite, security_intelligence,
    parse_managed_report_defaults_to_unknown_when_status_missing);
  add_test_with_context (
    suite, security_intelligence,
    parse_managed_report_defaults_to_unknown_when_status_invalid);
  add_test_with_context (
    suite, security_intelligence,
    parse_managed_report_defaults_to_unknown_when_status_empty);

  add_test_with_context (suite, security_intelligence,
                         parse_managed_appliance_parses_valid_object);
  add_test_with_context (suite, security_intelligence,
                         parse_managed_appliance_returns_null_on_null_out);
  add_test_with_context (suite, security_intelligence,
                         parse_managed_appliance_returns_null_on_null_item);
  add_test_with_context (suite, security_intelligence,
                         parse_managed_appliance_returns_null_on_non_object);
  add_test_with_context (
    suite, security_intelligence,
    parse_managed_appliance_returns_null_when_appliance_id_missing);
  add_test_with_context (suite, security_intelligence,
                         parse_managed_appliance_returns_null_when_ip_missing);
  add_test_with_context (
    suite, security_intelligence,
    parse_managed_appliance_returns_null_when_fingerprint_missing);

  add_test_with_context (
    suite, security_intelligence,
    build_create_managed_appliance_payload_returns_null_for_null_input);
  add_test_with_context (suite, security_intelligence,
                         build_create_managed_appliance_payload_requires_ip);
  add_test_with_context (
    suite, security_intelligence,
    build_create_managed_appliance_payload_requires_fingerprint);
  add_test_with_context (
    suite, security_intelligence,
    build_create_managed_appliance_payload_builds_expected_json);
  add_test_with_context (
    suite, security_intelligence,
    build_create_report_payload_returns_null_for_null_or_empty);
  add_test_with_context (suite, security_intelligence,
                         build_create_report_payload_builds_json);
  add_test_with_context (
    suite, security_intelligence,
    build_update_report_status_payload_returns_null_for_unknown);
  add_test_with_context (
    suite, security_intelligence,
    build_update_report_status_payload_builds_started_json);
  add_test_with_context (
    suite, security_intelligence,
    build_update_report_status_payload_builds_completed_json);

  add_test_with_context (suite, security_intelligence,
                         create_managed_appliance_fails_for_null_arguments);
  add_test_with_context (
    suite, security_intelligence,
    create_managed_appliance_sets_created_to_null_before_processing);
  add_test_with_context (
    suite, security_intelligence,
    create_managed_appliance_fails_when_appliance_id_missing);
  add_test_with_context (
    suite, security_intelligence,
    create_managed_appliance_fails_when_payload_build_fails);
  add_test_with_context (suite, security_intelligence,
                         create_managed_appliance_fails_when_no_http_response);
  add_test_with_context (
    suite, security_intelligence,
    create_managed_appliance_fails_on_non_2xx_and_parses_error_response);
  add_test_with_context (
    suite, security_intelligence,
    create_managed_appliance_fails_when_success_body_is_invalid_json);
  add_test_with_context (
    suite, security_intelligence,
    create_managed_appliance_fails_when_success_body_is_missing_fields);
  add_test_with_context (
    suite, security_intelligence,
    create_managed_appliance_success_returns_created_object_and_sends_put);

  add_test_with_context (suite, security_intelligence,
                         delete_managed_appliance_fails_for_null_arguments);
  add_test_with_context (suite, security_intelligence,
                         delete_managed_appliance_fails_with_response_status);
  add_test_with_context (suite, security_intelligence,
                         delete_managed_appliance_fails_when_no_http_response);
  add_test_with_context (suite, security_intelligence,
                         delete_managed_appliance_success_returns_ok_on_200);
  add_test_with_context (suite, security_intelligence,
                         delete_managed_appliance_success_returns_ok_on_204);
  add_test_with_context (
    suite, security_intelligence,
    delete_managed_appliance_uses_prebuilt_base_url_when_present);

  add_test_with_context (suite, security_intelligence,
                         list_reports_returns_null_on_null_conn);
  add_test_with_context (suite, security_intelligence,
                         list_reports_returns_null_when_no_http_response);
  add_test_with_context (suite, security_intelligence,
                         list_reports_returns_null_on_non_2xx_status);
  add_test_with_context (suite, security_intelligence,
                         list_reports_returns_null_on_invalid_json);
  add_test_with_context (suite, security_intelligence,
                         list_reports_returns_null_when_root_is_not_array);
  add_test_with_context (suite, security_intelligence,
                         list_reports_returns_empty_list_for_empty_array);
  add_test_with_context (suite, security_intelligence,
                         list_reports_parses_valid_reports);
  add_test_with_context (suite, security_intelligence,
                         list_reports_filters_invalid_items_and_keeps_order);
  add_test_with_context (suite, security_intelligence,
                         list_reports_all_invalid_items_returns_empty_list);
  add_test_with_context (suite, security_intelligence,
                         list_reports_uses_prebuilt_base_url_when_present);

  add_test_with_context (suite, security_intelligence,
                         get_report_returns_null_on_null_conn);
  add_test_with_context (suite, security_intelligence,
                         get_report_returns_null_on_null_report_id);
  add_test_with_context (suite, security_intelligence,
                         get_report_returns_null_on_empty_report_id);
  add_test_with_context (suite, security_intelligence,
                         get_report_returns_null_when_no_http_response);
  add_test_with_context (suite, security_intelligence,
                         get_report_non_2xx_populates_errors_from_json);
  add_test_with_context (suite, security_intelligence,
                         get_report_non_2xx_invalid_json_adds_fallback_error);
  add_test_with_context (suite, security_intelligence,
                         get_report_success_invalid_json_adds_parse_error);
  add_test_with_context (
    suite, security_intelligence,
    get_report_success_with_invalid_report_object_returns_null);
  add_test_with_context (suite, security_intelligence,
                         get_report_success_parses_report_with_started_status);
  add_test_with_context (
    suite, security_intelligence,
    get_report_success_parses_report_with_completed_status);
  add_test_with_context (
    suite, security_intelligence,
    get_report_success_defaults_status_to_unknown_when_missing);
  add_test_with_context (
    suite, security_intelligence,
    get_report_success_defaults_status_to_unknown_when_invalid);
  add_test_with_context (suite, security_intelligence,
                         get_report_uses_prebuilt_base_url_when_present);

  add_test_with_context (suite, security_intelligence,
                         create_report_fails_for_null_arguments);
  add_test_with_context (suite, security_intelligence,
                         create_report_sets_created_to_null_on_entry);
  add_test_with_context (suite, security_intelligence,
                         create_report_fails_when_no_http_response);
  add_test_with_context (suite, security_intelligence,
                         create_report_non_2xx_populates_errors_from_json);
  add_test_with_context (
    suite, security_intelligence,
    create_report_non_2xx_invalid_json_populates_fallback_error);
  add_test_with_context (suite, security_intelligence,
                         create_report_fails_on_invalid_success_json);
  add_test_with_context (
    suite, security_intelligence,
    create_report_fails_when_success_json_is_not_valid_report);
  add_test_with_context (
    suite, security_intelligence,
    create_report_success_returns_created_report_started_status);
  add_test_with_context (
    suite, security_intelligence,
    create_report_success_returns_created_report_completed_status);
  add_test_with_context (
    suite, security_intelligence,
    create_report_success_defaults_unknown_status_when_missing);
  add_test_with_context (suite, security_intelligence,
                         create_report_uses_prebuilt_base_url_when_present);

  add_test_with_context (suite, security_intelligence,
                         add_report_page_fails_with_null_conn);
  add_test_with_context (suite, security_intelligence,
                         add_report_page_fails_with_null_report_id);
  add_test_with_context (suite, security_intelligence,
                         add_report_page_fails_with_empty_report_id);
  add_test_with_context (suite, security_intelligence,
                         add_report_page_fails_with_negative_index);
  add_test_with_context (suite, security_intelligence,
                         add_report_page_fails_with_null_xml);
  add_test_with_context (suite, security_intelligence,
                         add_report_page_fails_with_zero_xml_len);
  add_test_with_context (suite, security_intelligence,
                         add_report_page_fails_when_no_http_response);
  add_test_with_context (suite, security_intelligence,
                         add_report_page_non_204_populates_errors_from_json);
  add_test_with_context (
    suite, security_intelligence,
    add_report_page_non_204_invalid_json_error_adds_fallback);
  add_test_with_context (suite, security_intelligence,
                         add_report_page_success_returns_ok_on_204);
  add_test_with_context (suite, security_intelligence,
                         add_report_page_uses_prebuilt_base_url_when_present);
  add_test_with_context (suite, security_intelligence,
                         add_report_page_respects_xml_len_for_payload_copy);

  add_test_with_context (suite, security_intelligence,
                         update_report_status_fails_with_null_conn);
  add_test_with_context (suite, security_intelligence,
                         update_report_status_fails_with_null_report_id);
  add_test_with_context (suite, security_intelligence,
                         update_report_status_fails_with_empty_report_id);
  add_test_with_context (
    suite, security_intelligence,
    update_report_status_fails_when_payload_build_fails_for_unknown_status);
  add_test_with_context (suite, security_intelligence,
                         update_report_status_fails_when_no_http_response);
  add_test_with_context (
    suite, security_intelligence,
    update_report_status_non_2xx_populates_errors_from_json);
  add_test_with_context (
    suite, security_intelligence,
    update_report_status_non_2xx_invalid_json_adds_fallback_error);
  add_test_with_context (
    suite, security_intelligence,
    update_report_status_success_returns_ok_for_started_status);
  add_test_with_context (
    suite, security_intelligence,
    update_report_status_success_returns_ok_for_completed_status);
  add_test_with_context (
    suite, security_intelligence,
    update_report_status_uses_prebuilt_base_url_when_present);

  add_test_with_context (suite, security_intelligence,
                         get_report_pages_fails_with_null_conn);
  add_test_with_context (suite, security_intelligence,
                         get_report_pages_fails_with_null_report_id);
  add_test_with_context (suite, security_intelligence,
                         get_report_pages_fails_with_empty_report_id);
  add_test_with_context (suite, security_intelligence,
                         get_report_pages_fails_when_no_http_response);
  add_test_with_context (suite, security_intelligence,
                         get_report_pages_non_2xx_populates_errors_from_json);
  add_test_with_context (
    suite, security_intelligence,
    get_report_pages_non_2xx_invalid_json_adds_fallback_error);
  add_test_with_context (suite, security_intelligence,
                         get_report_pages_fails_on_invalid_json);
  add_test_with_context (suite, security_intelligence,
                         get_report_pages_fails_when_root_not_array);
  add_test_with_context (suite, security_intelligence,
                         get_report_pages_returns_empty_list_for_empty_array);
  add_test_with_context (suite, security_intelligence,
                         get_report_pages_parses_valid_page_objects);
  add_test_with_context (
    suite, security_intelligence,
    get_report_pages_filters_non_object_items_and_keeps_order);
  add_test_with_context (
    suite, security_intelligence,
    get_report_pages_missing_index_defaults_to_zero_via_helper);
  add_test_with_context (suite, security_intelligence,
                         get_report_pages_uses_prebuilt_base_url_when_present);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);
  return ret;
}