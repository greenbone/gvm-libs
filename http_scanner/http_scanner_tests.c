/* SPDX-FileCopyrightText: 2025 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "http_scanner.c"

#include <cgreen/assertions.h>
#include <cgreen/cgreen.h>
#include <cgreen/constraint_syntax_helpers.h>
#include <cgreen/internal/c_assertions.h>
#include <cgreen/mocks.h>

Describe (http_scanner);
BeforeEach (http_scanner)
{
}

AfterEach (http_scanner)
{
}

/* http_scanner_delete_scan */

Ensure (http_scanner, http_scanner_delete_scan_handles_missing_id)
{
  http_scanner_resp_t resp;
  http_scanner_connector_t conn;

  conn = http_scanner_connector_new ();
  resp = http_scanner_delete_scan (conn);
  assert_that (resp, is_not_null);
  assert_that (resp->code, is_equal_to (RESP_CODE_ERR));
  assert_that (resp->body,
               is_equal_to_string ("{\"error\": \"Missing scan ID\"}"));
  http_scanner_response_cleanup (resp);
}

/* http_scanner_start_scan */

Ensure (http_scanner, http_scanner_start_scan_handles_missing_id)
{
  http_scanner_resp_t resp;
  http_scanner_connector_t conn;

  conn = http_scanner_connector_new ();
  resp = http_scanner_start_scan (conn);
  assert_that (resp, is_not_null);
  assert_that (resp->code, is_equal_to (RESP_CODE_ERR));
  assert_that (resp->body,
               is_equal_to_string ("{\"error\": \"Missing scan ID\"}"));
  http_scanner_response_cleanup (resp);
}

/* http_scanner_stop_scan */

Ensure (http_scanner, http_scanner_stop_scan_handles_missing_id)
{
  http_scanner_resp_t resp;
  http_scanner_connector_t conn;

  conn = http_scanner_connector_new ();
  resp = http_scanner_stop_scan (conn);
  assert_that (resp, is_not_null);
  assert_that (resp->code, is_equal_to (RESP_CODE_ERR));
  assert_that (resp->body,
               is_equal_to_string ("{\"error\": \"Missing scan ID\"}"));
  http_scanner_response_cleanup (resp);
}

/* parse_results */

Ensure (http_scanner, parse_results_handles_details)
{
  const gchar *str;
  GSList *results;
  http_scanner_result_t result;

  results = NULL;

  str =
    "[ {"
    "  \"id\": 16,"
    "  \"type\": \"host_detail\","
    "  \"ip_address\": \"192.168.0.101\","
    "  \"hostname\": \"g\","
    "  \"oid\": \"1.3.6.1.4.1.25623.1.0.103997\","
    "  \"message\": "
    "\"<host><detail><name>MAC</name><value>94:E6:F7:67:4B:C0</"
    "value><source><type>nvt</type><name>1.3.6.1.4.1.25623.1.0.103585</"
    "name><description>Nmap MAC Scan</description></source></detail></host>\","
    "  \"detail\": {"
    "    \"name\": \"MAC\","
    "    \"value\": \"00:1A:2B:3C:4D:5E\","
    "    \"source\": {"
    "      \"type\": \"nvt\","
    "      \"name\": \"1.3.6.1.4.1.25623.1.0.103585\","
    "      \"description\": \"Nmap MAC Scan\""
    "    }"
    "  }"
    "} ]";

  parse_results (str, &results);

  assert_that (g_slist_length (results), is_equal_to (1));

  result = results->data;
  assert_that (result->detail_name, is_equal_to_string ("MAC"));
  assert_that (result->detail_value, is_equal_to_string ("00:1A:2B:3C:4D:5E"));
  assert_that (result->detail_source_type, is_equal_to_string ("nvt"));
  assert_that (result->detail_source_name,
               is_equal_to_string ("1.3.6.1.4.1.25623.1.0.103585"));
  assert_that (result->detail_source_description,
               is_equal_to_string ("Nmap MAC Scan"));

  if (g_slist_length (results))
    g_slist_free_full (results, (GDestroyNotify) http_scanner_result_free);
}

/* parse_status */

Ensure (http_scanner, parse_status_start_end_time)
{
  const gchar *str;
  http_scanner_scan_status_t http_scanner_scan_status = NULL;

  http_scanner_scan_status =
    g_malloc0 (sizeof (struct http_scanner_scan_status));
  str = "{"
        "  \"start_time\":1737642308,"
        "  \"end_time\":1737642389,"
        "  \"status\":\"succeeded\","
        "  \"host_info\":{"
        "    \"all\":1,"
        "    \"excluded\":0,"
        "    \"dead\":0,"
        "    \"alive\":1,"
        "    \"queued\":0,"
        "    \"finished\":1,"
        "    \"scanning\":{},"
        "    \"remaining_vts_per_host\":{}"
        "  }"
        "}";

  parse_status (str, http_scanner_scan_status);

  assert_that (http_scanner_scan_status->status, is_equal_to (4));
  assert_that_double (http_scanner_scan_status->start_time,
                      is_equal_to_double (1737642308));
  assert_that_double (http_scanner_scan_status->end_time,
                      is_equal_to_double (1737642389));

  g_free (http_scanner_scan_status);
}

Ensure (http_scanner, http_scanner_connector_builder_all_valid_fields)
{
  http_scanner_connector_t conn = http_scanner_connector_new ();

  const char *ca_cert = "/path/to/ca.pem";
  const char *cert = "/path/to/cert.pem";
  const char *key = "/path/to/key.pem";
  const char *apikey = "apikey-value";
  const char *protocol = "https";
  const char *host = "localhost";
  const char *scan_id = "scan-uuid-123";
  const char *scan_prefix = "scan-prefix";
  int port = 9390;

  assert_that (
    http_scanner_connector_builder (conn, HTTP_SCANNER_CA_CERT, ca_cert),
    is_equal_to (HTTP_SCANNER_OK));
  assert_that (conn->ca_cert, is_equal_to_string (ca_cert));

  assert_that (http_scanner_connector_builder (conn, HTTP_SCANNER_CERT, cert),
               is_equal_to (HTTP_SCANNER_OK));
  assert_that (conn->cert, is_equal_to_string (cert));

  assert_that (http_scanner_connector_builder (conn, HTTP_SCANNER_KEY, key),
               is_equal_to (HTTP_SCANNER_OK));
  assert_that (conn->key, is_equal_to_string (key));

  assert_that (
    http_scanner_connector_builder (conn, HTTP_SCANNER_API_KEY, apikey),
    is_equal_to (HTTP_SCANNER_OK));
  assert_that (conn->apikey, is_equal_to_string (apikey));

  assert_that (
    http_scanner_connector_builder (conn, HTTP_SCANNER_PROTOCOL, protocol),
    is_equal_to (HTTP_SCANNER_OK));
  assert_that (conn->protocol, is_equal_to_string (protocol));

  assert_that (http_scanner_connector_builder (conn, HTTP_SCANNER_HOST, host),
               is_equal_to (HTTP_SCANNER_OK));
  assert_that (conn->host, is_equal_to_string (host));

  assert_that (
    http_scanner_connector_builder (conn, HTTP_SCANNER_SCAN_ID, scan_id),
    is_equal_to (HTTP_SCANNER_OK));
  assert_that (conn->scan_id, is_equal_to_string (scan_id));

  assert_that (http_scanner_connector_builder (conn, HTTP_SCANNER_PORT, &port),
               is_equal_to (HTTP_SCANNER_OK));
  assert_that (conn->port, is_equal_to (port));

  assert_that (http_scanner_connector_builder (conn, HTTP_SCANNER_SCAN_PREFIX,
                                               scan_prefix),
               is_equal_to (HTTP_SCANNER_OK));
  assert_that (conn->scan_prefix, is_equal_to_string (scan_prefix));

  g_free (conn->ca_cert);
  g_free (conn->cert);
  g_free (conn->key);
  g_free (conn->apikey);
  g_free (conn->protocol);
  g_free (conn->host);
  g_free (conn->scan_id);
  g_free (conn->scan_prefix);
  g_free (conn);
}

Ensure (http_scanner, http_scanner_connector_builder_valid_protocol_http)
{
  http_scanner_connector_t conn = http_scanner_connector_new ();
  http_scanner_error_t result =
    http_scanner_connector_builder (conn, HTTP_SCANNER_PROTOCOL, "http");

  assert_that (result, is_equal_to (HTTP_SCANNER_OK));
  assert_that (conn->protocol, is_equal_to_string ("http"));

  g_free (conn->protocol);
  g_free (conn);
}

Ensure (http_scanner, http_scanner_connector_builder_invalid_protocol)
{
  http_scanner_connector_t conn = http_scanner_connector_new ();
  http_scanner_error_t result =
    http_scanner_connector_builder (conn, HTTP_SCANNER_PROTOCOL, "ftp");

  assert_that (result, is_equal_to (HTTP_SCANNER_INVALID_VALUE));
  assert_that (conn->protocol, is_null);

  g_free (conn);
}

Ensure (http_scanner, http_scanner_connector_builder_null_conn)
{
  http_scanner_error_t result =
    http_scanner_connector_builder (NULL, HTTP_SCANNER_PROTOCOL, "https");

  assert_that (result, is_equal_to (HTTP_SCANNER_NOT_INITIALIZED));
}

Ensure (http_scanner, http_scanner_connector_free)
{
  http_scanner_connector_t conn = http_scanner_connector_new ();

  conn->ca_cert = g_strdup ("ca.pem");
  conn->cert = g_strdup ("cert.pem");
  conn->key = g_strdup ("key.pem");
  conn->apikey = g_strdup ("api-key");
  conn->protocol = g_strdup ("https");
  conn->host = g_strdup ("localhost");
  conn->scan_id = g_strdup ("scan-uuid");

  http_scanner_error_t result = http_scanner_connector_free (conn);

  assert_that (result, is_equal_to (HTTP_SCANNER_OK));
}

Ensure (http_scanner, http_scanner_connector_free_null_connector)
{
  http_scanner_connector_t null_conn = NULL;
  http_scanner_error_t result = http_scanner_connector_free (null_conn);

  assert_that (result, is_equal_to (HTTP_SCANNER_OK));
}

/* Test suite. */
int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, http_scanner, parse_results_handles_details);
  add_test_with_context (suite, http_scanner, parse_status_start_end_time);

  add_test_with_context (suite, http_scanner,
                         http_scanner_connector_builder_all_valid_fields);
  add_test_with_context (suite, http_scanner,
                         http_scanner_connector_builder_valid_protocol_http);
  add_test_with_context (suite, http_scanner,
                         http_scanner_connector_builder_invalid_protocol);
  add_test_with_context (suite, http_scanner,
                         http_scanner_connector_builder_null_conn);
  add_test_with_context (suite, http_scanner, http_scanner_connector_free);
  add_test_with_context (suite, http_scanner,
                         http_scanner_connector_builder_invalid_protocol);

  add_test_with_context (suite, http_scanner,
                         http_scanner_start_scan_handles_missing_id);
  add_test_with_context (suite, http_scanner,
                         http_scanner_stop_scan_handles_missing_id);
  add_test_with_context (suite, http_scanner,
                         http_scanner_delete_scan_handles_missing_id);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
