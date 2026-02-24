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
  http_scanner_connector_free (conn);
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
  http_scanner_connector_free (conn);
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
  http_scanner_connector_free (conn);
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

  http_scanner_connector_free (conn);
}

Ensure (http_scanner, http_scanner_connector_builder_valid_protocol_http)
{
  http_scanner_connector_t conn = http_scanner_connector_new ();
  http_scanner_error_t result =
    http_scanner_connector_builder (conn, HTTP_SCANNER_PROTOCOL, "http");

  assert_that (result, is_equal_to (HTTP_SCANNER_OK));
  assert_that (conn->protocol, is_equal_to_string ("http"));

  http_scanner_connector_free (conn);
}

Ensure (http_scanner, http_scanner_connector_builder_invalid_protocol)
{
  http_scanner_connector_t conn = http_scanner_connector_new ();
  http_scanner_error_t result =
    http_scanner_connector_builder (conn, HTTP_SCANNER_PROTOCOL, "ftp");

  assert_that (result, is_equal_to (HTTP_SCANNER_INVALID_VALUE));
  assert_that (conn->protocol, is_null);

  http_scanner_connector_free (conn);
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

Ensure (http_scanner, parse_results_invalid_json_returns_minus1)
{
  const gchar *str = "{ this is not json ";
  GSList *results = NULL;

  int ret = parse_results (str, &results);

  assert_that (ret, is_equal_to (-1));
  assert_that (results, is_null);
}

Ensure (http_scanner, parse_results_non_array_json_returns_minus1)
{
  const gchar *str = "{ \"id\": 1 }";
  GSList *results = NULL;

  int ret = parse_results (str, &results);

  assert_that (ret, is_equal_to (-1));
  assert_that (results, is_null);
}

Ensure (http_scanner, parse_results_empty_array_returns_200_and_no_results)
{
  const gchar *str = "[]";
  GSList *results = NULL;

  int ret = parse_results (str, &results);

  assert_that (ret, is_equal_to (200));
  assert_that (results, is_null);
}

Ensure (http_scanner, parse_results_array_with_non_object_item_returns_minus1)
{
  const gchar *str = "[ 1 ]";
  GSList *results = NULL;

  int ret = parse_results (str, &results);

  assert_that (ret, is_equal_to (-1));
  assert_that (results, is_null);
}

Ensure (http_scanner,
        parse_results_missing_detail_appends_result_and_detail_null)
{
  const gchar *str = "[ {"
                     "  \"id\": 1,"
                     "  \"type\": \"host_detail\","
                     "  \"ip_address\": \"10.0.0.1\","
                     "  \"hostname\": \"h1\","
                     "  \"oid\": \"1.3.6.1.4.1.25623.1.0.1\","
                     "  \"port\": 80,"
                     "  \"message\": \"m\""
                     "} ]";

  GSList *results = NULL;

  int ret = parse_results (str, &results);

  assert_that (ret, is_equal_to (200));
  assert_that (g_slist_length (results), is_equal_to (1));

  http_scanner_result_t r = results->data;

  assert_that (r->ip_address, is_equal_to_string ("10.0.0.1"));
  assert_that (r->hostname, is_equal_to_string ("h1"));
  assert_that (r->oid, is_equal_to_string ("1.3.6.1.4.1.25623.1.0.1"));
  assert_that (r->message, is_equal_to_string ("m"));

  assert_that (r->detail_name, is_null);
  assert_that (r->detail_value, is_null);
  assert_that (r->detail_source_type, is_null);
  assert_that (r->detail_source_name, is_null);
  assert_that (r->detail_source_description, is_null);

  g_slist_free_full (results, (GDestroyNotify) http_scanner_result_free);
}

Ensure (http_scanner, parse_results_detail_not_object_is_ignored)
{
  const gchar *str = "[ {"
                     "  \"id\": 2,"
                     "  \"type\": \"host_detail\","
                     "  \"ip_address\": \"10.0.0.1\","
                     "  \"hostname\": \"h2\","
                     "  \"oid\": \"oid-2\","
                     "  \"port\": 443,"
                     "  \"protocol\": \"tcp\","
                     "  \"message\": \"m2\","
                     "  \"detail\": \"not-an-object\""
                     "} ]";

  GSList *results = NULL;
  int ret = parse_results (str, &results);

  assert_that (ret, is_equal_to (200));
  assert_that (g_slist_length (results), is_equal_to (1));

  http_scanner_result_t r = results->data;
  assert_that (r->detail_name, is_null);
  assert_that (r->detail_value, is_null);
  assert_that (r->detail_source_type, is_null);
  assert_that (r->detail_source_name, is_null);
  assert_that (r->detail_source_description, is_null);

  g_slist_free_full (results, (GDestroyNotify) http_scanner_result_free);
}

Ensure (http_scanner, parse_results_detail_source_not_object_is_ignored)
{
  const gchar *str = "[ {"
                     "  \"id\": 3,"
                     "  \"type\": \"host_detail\","
                     "  \"ip_address\": \"10.0.0.2\","
                     "  \"hostname\": \"h3\","
                     "  \"oid\": \"oid-3\","
                     "  \"port\": 22,"
                     "  \"protocol\": \"tcp\","
                     "  \"message\": \"m3\","
                     "  \"detail\": {"
                     "    \"name\": \"MAC\","
                     "    \"value\": \"AA:BB:CC:DD:EE:FF\","
                     "    \"source\": 123"
                     "  }"
                     "} ]";

  GSList *results = NULL;
  int ret = parse_results (str, &results);

  assert_that (ret, is_equal_to (200));
  assert_that (g_slist_length (results), is_equal_to (1));

  http_scanner_result_t r = results->data;

  assert_that (r->detail_name, is_equal_to_string ("MAC"));
  assert_that (r->detail_value, is_equal_to_string ("AA:BB:CC:DD:EE:FF"));

  assert_that (r->detail_source_type, is_null);
  assert_that (r->detail_source_name, is_null);
  assert_that (r->detail_source_description, is_null);

  g_slist_free_full (results, (GDestroyNotify) http_scanner_result_free);
}

Ensure (http_scanner, parse_results_multiple_items_appended)
{
  const gchar *str = "["
                     " {"
                     "  \"id\": 10,"
                     "  \"type\": \"host_detail\","
                     "  \"ip_address\": \"10.0.0.2\","
                     "  \"hostname\": \"a\","
                     "  \"oid\": \"oid-a\","
                     "  \"port\": 80,"
                     "  \"protocol\": \"tcp\","
                     "  \"message\": \"ma\""
                     " },"
                     " {"
                     "  \"id\": 11,"
                     "  \"type\": \"host_detail\","
                     "  \"ip_address\": \"10.0.0.3\","
                     "  \"hostname\": \"b\","
                     "  \"oid\": \"oid-b\","
                     "  \"port\": 443,"
                     "  \"protocol\": \"tcp\","
                     "  \"message\": \"mb\","
                     "  \"detail\": {"
                     "    \"name\": \"OS\","
                     "    \"value\": \"Linux\""
                     "  }"
                     " }"
                     "]";

  GSList *results = NULL;
  int ret = parse_results (str, &results);

  assert_that (ret, is_equal_to (200));
  assert_that (g_slist_length (results), is_equal_to (2));

  http_scanner_result_t r1 = results->data;
  http_scanner_result_t r2 = results->next->data;

  assert_that (r1->ip_address, is_equal_to_string ("10.0.0.2"));
  assert_that (r1->hostname, is_equal_to_string ("a"));
  assert_that (r1->detail_name, is_null);

  assert_that (r2->ip_address, is_equal_to_string ("10.0.0.3"));
  assert_that (r2->hostname, is_equal_to_string ("b"));
  assert_that (r2->detail_name, is_equal_to_string ("OS"));
  assert_that (r2->detail_value, is_equal_to_string ("Linux"));

  g_slist_free_full (results, (GDestroyNotify) http_scanner_result_free);
}

Ensure (http_scanner, parse_results_port_is_stringified)
{
  const gchar *str = "[ {"
                     "  \"id\": 20,"
                     "  \"type\": \"host_detail\","
                     "  \"ip_address\": \"127.0.0.1\","
                     "  \"hostname\": \"local\","
                     "  \"oid\": \"oid-port\","
                     "  \"port\": 8080,"
                     "  \"message\": \"m\""
                     "} ]";

  GSList *results = NULL;
  int ret = parse_results (str, &results);

  assert_that (ret, is_equal_to (200));
  assert_that (g_slist_length (results), is_equal_to (1));

  http_scanner_result_t r = results->data;

  assert_that (r->port, is_equal_to_string ("general/Host_Details"));

  g_slist_free_full (results, (GDestroyNotify) http_scanner_result_free);
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

  add_test_with_context (suite, http_scanner,
                         parse_results_invalid_json_returns_minus1);
  add_test_with_context (suite, http_scanner,
                         parse_results_non_array_json_returns_minus1);
  add_test_with_context (suite, http_scanner,
                         parse_results_empty_array_returns_200_and_no_results);
  add_test_with_context (
    suite, http_scanner,
    parse_results_array_with_non_object_item_returns_minus1);
  add_test_with_context (
    suite, http_scanner,
    parse_results_missing_detail_appends_result_and_detail_null);
  add_test_with_context (suite, http_scanner,
                         parse_results_detail_not_object_is_ignored);
  add_test_with_context (suite, http_scanner,
                         parse_results_detail_source_not_object_is_ignored);
  add_test_with_context (suite, http_scanner,
                         parse_results_multiple_items_appended);
  add_test_with_context (suite, http_scanner,
                         parse_results_port_is_stringified);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
