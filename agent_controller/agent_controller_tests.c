/* SPDX-FileCopyrightText: 2019-2025 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "agent_controller.c"

#include <cgreen/cgreen.h>

static GPtrArray *called_headers = NULL;
static gchar *last_sent_url = NULL;
static gchar *last_sent_payload = NULL;
static long mock_http_status = 200;
static gchar *mock_response_data = NULL;

Describe (agent_controller);

BeforeEach (agent_controller)
{
  if (called_headers)
    {
      g_ptr_array_free (called_headers, TRUE);
      called_headers = NULL;
    }

  g_clear_pointer (&last_sent_url, g_free);
  g_clear_pointer (&last_sent_payload, g_free);
  g_clear_pointer (&mock_response_data, g_free);
  mock_http_status = 200;
}

AfterEach (agent_controller)
{
  g_clear_pointer (&last_sent_url, g_free);
  g_clear_pointer (&last_sent_payload, g_free);

  if (called_headers)
    {
      g_ptr_array_free (called_headers, TRUE);
      called_headers = NULL;
    }
}

// -------------------- Mock Functions --------------------
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

static agent_controller_connector_t
make_conn (void)
{
  agent_controller_connector_t conn = agent_controller_connector_new ();
  conn->protocol = g_strdup ("http");
  conn->host = g_strdup ("localhost");
  conn->port = 8081;
  conn->apikey = g_strdup ("token");
  return conn;
}

static agent_controller_scan_agent_config_t
make_scan_agent_config (void)
{
  agent_controller_scan_agent_config_t cfg =
    agent_controller_scan_agent_config_new ();
  /* agent_control.retry > 0 */
  cfg->agent_control.retry.attempts = 1;
  cfg->agent_control.retry.delay_in_seconds = 1;
  cfg->agent_control.retry.max_jitter_in_seconds = 1;

  /* agent_script_executor > 0 and cron present */
  cfg->agent_script_executor.bulk_size = 1;
  cfg->agent_script_executor.bulk_throttle_time_in_ms = 1;
  cfg->agent_script_executor.indexer_dir_depth = 1;
  cfg->agent_script_executor.scheduler_cron_time =
    g_ptr_array_new_with_free_func (g_free);
  g_ptr_array_add (cfg->agent_script_executor.scheduler_cron_time,
                   g_strdup ("* * * * *"));

  /* heartbeat */
  cfg->heartbeat.interval_in_seconds = 1;
  cfg->heartbeat.miss_until_inactive = 1;
  return cfg;
}

Ensure (agent_controller, connector_new_returns_valid_connector)
{
  agent_controller_connector_t conn = agent_controller_connector_new ();

  assert_that (conn, is_not_null);

  assert_that (conn->ca_cert, is_null);
  assert_that (conn->cert, is_null);
  assert_that (conn->key, is_null);
  assert_that (conn->apikey, is_null);
  assert_that (conn->protocol, is_null);
  assert_that (conn->host, is_null);
  assert_that (conn->port, is_equal_to (0));

  agent_controller_connector_free (conn);
}

Ensure (agent_controller, connector_free_handles_null_safely)
{
  agent_controller_connector_free (NULL);
  assert_that (true, is_true);
}

Ensure (agent_controller, connector_free_safely)
{
  agent_controller_connector_t conn = agent_controller_connector_new ();
  assert_that (conn, is_not_null);

  const char *ca_cert = "/dummy/ca.pem";
  const char *cert = "/dummy/cert.pem";
  const char *key = "/dummy/key.pem";
  const char *apikey = "apikey123";
  const char *protocol = "https";
  const char *host = "localhost";
  int port = 8443;

  agent_controller_connector_builder (conn, AGENT_CONTROLLER_CA_CERT, ca_cert);
  agent_controller_connector_builder (conn, AGENT_CONTROLLER_CERT, cert);
  agent_controller_connector_builder (conn, AGENT_CONTROLLER_KEY, key);
  agent_controller_connector_builder (conn, AGENT_CONTROLLER_API_KEY, apikey);
  agent_controller_connector_builder (conn, AGENT_CONTROLLER_PROTOCOL,
                                      protocol);
  agent_controller_connector_builder (conn, AGENT_CONTROLLER_HOST, host);
  agent_controller_connector_builder (conn, AGENT_CONTROLLER_PORT, &port);

  agent_controller_connector_free (conn);
  assert_that (true, is_true);
}

Ensure (agent_controller, connector_builder_all_valid_fields)
{
  agent_controller_connector_t conn = agent_controller_connector_new ();

  const char *ca_cert = "/path/ca.pem";
  const char *cert = "/path/cert.pem";
  const char *key = "/path/key.pem";
  const char *apikey = "123abc";
  const char *protocol = "https";
  const char *host = "127.0.0.1";
  int port = 8443;

  assert_that (agent_controller_connector_builder (
                 conn, AGENT_CONTROLLER_CA_CERT, ca_cert),
               is_equal_to (AGENT_CONTROLLER_OK));
  assert_that (conn->ca_cert, is_equal_to_string (ca_cert));

  assert_that (
    agent_controller_connector_builder (conn, AGENT_CONTROLLER_CERT, cert),
    is_equal_to (AGENT_CONTROLLER_OK));
  assert_that (conn->cert, is_equal_to_string (cert));

  assert_that (
    agent_controller_connector_builder (conn, AGENT_CONTROLLER_KEY, key),
    is_equal_to (AGENT_CONTROLLER_OK));
  assert_that (conn->key, is_equal_to_string (key));

  assert_that (
    agent_controller_connector_builder (conn, AGENT_CONTROLLER_API_KEY, apikey),
    is_equal_to (AGENT_CONTROLLER_OK));
  assert_that (conn->apikey, is_equal_to_string (apikey));

  assert_that (agent_controller_connector_builder (
                 conn, AGENT_CONTROLLER_PROTOCOL, protocol),
               is_equal_to (AGENT_CONTROLLER_OK));
  assert_that (conn->protocol, is_equal_to_string (protocol));

  assert_that (
    agent_controller_connector_builder (conn, AGENT_CONTROLLER_HOST, host),
    is_equal_to (AGENT_CONTROLLER_OK));
  assert_that (conn->host, is_equal_to_string (host));

  assert_that (
    agent_controller_connector_builder (conn, AGENT_CONTROLLER_PORT, &port),
    is_equal_to (AGENT_CONTROLLER_OK));
  assert_that (conn->port, is_equal_to (port));

  agent_controller_connector_free (conn);
}

Ensure (agent_controller, connector_builder_valid_protocol_http)
{
  agent_controller_connector_t conn = agent_controller_connector_new ();
  agent_controller_error_t result = agent_controller_connector_builder (
    conn, AGENT_CONTROLLER_PROTOCOL, "http");

  assert_that (result, is_equal_to (AGENT_CONTROLLER_OK));
  assert_that (conn->protocol, is_equal_to_string ("http"));

  agent_controller_connector_free (conn);
}

Ensure (agent_controller, connector_builder_invalid_protocol)
{
  agent_controller_connector_t conn = agent_controller_connector_new ();
  agent_controller_error_t result =
    agent_controller_connector_builder (conn, AGENT_CONTROLLER_PROTOCOL, "ftp");

  assert_that (result, is_equal_to (AGENT_CONTROLLER_INVALID_VALUE));
  assert_that (conn->protocol, is_null);

  agent_controller_connector_free (conn);
}

Ensure (agent_controller, agent_new_allocates_zero_initialized_agent)
{
  agent_controller_agent_t agent = agent_controller_agent_new ();

  assert_that (agent, is_not_null);
}

Ensure (agent_controller, agent_free_handles_agent)
{
  agent_controller_agent_free (NULL);
  assert_that (true, is_true);

  agent_controller_agent_t agent = agent_controller_agent_new ();
  assert_that (agent, is_not_null);

  agent->agent_id = g_strdup ("agent-001");
  agent->hostname = g_strdup ("localhost");
  agent->connection_status = g_strdup ("active");

  // IP addresses
  agent->ip_address_count = 2;
  agent->ip_addresses = g_malloc0 (sizeof (gchar *) * agent->ip_address_count);
  agent->ip_addresses[0] = g_strdup ("192.168.0.1");
  agent->ip_addresses[1] = g_strdup ("10.0.0.1");
  agent->config = agent_controller_scan_agent_config_new ();
  agent->updater_version = g_strdup ("1.2.3");
  agent->agent_version = g_strdup ("1.2.3");
  agent->operating_system = g_strdup ("linux");
  agent->architecture = g_strdup ("amd64");

  agent_controller_agent_free (agent);
  assert_that (true, is_true);
}

Ensure (agent_controller, agent_free_handles_null_agent)
{
  agent_controller_agent_free (NULL);
  assert_that (true, is_true);
}

Ensure (agent_controller, agent_list_new_allocates_list_and_agents_array)
{
  int count = 3;
  agent_controller_agent_list_t list = agent_controller_agent_list_new (count);

  assert_that (list, is_not_null);
  assert_that (list->count, is_equal_to (count));
  assert_that (list->agents, is_not_null);

  for (int i = 0; i < count; ++i)
    {
      assert_that (list->agents[i], is_null);
    }

  agent_controller_agent_list_free (list);
}

Ensure (agent_controller, agent_list_new_returns_null_for_invalid_count)
{
  agent_controller_agent_list_t list_negative =
    agent_controller_agent_list_new (-5);
  assert_that (list_negative, is_null);
}

Ensure (agent_controller, agent_list_new_returns_array_for_0_count)
{
  agent_controller_agent_list_t list_zero = agent_controller_agent_list_new (0);
  assert_that (list_zero, is_not_null);
  assert_that (list_zero->count, is_equal_to (0));
  agent_controller_agent_list_free (list_zero);
}

Ensure (agent_controller, agent_list_free_handles_populated_list)
{
  int count = 2;
  agent_controller_agent_list_t list = agent_controller_agent_list_new (count);
  assert_that (list, is_not_null);

  for (int i = 0; i < count; ++i)
    {
      list->agents[i] = agent_controller_agent_new ();
      list->agents[i]->agent_id = g_strdup_printf ("agent-%d", i);
    }

  agent_controller_agent_list_free (list);
  assert_that (true, is_true);
}

Ensure (agent_controller, agent_list_free_handles_null_list)
{
  agent_controller_agent_list_free (NULL);
  assert_that (true, is_true);
}

Ensure (agent_controller, agent_update_new_initializes_defaults_correctly)
{
  agent_controller_agent_update_t update = agent_controller_agent_update_new ();

  assert_that (update, is_not_null);

  assert_that (update->authorized, is_equal_to (-1));
  assert_that (update->config, is_null);

  agent_controller_agent_update_free (update);
}

Ensure (agent_controller, agent_update_free_handles_nested_schedule)
{
  agent_controller_agent_update_t update = agent_controller_agent_update_new ();
  assert_that (update, is_not_null);

  update->config = agent_controller_scan_agent_config_new ();

  agent_controller_agent_update_free (update);
  assert_that (true, is_true);
}

Ensure (agent_controller, agent_update_free_handles_null_schedule)
{
  agent_controller_agent_update_free (NULL);
  assert_that (true, is_true);
}

Ensure (agent_controller, init_custom_header_calls_add_header)
{
  called_headers = NULL;

  gvm_http_headers_t *headers = init_custom_header ("my-token", TRUE);
  assert_that (headers, is_not_null);
  assert_that (called_headers->len, is_equal_to (2));

  const gchar *auth = g_ptr_array_index (called_headers, 0);
  const gchar *ctype = g_ptr_array_index (called_headers, 1);

  assert_that (auth, contains_string ("Authorization: Bearer my-token"));
  assert_that (ctype, is_equal_to_string ("Content-Type: application/json"));

  g_ptr_array_free (called_headers, TRUE);
  called_headers = NULL;

  gvm_http_headers_free (headers);
}

Ensure (agent_controller, init_custom_header_calls_without_token_add_header)
{
  called_headers = NULL;

  gvm_http_headers_t *headers = init_custom_header (NULL, TRUE);
  assert_that (headers, is_not_null);
  assert_that (called_headers->len, is_equal_to (1));

  const gchar *ctype = g_ptr_array_index (called_headers, 0);

  assert_that (ctype, is_equal_to_string ("Content-Type: application/json"));

  g_ptr_array_free (called_headers, TRUE);
  called_headers = NULL;

  gvm_http_headers_free (headers);
}

Ensure (agent_controller, send_request_builds_url_and_calls_http_request)
{
  agent_controller_connector_t conn = agent_controller_connector_new ();
  conn->protocol = g_strdup ("https");
  conn->host = g_strdup ("localhost");
  conn->port = 8080;
  conn->ca_cert = g_strdup ("ca.pem");
  conn->cert = g_strdup ("cert.pem");
  conn->key = g_strdup ("key.pem");

  const gchar *path = "/api/v1/test";
  const gchar *token = "mytoken";
  const gchar *payload = "{\"key\":\"value\"}";

  gvm_http_response_t *resp =
    agent_controller_send_request (conn, POST, path, payload, token);

  assert_that (resp, is_not_null);
  assert_that (last_sent_url,
               is_equal_to_string ("https://localhost:8080/api/v1/test"));
  assert_that (last_sent_payload, is_equal_to_string (payload));

  g_free (resp);
  agent_controller_connector_free (conn);
}

Ensure (agent_controller, send_request_returns_null_if_conn_is_null)
{
  gvm_http_response_t *resp =
    agent_controller_send_request (NULL, POST, "/test", "{}", "token");
  assert_that (resp, is_null);
}

Ensure (agent_controller, send_request_returns_null_if_protocol_missing)
{
  agent_controller_connector_t conn = agent_controller_connector_new ();
  conn->host = g_strdup ("localhost");
  conn->port = 8080;

  gvm_http_response_t *resp =
    agent_controller_send_request (conn, GET, "/test", NULL, NULL);
  assert_that (resp, is_null);

  agent_controller_connector_free (conn);
}

Ensure (agent_controller, send_request_returns_null_if_host_missing)
{
  agent_controller_connector_t conn = agent_controller_connector_new ();
  conn->protocol = g_strdup ("http");
  conn->port = 8080;

  gvm_http_response_t *resp =
    agent_controller_send_request (conn, GET, "/test", NULL, NULL);
  assert_that (resp, is_null);

  agent_controller_connector_free (conn);
}

Ensure (agent_controller, send_request_works_without_bearer_token)
{
  agent_controller_connector_t conn = agent_controller_connector_new ();
  conn->protocol = g_strdup ("https");
  conn->host = g_strdup ("localhost");
  conn->port = 8080;

  gvm_http_response_t *resp =
    agent_controller_send_request (conn, GET, "/test", NULL, "");

  assert_that (resp, is_not_null);
  assert_that (last_sent_url,
               is_equal_to_string ("https://localhost:8080/test"));

  g_free (resp);
  agent_controller_connector_free (conn);
}

Ensure (agent_controller, parse_datetime_parses_valid_datetime)
{
  const char *datetime_str = "2025-04-29T13:06:00.34994Z";
  time_t t = parse_datetime (datetime_str);

  struct tm expected = {0};
  expected.tm_year = 2025 - 1900;
  expected.tm_mon = 3;
  expected.tm_mday = 29;
  expected.tm_hour = 13;
  expected.tm_min = 6;
  expected.tm_sec = 0;

  assert_that (t, is_equal_to (timegm (&expected)));
}

Ensure (agent_controller, parse_datetime_returns_zero_for_invalid_format)
{
  const char *invalid_str = "not-a-datetime";
  time_t t = parse_datetime (invalid_str);
  assert_that (t, is_equal_to ((time_t) 0));
}

Ensure (agent_controller, parse_datetime_handles_missing_fractional_seconds)
{
  const char *missing_fraction = "2025-04-29T13:06:00Z";
  time_t t = parse_datetime (missing_fraction);
  assert_that (t, is_equal_to ((time_t) 0));
}

Ensure (agent_controller, parse_datetime_parses_leap_year_date)
{
  const char *leap_date = "2024-02-29T00:00:00.00000Z";
  time_t t = parse_datetime (leap_date);

  struct tm expected = {0};
  expected.tm_year = 2024 - 1900;
  expected.tm_mon = 1;
  expected.tm_mday = 29;
  expected.tm_hour = 0;
  expected.tm_min = 0;
  expected.tm_sec = 0;

  assert_that (t, is_equal_to (timegm (&expected)));
}

Ensure (agent_controller, parse_datetime_returns_zero_if_null_input)
{
  time_t t = parse_datetime (NULL);
  assert_that (t, is_equal_to ((time_t) 0));
}

Ensure (agent_controller, parse_agent_with_minimal_fields)
{
  const char *json =
    "{"
    "\"agentid\": \"a1\","
    "\"hostname\": \"host1\","
    "\"connection_status\": \"active\","
    "\"authorized\": true,"
    "\"last_update\": \"2025-04-29T13:06:00.34994Z\","
    "\"last_updater_heartbeat\": \"2025-04-29T13:06:00.34994Z\","
    "\"ip_addresses\": [\"192.168.1.1\"]"
    "}";

  cJSON *obj = cJSON_Parse (json);
  agent_controller_agent_t agent = agent_controller_parse_agent (obj);

  assert_that (agent, is_not_null);
  assert_that (agent->agent_id, is_equal_to_string ("a1"));
  assert_that (agent->hostname, is_equal_to_string ("host1"));
  assert_that (agent->connection_status, is_equal_to_string ("active"));
  assert_that (agent->authorized, is_equal_to (1));
  assert_that (agent->ip_address_count, is_equal_to (1));
  assert_that (agent->ip_addresses[0], is_equal_to_string ("192.168.1.1"));
  assert_that (agent->last_update, is_not_equal_to ((time_t) 0));
  assert_that (agent->last_updater_heartbeat, is_not_equal_to ((time_t) 0));

  agent_controller_agent_free (agent);
  cJSON_Delete (obj);
}

Ensure (agent_controller, parse_agent_config_object_printed)
{
  const char *json = "{"
                     "  \"agentid\":\"a1\","
                     "  \"hostname\":\"h1\","
                     "  \"config\": {"
                     "    \"heartbeat\": {\"interval_in_seconds\": 1}"
                     "  }"
                     "}";

  cJSON *root = cJSON_Parse (json);
  assert_that (root, is_not_null);

  agent_controller_agent_t agent = agent_controller_parse_agent (root);
  assert_that (agent, is_not_null);

  /* config is now a struct, not a string */
  assert_that (agent->config, is_not_null);
  assert_that (agent->config->heartbeat.interval_in_seconds, is_equal_to (1));

  agent_controller_agent_free (agent);
  cJSON_Delete (root);
}

Ensure (agent_controller, parse_agent_config_string_stored_directly)
{
  const char *json = "{"
                     "  \"agentid\":\"a2\","
                     "  \"hostname\":\"h2\","
                     "  \"config\":"
                     "    \"{\\\"heartbeat\\\":{\\\"interval_in_seconds\\\":7,"
                     "      \\\"miss_until_inactive\\\":2},"
                     "      \\\"agent_script_executor\\\":{"
                     "        \\\"scheduler_cron_time\\\":[\\\"* * 1 * *\\\"]"
                     "      }"
                     "    }\""
                     "}";

  cJSON *root = cJSON_Parse (json);
  assert_that (root, is_not_null);

  agent_controller_agent_t agent = agent_controller_parse_agent (root);
  assert_that (agent, is_not_null);

  /* heartbeat */
  assert_that (agent->config, is_not_null);
  assert_that (agent->config->heartbeat.interval_in_seconds, is_equal_to (7));
  assert_that (agent->config->heartbeat.miss_until_inactive, is_equal_to (2));

  /* scheduler_cron_time: GPtrArray of gchar* */
  assert_that (agent->config->agent_script_executor.scheduler_cron_time,
               is_not_null);
  GPtrArray *cron = agent->config->agent_script_executor.scheduler_cron_time;
  assert_that ((int) cron->len, is_equal_to (1));

  const gchar *expr0 = g_ptr_array_index (cron, 0);
  assert_that (expr0, is_equal_to_string ("* * 1 * *"));

  agent_controller_agent_free (agent);
  cJSON_Delete (root);
}

Ensure (agent_controller, parse_agent_config_null_defaults_to_empty_object)
{
  const char *json = "{"
                     "  \"agentid\":\"a3\","
                     "  \"hostname\":\"h3\","
                     "  \"config\": null"
                     "}";

  cJSON *root = cJSON_Parse (json);
  assert_that (root, is_not_null);

  agent_controller_agent_t agent = agent_controller_parse_agent (root);
  assert_that (agent, is_not_null);

  assert_that (agent->config, is_null);

  agent_controller_agent_free (agent);
  cJSON_Delete (root);
}

Ensure (agent_controller, parse_agent_missing_optional_fields)
{
  const char *json = "{"
                     "\"agentid\": \"a3\","
                     "\"hostname\": \"host3\""
                     "}";

  cJSON *obj = cJSON_Parse (json);
  agent_controller_agent_t agent = agent_controller_parse_agent (obj);

  assert_that (agent, is_not_null);
  assert_that (agent->authorized, is_equal_to (0));
  assert_that (agent->ip_address_count, is_equal_to (0));
  assert_that (agent->config, is_null);

  agent_controller_agent_free (agent);
  cJSON_Delete (obj);
}

Ensure (agent_controller, parse_agent_returns_null_on_null_input)
{
  agent_controller_agent_t agent = agent_controller_parse_agent (NULL);
  assert_that (agent, is_null);
}

Ensure (agent_controller, build_patch_payload_from_single_agent)
{
  agent_controller_agent_list_t list = agent_controller_agent_list_new (1);
  agent_controller_agent_t agent = agent_controller_agent_new ();

  agent->agent_id = g_strdup ("agent1");
  agent->authorized = 1;

  agent->config = agent_controller_scan_agent_config_new ();

  list->agents[0] = agent;

  gchar *payload = agent_controller_build_patch_payload (list, NULL);

  assert_that (payload, contains_string ("\"agent1\""));
  assert_that (payload, contains_string ("\"authorized\":true"));
  assert_that (agent->config, is_equal_to_string (""));

  g_free (payload);
  agent_controller_agent_list_free (list);
}

Ensure (agent_controller, patch_payload_overrides_only_authorized_field)
{
  agent_controller_agent_list_t list = agent_controller_agent_list_new (1);
  agent_controller_agent_t agent = agent_controller_agent_new ();
  agent->agent_id = g_strdup ("agentA");
  agent->authorized = 0;

  list->agents[0] = agent;

  agent_controller_agent_update_t update = agent_controller_agent_update_new ();
  update->authorized = 1;

  gchar *payload = agent_controller_build_patch_payload (list, update);

  assert_that (payload, contains_string ("\"authorized\":true"));

  g_free (payload);
  agent_controller_agent_update_free (update);
  agent_controller_agent_list_free (list);
}

Ensure (agent_controller, patch_payload_overrides_only_min_interval)
{
  agent_controller_agent_list_t list = agent_controller_agent_list_new (1);
  agent_controller_agent_t agent = agent_controller_agent_new ();
  agent->agent_id = g_strdup ("agentB");
  agent->authorized = 1;

  list->agents[0] = agent;

  agent_controller_agent_update_t update = agent_controller_agent_update_new ();

  gchar *payload = agent_controller_build_patch_payload (list, update);

  assert_that (payload, contains_string ("\"authorized\":true"));

  g_free (payload);
  agent_controller_agent_update_free (update);
  agent_controller_agent_list_free (list);
}

Ensure (agent_controller, patch_payload_overrides_only_config)
{
  agent_controller_agent_list_t list = agent_controller_agent_list_new (1);
  agent_controller_agent_t agent = agent_controller_agent_new ();
  assert_that (list, is_not_null);
  assert_that (agent, is_not_null);

  agent->agent_id = g_strdup ("agentC");
  agent->authorized = 0;

  agent->config = agent_controller_scan_agent_config_new ();
  assert_that (agent->config, is_not_null);
  agent->config->heartbeat.interval_in_seconds = 99; /* old */

  list->agents[0] = agent;

  agent_controller_agent_update_t update = agent_controller_agent_update_new ();
  assert_that (update, is_not_null);
  update->authorized = -1;

  /* Provide a fully valid config */
  update->config = agent_controller_scan_agent_config_new ();
  assert_that (update->config, is_not_null);

  /* agent_control.retry > 0 */
  update->config->agent_control.retry.attempts = 1;
  update->config->agent_control.retry.delay_in_seconds = 1;
  update->config->agent_control.retry.max_jitter_in_seconds = 1;

  /* agent_script_executor > 0 and cron present */
  update->config->agent_script_executor.bulk_size = 1;
  update->config->agent_script_executor.bulk_throttle_time_in_ms = 1;
  update->config->agent_script_executor.indexer_dir_depth = 1;
  update->config->agent_script_executor.scheduler_cron_time =
    g_ptr_array_new_with_free_func (g_free);
  g_ptr_array_add (update->config->agent_script_executor.scheduler_cron_time,
                   g_strdup ("* * * * *"));

  /* heartbeat > 0 with the override value */
  update->config->heartbeat.interval_in_seconds = 42; /* override */
  update->config->heartbeat.miss_until_inactive = 1;

  gchar *payload = agent_controller_build_patch_payload (list, update);

  /* Assert */
  assert_that (payload, is_not_null);
  assert_that (payload, contains_string ("\"config\""));
  assert_that (payload, contains_string ("\"interval_in_seconds\":42"));
  assert_that (payload, does_not_contain_string ("\"interval_in_seconds\":99"));

  /* Cleanup */
  cJSON_free (payload);
  agent_controller_agent_update_free (update);
  agent_controller_agent_list_free (list);
}

Ensure (agent_controller, scan_agent_config_new_initializes_defaults)
{
  agent_controller_scan_agent_config_t cfg =
    agent_controller_scan_agent_config_new ();
  assert_that (cfg, is_not_null);

  /* agent_control.retry defaults */
  assert_that (cfg->agent_control.retry.attempts, is_equal_to (0));
  assert_that (cfg->agent_control.retry.delay_in_seconds, is_equal_to (0));
  assert_that (cfg->agent_control.retry.max_jitter_in_seconds, is_equal_to (0));

  /* agent_script_executor defaults */
  assert_that (cfg->agent_script_executor.bulk_size, is_equal_to (0));
  assert_that (cfg->agent_script_executor.bulk_throttle_time_in_ms,
               is_equal_to (0));
  assert_that (cfg->agent_script_executor.indexer_dir_depth, is_equal_to (0));
  assert_that (cfg->agent_script_executor.scheduler_cron_time, is_null);

  /* heartbeat defaults */
  assert_that (cfg->heartbeat.interval_in_seconds, is_equal_to (0));
  assert_that (cfg->heartbeat.miss_until_inactive, is_equal_to (0));

  agent_controller_scan_agent_config_free (cfg);
}

Ensure (agent_controller, scan_agent_config_free_handles_null)
{
  /* Should be a no-op (no crash) */
  agent_controller_scan_agent_config_free (NULL);
  assert_that (true, is_true);
}

Ensure (agent_controller, scan_agent_config_free_frees_cron_array_safely)
{
  agent_controller_scan_agent_config_t cfg =
    agent_controller_scan_agent_config_new ();
  assert_that (cfg, is_not_null);

  cfg->agent_script_executor.scheduler_cron_time =
    g_ptr_array_new_with_free_func (g_free);
  g_ptr_array_add (cfg->agent_script_executor.scheduler_cron_time,
                   g_strdup ("0 23 * * *"));
  g_ptr_array_add (cfg->agent_script_executor.scheduler_cron_time,
                   g_strdup ("*/5 * * * *"));
  g_ptr_array_add (cfg->agent_script_executor.scheduler_cron_time,
                   g_strdup ("15 2 * * 1"));

  cfg->agent_control.retry.attempts = 5;
  cfg->heartbeat.interval_in_seconds = 600;

  agent_controller_scan_agent_config_free (cfg);

  assert_that (true, is_true);
}

Ensure (agent_controller, scan_agent_config_new_then_immediate_free)
{
  agent_controller_scan_agent_config_t cfg =
    agent_controller_scan_agent_config_new ();
  assert_that (cfg, is_not_null);
  agent_controller_scan_agent_config_free (cfg);
  assert_that (true, is_true);
}

Ensure (agent_controller, build_scan_agent_config_payload_defaults)
{
  agent_controller_scan_agent_config_t cfg =
    agent_controller_scan_agent_config_new ();
  assert_that (cfg, is_not_null);

  gchar *payload = agent_controller_convert_scan_agent_config_string (cfg);
  assert_that (payload, is_not_null);

  cJSON_free (payload);
  agent_controller_scan_agent_config_free (cfg);
}

Ensure (agent_controller, build_scan_agent_config_payload_with_values)
{
  agent_controller_scan_agent_config_t cfg =
    agent_controller_scan_agent_config_new ();
  assert_that (cfg, is_not_null);

  cfg->agent_control.retry.attempts = 5;
  cfg->agent_control.retry.delay_in_seconds = 60;
  cfg->agent_control.retry.max_jitter_in_seconds = 10;

  cfg->agent_script_executor.bulk_size = 2;
  cfg->agent_script_executor.bulk_throttle_time_in_ms = 100;
  cfg->agent_script_executor.indexer_dir_depth = 10;

  /* GPtrArray-based cron list */
  cfg->agent_script_executor.scheduler_cron_time =
    g_ptr_array_new_with_free_func (g_free);
  g_ptr_array_add (cfg->agent_script_executor.scheduler_cron_time,
                   g_strdup ("0 23 * * *"));
  g_ptr_array_add (cfg->agent_script_executor.scheduler_cron_time,
                   g_strdup ("*/5 * * * *"));

  cfg->heartbeat.interval_in_seconds = 600;
  cfg->heartbeat.miss_until_inactive = 1;

  gchar *payload = agent_controller_convert_scan_agent_config_string (cfg);
  assert_that (payload, is_not_null);

  /* retry */
  assert_that (payload, contains_string ("\"attempts\":5"));
  assert_that (payload, contains_string ("\"delay_in_seconds\":60"));
  assert_that (payload, contains_string ("\"max_jitter_in_seconds\":10"));

  /* exec */
  assert_that (payload, contains_string ("\"bulk_size\":2"));
  assert_that (payload, contains_string ("\"bulk_throttle_time_in_ms\":100"));
  assert_that (payload, contains_string ("\"indexer_dir_depth\":10"));

  assert_that (payload, contains_string ("\"scheduler_cron_time\":["));
  assert_that (payload, contains_string ("\"0 23 * * *\""));
  assert_that (payload, contains_string ("\"*/5 * * * *\""));

  /* heartbeat */
  assert_that (payload, contains_string ("\"interval_in_seconds\":600"));
  assert_that (payload, contains_string ("\"miss_until_inactive\":1"));

  cJSON_free (payload);
  agent_controller_scan_agent_config_free (cfg);
}

Ensure (agent_controller, parse_scan_agent_config_full)
{
  const char *json =
    "{"
    "  \"agent_control\": {"
    "    \"retry\": {"
    "      \"attempts\":5,\"delay_in_seconds\":60,\"max_jitter_in_seconds\":10"
    "    }"
    "  },"
    "  \"agent_script_executor\": {"
    "    \"bulk_size\":2,"
    "    \"bulk_throttle_time_in_ms\":100,"
    "    \"indexer_dir_depth\":10,"
    "    \"period_in_seconds\":60,"
    "    \"scheduler_cron_time\":[\"0 23 * * *\",\"*/5 * * * *\"]"
    "  },"
    "  \"heartbeat\": {\"interval_in_seconds\":600,\"miss_until_inactive\":1}"
    "}";

  cJSON *root = cJSON_Parse (json);
  assert_that (root, is_not_null);

  agent_controller_scan_agent_config_t cfg =
    agent_controller_parse_scan_agent_config (root);
  assert_that (cfg, is_not_null);

  /* retry */
  assert_that (cfg->agent_control.retry.attempts, is_equal_to (5));
  assert_that (cfg->agent_control.retry.delay_in_seconds, is_equal_to (60));
  assert_that (cfg->agent_control.retry.max_jitter_in_seconds,
               is_equal_to (10));

  /* exec */
  assert_that (cfg->agent_script_executor.bulk_size, is_equal_to (2));
  assert_that (cfg->agent_script_executor.bulk_throttle_time_in_ms,
               is_equal_to (100));
  assert_that (cfg->agent_script_executor.indexer_dir_depth, is_equal_to (10));

  assert_that (cfg->agent_script_executor.scheduler_cron_time, is_not_null);
  GPtrArray *cron = cfg->agent_script_executor.scheduler_cron_time;
  assert_that ((int) cron->len, is_equal_to (2));
  assert_that ((const gchar *) g_ptr_array_index (cron, 0),
               is_equal_to_string ("0 23 * * *"));
  assert_that ((const gchar *) g_ptr_array_index (cron, 1),
               is_equal_to_string ("*/5 * * * *"));

  /* heartbeat */
  assert_that (cfg->heartbeat.interval_in_seconds, is_equal_to (600));
  assert_that (cfg->heartbeat.miss_until_inactive, is_equal_to (1));

  agent_controller_scan_agent_config_free (cfg);
  cJSON_Delete (root);
}

Ensure (agent_controller, parse_scan_agent_config_missing_blocks)
{
  const char *json = "{}";

  cJSON *root = cJSON_Parse (json);
  assert_that (root, is_not_null);

  agent_controller_scan_agent_config_t cfg =
    agent_controller_parse_scan_agent_config (root);
  assert_that (cfg, is_not_null);

  /* All numeric fields default to 0 */
  assert_that (cfg->agent_control.retry.attempts, is_equal_to (0));
  assert_that (cfg->agent_control.retry.delay_in_seconds, is_equal_to (0));
  assert_that (cfg->agent_control.retry.max_jitter_in_seconds, is_equal_to (0));

  assert_that (cfg->agent_script_executor.bulk_size, is_equal_to (0));
  assert_that (cfg->agent_script_executor.bulk_throttle_time_in_ms,
               is_equal_to (0));
  assert_that (cfg->agent_script_executor.indexer_dir_depth, is_equal_to (0));

  assert_that (cfg->agent_script_executor.scheduler_cron_time, is_null);

  assert_that (cfg->heartbeat.interval_in_seconds, is_equal_to (0));
  assert_that (cfg->heartbeat.miss_until_inactive, is_equal_to (0));

  agent_controller_scan_agent_config_free (cfg);
  cJSON_Delete (root);
}

Ensure (agent_controller, scan_agent_config_roundtrip_build_then_parse)
{
  agent_controller_scan_agent_config_t cfg =
    agent_controller_scan_agent_config_new ();
  assert_that (cfg, is_not_null);

  cfg->agent_control.retry.attempts = 3;
  cfg->agent_control.retry.delay_in_seconds = 7;
  cfg->agent_control.retry.max_jitter_in_seconds = 9;

  cfg->agent_script_executor.bulk_size = 4;
  cfg->agent_script_executor.bulk_throttle_time_in_ms = 250;
  cfg->agent_script_executor.indexer_dir_depth = 2;

  cfg->agent_script_executor.scheduler_cron_time =
    g_ptr_array_new_with_free_func (g_free);
  g_ptr_array_add (cfg->agent_script_executor.scheduler_cron_time,
                   g_strdup ("15 2 * * 1"));

  cfg->heartbeat.interval_in_seconds = 30;
  cfg->heartbeat.miss_until_inactive = 3;

  gchar *payload = agent_controller_convert_scan_agent_config_string (cfg);
  assert_that (payload, is_not_null);

  cJSON *root = cJSON_Parse (payload);
  assert_that (root, is_not_null);

  agent_controller_scan_agent_config_t parsed =
    agent_controller_parse_scan_agent_config (root);
  assert_that (parsed, is_not_null);

  assert_that (parsed->agent_control.retry.attempts, is_equal_to (3));
  assert_that (parsed->agent_control.retry.delay_in_seconds, is_equal_to (7));
  assert_that (parsed->agent_control.retry.max_jitter_in_seconds,
               is_equal_to (9));

  assert_that (parsed->agent_script_executor.bulk_size, is_equal_to (4));
  assert_that (parsed->agent_script_executor.bulk_throttle_time_in_ms,
               is_equal_to (250));
  assert_that (parsed->agent_script_executor.indexer_dir_depth,
               is_equal_to (2));

  assert_that (parsed->agent_script_executor.scheduler_cron_time, is_not_null);
  GPtrArray *cron = parsed->agent_script_executor.scheduler_cron_time;
  assert_that ((int) cron->len, is_equal_to (1));
  assert_that ((const gchar *) g_ptr_array_index (cron, 0),
               is_equal_to_string ("15 2 * * 1"));

  assert_that (parsed->heartbeat.interval_in_seconds, is_equal_to (30));
  assert_that (parsed->heartbeat.miss_until_inactive, is_equal_to (3));

  /* Cleanup */
  cJSON_free (payload);
  agent_controller_scan_agent_config_free (cfg);
  agent_controller_scan_agent_config_free (parsed);
  cJSON_Delete (root);
}

Ensure (agent_controller, json_has_update_returns_false_on_null)
{
  assert_that (agent_controller_json_has_update_available (NULL), is_false);
}

Ensure (agent_controller, json_has_update_returns_false_on_non_object)
{
  cJSON *arr = cJSON_CreateArray ();
  assert_that (agent_controller_json_has_update_available (arr), is_false);
  cJSON_Delete (arr);
}

Ensure (agent_controller, json_has_update_returns_false_when_keys_missing)
{
  cJSON *obj = cJSON_CreateObject ();
  cJSON_AddStringToObject (obj, "agentid", "A1");
  assert_that (agent_controller_json_has_update_available (obj), is_false);
  cJSON_Delete (obj);
}

Ensure (agent_controller, json_has_update_true_when_agent_update_available_true)
{
  cJSON *obj = cJSON_CreateObject ();
  cJSON_AddBoolToObject (obj, "agent_update_available", 1);
  cJSON_AddBoolToObject (obj, "updater_update_available", 0);
  assert_that (agent_controller_json_has_update_available (obj), is_true);
  cJSON_Delete (obj);
}

Ensure (agent_controller,
        json_has_update_true_when_updater_update_available_true)
{
  cJSON *obj = cJSON_CreateObject ();
  cJSON_AddBoolToObject (obj, "agent_update_available", 0);
  cJSON_AddBoolToObject (obj, "updater_update_available", 1);
  assert_that (agent_controller_json_has_update_available (obj), is_true);
  cJSON_Delete (obj);
}

Ensure (agent_controller, json_has_update_true_when_both_true)
{
  cJSON *obj = cJSON_CreateObject ();
  cJSON_AddBoolToObject (obj, "agent_update_available", 1);
  cJSON_AddBoolToObject (obj, "updater_update_available", 1);
  assert_that (agent_controller_json_has_update_available (obj), is_true);
  cJSON_Delete (obj);
}

Ensure (agent_controller, json_has_update_ignores_non_boolean_values)
{
  /* strings "true"/"false" should be ignored (treated as FALSE) */
  const char *json = "{"
                     "  \"agent_update_available\":\"true\","
                     "  \"updater_update_available\":\"false\""
                     "}";
  cJSON *obj = cJSON_Parse (json);
  assert_that (obj, is_not_null);
  assert_that (agent_controller_json_has_update_available (obj), is_false);
  cJSON_Delete (obj);
}

Ensure (agent_controller, json_has_update_ignores_numbers)
{
  /* numbers should be ignored (treated as FALSE) */
  const char *json = "{"
                     "  \"agent_update_available\":1,"
                     "  \"updater_update_available\":0"
                     "}";
  cJSON *obj = cJSON_Parse (json);
  assert_that (obj, is_not_null);
  assert_that (agent_controller_json_has_update_available (obj), is_false);
  cJSON_Delete (obj);
}

Ensure (agent_controller, get_agents_returns_list_on_successful_response)
{
  mock_response_data = "[{"
                       "\"agentid\": \"agent1\","
                       "\"hostname\": \"host-a\","
                       "\"authorized\": true,"
                       "\"min_interval\": 5,"
                       "\"heartbeat_interval\": 10,"
                       "\"connection_status\": \"online\""
                       "}]";
  mock_http_status = 200;

  agent_controller_connector_t conn = make_conn ();

  agent_controller_agent_list_t list = agent_controller_get_agents (conn);

  assert_that (list, is_not_null);
  assert_that (list->count, is_equal_to (1));
  assert_that (list->agents[0], is_not_null);
  assert_that (list->agents[0]->agent_id, is_equal_to_string ("agent1"));

  agent_controller_agent_list_free (list);
  agent_controller_connector_free (conn);
}

Ensure (agent_controller,
        get_agents_returns_list_on_successful_response_with_extended_fields)
{
  mock_response_data = "[{"
                       "\"agentid\":\"agent1\","
                       "\"hostname\":\"host-a\","
                       "\"authorized\":true,"
                       "\"connection_status\":\"active\","
                       "\"updater_version\":\"1.2.3\","
                       "\"agent_version\":\"0.9.0\","
                       "\"operating_system\":\"Linux\","
                       "\"architecture\":\"amd64\","
                       "\"update_to_latest\":true"
                       "}]";
  mock_http_status = 200;

  agent_controller_connector_t conn = make_conn ();

  agent_controller_agent_list_t list = agent_controller_get_agents (conn);

  assert_that (list, is_not_null);
  assert_that (list->count, is_equal_to (1));
  assert_that (list->agents[0], is_not_null);

  /* existing fields */
  assert_that (list->agents[0]->agent_id, is_equal_to_string ("agent1"));
  assert_that (list->agents[0]->hostname, is_equal_to_string ("host-a"));
  assert_that (list->agents[0]->authorized, is_equal_to (1));
  assert_that (list->agents[0]->connection_status,
               is_equal_to_string ("active"));

  /* new extended fields */
  assert_that (list->agents[0]->updater_version, is_equal_to_string ("1.2.3"));
  assert_that (list->agents[0]->agent_version, is_equal_to_string ("0.9.0"));
  assert_that (list->agents[0]->operating_system, is_equal_to_string ("Linux"));
  assert_that (list->agents[0]->architecture, is_equal_to_string ("amd64"));
  assert_that (list->agents[0]->update_to_latest, is_equal_to (1));

  agent_controller_agent_list_free (list);
  agent_controller_connector_free (conn);
}

Ensure (agent_controller, get_agents_returns_null_on_non_200_status)
{
  mock_http_status = 403;
  mock_response_data = "[{\"agentid\": \"a\"}]";

  agent_controller_connector_t conn = make_conn ();

  agent_controller_agent_list_t list = agent_controller_get_agents (conn);
  assert_that (list, is_null);

  agent_controller_connector_free (conn);
}

Ensure (agent_controller, get_agents_returns_null_on_invalid_json)
{
  mock_http_status = 200;
  mock_response_data = "not-a-json-array";

  agent_controller_connector_t conn = make_conn ();

  agent_controller_agent_list_t list = agent_controller_get_agents (conn);
  assert_that (list, is_null);

  agent_controller_connector_free (conn);
}

Ensure (agent_controller, update_agents_returns_zero_on_success)
{
  mock_http_status = 200;
  g_clear_pointer (&mock_response_data, g_free);
  mock_response_data = g_strdup ("");

  agent_controller_connector_t conn = make_conn ();

  agent_controller_agent_list_t list = agent_controller_agent_list_new (1);
  agent_controller_agent_t agent = agent_controller_agent_new ();
  agent->agent_id = g_strdup ("agent1");
  list->agents[0] = agent;

  agent_controller_agent_update_t update = agent_controller_agent_update_new ();

  int result = agent_controller_update_agents (conn, list, update, NULL);
  assert_that (result, is_equal_to (0));

  agent_controller_agent_list_free (list);
  agent_controller_agent_update_free (update);
  agent_controller_connector_free (conn);
}

Ensure (agent_controller, update_agents_fails_with_null_connection)
{
  agent_controller_agent_list_t list = agent_controller_agent_list_new (1);
  list->agents[0] = agent_controller_agent_new ();
  list->agents[0]->agent_id = g_strdup ("agent");

  agent_controller_agent_update_t update = agent_controller_agent_update_new ();
  update->authorized = 1;

  int result = agent_controller_update_agents (NULL, list, update, NULL);
  assert_that (result, is_equal_to (-1));

  agent_controller_agent_list_free (list);
  agent_controller_agent_update_free (update);
}

Ensure (agent_controller, update_agents_fails_with_null_agents)
{
  agent_controller_connector_t conn = agent_controller_connector_new ();
  agent_controller_agent_update_t update = agent_controller_agent_update_new ();

  int result = agent_controller_update_agents (conn, NULL, update, NULL);
  assert_that (result, is_equal_to (-1));

  agent_controller_agent_update_free (update);
  agent_controller_connector_free (conn);
}

Ensure (agent_controller, update_agents_fails_with_null_update)
{
  agent_controller_connector_t conn = agent_controller_connector_new ();
  agent_controller_agent_list_t list = agent_controller_agent_list_new (1);
  list->agents[0] = agent_controller_agent_new ();
  list->agents[0]->agent_id = g_strdup ("agent");

  int result = agent_controller_update_agents (conn, list, NULL, NULL);
  assert_that (result, is_equal_to (-1));

  agent_controller_agent_list_free (list);
  agent_controller_connector_free (conn);
}

Ensure (agent_controller, update_agents_fails_on_http_error_status)
{
  mock_http_status = 400;
  mock_response_data = g_strdup ("{}");

  agent_controller_connector_t conn = make_conn ();

  agent_controller_agent_list_t list = agent_controller_agent_list_new (1);
  list->agents[0] = agent_controller_agent_new ();
  list->agents[0]->agent_id = g_strdup ("agent");

  agent_controller_agent_update_t update = agent_controller_agent_update_new ();
  update->authorized = 1;

  int result = agent_controller_update_agents (conn, list, update, NULL);
  assert_that (result, is_equal_to (-1));

  agent_controller_agent_list_free (list);
  agent_controller_agent_update_free (update);
  agent_controller_connector_free (conn);
}

Ensure (agent_controller, update_agents_400_populates_errors_from_json)
{
  mock_http_status = 400;
  mock_response_data =
    g_strdup ("{ \"errors\": [\"e1\", \"e2\"], \"warnings\": null }");

  agent_controller_connector_t conn = make_conn ();

  agent_controller_agent_list_t list = agent_controller_agent_list_new (1);
  list->agents[0] = agent_controller_agent_new ();
  list->agents[0]->agent_id = g_strdup ("agent1");

  agent_controller_agent_update_t update = agent_controller_agent_update_new ();
  update->authorized = 1;

  GPtrArray *errs = NULL;
  int rc = agent_controller_update_agents (conn, list, update, &errs);

  assert_that (rc, is_equal_to (-1));
  assert_that (errs, is_not_null);
  assert_that ((int) errs->len, is_equal_to (2));
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               is_equal_to_string ("e1"));
  assert_that ((const gchar *) g_ptr_array_index (errs, 1),
               is_equal_to_string ("e2"));
  assert_that (last_sent_url, contains_string ("/api/v1/admin/agents"));

  g_ptr_array_free (errs, TRUE);
  agent_controller_agent_list_free (list);
  agent_controller_agent_update_free (update);
  agent_controller_connector_free (conn);
}

Ensure (agent_controller, update_agents_400_invalid_json_adds_invalid_payload)
{
  mock_http_status = 400;
  mock_response_data = g_strdup ("not-json");

  agent_controller_connector_t conn = make_conn ();

  agent_controller_agent_list_t list = agent_controller_agent_list_new (1);
  list->agents[0] = agent_controller_agent_new ();
  list->agents[0]->agent_id = g_strdup ("agent1");

  agent_controller_agent_update_t update = agent_controller_agent_update_new ();

  GPtrArray *errs = NULL;
  int rc = agent_controller_update_agents (conn, list, update, &errs);

  assert_that (rc, is_equal_to (-1));
  assert_that (errs, is_not_null);
  assert_that ((int) errs->len, is_equal_to (1));
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               contains_string ("invalid JSON payload"));

  g_ptr_array_free (errs, TRUE);
  agent_controller_agent_list_free (list);
  agent_controller_agent_update_free (update);
  agent_controller_connector_free (conn);
}

Ensure (agent_controller, update_agents_500_does_not_allocate_errors)
{
  mock_http_status = 500;
  mock_response_data = g_strdup ("{}");

  agent_controller_connector_t conn = make_conn ();

  agent_controller_agent_list_t list = agent_controller_agent_list_new (1);
  list->agents[0] = agent_controller_agent_new ();
  list->agents[0]->agent_id = g_strdup ("agent1");

  agent_controller_agent_update_t update = agent_controller_agent_update_new ();

  GPtrArray *errs = NULL;
  int rc = agent_controller_update_agents (conn, list, update, &errs);

  assert_that (rc, is_equal_to (-1));
  assert_that (errs, is_null);

  agent_controller_agent_list_free (list);
  agent_controller_agent_update_free (update);
  agent_controller_connector_free (conn);
}

Ensure (agent_controller, update_agents_no_response_returns_error)
{
  mock_http_status = 500;
  g_clear_pointer (&mock_response_data, g_free);

  agent_controller_connector_t conn = make_conn ();

  agent_controller_agent_list_t list = agent_controller_agent_list_new (1);
  list->agents[0] = agent_controller_agent_new ();
  list->agents[0]->agent_id = g_strdup ("agent1");

  agent_controller_agent_update_t update = agent_controller_agent_update_new ();

  int rc = agent_controller_update_agents (conn, list, update, NULL);
  assert_that (rc, is_equal_to (-1));

  agent_controller_agent_list_free (list);
  agent_controller_agent_update_free (update);
  agent_controller_connector_free (conn);
}

Ensure (agent_controller, delete_agents_returns_zero_on_success)
{
  mock_http_status = 200;
  g_clear_pointer (&mock_response_data, g_free);
  mock_response_data = g_strdup ("");

  agent_controller_connector_t conn = agent_controller_connector_new ();
  conn->protocol = g_strdup ("https");
  conn->host = g_strdup ("localhost");
  conn->port = 8080;
  conn->apikey = g_strdup ("key");

  agent_controller_agent_list_t list = agent_controller_agent_list_new (2);
  agent_controller_agent_t agent1 = agent_controller_agent_new ();
  agent1->agent_id = g_strdup ("agent-1");
  list->agents[0] = agent1;

  agent_controller_agent_t agent2 = agent_controller_agent_new ();
  agent2->agent_id = g_strdup ("agent-2");
  list->agents[1] = agent2;

  int result = agent_controller_delete_agents (conn, list);
  assert_that (result, is_equal_to (0));

  agent_controller_agent_list_free (list);
  agent_controller_connector_free (conn);
}

Ensure (agent_controller, delete_agents_fails_with_null_conn)
{
  agent_controller_agent_list_t list = agent_controller_agent_list_new (1);
  list->agents[0] = agent_controller_agent_new ();
  list->agents[0]->agent_id = g_strdup ("agent");

  int result = agent_controller_delete_agents (NULL, list);
  assert_that (result, is_equal_to (-1));

  agent_controller_agent_list_free (list);
}

Ensure (agent_controller, delete_agents_fails_with_null_list)
{
  agent_controller_connector_t conn = agent_controller_connector_new ();
  int result = agent_controller_delete_agents (conn, NULL);
  assert_that (result, is_equal_to (-1));
  agent_controller_connector_free (conn);
}

Ensure (agent_controller, delete_agents_fails_if_no_valid_ids)
{
  agent_controller_connector_t conn = agent_controller_connector_new ();
  agent_controller_agent_list_t list = agent_controller_agent_list_new (2);
  list->agents[0] = agent_controller_agent_new ();
  list->agents[1] = agent_controller_agent_new ();

  int result = agent_controller_delete_agents (conn, list);
  assert_that (result, is_equal_to (-1));

  agent_controller_agent_list_free (list);
  agent_controller_connector_free (conn);
}

Ensure (agent_controller, delete_agents_fails_on_http_422)
{
  mock_http_status = 422;
  g_clear_pointer (&mock_response_data, g_free);
  mock_response_data = g_strdup ("{}");

  agent_controller_connector_t conn = agent_controller_connector_new ();
  conn->protocol = g_strdup ("https");
  conn->host = g_strdup ("localhost");
  conn->port = 8080;
  conn->apikey = g_strdup ("token");

  agent_controller_agent_list_t list = agent_controller_agent_list_new (1);
  list->agents[0] = agent_controller_agent_new ();
  list->agents[0]->agent_id = g_strdup ("agent");

  int result = agent_controller_delete_agents (conn, list);
  assert_that (result, is_equal_to (-1));

  agent_controller_agent_list_free (list);
  agent_controller_connector_free (conn);
}

Ensure (agent_controller, get_scan_agent_config_null_conn_returns_null)
{
  agent_controller_scan_agent_config_t cfg =
    agent_controller_get_scan_agent_config (NULL);

  assert_that (cfg, is_null);
  assert_that (last_sent_url, is_null);
}

Ensure (agent_controller, get_scan_agent_config_no_response_returns_null)
{
  agent_controller_connector_t conn = make_conn ();

  mock_http_status = 500;

  agent_controller_scan_agent_config_t cfg =
    agent_controller_get_scan_agent_config (conn);

  assert_that (cfg, is_null);
  assert_that (last_sent_url,
               contains_string ("/api/v1/admin/scan-agent-config"));

  agent_controller_connector_free (conn);
}

Ensure (agent_controller, get_scan_agent_config_non2xx_with_body_returns_null)
{
  agent_controller_connector_t conn = make_conn ();

  mock_http_status = 500;
  mock_response_data = g_strdup ("{}");

  agent_controller_scan_agent_config_t cfg =
    agent_controller_get_scan_agent_config (conn);

  assert_that (cfg, is_null);

  agent_controller_connector_free (conn);
}

Ensure (agent_controller, get_scan_agent_config_invalid_json_returns_null)
{
  agent_controller_connector_t conn = make_conn ();

  mock_http_status = 200;
  mock_response_data = g_strdup ("not-json");

  agent_controller_scan_agent_config_t cfg =
    agent_controller_get_scan_agent_config (conn);

  assert_that (cfg, is_null);

  agent_controller_connector_free (conn);
}

Ensure (agent_controller, get_scan_agent_config_success_parses_values)
{
  agent_controller_connector_t conn = make_conn ();

  mock_http_status = 200;
  mock_response_data = g_strdup (
    "{"
    "  \"agent_control\": {\"retry\": "
    "{\"attempts\":5,\"delay_in_seconds\":60,\"max_jitter_in_seconds\":10}},"
    "  \"agent_script_executor\": {"
    "    \"bulk_size\":2,"
    "    \"bulk_throttle_time_in_ms\":100,"
    "    \"indexer_dir_depth\":10,"
    "    \"period_in_seconds\":60,"
    "    \"scheduler_cron_time\":[\"0 23 * * *\",\"*/5 * * * *\"]"
    "  },"
    "  \"heartbeat\": {\"interval_in_seconds\":600,\"miss_until_inactive\":1}"
    "}");

  agent_controller_scan_agent_config_t cfg =
    agent_controller_get_scan_agent_config (conn);

  assert_that (cfg, is_not_null);

  assert_that (cfg->agent_control.retry.attempts, is_equal_to (5));
  assert_that (cfg->agent_script_executor.bulk_size, is_equal_to (2));

  assert_that (cfg->agent_script_executor.scheduler_cron_time, is_not_null);
  GPtrArray *cron = cfg->agent_script_executor.scheduler_cron_time;
  assert_that ((int) cron->len, is_equal_to (2));
  assert_that ((const gchar *) g_ptr_array_index (cron, 0),
               is_equal_to_string ("0 23 * * *"));
  assert_that ((const gchar *) g_ptr_array_index (cron, 1),
               is_equal_to_string ("*/5 * * * *"));

  assert_that (cfg->heartbeat.interval_in_seconds, is_equal_to (600));

  agent_controller_scan_agent_config_free (cfg);
  agent_controller_connector_free (conn);
}

Ensure (agent_controller, update_scan_agent_config_null_args_return_error)
{
  assert_that (agent_controller_update_scan_agent_config (NULL, NULL, NULL),
               is_equal_to (-1));

  agent_controller_connector_t conn = make_conn ();
  assert_that (agent_controller_update_scan_agent_config (conn, NULL, NULL),
               is_equal_to (-1));
  agent_controller_connector_free (conn);

  agent_controller_scan_agent_config_t cfg =
    agent_controller_scan_agent_config_new ();
  assert_that (agent_controller_update_scan_agent_config (NULL, cfg, NULL),
               is_equal_to (-1));
  agent_controller_scan_agent_config_free (cfg);
}

Ensure (agent_controller, update_scan_agent_config_no_response_return_error)
{
  agent_controller_connector_t conn = make_conn ();
  agent_controller_scan_agent_config_t cfg =
    agent_controller_scan_agent_config_new ();

  /* Provide a fully valid config */
  assert_that (cfg, is_not_null);

  /* agent_control.retry > 0 */
  cfg->agent_control.retry.attempts = 1;
  cfg->agent_control.retry.delay_in_seconds = 1;
  cfg->agent_control.retry.max_jitter_in_seconds = 1;

  /* agent_script_executor > 0 and cron present */
  cfg->agent_script_executor.bulk_size = 1;
  cfg->agent_script_executor.bulk_throttle_time_in_ms = 1;
  cfg->agent_script_executor.indexer_dir_depth = 1;
  cfg->agent_script_executor.scheduler_cron_time =
    g_ptr_array_new_with_free_func (g_free);
  g_ptr_array_add (cfg->agent_script_executor.scheduler_cron_time,
                   g_strdup ("* * * * *"));

  /* heartbeat > 0 with the override value */
  cfg->heartbeat.interval_in_seconds = 42; /* override */
  cfg->heartbeat.miss_until_inactive = 1;

  mock_http_status = 500;

  int rc = agent_controller_update_scan_agent_config (conn, cfg, NULL);
  assert_that (rc, is_equal_to (-1));

  assert_that (last_sent_url,
               contains_string ("/api/v1/admin/scan-agent-config"));
  assert_that (last_sent_payload, contains_string ("\"agent_control\""));
  assert_that (last_sent_payload, contains_string ("\"heartbeat\""));

  agent_controller_scan_agent_config_free (cfg);
  agent_controller_connector_free (conn);
}

Ensure (agent_controller,
        update_scan_agent_config_non2xx_with_body_return_error)
{
  agent_controller_connector_t conn = make_conn ();
  agent_controller_scan_agent_config_t cfg =
    agent_controller_scan_agent_config_new ();

  mock_http_status = 400;
  mock_response_data = g_strdup ("{}");

  int rc = agent_controller_update_scan_agent_config (conn, cfg, NULL);
  assert_that (rc, is_equal_to (-1));

  agent_controller_scan_agent_config_free (cfg);
  agent_controller_connector_free (conn);
}

Ensure (agent_controller,
        update_scan_agent_config_success_returns_ok_and_sends_payload)
{
  agent_controller_connector_t conn = make_conn ();
  agent_controller_scan_agent_config_t cfg =
    agent_controller_scan_agent_config_new ();

  /* populate values */
  cfg->agent_control.retry.attempts = 5;
  cfg->agent_control.retry.delay_in_seconds = 60;
  cfg->agent_control.retry.max_jitter_in_seconds = 10;

  cfg->agent_script_executor.bulk_size = 2;
  cfg->agent_script_executor.bulk_throttle_time_in_ms = 100;
  cfg->agent_script_executor.indexer_dir_depth = 10;

  cfg->agent_script_executor.scheduler_cron_time =
    g_ptr_array_new_with_free_func (g_free);
  g_ptr_array_add (cfg->agent_script_executor.scheduler_cron_time,
                   g_strdup ("0 23 * * *"));

  cfg->heartbeat.interval_in_seconds = 600;
  cfg->heartbeat.miss_until_inactive = 1;

  mock_http_status = 200;
  mock_response_data = g_strdup ("{}");

  int rc = agent_controller_update_scan_agent_config (conn, cfg, NULL);
  assert_that (rc, is_equal_to (0));

  assert_that (last_sent_url, is_not_null);
  assert_that (last_sent_url,
               contains_string ("/api/v1/admin/scan-agent-config"));
  assert_that (last_sent_payload, contains_string ("\"retry\""));
  assert_that (last_sent_payload,
               contains_string ("\"scheduler_cron_time\":[\"0 23 * * *\"]"));
  assert_that (last_sent_payload,
               contains_string ("\"miss_until_inactive\":1"));

  agent_controller_scan_agent_config_free (cfg);
  agent_controller_connector_free (conn);
}

Ensure (agent_controller,
        update_scan_agent_config_400_populates_errors_from_json)
{
  mock_http_status = 400;
  mock_response_data =
    g_strdup ("{ \"errors\": [\"e1\", \"e2\"], \"warnings\": null }");

  agent_controller_connector_t conn = make_conn ();
  agent_controller_scan_agent_config_t cfg = make_scan_agent_config ();

  GPtrArray *errs = NULL;
  int rc = agent_controller_update_scan_agent_config (conn, cfg, &errs);

  assert_that (rc, is_equal_to (-1));
  assert_that (errs, is_not_null);
  assert_that ((int) errs->len, is_equal_to (2));
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               is_equal_to_string ("e1"));
  assert_that ((const gchar *) g_ptr_array_index (errs, 1),
               is_equal_to_string ("e2"));
  assert_that (last_sent_url,
               contains_string ("/api/v1/admin/scan-agent-config"));

  g_ptr_array_free (errs, TRUE);
  agent_controller_scan_agent_config_free (cfg);
  agent_controller_connector_free (conn);
}

Ensure (agent_controller, update_scan_agent_config_400_empty_body_adds_fallback)
{
  mock_http_status = 400;
  mock_response_data = g_strdup (""); /* ensures size/body_len == 0 */

  agent_controller_connector_t conn = make_conn ();
  agent_controller_scan_agent_config_t cfg = make_scan_agent_config ();

  GPtrArray *errs = NULL;
  int rc = agent_controller_update_scan_agent_config (conn, cfg, &errs);

  assert_that (rc, is_equal_to (-1));
  assert_that (errs, is_not_null);
  assert_that ((int) errs->len, is_equal_to (1));
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               contains_string ("invalid JSON payload"));

  g_ptr_array_free (errs, TRUE);
  agent_controller_scan_agent_config_free (cfg);
  agent_controller_connector_free (conn);
}

Ensure (agent_controller,
        update_scan_agent_config_400_invalid_json_adds_invalid_payload)
{
  mock_http_status = 400;
  mock_response_data = g_strdup ("not-json");

  agent_controller_connector_t conn = make_conn ();
  agent_controller_scan_agent_config_t cfg = make_scan_agent_config ();

  GPtrArray *errs = NULL;
  int rc = agent_controller_update_scan_agent_config (conn, cfg, &errs);

  assert_that (rc, is_equal_to (-1));
  assert_that (errs, is_not_null);
  assert_that ((int) errs->len, is_equal_to (1));
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               contains_string ("invalid JSON payload"));

  g_ptr_array_free (errs, TRUE);
  agent_controller_scan_agent_config_free (cfg);
  agent_controller_connector_free (conn);
}

Ensure (agent_controller, update_scan_agent_config_500_does_not_allocate_errors)
{
  mock_http_status = 500;
  mock_response_data = g_strdup ("{}");

  agent_controller_connector_t conn = make_conn ();
  agent_controller_scan_agent_config_t cfg = make_scan_agent_config ();

  GPtrArray *errs = NULL;
  int rc = agent_controller_update_scan_agent_config (conn, cfg, &errs);

  assert_that (rc, is_equal_to (-1));
  assert_that (errs, is_null);

  agent_controller_scan_agent_config_free (cfg);
  agent_controller_connector_free (conn);
}

Ensure (agent_controller, update_scan_agent_config_no_response_returns_error)
{
  mock_http_status = 500;
  g_clear_pointer (&mock_response_data, g_free);
  agent_controller_connector_t conn = make_conn ();
  agent_controller_scan_agent_config_t cfg = make_scan_agent_config ();

  GPtrArray *errs = NULL;
  int rc = agent_controller_update_scan_agent_config (conn, cfg, &errs);

  assert_that (rc, is_equal_to (-1));
  assert_that (errs, is_null);

  agent_controller_scan_agent_config_free (cfg);
  agent_controller_connector_free (conn);
}

Ensure (agent_controller, get_agents_with_updates_null_conn_returns_null)
{
  agent_controller_agent_list_t list =
    agent_controller_get_agents_with_updates (NULL);

  assert_that (list, is_null);
  assert_that (last_sent_url, is_null);
}

Ensure (agent_controller, get_agents_with_updates_no_response_returns_null)
{
  agent_controller_connector_t conn = make_conn ();

  mock_http_status = 500;

  agent_controller_agent_list_t list =
    agent_controller_get_agents_with_updates (conn);

  assert_that (list, is_null);
  assert_that (last_sent_url, contains_string ("/api/v1/admin/agents/updates"));

  agent_controller_connector_free (conn);
}

Ensure (agent_controller, get_agents_with_updates_non200_with_body_returns_null)
{
  agent_controller_connector_t conn = make_conn ();

  mock_http_status = 403;
  mock_response_data = g_strdup ("[]");

  agent_controller_agent_list_t list =
    agent_controller_get_agents_with_updates (conn);

  assert_that (list, is_null);

  agent_controller_connector_free (conn);
}

Ensure (agent_controller, get_agents_with_updates_invalid_json_returns_null)
{
  agent_controller_connector_t conn = make_conn ();

  mock_http_status = 200;
  mock_response_data = g_strdup ("not-json");

  agent_controller_agent_list_t list =
    agent_controller_get_agents_with_updates (conn);

  assert_that (list, is_null);

  agent_controller_connector_free (conn);
}

Ensure (agent_controller, get_agents_with_updates_non_array_returns_null)
{
  agent_controller_connector_t conn = make_conn ();

  mock_http_status = 200;
  mock_response_data = g_strdup ("{\"agents\":[]}");

  agent_controller_agent_list_t list =
    agent_controller_get_agents_with_updates (conn);

  assert_that (list, is_null);

  agent_controller_connector_free (conn);
}

Ensure (agent_controller, get_agents_with_updates_filters_only_true_flags)
{
  agent_controller_connector_t conn = make_conn ();

  mock_http_status = 200;
  mock_response_data =
    g_strdup ("["
              " {\"agentid\":\"A1\",\"agent_update_available\":true,\"updater_"
              "update_available\":false},"
              " {\"agentid\":\"A2\",\"agent_update_available\":false,\"updater_"
              "update_available\":false},"
              " {\"agentid\":\"A3\",\"agent_update_available\":false,\"updater_"
              "update_available\":true},"
              " {\"agentid\":\"A4\"}" /* missing flags -> treated as false */
              "]");

  agent_controller_agent_list_t list =
    agent_controller_get_agents_with_updates (conn);

  assert_that (list, is_not_null);
  assert_that (list->count, is_equal_to (2));
  assert_that (list->agents[0], is_not_null);
  assert_that (list->agents[1], is_not_null);

  /* order preserved from input array, but only filtered ones are kept */
  assert_that (list->agents[0]->agent_id, is_equal_to_string ("A1"));
  assert_that (list->agents[1]->agent_id, is_equal_to_string ("A3"));

  agent_controller_agent_list_free (list);
  agent_controller_connector_free (conn);
}

Ensure (agent_controller,
        get_agents_with_updates_returns_empty_list_when_none_match)
{
  agent_controller_connector_t conn = make_conn ();

  mock_http_status = 200;
  mock_response_data =
    g_strdup ("["
              " {\"agentid\":\"B1\",\"agent_update_available\":false,\"updater_"
              "update_available\":false},"
              " {\"agentid\":\"B2\"}"
              "]");

  agent_controller_agent_list_t list =
    agent_controller_get_agents_with_updates (conn);

  assert_that (list, is_not_null);
  assert_that (list->count, is_equal_to (0));

  agent_controller_agent_list_free (list);
  agent_controller_connector_free (conn);
}

Ensure (agent_controller, get_agents_with_updates_ignores_non_boolean_flags)
{
  agent_controller_connector_t conn = make_conn ();

  mock_http_status = 200;
  mock_response_data =
    g_strdup ("["
              " {\"agentid\":\"C1\",\"agent_update_available\":1,\"updater_"
              "update_available\":\"true\"},"
              " {\"agentid\":\"C2\",\"agent_update_available\":\"false\","
              "\"updater_update_available\":0}"
              "]");

  agent_controller_agent_list_t list =
    agent_controller_get_agents_with_updates (conn);

  assert_that (list, is_not_null);
  assert_that (list->count, is_equal_to (0));

  agent_controller_agent_list_free (list);
  agent_controller_connector_free (conn);
}

Ensure (agent_controller,
        get_agents_with_updates_hits_correct_endpoint_and_builds_agents)
{
  agent_controller_connector_t conn = make_conn ();

  mock_http_status = 200;
  mock_response_data = g_strdup (
    "["
    " {\"agentid\":\"D1\",\"hostname\":\"h1\",\"agent_update_available\":true},"
    " {\"agentid\":\"D2\",\"hostname\":\"h2\",\"updater_update_available\":"
    "true}"
    "]");

  agent_controller_agent_list_t list =
    agent_controller_get_agents_with_updates (conn);

  assert_that (last_sent_url, contains_string ("/api/v1/admin/agents/updates"));
  assert_that (list, is_not_null);
  assert_that (list->count, is_equal_to (2));
  assert_that (list->agents[0]->agent_id, is_equal_to_string ("D1"));
  assert_that (list->agents[0]->hostname, is_equal_to_string ("h1"));
  assert_that (list->agents[1]->agent_id, is_equal_to_string ("D2"));
  assert_that (list->agents[1]->hostname, is_equal_to_string ("h2"));

  agent_controller_agent_list_free (list);
  agent_controller_connector_free (conn);
}

Ensure (agent_controller, parse_cfg_string_null_returns_null)
{
  agent_controller_scan_agent_config_t cfg =
    agent_controller_parse_scan_agent_config_string (NULL);
  assert_that (cfg, is_null);
}

Ensure (agent_controller, parse_cfg_string_invalid_json_returns_null)
{
  const char *json = "{";
  agent_controller_scan_agent_config_t cfg =
    agent_controller_parse_scan_agent_config_string (json);
  assert_that (cfg, is_null);
}

Ensure (agent_controller, parse_cfg_string_array_root_returns_null)
{
  const char *json = "[]";
  agent_controller_scan_agent_config_t cfg =
    agent_controller_parse_scan_agent_config_string (json);
  assert_that (cfg, is_null);
}

Ensure (agent_controller, parse_cfg_string_empty_object_gives_defaults)
{
  const char *json = "{}";
  agent_controller_scan_agent_config_t cfg =
    agent_controller_parse_scan_agent_config_string (json);
  assert_that (cfg, is_not_null);

  /* defaults (all zeros / empty) */
  assert_that (cfg->agent_control.retry.attempts, is_equal_to (0));
  assert_that (cfg->agent_control.retry.delay_in_seconds, is_equal_to (0));
  assert_that (cfg->agent_control.retry.max_jitter_in_seconds, is_equal_to (0));

  assert_that (cfg->agent_script_executor.bulk_size, is_equal_to (0));
  assert_that (cfg->agent_script_executor.bulk_throttle_time_in_ms,
               is_equal_to (0));
  assert_that (cfg->agent_script_executor.indexer_dir_depth, is_equal_to (0));

  assert_that (cfg->heartbeat.interval_in_seconds, is_equal_to (0));
  assert_that (cfg->heartbeat.miss_until_inactive, is_equal_to (0));

  agent_controller_scan_agent_config_free (cfg);
}

Ensure (agent_controller, parse_cfg_string_populates_fields_correctly)
{
  const char *json =
    "{"
    "  \"agent_control\": {"
    "    \"retry\": {\"attempts\":4, \"delay_in_seconds\":60, "
    "\"max_jitter_in_seconds\":10}"
    "  },"
    "  \"agent_script_executor\": {"
    "    \"bulk_size\":2,"
    "    \"bulk_throttle_time_in_ms\":100,"
    "    \"indexer_dir_depth\":10,"
    "    \"period_in_seconds\":60,"
    "    \"scheduler_cron_time\":[\"0 23 * * *\",\"@hourly\"]"
    "  },"
    "  \"heartbeat\": {\"interval_in_seconds\":600, \"miss_until_inactive\":1}"
    "}";

  agent_controller_scan_agent_config_t cfg =
    agent_controller_parse_scan_agent_config_string (json);
  assert_that (cfg, is_not_null);

  /* retry */
  assert_that (cfg->agent_control.retry.attempts, is_equal_to (4));
  assert_that (cfg->agent_control.retry.delay_in_seconds, is_equal_to (60));
  assert_that (cfg->agent_control.retry.max_jitter_in_seconds,
               is_equal_to (10));

  /* executor */
  assert_that (cfg->agent_script_executor.bulk_size, is_equal_to (2));
  assert_that (cfg->agent_script_executor.bulk_throttle_time_in_ms,
               is_equal_to (100));
  assert_that (cfg->agent_script_executor.indexer_dir_depth, is_equal_to (10));

  assert_that (cfg->agent_script_executor.scheduler_cron_time, is_not_null);
  GPtrArray *cron = cfg->agent_script_executor.scheduler_cron_time;
  assert_that ((int) cron->len, is_equal_to (2));
  assert_that ((const gchar *) g_ptr_array_index (cron, 0),
               is_equal_to_string ("0 23 * * *"));
  assert_that ((const gchar *) g_ptr_array_index (cron, 1),
               is_equal_to_string ("@hourly"));

  /* heartbeat */
  assert_that (cfg->heartbeat.interval_in_seconds, is_equal_to (600));
  assert_that (cfg->heartbeat.miss_until_inactive, is_equal_to (1));

  agent_controller_scan_agent_config_free (cfg);
}

Ensure (agent_controller, parse_cfg_string_whitespace_returns_null)
{
  const char *json = "   \t  \n";
  agent_controller_scan_agent_config_t cfg =
    agent_controller_parse_scan_agent_config_string (json);
  assert_that (cfg, is_null);
}

Ensure (agent_controller, ensure_error_array_initializes_new_array)
{
  GPtrArray *errs = NULL;

  ensure_error_array (&errs);

  assert_that (errs, is_not_null);
  assert_that ((int) errs->len, is_equal_to (0));

  g_ptr_array_free (errs, TRUE);
}

Ensure (agent_controller, ensure_error_array_noop_when_already_initialized)
{
  GPtrArray *errs = g_ptr_array_new_with_free_func (g_free);
  g_ptr_array_add (errs, g_strdup ("existing"));

  ensure_error_array (&errs);

  assert_that ((int) errs->len, is_equal_to (1));
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               is_equal_to_string ("existing"));

  g_ptr_array_free (errs, TRUE);
}

Ensure (agent_controller, ensure_error_array_handles_null_parameter)
{
  ensure_error_array (NULL);
  assert_that (true, is_true);
}

Ensure (agent_controller, push_error_initializes_and_adds_message)
{
  GPtrArray *errs = NULL;

  push_error (&errs, "first error");

  assert_that (errs, is_not_null);
  assert_that ((int) errs->len, is_equal_to (1));
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               is_equal_to_string ("first error"));

  g_ptr_array_free (errs, TRUE);
}

Ensure (agent_controller, push_error_appends_preserving_existing)
{
  GPtrArray *errs = g_ptr_array_new_with_free_func (g_free);
  g_ptr_array_add (errs, g_strdup ("existing"));

  push_error (&errs, "second");

  assert_that ((int) errs->len, is_equal_to (2));
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               is_equal_to_string ("existing"));
  assert_that ((const gchar *) g_ptr_array_index (errs, 1),
               is_equal_to_string ("second"));

  g_ptr_array_free (errs, TRUE);
}

Ensure (agent_controller, push_error_ignores_null_or_empty_and_doesnt_alloc)
{
  GPtrArray *errs = NULL;

  push_error (&errs, NULL);
  assert_that (errs, is_null);

  push_error (&errs, "");
  assert_that (errs, is_null);
}

Ensure (agent_controller, push_error_handles_null_errors_parameter)
{
  push_error (NULL, "won't be used");
  assert_that (true, is_true);
}

Ensure (agent_controller, push_error_does_not_change_existing_on_null_or_empty)
{
  GPtrArray *errs = g_ptr_array_new_with_free_func (g_free);
  g_ptr_array_add (errs, g_strdup ("keep"));

  push_error (&errs, NULL);
  push_error (&errs, "");

  assert_that ((int) errs->len, is_equal_to (1));
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               is_equal_to_string ("keep"));

  g_ptr_array_free (errs, TRUE);
}

Ensure (agent_controller, parse_errors_collects_messages_from_array)
{
  const char *json = "{"
                     "  \"errors\":[\"e1\",\"e2\"],"
                     "  \"warnings\":null"
                     "}";
  GPtrArray *errs = NULL;

  parse_errors_json_into_array (json, &errs);

  assert_that (errs, is_not_null);
  assert_that ((int) errs->len, is_equal_to (2));
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               is_equal_to_string ("e1"));
  assert_that ((const gchar *) g_ptr_array_index (errs, 1),
               is_equal_to_string ("e2"));

  g_ptr_array_free (errs, TRUE);
}

Ensure (agent_controller, parse_errors_missing_array_adds_fallback_message)
{
  const char *json = "{ \"warnings\": null }";
  GPtrArray *errs = NULL;

  parse_errors_json_into_array (json, &errs);

  assert_that (errs, is_not_null);
  assert_that ((int) errs->len, is_equal_to (1));
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               contains_string ("no detailed errors were provided"));

  g_ptr_array_free (errs, TRUE);
}

Ensure (agent_controller, parse_errors_non_string_items_adds_fallback_message)
{
  const char *json = "{ \"errors\": [1, true, null, {}, []] }";
  GPtrArray *errs = NULL;

  parse_errors_json_into_array (json, &errs);

  assert_that (errs, is_not_null);
  assert_that ((int) errs->len, is_equal_to (1));
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               contains_string ("no detailed errors were provided"));

  g_ptr_array_free (errs, TRUE);
}

Ensure (agent_controller, parse_errors_invalid_json_adds_invalid_payload_error)
{
  const char *json = "not-json";
  GPtrArray *errs = NULL;

  parse_errors_json_into_array (json, &errs);

  assert_that (errs, is_not_null);
  assert_that ((int) errs->len, is_equal_to (1));
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               contains_string ("invalid JSON payload"));

  g_ptr_array_free (errs, TRUE);
}

Ensure (agent_controller, parse_errors_handles_null_errors_parameter)
{
  const char *json = "{\"errors\":[\"x\"]}";
  parse_errors_json_into_array (json, NULL);
  assert_that (true, is_true);
}

Ensure (agent_controller, parse_errors_ignores_empty_strings_then_fallback)
{
  const char *json = "{ \"errors\": [\"\"] }";
  GPtrArray *errs = NULL;

  parse_errors_json_into_array (json, &errs);

  assert_that (errs, is_not_null);
  assert_that ((int) errs->len, is_equal_to (1));
  assert_that ((const gchar *) g_ptr_array_index (errs, 0),
               contains_string ("no detailed errors were provided"));

  g_ptr_array_free (errs, TRUE);
}

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite = create_test_suite ();

  add_test_with_context (suite, agent_controller,
                         connector_new_returns_valid_connector);
  add_test_with_context (suite, agent_controller,
                         connector_free_handles_null_safely);
  add_test_with_context (suite, agent_controller, connector_free_safely);
  add_test_with_context (suite, agent_controller,
                         connector_builder_all_valid_fields);
  add_test_with_context (suite, agent_controller,
                         connector_builder_valid_protocol_http);
  add_test_with_context (suite, agent_controller,
                         connector_builder_invalid_protocol);
  add_test_with_context (suite, agent_controller,
                         agent_new_allocates_zero_initialized_agent);
  add_test_with_context (suite, agent_controller, agent_free_handles_agent);
  add_test_with_context (suite, agent_controller,
                         agent_free_handles_null_agent);
  add_test_with_context (suite, agent_controller,
                         agent_list_new_allocates_list_and_agents_array);
  add_test_with_context (suite, agent_controller,
                         agent_list_new_returns_null_for_invalid_count);
  add_test_with_context (suite, agent_controller,
                         agent_list_new_returns_array_for_0_count);
  add_test_with_context (suite, agent_controller,
                         agent_list_free_handles_populated_list);
  add_test_with_context (suite, agent_controller,
                         agent_list_free_handles_null_list);
  add_test_with_context (suite, agent_controller,
                         agent_update_new_initializes_defaults_correctly);
  add_test_with_context (suite, agent_controller,
                         agent_update_free_handles_nested_schedule);
  add_test_with_context (suite, agent_controller,
                         agent_update_free_handles_null_schedule);
  add_test_with_context (suite, agent_controller,
                         init_custom_header_calls_add_header);
  add_test_with_context (suite, agent_controller,
                         init_custom_header_calls_without_token_add_header);
  add_test_with_context (suite, agent_controller,
                         send_request_builds_url_and_calls_http_request);
  add_test_with_context (suite, agent_controller,
                         send_request_returns_null_if_conn_is_null);
  add_test_with_context (suite, agent_controller,
                         send_request_returns_null_if_protocol_missing);
  add_test_with_context (suite, agent_controller,
                         send_request_returns_null_if_host_missing);
  add_test_with_context (suite, agent_controller,
                         send_request_works_without_bearer_token);
  add_test_with_context (suite, agent_controller,
                         parse_datetime_parses_valid_datetime);
  add_test_with_context (suite, agent_controller,
                         parse_datetime_returns_zero_for_invalid_format);
  add_test_with_context (suite, agent_controller,
                         parse_datetime_handles_missing_fractional_seconds);
  add_test_with_context (suite, agent_controller,
                         parse_datetime_parses_leap_year_date);
  add_test_with_context (suite, agent_controller,
                         parse_datetime_returns_zero_if_null_input);
  add_test_with_context (suite, agent_controller,
                         parse_agent_with_minimal_fields);
  add_test_with_context (suite, agent_controller,
                         parse_agent_config_object_printed);
  add_test_with_context (suite, agent_controller,
                         parse_agent_config_string_stored_directly);
  add_test_with_context (suite, agent_controller,
                         parse_agent_config_null_defaults_to_empty_object);
  add_test_with_context (suite, agent_controller,
                         parse_agent_missing_optional_fields);
  add_test_with_context (suite, agent_controller,
                         parse_agent_returns_null_on_null_input);
  add_test_with_context (suite, agent_controller,
                         build_patch_payload_from_single_agent);
  add_test_with_context (suite, agent_controller,
                         patch_payload_overrides_only_authorized_field);
  add_test_with_context (suite, agent_controller,
                         patch_payload_overrides_only_min_interval);
  add_test_with_context (suite, agent_controller,
                         patch_payload_overrides_only_config);
  add_test_with_context (suite, agent_controller,
                         scan_agent_config_new_initializes_defaults);
  add_test_with_context (suite, agent_controller,
                         scan_agent_config_free_handles_null);
  add_test_with_context (suite, agent_controller,
                         scan_agent_config_free_frees_cron_array_safely);
  add_test_with_context (suite, agent_controller,
                         scan_agent_config_new_then_immediate_free);
  add_test_with_context (suite, agent_controller,
                         build_scan_agent_config_payload_defaults);
  add_test_with_context (suite, agent_controller,
                         build_scan_agent_config_payload_with_values);
  add_test_with_context (suite, agent_controller, parse_scan_agent_config_full);
  add_test_with_context (suite, agent_controller,
                         parse_scan_agent_config_missing_blocks);
  add_test_with_context (suite, agent_controller,
                         scan_agent_config_roundtrip_build_then_parse);
  add_test_with_context (suite, agent_controller,
                         json_has_update_returns_false_on_null);
  add_test_with_context (suite, agent_controller,
                         get_agents_returns_list_on_successful_response);
  add_test_with_context (suite, agent_controller,
                         json_has_update_returns_false_on_non_object);
  add_test_with_context (suite, agent_controller,
                         json_has_update_returns_false_when_keys_missing);
  add_test_with_context (suite, agent_controller,
                         json_has_update_true_when_agent_update_available_true);
  add_test_with_context (
    suite, agent_controller,
    json_has_update_true_when_updater_update_available_true);
  add_test_with_context (suite, agent_controller,
                         json_has_update_true_when_both_true);
  add_test_with_context (suite, agent_controller,
                         json_has_update_ignores_non_boolean_values);
  add_test_with_context (suite, agent_controller,
                         json_has_update_ignores_numbers);
  add_test_with_context (
    suite, agent_controller,
    get_agents_returns_list_on_successful_response_with_extended_fields);
  add_test_with_context (suite, agent_controller,
                         get_agents_returns_null_on_non_200_status);
  add_test_with_context (suite, agent_controller,
                         get_agents_returns_null_on_invalid_json);
  add_test_with_context (suite, agent_controller,
                         update_agents_returns_zero_on_success);
  add_test_with_context (suite, agent_controller,
                         update_agents_fails_with_null_connection);
  add_test_with_context (suite, agent_controller,
                         update_agents_fails_with_null_agents);
  add_test_with_context (suite, agent_controller,
                         update_agents_fails_with_null_update);
  add_test_with_context (suite, agent_controller,
                         update_agents_fails_on_http_error_status);
  add_test_with_context (suite, agent_controller,
                         update_agents_400_populates_errors_from_json);
  add_test_with_context (suite, agent_controller,
                         update_agents_400_invalid_json_adds_invalid_payload);
  add_test_with_context (suite, agent_controller,
                         update_agents_500_does_not_allocate_errors);
  add_test_with_context (suite, agent_controller,
                         update_agents_no_response_returns_error);
  add_test_with_context (suite, agent_controller,
                         delete_agents_returns_zero_on_success);
  add_test_with_context (suite, agent_controller,
                         delete_agents_fails_with_null_conn);
  add_test_with_context (suite, agent_controller,
                         delete_agents_fails_with_null_list);
  add_test_with_context (suite, agent_controller,
                         delete_agents_fails_if_no_valid_ids);
  add_test_with_context (suite, agent_controller,
                         delete_agents_fails_on_http_422);
  add_test_with_context (suite, agent_controller,
                         get_scan_agent_config_null_conn_returns_null);
  add_test_with_context (suite, agent_controller,
                         get_scan_agent_config_no_response_returns_null);
  add_test_with_context (suite, agent_controller,
                         get_scan_agent_config_non2xx_with_body_returns_null);
  add_test_with_context (suite, agent_controller,
                         get_scan_agent_config_invalid_json_returns_null);
  add_test_with_context (suite, agent_controller,
                         get_scan_agent_config_success_parses_values);
  add_test_with_context (suite, agent_controller,
                         update_scan_agent_config_null_args_return_error);
  add_test_with_context (suite, agent_controller,
                         update_scan_agent_config_no_response_return_error);
  add_test_with_context (
    suite, agent_controller,
    update_scan_agent_config_non2xx_with_body_return_error);
  add_test_with_context (
    suite, agent_controller,
    update_scan_agent_config_success_returns_ok_and_sends_payload);
  add_test_with_context (
    suite, agent_controller,
    update_scan_agent_config_400_populates_errors_from_json);
  add_test_with_context (suite, agent_controller,
                         update_scan_agent_config_400_empty_body_adds_fallback);
  add_test_with_context (
    suite, agent_controller,
    update_scan_agent_config_400_invalid_json_adds_invalid_payload);
  add_test_with_context (suite, agent_controller,
                         update_scan_agent_config_500_does_not_allocate_errors);
  add_test_with_context (suite, agent_controller,
                         update_scan_agent_config_no_response_returns_error);
  add_test_with_context (suite, agent_controller,
                         get_agents_with_updates_null_conn_returns_null);
  add_test_with_context (suite, agent_controller,
                         get_agents_with_updates_non200_with_body_returns_null);
  add_test_with_context (suite, agent_controller,
                         get_agents_with_updates_invalid_json_returns_null);
  add_test_with_context (suite, agent_controller,
                         get_agents_with_updates_non_array_returns_null);
  add_test_with_context (suite, agent_controller,
                         get_agents_with_updates_filters_only_true_flags);
  add_test_with_context (suite, agent_controller,
                         get_agents_with_updates_no_response_returns_null);
  add_test_with_context (
    suite, agent_controller,
    get_agents_with_updates_returns_empty_list_when_none_match);
  add_test_with_context (suite, agent_controller,
                         get_agents_with_updates_ignores_non_boolean_flags);
  add_test_with_context (
    suite, agent_controller,
    get_agents_with_updates_hits_correct_endpoint_and_builds_agents);
  add_test_with_context (suite, agent_controller,
                         parse_cfg_string_null_returns_null);
  add_test_with_context (suite, agent_controller,
                         parse_cfg_string_invalid_json_returns_null);
  add_test_with_context (suite, agent_controller,
                         parse_cfg_string_array_root_returns_null);
  add_test_with_context (suite, agent_controller,
                         parse_cfg_string_empty_object_gives_defaults);
  add_test_with_context (suite, agent_controller,
                         parse_cfg_string_populates_fields_correctly);
  add_test_with_context (suite, agent_controller,
                         parse_cfg_string_whitespace_returns_null);
  add_test_with_context (suite, agent_controller,
                         ensure_error_array_initializes_new_array);
  add_test_with_context (suite, agent_controller,
                         ensure_error_array_noop_when_already_initialized);
  add_test_with_context (suite, agent_controller,
                         ensure_error_array_handles_null_parameter);
  add_test_with_context (suite, agent_controller,
                         push_error_initializes_and_adds_message);
  add_test_with_context (suite, agent_controller,
                         push_error_appends_preserving_existing);
  add_test_with_context (suite, agent_controller,
                         push_error_ignores_null_or_empty_and_doesnt_alloc);
  add_test_with_context (suite, agent_controller,
                         push_error_handles_null_errors_parameter);
  add_test_with_context (suite, agent_controller,
                         push_error_does_not_change_existing_on_null_or_empty);
  add_test_with_context (suite, agent_controller,
                         parse_errors_collects_messages_from_array);
  add_test_with_context (suite, agent_controller,
                         parse_errors_missing_array_adds_fallback_message);
  add_test_with_context (suite, agent_controller,
                         parse_errors_non_string_items_adds_fallback_message);
  add_test_with_context (suite, agent_controller,
                         parse_errors_invalid_json_adds_invalid_payload_error);
  add_test_with_context (suite, agent_controller,
                         parse_errors_handles_null_errors_parameter);
  add_test_with_context (suite, agent_controller,
                         parse_errors_ignores_empty_strings_then_fallback);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}