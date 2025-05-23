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
  (void)headers;

  if (!called_headers)
    called_headers = g_ptr_array_new_with_free_func (g_free);

  g_ptr_array_add (called_headers, g_strdup (header));
  return TRUE;
}

gvm_http_response_t *
gvm_http_request (const gchar *url, gvm_http_method_t method,
                  const gchar *payload, gvm_http_headers_t *headers,
                  const gchar *ca_cert, const gchar *cert,
                  const gchar *key, gvm_http_response_stream_t stream)
{
  (void)headers; (void)ca_cert; (void)cert; (void)key; (void)stream; (void)method;

  last_sent_url = g_strdup (url);
  last_sent_payload = g_strdup (payload);

  if (!mock_response_data && mock_http_status != 200)
    return NULL;

  gvm_http_response_t *response = g_malloc0 (sizeof (gvm_http_response_t));
  response->http_status = mock_http_status;
  response->data = mock_response_data ? g_strdup (mock_response_data) : g_strdup ("{}");
  return response;
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
  agent_controller_connector_builder (conn, AGENT_CONTROLLER_PROTOCOL, protocol);
  agent_controller_connector_builder (conn, AGENT_CONTROLLER_HOST, host);
  agent_controller_connector_builder (conn, AGENT_CONTROLLER_PORT, &port);

  agent_controller_connector_free (conn);
  assert_that (true, is_true);
}

Ensure (agent_controller, connector_builder_all_valid_fields)
{
  agent_controller_connector_t conn = agent_controller_connector_new();

  const char *ca_cert = "/path/ca.pem";
  const char *cert = "/path/cert.pem";
  const char *key = "/path/key.pem";
  const char *apikey = "123abc";
  const char *protocol = "https";
  const char *host = "127.0.0.1";
  int port = 8443;

  assert_that (agent_controller_connector_builder (conn, AGENT_CONTROLLER_CA_CERT, ca_cert), is_equal_to (AGENT_CONTROLLER_OK));
  assert_that (conn->ca_cert, is_equal_to_string (ca_cert));

  assert_that (agent_controller_connector_builder (conn, AGENT_CONTROLLER_CERT, cert), is_equal_to (AGENT_CONTROLLER_OK));
  assert_that (conn->cert, is_equal_to_string (cert));

  assert_that (agent_controller_connector_builder (conn, AGENT_CONTROLLER_KEY, key), is_equal_to (AGENT_CONTROLLER_OK));
  assert_that (conn->key, is_equal_to_string (key));

  assert_that (agent_controller_connector_builder (conn, AGENT_CONTROLLER_API_KEY, apikey), is_equal_to (AGENT_CONTROLLER_OK));
  assert_that (conn->apikey, is_equal_to_string (apikey));

  assert_that (agent_controller_connector_builder (conn, AGENT_CONTROLLER_PROTOCOL, protocol), is_equal_to (AGENT_CONTROLLER_OK));
  assert_that (conn->protocol, is_equal_to_string(protocol));

  assert_that (agent_controller_connector_builder (conn, AGENT_CONTROLLER_HOST, host), is_equal_to (AGENT_CONTROLLER_OK));
  assert_that (conn->host, is_equal_to_string(host));

  assert_that (agent_controller_connector_builder (conn, AGENT_CONTROLLER_PORT, &port), is_equal_to (AGENT_CONTROLLER_OK));
  assert_that (conn->port, is_equal_to (port));

  agent_controller_connector_free (conn);
}

Ensure (agent_controller, connector_builder_valid_protocol_http)
{
  agent_controller_connector_t conn = agent_controller_connector_new ();
  agent_controller_error_t result = agent_controller_connector_builder (conn, AGENT_CONTROLLER_PROTOCOL, "http");

  assert_that (result, is_equal_to (AGENT_CONTROLLER_OK));
  assert_that (conn->protocol, is_equal_to_string ("http"));

  agent_controller_connector_free (conn);
}

Ensure (agent_controller, connector_builder_invalid_protocol)
{
  agent_controller_connector_t conn = agent_controller_connector_new ();
  agent_controller_error_t result = agent_controller_connector_builder (conn, AGENT_CONTROLLER_PROTOCOL, "ftp");

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

  // Schedule config
  agent->schedule_config = agent_controller_config_schedule_new ();
  agent->schedule_config->schedule = g_strdup ("@every 12h");

  // Server config
  agent->server_config = agent_controller_config_server_new ();
  agent->server_config->base_url = g_strdup ("http://localhost");
  agent->server_config->agent_id = g_strdup ("agent-001");
  agent->server_config->token = g_strdup ("token-xyz");
  agent->server_config->server_cert_hash = g_strdup ("hashvalue");

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
  agent_controller_agent_list_t list_negative = agent_controller_agent_list_new (-5);
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
  assert_that (update->min_interval, is_equal_to (-1));
  assert_that (update->heartbeat_interval, is_equal_to (-1));
  assert_that (update->schedule_config, is_null);

  agent_controller_agent_update_free(update);
}

Ensure (agent_controller, agent_update_free_handles_nested_schedule)
{
  agent_controller_agent_update_t update = agent_controller_agent_update_new ();
  assert_that (update, is_not_null);

  update->schedule_config = agent_controller_config_schedule_new ();
  update->schedule_config->schedule = g_strdup ("@every 12h");

  agent_controller_agent_update_free (update);
  assert_that (true, is_true);
}

Ensure (agent_controller, agent_update_free_handles_null_schedule)
{
  agent_controller_agent_update_free (NULL);
  assert_that (true, is_true);
}

Ensure (agent_controller, config_schedule_new_allocates_struct)
{
  agent_controller_config_schedule_t schedule = agent_controller_config_schedule_new ();

  assert_that (schedule, is_not_null);

  assert_that (schedule->schedule, is_null);

  agent_controller_config_schedule_free (schedule);
}

Ensure (agent_controller, config_schedule_free_handles_populated_struct)
{
  agent_controller_config_schedule_t schedule = agent_controller_config_schedule_new ();
  assert_that (schedule, is_not_null);

  schedule->schedule = g_strdup ("@every 12h");

  agent_controller_config_schedule_free (schedule);
  assert_that (true, is_true);
}

Ensure (agent_controller, config_schedule_free_handles_null_struct)
{
  agent_controller_config_schedule_free (NULL);
  assert_that (true, is_true);
}

Ensure (agent_controller, config_server_new_allocates_struct)
{
  agent_controller_config_server_t server = agent_controller_config_server_new ();

  assert_that (server, is_not_null);

  assert_that (server->base_url, is_null);
  assert_that (server->agent_id, is_null);
  assert_that (server->token, is_null);
  assert_that (server->server_cert_hash, is_null);

  agent_controller_config_server_free (server);
}

Ensure (agent_controller, config_server_free_handles_populated_struct)
{
  agent_controller_config_server_t server = agent_controller_config_server_new ();
  assert_that (server, is_not_null);

  server->base_url = g_strdup ("https://example.com");
  server->agent_id = g_strdup ("agent-007");
  server->token = g_strdup ("secrettoken");
  server->server_cert_hash = g_strdup ("abc123hash");

  agent_controller_config_server_free(server);
  assert_that (true, is_true);
}

Ensure (agent_controller, config_server_free_handles_null_struct)
{
  agent_controller_config_server_free (NULL);
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

Ensure(agent_controller, init_custom_header_calls_without_token_add_header)
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
  conn->protocol = g_strdup("https");
  conn->host = g_strdup("localhost");
  conn->port = 8080;
  conn->ca_cert = g_strdup("ca.pem");
  conn->cert = g_strdup("cert.pem");
  conn->key = g_strdup("key.pem");

  const gchar *path = "/api/v1/test";
  const gchar *token = "mytoken";
  const gchar *payload = "{\"key\":\"value\"}";

  gvm_http_response_t *resp = agent_controller_send_request (conn, POST,
                                                             path, payload, token);

  assert_that (resp, is_not_null);
  assert_that (last_sent_url, is_equal_to_string ("https://localhost:8080/api/v1/test"));
  assert_that (last_sent_payload, is_equal_to_string (payload));

  g_free (resp);
  agent_controller_connector_free (conn);
}

Ensure (agent_controller, send_request_returns_null_if_conn_is_null)
{
  gvm_http_response_t *resp = agent_controller_send_request (NULL, POST, "/test", "{}", "token");
  assert_that (resp, is_null);
}

Ensure (agent_controller, send_request_returns_null_if_protocol_missing)
{
  agent_controller_connector_t conn = agent_controller_connector_new ();
  conn->host = g_strdup("localhost");
  conn->port = 8080;

  gvm_http_response_t *resp = agent_controller_send_request (conn, GET, "/test", NULL, NULL);
  assert_that (resp, is_null);

  agent_controller_connector_free (conn);
}

Ensure (agent_controller, send_request_returns_null_if_host_missing)
{
  agent_controller_connector_t conn = agent_controller_connector_new ();
  conn->protocol = g_strdup ("http");
  conn->port = 8080;

  gvm_http_response_t *resp = agent_controller_send_request (conn, GET, "/test", NULL, NULL);
  assert_that (resp, is_null);

  agent_controller_connector_free (conn);
}

Ensure (agent_controller, send_request_works_without_bearer_token)
{
  agent_controller_connector_t conn = agent_controller_connector_new ();
  conn->protocol = g_strdup ("https");
  conn->host = g_strdup ("localhost");
  conn->port = 8080;

  gvm_http_response_t *resp = agent_controller_send_request (conn, GET, "/test", NULL, "");

  assert_that (resp, is_not_null);
  assert_that (last_sent_url, is_equal_to_string ("https://localhost:8080/test"));

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

  assert_that(t, is_equal_to (timegm (&expected)));
}

Ensure (agent_controller, parse_datetime_returns_zero_for_invalid_format)
{
  const char *invalid_str = "not-a-datetime";
  time_t t = parse_datetime (invalid_str);
  assert_that(t, is_equal_to ((time_t)0));
}

Ensure (agent_controller, parse_datetime_handles_missing_fractional_seconds)
{
  const char *missing_fraction = "2025-04-29T13:06:00Z";
  time_t t = parse_datetime (missing_fraction);
  assert_that (t, is_equal_to ((time_t)0));
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
  assert_that (t, is_equal_to ((time_t)0));
}

Ensure (agent_controller, parse_agent_with_minimal_fields)
{
  const char *json = "{"
    "\"agentid\": \"a1\","
    "\"hostname\": \"host1\","
    "\"connection_status\": \"active\","
    "\"authorized\": true,"
    "\"min_interval\": 10,"
    "\"heartbeat_interval\": 20,"
    "\"last_update\": \"2025-04-29T13:06:00.34994Z\","
    "\"ip_addresses\": [\"192.168.1.1\"]"
  "}";

  cJSON *obj = cJSON_Parse(json);
  agent_controller_agent_t agent = agent_controller_parse_agent (obj);

  assert_that (agent, is_not_null);
  assert_that (agent->agent_id, is_equal_to_string ("a1"));
  assert_that (agent->hostname, is_equal_to_string ("host1"));
  assert_that (agent->connection_status, is_equal_to_string ("active"));
  assert_that (agent->authorized, is_equal_to (1));
  assert_that (agent->min_interval, is_equal_to (10));
  assert_that (agent->heartbeat_interval, is_equal_to (20));
  assert_that (agent->ip_address_count, is_equal_to (1));
  assert_that (agent->ip_addresses[0], is_equal_to_string ("192.168.1.1"));
  assert_that (agent->last_update, is_not_equal_to ((time_t)0));

  agent_controller_agent_free (agent);
  cJSON_Delete (obj);
}

Ensure (agent_controller, parse_agent_with_config_and_server)
{
  const char *json = "{"
    "\"agentid\": \"a2\","
    "\"hostname\": \"host2\","
    "\"authorized\": false,"
    "\"min_interval\": 15,"
    "\"heartbeat_interval\": 25,"
    "\"connection_status\": \"idle\","
    "\"last_update\": \"2025-04-29T10:00:00.00000Z\","
    "\"ip_addresses\": [],"
    "\"config\": {"
      "\"schedule\": { \"schedule\": \"@every 5m\" },"
      "\"control-server\": {"
        "\"base_url\": \"https://ctrl.local\","
        "\"agent_id\": \"agent-ctrl\","
        "\"token\": \"xyz123\","
        "\"server_cert_hash\": \"abc123hash\""
      "}"
    "}"
  "}";

  cJSON *obj = cJSON_Parse (json);
  agent_controller_agent_t agent = agent_controller_parse_agent (obj);

  assert_that (agent, is_not_null);
  assert_that (agent->schedule_config, is_not_null);
  assert_that (agent->schedule_config->schedule, is_equal_to_string ("@every 5m"));

  assert_that (agent->server_config, is_not_null);
  assert_that (agent->server_config->base_url, is_equal_to_string ("https://ctrl.local"));
  assert_that (agent->server_config->agent_id, is_equal_to_string ("agent-ctrl"));
  assert_that (agent->server_config->token, is_equal_to_string ("xyz123"));
  assert_that (agent->server_config->server_cert_hash, is_equal_to_string ("abc123hash"));

  agent_controller_agent_free (agent);
  cJSON_Delete (obj);
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
  assert_that (agent->schedule_config, is_null);
  assert_that (agent->server_config, is_null);

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
  agent->min_interval = 30;
  agent->heartbeat_interval = 60;

  agent->schedule_config = agent_controller_config_schedule_new ();
  agent->schedule_config->schedule = g_strdup ("@every 1h");

  list->agents[0] = agent;

  gchar *payload = agent_controller_build_patch_payload (list, NULL);

  assert_that (payload, contains_string ("\"agent1\""));
  assert_that (payload, contains_string ("\"authorized\":true"));
  assert_that (payload, contains_string ("\"min_interval\":30"));
  assert_that (payload, contains_string ("\"heartbeat_interval\":60"));
  assert_that (payload, contains_string ("\"schedule\":\"@every 1h\""));

  g_free (payload);
  agent_controller_agent_list_free (list);
}

Ensure (agent_controller, patch_payload_overrides_only_authorized_field)
{
  agent_controller_agent_list_t list = agent_controller_agent_list_new (1);
  agent_controller_agent_t agent = agent_controller_agent_new ();
  agent->agent_id = g_strdup ("agentA");
  agent->authorized = 0;
  agent->min_interval = 15;
  agent->heartbeat_interval = 30;

  list->agents[0] = agent;

  agent_controller_agent_update_t update = agent_controller_agent_update_new ();
  update->authorized = 1;

  gchar *payload = agent_controller_build_patch_payload (list, update);

  assert_that (payload, contains_string ("\"authorized\":true"));
  assert_that (payload, contains_string ("\"min_interval\":15"));
  assert_that (payload, contains_string ("\"heartbeat_interval\":30"));

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
  agent->min_interval = 15;
  agent->heartbeat_interval = 45;

  list->agents[0] = agent;

  agent_controller_agent_update_t update = agent_controller_agent_update_new ();
  update->min_interval = 99;

  gchar *payload = agent_controller_build_patch_payload (list, update);

  assert_that (payload, contains_string ("\"authorized\":true"));
  assert_that (payload, contains_string ("\"min_interval\":99"));
  assert_that (payload, contains_string ("\"heartbeat_interval\":45"));

  g_free (payload);
  agent_controller_agent_update_free (update);
  agent_controller_agent_list_free (list);
}

Ensure (agent_controller, patch_payload_overrides_only_schedule_config)
{
  agent_controller_agent_list_t list = agent_controller_agent_list_new (1);
  agent_controller_agent_t agent = agent_controller_agent_new ();
  agent->agent_id = g_strdup ("agentC");
  agent->authorized = 0;
  agent->min_interval = 5;
  agent->heartbeat_interval = 10;
  agent->schedule_config = agent_controller_config_schedule_new ();
  agent->schedule_config->schedule = g_strdup ("@hourly");

  list->agents[0] = agent;

  agent_controller_agent_update_t update = agent_controller_agent_update_new ();
  update->schedule_config = agent_controller_config_schedule_new ();
  update->schedule_config->schedule = g_strdup ("@every 10m");

  gchar *payload = agent_controller_build_patch_payload (list, update);

  assert_that (payload, contains_string ("\"schedule\":\"@every 10m\""));
  assert_that (payload, does_not_contain_string ("@hourly"));
  assert_that (payload, contains_string ("\"min_interval\":5"));

  g_free (payload);
  agent_controller_agent_update_free (update);
  agent_controller_agent_list_free (list);
}

Ensure (agent_controller, get_agents_returns_list_on_successful_response)
{
  mock_response_data =
    "[{"
    "\"agentid\": \"agent1\","
    "\"hostname\": \"host-a\","
    "\"authorized\": true,"
    "\"min_interval\": 5,"
    "\"heartbeat_interval\": 10,"
    "\"connection_status\": \"online\""
    "}]";
  mock_http_status = 200;

  agent_controller_connector_t conn = agent_controller_connector_new ();
  conn->protocol = g_strdup ("https");
  conn->host = g_strdup ("localhost");
  conn->port = 8080;
  conn->apikey = g_strdup ("mock-key");

  agent_controller_agent_list_t list = agent_controller_get_agents (conn);

  assert_that (list, is_not_null);
  assert_that (list->count, is_equal_to (1));
  assert_that (list->agents[0], is_not_null);
  assert_that (list->agents[0]->agent_id, is_equal_to_string ("agent1"));

  agent_controller_agent_list_free (list);
  agent_controller_connector_free (conn);
}

Ensure (agent_controller, get_agents_returns_null_on_non_200_status)
{
  mock_http_status = 403;
  mock_response_data = "[{\"agentid\": \"a\"}]";

  agent_controller_connector_t conn = agent_controller_connector_new ();
  conn->protocol = g_strdup ("https");
  conn->host = g_strdup ("localhost");
  conn->port = 8080;
  conn->apikey = g_strdup ("mock-key");

  agent_controller_agent_list_t list = agent_controller_get_agents (conn);
  assert_that (list, is_null);

  agent_controller_connector_free (conn);
}

Ensure (agent_controller, get_agents_returns_null_on_invalid_json)
{
  mock_http_status = 200;
  mock_response_data = "not-a-json-array";

  agent_controller_connector_t conn = agent_controller_connector_new ();
  conn->protocol = g_strdup ("https");
  conn->host = g_strdup ("localhost");
  conn->port = 8080;
  conn->apikey = g_strdup ("token");

  agent_controller_agent_list_t list = agent_controller_get_agents (conn);
  assert_that (list, is_null);

  agent_controller_connector_free (conn);
}

Ensure (agent_controller, authorize_agents_succeeds_with_valid_input)
{
  mock_http_status = 200;
  mock_response_data = g_strdup ("{}");

  agent_controller_connector_t conn = agent_controller_connector_new ();
  conn->protocol = g_strdup ("https");
  conn->host = g_strdup ("localhost");
  conn->port = 8080;
  conn->apikey = g_strdup ("token");

  agent_controller_agent_list_t list = agent_controller_agent_list_new (1);
  agent_controller_agent_t agent = agent_controller_agent_new ();
  agent->agent_id = g_strdup ("agent");
  list->agents[0] = agent;

  int result = agent_controller_authorize_agents (conn, list);
  assert_that (result, is_equal_to(0));

  agent_controller_agent_list_free (list);
  agent_controller_connector_free (conn);
}

Ensure (agent_controller, authorize_agents_fails_with_null_conn)
{
  agent_controller_agent_list_t list = agent_controller_agent_list_new (1);
  list->agents[0] = agent_controller_agent_new ();
  list->agents[0]->agent_id = g_strdup ("agent");

  int result = agent_controller_authorize_agents (NULL, list);
  assert_that (result, is_equal_to (-1));

  agent_controller_agent_list_free (list);
}

Ensure (agent_controller, authorize_agents_fails_with_null_agents)
{
  agent_controller_connector_t conn = agent_controller_connector_new ();
  int result = agent_controller_authorize_agents (conn, NULL);
  assert_that (result, is_equal_to (-1));
  agent_controller_connector_free (conn);
}

Ensure (agent_controller, authorize_agents_fails_when_payload_is_null)
{
  agent_controller_connector_t conn = agent_controller_connector_new ();
  conn->protocol = g_strdup ("https");
  conn->host = g_strdup ("localhost");
  conn->port = 8080;
  conn->apikey = g_strdup ("token");

  agent_controller_agent_list_t list = agent_controller_agent_list_new (1);
  list->count = 0;

  int result = agent_controller_authorize_agents (conn, list);
  assert_that (result, is_equal_to (-1));

  agent_controller_agent_list_free (list);
  agent_controller_connector_free (conn);
}

Ensure(agent_controller, authorize_agents_fails_on_http_422)
{
  mock_http_status = 422;
  mock_response_data = g_strdup ("{}");

  agent_controller_connector_t conn = agent_controller_connector_new ();
  conn->protocol = g_strdup ("https");
  conn->host = g_strdup ("localhost");
  conn->port = 8080;
  conn->apikey = g_strdup ("token");

  agent_controller_agent_list_t list = agent_controller_agent_list_new (1);
  agent_controller_agent_t agent = agent_controller_agent_new ();
  agent->agent_id = g_strdup ("no-agent");
  list->agents[0] = agent;

  int result = agent_controller_authorize_agents (conn, list);
  assert_that (result, is_equal_to (-1));

  agent_controller_agent_list_free (list);
  agent_controller_connector_free (conn);
}

Ensure (agent_controller, update_agents_returns_zero_on_success)
{
  mock_http_status = 200;
  g_clear_pointer (&mock_response_data, g_free);
  mock_response_data = g_strdup ("");

  agent_controller_connector_t conn = agent_controller_connector_new ();
  conn->protocol = g_strdup ("https");
  conn->host = g_strdup ("localhost");
  conn->port = 8080;
  conn->apikey = g_strdup ("token");

  agent_controller_agent_list_t list = agent_controller_agent_list_new (1);
  agent_controller_agent_t agent = agent_controller_agent_new ();
  agent->agent_id = g_strdup ("agent1");
  list->agents[0] = agent;

  agent_controller_agent_update_t update = agent_controller_agent_update_new ();
  update->min_interval = 60;

  int result = agent_controller_update_agents (conn, list, update);
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

  int result = agent_controller_update_agents (NULL, list, update);
  assert_that (result, is_equal_to(-1));

  agent_controller_agent_list_free (list);
  agent_controller_agent_update_free (update);
}

Ensure (agent_controller, update_agents_fails_with_null_agents)
{
  agent_controller_connector_t conn = agent_controller_connector_new ();
  agent_controller_agent_update_t update = agent_controller_agent_update_new ();

  int result = agent_controller_update_agents (conn, NULL, update);
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

  int result = agent_controller_update_agents (conn, list, NULL);
  assert_that (result, is_equal_to (-1));

  agent_controller_agent_list_free (list);
  agent_controller_connector_free (conn);
}

Ensure (agent_controller, update_agents_fails_on_http_error_status)
{
  mock_http_status = 400;
  mock_response_data = g_strdup("{}");

  agent_controller_connector_t conn = agent_controller_connector_new ();
  conn->protocol = g_strdup("https");
  conn->host = g_strdup("localhost");
  conn->port = 8080;
  conn->apikey = g_strdup("token");

  agent_controller_agent_list_t list = agent_controller_agent_list_new (1);
  list->agents[0] = agent_controller_agent_new ();
  list->agents[0]->agent_id = g_strdup ("agent");

  agent_controller_agent_update_t update = agent_controller_agent_update_new ();
  update->authorized = 1;

  int result = agent_controller_update_agents (conn, list, update);
  assert_that (result, is_equal_to (-1));

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

  agent_controller_agent_list_free(list);
  agent_controller_connector_free(conn);
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
  conn->apikey = g_strdup("token");

  agent_controller_agent_list_t list = agent_controller_agent_list_new(1);
  list->agents[0] = agent_controller_agent_new();
  list->agents[0]->agent_id = g_strdup("agent");

  int result = agent_controller_delete_agents (conn, list);
  assert_that (result, is_equal_to (-1));

  agent_controller_agent_list_free (list);
  agent_controller_connector_free (conn);
}

int
main (int argc, char **argv)
{
  TestSuite *suite = create_test_suite ();

  add_test_with_context (suite, agent_controller, connector_new_returns_valid_connector);
  add_test_with_context (suite, agent_controller, connector_free_handles_null_safely);
  add_test_with_context (suite, agent_controller, connector_free_safely);
  add_test_with_context (suite, agent_controller, connector_builder_all_valid_fields);
  add_test_with_context (suite, agent_controller, connector_builder_valid_protocol_http);
  add_test_with_context (suite, agent_controller, connector_builder_invalid_protocol);
  add_test_with_context (suite, agent_controller, agent_new_allocates_zero_initialized_agent);
  add_test_with_context (suite, agent_controller, agent_free_handles_agent);
  add_test_with_context (suite, agent_controller, agent_free_handles_null_agent);
  add_test_with_context (suite, agent_controller, agent_list_new_allocates_list_and_agents_array);
  add_test_with_context (suite, agent_controller, agent_list_new_returns_null_for_invalid_count);
  add_test_with_context (suite, agent_controller, agent_list_new_returns_array_for_0_count);
  add_test_with_context (suite, agent_controller, agent_list_free_handles_populated_list);
  add_test_with_context (suite, agent_controller, agent_list_free_handles_null_list);
  add_test_with_context (suite, agent_controller, agent_update_new_initializes_defaults_correctly);
  add_test_with_context (suite, agent_controller, agent_update_free_handles_nested_schedule);
  add_test_with_context (suite, agent_controller, agent_update_free_handles_null_schedule);
  add_test_with_context (suite, agent_controller, config_schedule_new_allocates_struct);
  add_test_with_context (suite, agent_controller, config_schedule_free_handles_populated_struct);
  add_test_with_context (suite, agent_controller, config_schedule_free_handles_null_struct);
  add_test_with_context (suite, agent_controller, config_server_new_allocates_struct);
  add_test_with_context (suite, agent_controller, config_server_free_handles_populated_struct);
  add_test_with_context (suite, agent_controller, config_server_free_handles_null_struct);
  add_test_with_context (suite, agent_controller, init_custom_header_calls_add_header);
  add_test_with_context (suite, agent_controller, init_custom_header_calls_without_token_add_header);
  add_test_with_context (suite, agent_controller, send_request_builds_url_and_calls_http_request);
  add_test_with_context (suite, agent_controller, send_request_returns_null_if_conn_is_null);
  add_test_with_context (suite, agent_controller, send_request_returns_null_if_protocol_missing);
  add_test_with_context (suite, agent_controller, send_request_returns_null_if_host_missing);
  add_test_with_context (suite, agent_controller, send_request_works_without_bearer_token);
  add_test_with_context (suite, agent_controller, parse_datetime_parses_valid_datetime);
  add_test_with_context (suite, agent_controller, parse_datetime_returns_zero_for_invalid_format);
  add_test_with_context (suite, agent_controller, parse_datetime_handles_missing_fractional_seconds);
  add_test_with_context (suite, agent_controller, parse_datetime_parses_leap_year_date);
  add_test_with_context (suite, agent_controller, parse_agent_with_minimal_fields);
  add_test_with_context (suite, agent_controller, parse_agent_with_config_and_server);
  add_test_with_context (suite, agent_controller, parse_agent_missing_optional_fields);
  add_test_with_context (suite, agent_controller, parse_agent_returns_null_on_null_input);
  add_test_with_context (suite, agent_controller, build_patch_payload_from_single_agent);
  add_test_with_context (suite, agent_controller, patch_payload_overrides_only_authorized_field);
  add_test_with_context (suite, agent_controller, patch_payload_overrides_only_min_interval);
  add_test_with_context (suite, agent_controller, patch_payload_overrides_only_schedule_config);
  add_test_with_context (suite, agent_controller, get_agents_returns_list_on_successful_response);
  add_test_with_context (suite, agent_controller, get_agents_returns_null_on_non_200_status);
  add_test_with_context (suite, agent_controller, get_agents_returns_null_on_invalid_json);
  add_test_with_context (suite, agent_controller, authorize_agents_succeeds_with_valid_input);
  add_test_with_context (suite, agent_controller, authorize_agents_fails_with_null_conn);
  add_test_with_context (suite, agent_controller, authorize_agents_fails_with_null_agents);
  add_test_with_context (suite, agent_controller, authorize_agents_fails_when_payload_is_null);
  add_test_with_context (suite, agent_controller, authorize_agents_fails_on_http_422);
  add_test_with_context (suite, agent_controller, update_agents_returns_zero_on_success);
  add_test_with_context (suite, agent_controller, update_agents_fails_with_null_connection);
  add_test_with_context (suite, agent_controller, update_agents_fails_with_null_agents);
  add_test_with_context (suite, agent_controller, update_agents_fails_with_null_update);
  add_test_with_context (suite, agent_controller, update_agents_fails_on_http_error_status);
  add_test_with_context (suite, agent_controller, delete_agents_returns_zero_on_success);
  add_test_with_context (suite, agent_controller, delete_agents_fails_with_null_conn);
  add_test_with_context (suite, agent_controller, delete_agents_fails_with_null_list);
  add_test_with_context (suite, agent_controller, delete_agents_fails_if_no_valid_ids);
  add_test_with_context (suite, agent_controller, delete_agents_fails_on_http_422);

  if (argc > 1)
    return run_single_test (suite, argv[1], create_text_reporter ());
  return run_test_suite (suite, create_text_reporter ());
}