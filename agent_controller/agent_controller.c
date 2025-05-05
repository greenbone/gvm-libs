/* SPDX-FileCopyrightText: 2019-2025 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file agent_controller.c
 * @brief Agent Controller client implementation for agent management.
 *
 * This module provides the implementation of functions for interacting with
 * an Agent Controller service. It supports:
 *
 * - Building and configuring connections with authentication and TLS options
 * - Creating, updating, authorizing, and deleting agent records
 * - Managing agent data structures like agent lists, configurations, and updates
 * - Memory-safe allocation and cleanup routines for agents and configurations
 *
 * The API abstracts the communication and management logic to simplify
 * higher-level applications interacting with managed agents.
 */

#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "libgvm agents"

#include "agent_controller.h"

#include "../http/httputils.h"
#include "../util/json.h"

#include <cjson/cJSON.h>
#include <stdio.h>
#include <time.h>

/**
 * @brief Struct holding the data for connecting with the agent controller.
 */
struct agent_controller_connector
{
  gchar *ca_cert;  /**< Path to CA certificate directory (if using HTTPS). */
  gchar *cert;     /**< Client certificate path. */
  gchar *key;      /**< Client private key path. */
  gchar *apikey;   /**< API key for authentication.(Optional) */
  gchar *host;     /**< Agent controller hostname or IP. */
  gint port;       /**< Port number of agent controller (default 8080?). */
  gchar *protocol; /**< "http" or "https". */
};

/**
 * @brief Initialize custom HTTP headers for Agent Controller requests.
 *
 * @param[in] bearer_token The Bearer token to use for Authorization (optional).
 * @param[in] content_type Whether to add "Content-Type: application/json" (TRUE/FALSE).
 *
 * @return A newly allocated `gvm_http_headers_t *` containing the headers.
 *         Must be freed with `gvm_http_headers_free()`.
 */
static gvm_http_headers_t *
init_custom_header (const gchar *bearer_token, gboolean content_type)
{
  gvm_http_headers_t *headers = gvm_http_headers_new ();

  // Set Authorization header if API key exists
  if (bearer_token && *bearer_token)
    {
      GString *auth = g_string_new ("Authorization: Bearer ");
      g_string_append (auth, bearer_token);

      if (!gvm_http_add_header (headers, auth->str))
        g_warning ("%s: Failed to set Authorization header", __func__);

      g_string_free (auth, TRUE);
    }

  // Set Content-Type: application/json
  if (content_type)
    {
      if (!gvm_http_add_header (headers, "Content-Type: application/json"))
        g_warning ("%s: Failed to set Content-Type header", __func__);
    }

  return headers;
}

/**
 * @brief Sends an HTTP(S) request to the agent-control server.
 *
 * @param[in] conn          The `agent_controller_connector_t` containing server and
 * certificate details.
 * @param[in] method        The HTTP method (GET, POST, PUT, etc.).
 * @param[in] path          The request path (e.g., "/api/v1/admin/agents").
 * @param[in] payload       Optional request body payload.
 * @param[in] bearer_token  Optional Bearer token for Authorization header.
 *
 * @return Pointer to a `gvm_http_response_t` containing status code and body.
 *         Must be freed using `gvm_http_response_cleanup()`.
 */
static gvm_http_response_t *
agent_controller_send_request (agent_controller_connector_t conn,
                               gvm_http_method_t method, const gchar *path,
                               const gchar *payload, const gchar *bearer_token)
{
  if (!conn)
    {
      g_warning ("%s: Missing connection", __func__);
      return NULL;
    }

  if (!conn->protocol || !conn->host || !path)
    {
      g_warning ("%s: Missing URL components", __func__);
      return NULL;
    }

  gchar *url = g_strdup_printf ("%s://%s:%d%s", conn->protocol, conn->host,
                                conn->port, path);

  gvm_http_headers_t *headers = init_custom_header (bearer_token, TRUE);

  gvm_http_response_t *http_response = gvm_http_request (
    url, method, payload, headers, conn->ca_cert, conn->cert, conn->key,
    NULL // No manual stream allocation
  );

  g_free (url);
  gvm_http_headers_free (headers);

  if (!http_response)
    {
      g_warning ("%s: HTTP request failed", __func__);
      return NULL;
    }

  return http_response;
}

/**
 * @brief Parse an ISO 8601 UTC datetime string into a time_t value.
 *
 * Parses a datetime string in the format "YYYY-MM-DDTHH:MM:SS.sssZ",
 * extracting the date and time components (ignoring milliseconds).
 * Returns the corresponding UTC time as a time_t value.
 *
 * @param[in] datetime_str The datetime string to parse.
 *
 * @return Parsed time as time_t, or 0 on failure.
 */
static time_t
parse_datetime(const char *datetime_str) {
  struct tm tm = {0};
  int milliseconds = 0;

  // Read year, month, day, hour, minute, second
  if (sscanf(datetime_str, "%4d-%2d-%2dT%2d:%2d:%2d.%dZ",
             &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
             &tm.tm_hour, &tm.tm_min, &tm.tm_sec, &milliseconds) != 7)
    {
      return (time_t) 0; // Failed
    }

  tm.tm_year -= 1900;
  tm.tm_mon -= 1;

  return timegm(&tm);
}

/**
 * @brief Parses a single agent JSON object into an agent_controller_agent_t.
 *
 * @param[in] item The cJSON object representing one agent.
 *
 * @return A newly allocated agent_controller_agent_t, or NULL if parsing fails.
 */
static agent_controller_agent_t
agent_controller_parse_agent (cJSON *item)
{
  if (!item)
    return NULL;

  agent_controller_agent_t agent = agent_controller_agent_new ();
  if (!agent)
    return NULL;

  const gchar *agent_id = gvm_json_obj_str (item, "agentid");
  const gchar *hostname = gvm_json_obj_str (item, "hostname");
  const gchar *conn_status = gvm_json_obj_str (item, "connection_status");
  const gchar *last_update_str = gvm_json_obj_str (item, "last_update");

  agent->agent_id = agent_id ? g_strdup (agent_id) : NULL;
  agent->hostname = hostname ? g_strdup (hostname) : NULL;
  agent->authorized = cJSON_IsTrue (cJSON_GetObjectItem (item, "authorized"));
  agent->min_interval = gvm_json_obj_int (item, "min_interval");
  agent->heartbeat_interval = gvm_json_obj_int (item, "heartbeat_interval");
  agent->connection_status = conn_status ? g_strdup (conn_status) : NULL;

  if (last_update_str && *last_update_str)
    {
      agent->last_update = parse_datetime (last_update_str);
    }
  else
    {
      agent->last_update = 0;
    }

  cJSON *ips_array = cJSON_GetObjectItem (item, "ip_addresses");
  if (ips_array && cJSON_IsArray (ips_array))
    {
      int ips_count = cJSON_GetArraySize (ips_array);
      agent->ip_address_count = ips_count;
      agent->ip_addresses = g_malloc0 (sizeof (gchar *) * (ips_count > 0 ? ips_count : 1));

      for (int j = 0; j < ips_count; ++j)
        {
          cJSON *ip_item = cJSON_GetArrayItem (ips_array, j);
          if (cJSON_IsString (ip_item))
            agent->ip_addresses[j] = g_strdup (ip_item->valuestring);
        }
    }

  cJSON *config_obj = cJSON_GetObjectItem (item, "config");
  if (config_obj && cJSON_IsObject (config_obj))
    {
      // Parse "schedule"
      cJSON *schedule_obj = cJSON_GetObjectItem (config_obj, "schedule");
      if (schedule_obj && cJSON_IsObject (schedule_obj))
        {
          const gchar *schedule_str =
            gvm_json_obj_str (schedule_obj, "schedule");
          if (schedule_str)
            {
              agent->schedule_config =
                g_malloc0 (sizeof (struct agent_controller_config_schedule));
              agent->schedule_config->schedule = g_strdup (schedule_str);
            }
        }

      // Parse "control-server"
      cJSON *server_obj = cJSON_GetObjectItem (config_obj, "control-server");
      if (server_obj && cJSON_IsObject (server_obj))
        {
          agent->server_config = g_malloc0 (sizeof (struct agent_controller_config_server));

          const gchar *base_url = gvm_json_obj_str (server_obj, "base_url");
          const gchar *server_agent_id = gvm_json_obj_str (server_obj, "agent_id");
          const gchar *token = gvm_json_obj_str (server_obj, "token");
          const gchar *server_cert_hash = gvm_json_obj_str (server_obj, "server_cert_hash");

          agent->server_config->base_url = base_url ? g_strdup (base_url) : NULL;
          agent->server_config->agent_id = server_agent_id ? g_strdup (server_agent_id) : NULL;
          agent->server_config->token = token ? g_strdup (token) : NULL;
          agent->server_config->server_cert_hash = server_cert_hash ? g_strdup (server_cert_hash) : NULL;
        }
    }

  return agent;
}

/**
 * @brief Build a JSON payload for updating agents.
 *
 * @param[in] agents List of agents to include in the payload.
 * @param[in] update Optional update template to override agent fields.
 *
 * @return A newly allocated JSON string (unformatted) representing the update payload.
 *         The caller is responsible for freeing the returned string using `g_free()`.
 */
static gchar *
agent_controller_build_patch_payload (agent_controller_agent_list_t agents,
                                      agent_controller_agent_update_t update)
{
  if (!agents || agents->count <=0)
    return NULL;

  cJSON *patch_body = cJSON_CreateObject ();

  for (int i = 0; i < agents->count; ++i)
    {
      agent_controller_agent_t agent = agents->agents[i];
      if (!agent || !agent->agent_id)
        continue;

      cJSON *agent_obj = cJSON_CreateObject ();

      // authorized
      int use_authorized = agent->authorized;
      if (update && update->authorized != -1)
        use_authorized = update->authorized;
      cJSON_AddBoolToObject(agent_obj, "authorized", use_authorized);

      // min_interval
      int use_min_interval = agent->min_interval;
      if (update && update->min_interval != -1)
        use_min_interval = update->min_interval;
      cJSON_AddNumberToObject(agent_obj, "min_interval", use_min_interval);

      // heartbeat_interval
      int use_heartbeat_interval = agent->heartbeat_interval;
      if (update && update->heartbeat_interval != -1)
        use_heartbeat_interval = update->heartbeat_interval;
      cJSON_AddNumberToObject(agent_obj, "heartbeat_interval", use_heartbeat_interval);

      // Config block
      cJSON *config_obj = NULL;

      // Use schedule override if given, else agent's own
      agent_controller_config_schedule_t schedule_to_use =
        (update && update->schedule_config) ? update->schedule_config
                                            : agent->schedule_config;
      if (schedule_to_use && schedule_to_use->schedule)
        {
          config_obj = cJSON_CreateObject ();

          cJSON *schedule_obj = cJSON_CreateObject ();
          cJSON_AddStringToObject (schedule_obj, "schedule",
                                   schedule_to_use->schedule);
          cJSON_AddItemToObject (config_obj, "schedule", schedule_obj);
        }

      if (config_obj)
        {
          cJSON_AddItemToObject (agent_obj, "config", config_obj);
        }

      cJSON_AddItemToObject (patch_body, agent->agent_id, agent_obj);
    }

  gchar *payload = cJSON_PrintUnformatted (patch_body);
  cJSON_Delete (patch_body);

  return payload;
}

/**
 * @brief Creates a new Agent Controller connector.
 */
agent_controller_connector_t
agent_controller_connector_new (void)
{
  agent_controller_connector_t connector;

  connector = g_malloc0 (sizeof (struct agent_controller_connector));
  if (!connector)
    return NULL;

  return connector;
}

/**
 * @brief Frees an Agent Controller connector.
 *
 * @param[in] connector Connector to be freed
 */
void
agent_controller_connector_free (agent_controller_connector_t connector)
{
  if (!connector)
    return;

  g_free (connector->ca_cert);
  g_free (connector->cert);
  g_free (connector->key);
  g_free (connector->host);
  g_free (connector->apikey);
  g_free (connector->protocol);

  g_free (connector);
}

/**
 * @brief Configures a connector with an option and its value.
 *
 * @param[in] conn Connector to configure
 * @param[in] opt Option type
 * @param[in] val Value to assign (expected type depends on the option)
 *
 * @return AGENT_CONTROLLER_OK on success, error code otherwise
 */
agent_controller_error_t
agent_controller_connector_builder (agent_controller_connector_t conn,
                                    agent_controller_connector_opts_t opt,
                                    const void *val)
{
  if (conn == NULL || val == NULL)
    return AGENT_CONTROLLER_INVALID_VALUE;

  switch (opt)
    {
    case AGENT_CONTROLLER_CA_CERT:
      conn->ca_cert = g_strdup ((const gchar *) val);
      break;
    case AGENT_CONTROLLER_CERT:
      conn->cert = g_strdup ((const gchar *) val);
      break;
    case AGENT_CONTROLLER_KEY:
      conn->key = g_strdup ((const gchar *) val);
      break;
    case AGENT_CONTROLLER_API_KEY:
      conn->apikey = g_strdup ((const gchar *) val);
      break;
    case AGENT_CONTROLLER_PROTOCOL:
      if (g_strcmp0 ((const gchar *) val, "http") != 0
          && g_strcmp0 ((const gchar *) val, "https") != 0)
        return AGENT_CONTROLLER_INVALID_VALUE;
      conn->protocol = g_strdup ((const gchar *) val);
      break;
    case AGENT_CONTROLLER_HOST:
      conn->host = g_strdup ((const gchar *) val);
      break;
    case AGENT_CONTROLLER_PORT:
      conn->port = *((const int *) val);
      break;
    default:
      return AGENT_CONTROLLER_INVALID_OPT;
    }

  return AGENT_CONTROLLER_OK;
}

/**
 * @brief Allocates and initializes a new agent structure.
 *
 * @return agent_controller_agent_t pointer
 */
agent_controller_agent_t
agent_controller_agent_new (void)
{
  agent_controller_agent_t agent = g_malloc0 (sizeof (struct agent_controller_agent));
  return agent;
}

/**
 * @brief Frees an agent structure.
 *
 * @param[in] agent to be freed
 */
void
agent_controller_agent_free (agent_controller_agent_t agent)
{
  if (!agent)
    return;

  g_free (agent->agent_id);
  g_free (agent->hostname);
  g_free (agent->connection_status);

  if (agent->ip_addresses)
    {
      for (int i = 0; i < agent->ip_address_count; ++i)
        g_free (agent->ip_addresses[i]);
      g_free (agent->ip_addresses);
    }

  if (agent->schedule_config)
    {
      agent_controller_config_schedule_free (agent->schedule_config);
    }

  if (agent->server_config)
    {
      agent_controller_config_server_free (agent->server_config);
    }

  g_free (agent);
}

/**
 * @brief Allocates a new list to hold a specified number of agents.
 *
 * @param[in] count Number of agents the list should hold
 *
 * @return agent_controller_agent_list_t
 */
agent_controller_agent_list_t
agent_controller_agent_list_new (int count)
{
  if (count <= 0)
    return NULL;

  agent_controller_agent_list_t list =
    g_malloc0 (sizeof (struct agent_controller_agent_list));
  list->count = count;
  list->agents = g_malloc0 (sizeof (agent_controller_agent_t) * count);
  return list;
}

/**
 * @brief Frees an agent list structure.
 *
 * @param[in] list to be freed
 */
void
agent_controller_agent_list_free (agent_controller_agent_list_t list)
{
  if (!list)
    return;

  if (list->agents)
    {
      for (int i = 0; i < list->count; ++i)
        agent_controller_agent_free (list->agents[i]);
      g_free (list->agents);
    }

  g_free (list);
}

/**
 * @brief Allocates and initializes a new agent update structure.
 *
 * @return agent_controller_agent_update_t pointer
 */
agent_controller_agent_update_t
agent_controller_agent_update_new (void)
{
  agent_controller_agent_update_t update = g_malloc0 (sizeof(struct agent_controller_agent_update));
  if (!update)
    return NULL;

  update->authorized = -1;
  update->min_interval = -1;
  update->heartbeat_interval = -1;
  update->schedule_config = NULL;

  return update;
}

/**
 * @brief Frees an agent update structure.
 *
 * @param[in] update to be freed
 */
void
agent_controller_agent_update_free (agent_controller_agent_update_t update)
{
  if (!update)
    return;

  if (update->schedule_config)
    {
      agent_controller_config_schedule_free (update->schedule_config);
    }

  g_free (update);
}

/**
 * @brief Allocates and initializes a new schedule configuration.
 *
 * @return agent_controller_config_schedule_t pointer
 */
agent_controller_config_schedule_t
agent_controller_config_schedule_new (void)
{
  return g_malloc0 (sizeof(struct agent_controller_config_schedule));
}

/**
 * @brief Frees a schedule configuration structure.
 *
 * @param[in] schedule to be freed
 */
void
agent_controller_config_schedule_free (agent_controller_config_schedule_t schedule)
{
  if (!schedule)
    return;

  g_free (schedule->schedule);

  g_free (schedule);
}

/**
 * @brief Allocates and initializes a new server configuration.
 *
 * @return agent_controller_config_server_t pointer
 */
agent_controller_config_server_t
agent_controller_config_server_new (void)
{
  return g_malloc0 (sizeof(struct agent_controller_config_server));
}

/**
 * @brief Frees a server configuration structure.
 *
 * @param server to be freed
 */
void
agent_controller_config_server_free (agent_controller_config_server_t server)
{
  if (!server)
    return;

  g_free(server->base_url);
  g_free(server->agent_id);
  g_free(server->token);
  g_free(server->server_cert_hash);

  g_free(server);
}

/**
 * @brief Fetches the list of agents from the Agent Controller.
 *
 * @param[in] conn Active connector to the Agent Controller
 *
 * @return List of agents on success, NULL on failure
 */
agent_controller_agent_list_t
agent_controller_get_agents (agent_controller_connector_t conn)
{
  if (!conn)
    {
      g_warning ("%s: Connector is NULL", __func__);
      return NULL;
    }

  gvm_http_response_t *response = agent_controller_send_request (
    conn,
    GET,
    "/api/v1/admin/agents",
    NULL,
    conn->apikey
  );

  if (!response)
    {
      g_warning ("%s: Failed to get response", __func__);
      return NULL;
    }

  if (response->http_status != 200)
    {
      g_warning ("%s: Received HTTP status %ld", __func__,
                 response->http_status);
      gvm_http_response_cleanup (response);
      return NULL;
    }

  cJSON *root = cJSON_Parse (response->data);
  if (!root || !cJSON_IsArray (root))
    {
      g_warning ("%s: Failed to parse JSON array", __func__);
      if (root)
        cJSON_Delete (root);
      gvm_http_response_cleanup (response);
      return NULL;
    }

  int count = cJSON_GetArraySize (root);
  agent_controller_agent_list_t agent_list = agent_controller_agent_list_new (count);

  if (!agent_list)
    {
      g_warning ("%s: Failed to initialize Agent List. Count: %d", __func__, count);
      return NULL;
    }

  int valid_index = 0;
  for (int i = 0; i < count; ++i)
    {
      cJSON *item = cJSON_GetArrayItem (root, i);
      agent_controller_agent_t agent = agent_controller_parse_agent (item);
      if (agent)
        agent_list->agents[valid_index++] = agent;
    }
  agent_list->count = valid_index;

  cJSON_Delete (root);
  gvm_http_response_cleanup (response);

  return agent_list;
}

/**
 * @brief Authorizes a list of agents.
 *
 * @param[in] conn Active connector
 * @param[in] agents List of agents to authorize
 *
 * @return RESP_CODE_OK (0) on success, RESP_CODE_ERR (-1) on failure
 */
int
agent_controller_authorize_agents (agent_controller_connector_t conn,
                                   agent_controller_agent_list_t agents)
{
  if (!conn || !agents)
    {
      g_warning ("%s: Invalid connection or agent list", __func__);
      return -1;
    }

  agent_controller_agent_update_t update = agent_controller_agent_update_new ();
  if (!update)
    {
      g_warning ("%s: Failed to allocate update override", __func__);
      return -1;
    }

  update->authorized = 1;          // Force authorized = 1
  update->min_interval = -1;       // No override
  update->heartbeat_interval = -1; // No override
  update->schedule_config = NULL;  // No schedule override

  gchar *payload = agent_controller_build_patch_payload (agents, update);
  agent_controller_agent_update_free (update);

  if (!payload)
    {
      g_warning ("%s: Failed to build PATCH payload", __func__);
      return -1;
    }

  gvm_http_response_t *response = agent_controller_send_request (
    conn,
    PATCH,
    "/api/v1/admin/agents",
    payload,
    conn->apikey
  );

  g_free (payload);

  if (!response)
    {
      g_warning ("%s: Failed to get response", __func__);
      return -1;
    }

  if (response->http_status != 200)
    {
      g_warning ("%s: Received HTTP status %ld", __func__, response->http_status);
      gvm_http_response_cleanup (response);
      return -1;
    }

  gvm_http_response_cleanup (response);

  return 0;
}

/**
 * @brief Updates properties of a list of agents.
 *
 * @param[in] conn Active connector
 * @param[in] agents List of agents to update
 * @param[in] update Update information
 *
 * @return RESP_CODE_OK (0) on success, RESP_CODE_ERR (-1) on failure
 */
int
agent_controller_update_agents (agent_controller_connector_t conn,
                                agent_controller_agent_list_t agents,
                                agent_controller_agent_update_t update)
{
  if (!conn || !agents || !update)
    {
      g_warning ("%s: Invalid connection, agent list, or update override", __func__);
      return -1;
    }

  gchar *payload = agent_controller_build_patch_payload (agents, update);
  if (!payload)
    {
      g_warning("%s: Failed to build PATCH payload", __func__);
      return -1;
    }

  gvm_http_response_t *response = agent_controller_send_request (
    conn,
    PATCH,
    "/api/v1/admin/agents",
    payload,
    conn->apikey
  );

  g_free (payload);

  if (!response)
    {
      g_warning ("%s: Failed to get response", __func__);
      return -1;
    }

  if (response->http_status != 200)
    {
      g_warning ("%s: Received HTTP status %ld", __func__, response->http_status);
      gvm_http_response_cleanup (response);
      return -1;
    }

  gvm_http_response_cleanup (response);

  return 0;
}

/**
 * @brief Deletes a list of agents.
 *
 * @param[in] conn Active connector
 * @param[in] agents List of agents to delete
 *
 * @return RESP_CODE_OK (0) on success, RESP_CODE_ERR (-1) on failure
 */
int
agent_controller_delete_agents (agent_controller_connector_t conn,
                                agent_controller_agent_list_t agents)
{
  if (!conn || !agents)
    {
      g_warning ("%s: Invalid connection or agent list", __func__);
      return -1;
    }

  cJSON *payload_array = cJSON_CreateArray ();
  if (!payload_array)
    {
      g_warning("%s: Failed to create JSON array", __func__);
      return -1;
    }

  for (int i = 0; i < agents->count; ++i)
    {
      agent_controller_agent_t agent = agents->agents[i];
      if (agent && agent->agent_id)
        {
          cJSON_AddItemToArray (payload_array, cJSON_CreateString(agent->agent_id));
        }
    }

  gchar *payload = cJSON_PrintUnformatted (payload_array);
  cJSON_Delete (payload_array);

  if (!payload)
    {
      g_warning ("%s: Failed to build JSON payload", __func__);
      return -1;
    }

  gvm_http_response_t *response = agent_controller_send_request (
    conn,
    POST,
    "/api/v1/admin/agents/delete",
    payload,
    conn->apikey
  );

  g_free (payload);

  if (!response)
    {
      g_warning ("%s: Failed to get response", __func__);
      return -1;
    }

  if (response->http_status != 200)
    {
      g_warning ("%s: Received HTTP status %ld", __func__, response->http_status);
      gvm_http_response_cleanup (response);
      return -1;
    }

  gvm_http_response_cleanup (response);

  return 0;
}