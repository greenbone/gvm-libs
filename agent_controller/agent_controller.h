/* SPDX-FileCopyrightText: 2019-2025 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file agent_controller.h
 * @brief Agent Controller client API for managing agents over HTTP(S).
 *
 * This module provides a high-level API for interacting with an Agent
 * Controller service. It includes functionalities for:
 *
 * - Building and managing connector configurations (e.g., certificates, API
 * keys, etc.)
 * - Creating, updating, authorizing, and deleting agent entries
 * - Managing agent lists and updating their configuration schedules and servers
 * - Allocating and freeing data structures associated with agents and their
 * updates
 *
 * Core data structures:
 * - `agent_controller_connector_t`: Handles connection settings for the Agent
 * Controller
 * - `agent_controller_agent_t`: Represents a single agent with its metadata
 * - `agent_controller_agent_list_t`: Holds a collection of agents
 * - `agent_controller_agent_update_t`: Represents update parameters for agents
 * - `agent_controller_config_schedule_t`: Represents agent scheduling settings
 * - `agent_controller_config_server_t`: Represents server configuration for an
 * agent
 */

#ifndef AGENT_CONTROLLER_H
#define AGENT_CONTROLLER_H

#include <glib.h>

#define AGENT_RESP_ERR -1 ///< Generic error response code
#define AGENT_RESP_OK 0   ///< Generic success response code

/**
 * @brief Agent Controller options for the connector
 */
typedef enum
{
  AGENT_CONTROLLER_CA_CERT,  /**< Path to the CA certificate directory */
  AGENT_CONTROLLER_CERT,     /**< Client certificate file */
  AGENT_CONTROLLER_KEY,      /**< Client private key file */
  AGENT_CONTROLLER_API_KEY,  /**< API key for authentication  */
  AGENT_CONTROLLER_PROTOCOL, /**< "http" or "https" */
  AGENT_CONTROLLER_HOST,     /**< Hostname or IP address */
  AGENT_CONTROLLER_PORT      /**< Port number */
} agent_controller_connector_opts_t;

/**
 * @brief Error codes for Agent Controller operations.
 */
typedef enum
{
  AGENT_CONTROLLER_OK = 0,            /**< No error */
  AGENT_CONTROLLER_INVALID_OPT = -1,  /**< Invalid option specified */
  AGENT_CONTROLLER_INVALID_VALUE = -2 /**< Invalid value specified */
} agent_controller_error_t;

/**
 * @brief Struct for agent scheduling configuration.
 */
struct agent_controller_config_schedule
{
  gchar *schedule; ///< Schedule expression, e.g., "@every 12h"
};
typedef struct agent_controller_config_schedule
  *agent_controller_config_schedule_t;

/**
 * @brief Struct for agent server configuration.
 */
struct agent_controller_config_server
{
  gchar *base_url;         ///< Base URL of the agent control server
  gchar *agent_id;         ///< Agent ID assigned by the scan-agent
  gchar *token;            ///< Authentication token
  gchar *server_cert_hash; ///< Server certificate fingerprint or hash
};
typedef struct agent_controller_config_server *agent_controller_config_server_t;

/**
 * @brief Struct representing an individual agent.
 */
struct agent_controller_agent
{
  gchar *agent_id;  ///< Unique agent identifier
  gchar *hostname;  ///< Hostname of the agent machine
  int authorized;   ///< Authorization status (1: authorized, 0: unauthorized)
  int min_interval; ///< Minimum update interval in seconds
  int heartbeat_interval;   ///< Heartbeat reporting interval
  gchar *connection_status; ///< Connection status ("active"or "inactive")
  gchar **ip_addresses;     ///< List of IP addresses
  int ip_address_count;     ///< Number of IP addresses
  time_t last_update; ///< Timestamp of the last update (seconds since epoch)
  agent_controller_config_schedule_t
    schedule_config; ///< Agent schedule configuration
  agent_controller_config_server_t server_config; ///< Server configuration
                                                  ///< associated with the agent
};
typedef struct agent_controller_agent *agent_controller_agent_t;

/**
 * @brief Struct representing a list of agents.
 */
struct agent_controller_agent_list
{
  int count;                        ///< Number of agents in the list
  agent_controller_agent_t *agents; ///< Array of pointers to agents
};
typedef struct agent_controller_agent_list *agent_controller_agent_list_t;

/**
 * @brief Struct representing an agent update configuration.
 */
struct agent_controller_agent_update
{
  int authorized;         ///< Authorization status for update
  int min_interval;       ///< New minimum interval
  int heartbeat_interval; ///< New heartbeat interval
  agent_controller_config_schedule_t
    schedule_config; ///< New schedule configuration
};
typedef struct agent_controller_agent_update *agent_controller_agent_update_t;

/**
 * @brief The struct representing a connector to the Agent Controller service.
 */
typedef struct agent_controller_connector *agent_controller_connector_t;

agent_controller_connector_t
agent_controller_connector_new (void);

agent_controller_error_t
agent_controller_connector_builder (agent_controller_connector_t conn,
                                    agent_controller_connector_opts_t opt,
                                    const void *val);

void
agent_controller_connector_free (agent_controller_connector_t connector);

agent_controller_agent_t
agent_controller_agent_new (void);

void
agent_controller_agent_free (agent_controller_agent_t agent);

agent_controller_agent_list_t
agent_controller_agent_list_new (int count);

void
agent_controller_agent_list_free (agent_controller_agent_list_t list);

agent_controller_agent_update_t
agent_controller_agent_update_new (void);

void
agent_controller_agent_update_free (agent_controller_agent_update_t update);

agent_controller_config_schedule_t
agent_controller_config_schedule_new (void);

void
agent_controller_config_schedule_free (
  agent_controller_config_schedule_t schedule);

agent_controller_config_server_t
agent_controller_config_server_new (void);

void
agent_controller_config_server_free (agent_controller_config_server_t server);

agent_controller_agent_list_t
agent_controller_get_agents (agent_controller_connector_t conn);

int
agent_controller_authorize_agents (agent_controller_connector_t conn,
                                   agent_controller_agent_list_t agents);

int
agent_controller_update_agents (agent_controller_connector_t conn,
                                agent_controller_agent_list_t agents,
                                agent_controller_agent_update_t update);

int
agent_controller_delete_agents (agent_controller_connector_t conn,
                                agent_controller_agent_list_t agents);

#endif // AGENT_CONTROLLER_H
