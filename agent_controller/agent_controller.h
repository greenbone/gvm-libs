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

#ifndef _GVM_AGENT_CONTROLLER_AGENT_CONTROLLER_H
#define _GVM_AGENT_CONTROLLER_AGENT_CONTROLLER_H

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
 * @brief Retry settings under agent_control.
 */
struct agent_controller_retry_cfg
{
  int attempts;         ///< Max retry attempts before giving up (e.g., 5)
  int delay_in_seconds; ///< Base delay between retries in seconds (e.g., 60)
  int max_jitter_in_seconds; ///< Random jitter added to delay to avoid
  ///< stampedes (0..max)
};

/**
 * @brief agent_control block.
 */
struct agent_controller_agent_control_cfg
{
  struct agent_controller_retry_cfg retry; ///< Retry/backoff policy
};

/**
 * @brief agent_script_executor block.
 */
struct agent_controller_script_exec_cfg
{
  int bulk_size;                ///< Number of scripts/tasks processed per batch
  int bulk_throttle_time_in_ms; ///< Throttle/sleep between batches in
  ///< milliseconds
  int indexer_dir_depth; ///< Max directory depth to scan/index

  GPtrArray *scheduler_cron_time; ///< Optional list of cron expressions
  ///< Format: standard 5-field cron like
  /// "0 23 * * *"
};

/**
 * @brief heartbeat block.
 */
struct agent_controller_heartbeat_cfg
{
  int interval_in_seconds; ///< Agent heartbeat interval in seconds (e.g., 600)
  int miss_until_inactive; ///< Missed heartbeats before marking agent inactive
  ///< (e.g., 1)
};

/**
 * @brief Top-level scan agent config.
 *
 * Groups all configuration sections for the scan agent service.
 */
struct agent_controller_scan_agent_config
{
  struct agent_controller_agent_control_cfg agent_control;
  struct agent_controller_script_exec_cfg agent_script_executor;
  struct agent_controller_heartbeat_cfg heartbeat;
};

typedef struct agent_controller_scan_agent_config
  *agent_controller_scan_agent_config_t;

/**
 * @brief Struct representing an individual agent.
 */
struct agent_controller_agent
{
  gchar *agent_id; ///< Unique agent identifier
  gchar *hostname; ///< Hostname of the agent machine
  int authorized;  ///< Authorization status (1: authorized, 0: unauthorized)
  gchar *connection_status; ///< Connection status ("active"or "inactive")
  gchar **ip_addresses;     ///< List of IP addresses
  int ip_address_count;     ///< Number of IP addresses
  time_t last_update; ///< Timestamp of the last update (seconds since epoch)
  time_t last_updater_heartbeat; ///< Timestamp of the last updater
                                 ///  (seconds since epoch)
  agent_controller_scan_agent_config_t config; ///< agent scan config

  gchar *updater_version;  ///< Updater version string (may be empty)
  gchar *agent_version;    ///< Agent version string (may be empty)
  gchar *operating_system; ///< OS string (may be empty)
  gchar *architecture; ///< Architecture string (e.g., "amd64", may be empty)

  int update_to_latest;         ///< 1: update to latest, 0: do not
  int agent_update_available;   ///< 1 agent update available, 0 do not
  int updater_update_available; ///< 1 updater update available, 0 do not
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
  int authorized;       ///< Authorization status for update
  int update_to_latest; ///< Automatically update the agent
                        ///  to the latest available version.
  agent_controller_scan_agent_config_t config; ///< The Agent scan configuration
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

agent_controller_scan_agent_config_t
agent_controller_scan_agent_config_new (void);

void
agent_controller_scan_agent_config_free (
  agent_controller_scan_agent_config_t cfg);

agent_controller_agent_list_t
agent_controller_get_agents (agent_controller_connector_t conn);

int
agent_controller_update_agents (agent_controller_connector_t conn,
                                agent_controller_agent_list_t agents,
                                agent_controller_agent_update_t update,
                                GPtrArray **errors);

int
agent_controller_delete_agents (agent_controller_connector_t conn,
                                agent_controller_agent_list_t agents);

agent_controller_scan_agent_config_t
agent_controller_get_scan_agent_config (agent_controller_connector_t conn);

int
agent_controller_update_scan_agent_config (
  agent_controller_connector_t conn, agent_controller_scan_agent_config_t cfg,
  GPtrArray **errors);

agent_controller_agent_list_t
agent_controller_get_agents_with_updates (agent_controller_connector_t conn);

gchar *
agent_controller_convert_scan_agent_config_string (
  agent_controller_scan_agent_config_t cfg);

agent_controller_scan_agent_config_t
agent_controller_parse_scan_agent_config_string (const gchar *config);

gchar *
agent_controller_build_create_scan_payload (
  agent_controller_agent_list_t agents);

gchar *
agent_controller_get_scan_id (const gchar *body);

#endif /* not _GVM_AGENT_CONTROLLER_AGENT_CONTROLLER_H */
