/* SPDX-FileCopyrightText: 2026 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "ad_connector.c"

#include <cgreen/cgreen.h>
#include <glib.h>

Describe (ad_connector);

static gvm_ldap_return_t stub_open_ret;
static gvm_ldap_return_t stub_bind_ret;
static gvm_ldap_connection_t *stub_open_connection;

static gint stub_open_calls;
static gint stub_bind_calls;
static gint stub_close_calls;

static gchar *stub_last_open_host;
static gint stub_last_open_port;
static gvm_ldap_tls_mode_t stub_last_open_tls_mode;
static guint stub_last_open_network_timeout;
static guint stub_last_open_operation_timeout;
static gchar *stub_last_bind_dn;
static gchar *stub_last_bind_password;

static gchar *stub_last_entry_dn;
static gchar *stub_last_entry_name;

static gvm_ldap_return_t stub_search_paged_ret;
static gboolean stub_search_params_new_returns_null;
static gint stub_search_paged_calls;

static GHashTable *stub_entry_attributes;

/* -------------------- Mock Functions -------------------- */
gvm_ldap_return_t
gvm_ldap_open (gvm_ldap_connection_t **connection,
               const gchar *host,
               gint port,
               const gchar *cacert_file,
               gvm_ldap_tls_mode_t tls_mode,
               guint network_timeout,
               guint operation_timeout)
{
  (void) cacert_file;
  stub_open_calls++;
  g_free (stub_last_open_host);
  stub_last_open_host = g_strdup (host);
  stub_last_open_port = port;
  stub_last_open_tls_mode = tls_mode;
  stub_last_open_network_timeout = network_timeout;
  stub_last_open_operation_timeout = operation_timeout;

  if (stub_open_ret == GVM_LDAP_SUCCESS)
  {
    if (stub_open_connection == NULL)
    stub_open_connection = (gvm_ldap_connection_t *) 0x1234;
    *connection = stub_open_connection;
  }
  return stub_open_ret;
}

gvm_ldap_return_t
gvm_ldap_bind_simple (gvm_ldap_connection_t *connection,
                      const gchar *bind_dn,
                      const gchar *password)
{
  (void) connection;

  stub_bind_calls++;
  g_free (stub_last_bind_dn);
  g_free (stub_last_bind_password);
  stub_last_bind_dn = g_strdup (bind_dn);
  stub_last_bind_password = g_strdup (password);
  return stub_bind_ret;
}

void
gvm_ldap_close (gvm_ldap_connection_t *connection)
{
  (void) connection;

  stub_close_calls++;
}

gchar *
gvm_ldap_entry_get_dn (gvm_ldap_entry_t *entry)
{
  (void) (entry);

  return stub_last_entry_dn ? g_strdup (stub_last_entry_dn) : NULL;
}

gchar *
gvm_ldap_entry_get_string (gvm_ldap_entry_t *entry, const gchar *attribute)
{
  (void) (entry);

  if (!attribute || g_ascii_strcasecmp (attribute, "name") != 0)
    return NULL;

  return stub_last_entry_name ? g_strdup (stub_last_entry_name) : NULL;
}

gvm_ldap_search_params_t *
gvm_ldap_search_params_new (const gchar *base_dn,
                            gvm_ldap_scope_t scope,
                            const gchar *filter,
                            gchar **attributes,
                            guint page_size,
                            guint size_limit,
                            guint timeout_seconds)
{
  (void) base_dn;
  (void) scope;
  (void) filter;
  (void) attributes;
  (void) page_size;
  (void) size_limit;
  (void) timeout_seconds;

  if (stub_search_params_new_returns_null)
    return NULL;

  return g_malloc0 (sizeof (gvm_ldap_search_params_t));
}

void
gvm_ldap_search_params_free (gvm_ldap_search_params_t *params)
{
  g_free (params);
}

gvm_ldap_return_t
gvm_ldap_search_paged (gvm_ldap_connection_t *connection,
                       const gvm_ldap_search_params_t *search_params,
                       gvm_ldap_search_callback_t callback,
                       gpointer user_data)
{
  (void) connection;
  (void) search_params;
  (void) callback;
  (void) user_data;

  stub_search_paged_calls++;
  return stub_search_paged_ret;
}

/* -------------------- Helper Functions -------------------- */

static void
reset_ldap_stubs (void)
{
  stub_open_ret = GVM_LDAP_SUCCESS;
  stub_bind_ret = GVM_LDAP_SUCCESS;
  stub_open_connection = (gvm_ldap_connection_t *) 0x1234;

  stub_open_calls = 0;
  stub_bind_calls = 0;
  stub_close_calls = 0;

  g_free (stub_last_open_host);
  stub_last_open_host = NULL;
  stub_last_open_port = 0;
  stub_last_open_tls_mode = GVM_LDAP_TLS_LDAPS;
  stub_last_open_network_timeout = 0;
  stub_last_open_operation_timeout = 0;

  g_free (stub_last_bind_dn);
  stub_last_bind_dn = NULL;

  g_free (stub_last_bind_password);
  stub_last_bind_password = NULL;

  g_free (stub_last_entry_dn);
  stub_last_entry_dn = NULL;
  g_free (stub_last_entry_name);
  stub_last_entry_name = NULL;

  stub_search_paged_ret = GVM_LDAP_SUCCESS;
  stub_search_paged_calls = 0;
  stub_search_params_new_returns_null = FALSE;
}

static void
set_valid_connection_config (ad_connector_t connector)
{
  const gchar *host = "ad.example.org";
  const gchar *bind_dn = "CN=svc,DC=example,DC=org";
  gint network_timeout = 12;
  gint operation_timeout = 34;

  assert_that (ad_connector_builder (connector,
                                     AD_CONNECTOR_OPT_HOST, host),
               is_equal_to (AD_CONNECTOR_OK));
  assert_that (ad_connector_builder (connector,
                                     AD_CONNECTOR_OPT_BIND_DN,
                                     bind_dn),
               is_equal_to (AD_CONNECTOR_OK));
  assert_that (ad_connector_builder (connector,
                                     AD_CONNECTOR_OPT_NETWORK_TIMEOUT,
                                     &network_timeout),
               is_equal_to (AD_CONNECTOR_OK));
  assert_that (ad_connector_builder (connector,
                                     AD_CONNECTOR_OPT_OPERATION_TIMEOUT,
                                     &operation_timeout),
               is_equal_to (AD_CONNECTOR_OK));
}

static gchar *
make_entry_attr_key (gvm_ldap_entry_t *entry, const gchar *attribute)
{
  return g_strdup_printf ("%p|%s", (void *) entry,
                          attribute ? attribute : "");
}

static void
ptr_array_free_cb (gpointer data)
{
  if (data)
   g_ptr_array_free ((GPtrArray *) data, TRUE);
}

static void
stub_set_entry_attr_values (gvm_ldap_entry_t *entry,
                            const gchar *attribute,
                            const gchar *v1,
                            const gchar *v2,
                            const gchar *v3)
{
  gchar *key;
  GPtrArray *values;

  if (!stub_entry_attributes || !entry || !attribute)
    return;

  key = make_entry_attr_key (entry, attribute);
  values = g_ptr_array_new_with_free_func (g_free);

  if (v1)
    g_ptr_array_add (values, g_strdup (v1));
  if (v2)
    g_ptr_array_add (values, g_strdup (v2));
  if (v3)
    g_ptr_array_add (values, g_strdup (v3));

  g_hash_table_replace (stub_entry_attributes, key, values);
}

GPtrArray *
gvm_ldap_entry_get_strings (gvm_ldap_entry_t *entry, const gchar *attribute)
{
  gchar *key;
  GPtrArray *stored;
  GPtrArray *copy;

  if (!stub_entry_attributes || !entry || !attribute)
    return NULL;
  key = make_entry_attr_key (entry, attribute);
  stored = g_hash_table_lookup (stub_entry_attributes, key);
  g_free (key);

  if (!stored)
    return NULL;

  copy = g_ptr_array_new_with_free_func (g_free);
  for (guint i = 0; i < stored->len; i++)
  {
    const gchar *value = g_ptr_array_index (stored, i);
    g_ptr_array_add (copy, g_strdup (value));
  }
  return copy;
}

typedef struct
{
  guint calls;
  ad_object_type_t last_type;
  gchar *last_name;
} mock_callback_context_t;

static ad_object_callback_result_t
mock_callback_continue (ad_object_t *object, gpointer user_data)
{
  mock_callback_context_t *probe = user_data;

  if (!probe || !object)
    return AD_OBJECT_CALLBACK_ERROR;

  probe->calls++;
  probe->last_type = object->type;

  g_free (probe->last_name);
  probe->last_name = object->name ? g_strdup (object->name) : NULL;

  return AD_OBJECT_CALLBACK_CONTINUE;
}

static ad_object_callback_result_t
mock_callback_error (ad_object_t *object, gpointer user_data)
{
  mock_callback_context_t *probe = user_data;

  if (probe && object)
    probe->calls++;

  return AD_OBJECT_CALLBACK_ERROR;
}

static ad_object_callback_result_t
mock_callback_invalid_enum (ad_object_t *object, gpointer user_data)
{
  mock_callback_context_t *probe = user_data;

  if (probe && object)
    probe->calls++;

  return (ad_object_callback_result_t) 999;
}

static guint
attr_list_count (gchar **attributes, const gchar *attr)
{
  guint i;
  guint count = 0;

  if (!attributes || !attr)
    return 0;

  for (i = 0; attributes[i]; i++)
    {
      if (g_ascii_strcasecmp (attributes[i], attr) == 0)
        count++;
    }

  return count;
}

static ad_object_callback_result_t
dummy_object_callback (ad_object_t *object, gpointer user_data)
{
  (void) object;
  (void) user_data;
  return AD_OBJECT_CALLBACK_CONTINUE;
}
/* -------------------- End of helper Functions -------------------- */

BeforeEach (ad_connector)
{
  reset_ldap_stubs ();
  stub_entry_attributes = g_hash_table_new_full (g_str_hash,
                                                 g_str_equal,
                                                 g_free,
                                                 ptr_array_free_cb);
}

AfterEach (ad_connector)
{
  g_free (stub_last_open_host);
  stub_last_open_host = NULL;

  g_free (stub_last_bind_dn);
  stub_last_bind_dn = NULL;

  g_free (stub_last_bind_password);
  stub_last_bind_password = NULL;

  if (stub_entry_attributes)
    {
      g_hash_table_destroy (stub_entry_attributes);
      stub_entry_attributes = NULL;
    }

  g_free (stub_last_entry_dn);
  stub_last_entry_dn = NULL;

  g_free (stub_last_entry_name);
  stub_last_entry_name = NULL;

}

/* ad_connector_builder */
Ensure (ad_connector, builder_rejects_null_connector)
{
  gint timeout = 5;

  assert_that (ad_connector_builder (NULL,
  AD_CONNECTOR_OPT_NETWORK_TIMEOUT,
  &timeout),
  is_equal_to (AD_CONNECTOR_INVALID_VALUE));
}

Ensure (ad_connector, builder_rejects_empty_host_or_bind_dn)
{
  ad_connector_t connector;
  const gchar *host = "ad.example.org";
  const gchar *bind_dn = "CN=svc,DC=example,DC=org";
  const gchar *empty = "";

  connector = ad_connector_new ();
  assert_that (connector, is_not_null);

  assert_that (ad_connector_builder (connector, AD_CONNECTOR_OPT_HOST, host),
  is_equal_to (AD_CONNECTOR_OK));
  assert_that (connector->ldap_host, is_equal_to_string ("ad.example.org"));

  assert_that (ad_connector_builder (connector, AD_CONNECTOR_OPT_BIND_DN, bind_dn),
  is_equal_to (AD_CONNECTOR_OK));
  assert_that (connector->bind_dn, is_equal_to_string ("CN=svc,DC=example,DC=org"));

  assert_that (ad_connector_builder (connector, AD_CONNECTOR_OPT_HOST, empty),
  is_equal_to (AD_CONNECTOR_INVALID_VALUE));
  assert_that (ad_connector_builder (connector, AD_CONNECTOR_OPT_BIND_DN, empty),
  is_equal_to (AD_CONNECTOR_INVALID_VALUE));

  ad_connector_free (connector);
}

Ensure (ad_connector, builder_validates_non_negative_timeouts)
{
  ad_connector_t connector;
  gint negative = -1;
  gint zero = 0;
  gint positive = 30;

  connector = ad_connector_new ();
  assert_that (connector, is_not_null);

  assert_that (ad_connector_builder (connector,
                                    AD_CONNECTOR_OPT_NETWORK_TIMEOUT,
                                    &negative),
              is_equal_to (AD_CONNECTOR_INVALID_VALUE));
  assert_that (ad_connector_builder (connector,
                                    AD_CONNECTOR_OPT_OPERATION_TIMEOUT,
                                    &negative),
              is_equal_to (AD_CONNECTOR_INVALID_VALUE));
  assert_that (ad_connector_builder (connector,
                                    AD_CONNECTOR_OPT_NETWORK_TIMEOUT,
                                    &zero),
              is_equal_to (AD_CONNECTOR_OK));
  assert_that (connector->network_timeout, is_equal_to (0));

  assert_that (ad_connector_builder (connector,
                                    AD_CONNECTOR_OPT_OPERATION_TIMEOUT,
                                    &positive),
              is_equal_to (AD_CONNECTOR_OK));
  assert_that (connector->operation_timeout, is_equal_to (30));

  ad_connector_free (connector);
}

Ensure (ad_connector, builder_allows_null_ca_cert_file)
{
  ad_connector_t connector;
  const gchar *ca = "/tmp/test-ca.pem";

  connector = ad_connector_new ();
  assert_that (connector, is_not_null);

  assert_that (ad_connector_builder (connector,
                                    AD_CONNECTOR_OPT_CA_CERT_FILE,
                                    ca),
              is_equal_to (AD_CONNECTOR_OK));
  assert_that (connector->cacert_file, is_equal_to_string ("/tmp/test-ca.pem"));

  assert_that (ad_connector_builder (connector,
                                    AD_CONNECTOR_OPT_CA_CERT_FILE,
                                    NULL),
              is_equal_to (AD_CONNECTOR_OK));
  assert_that (connector->cacert_file, is_null);

  ad_connector_free (connector);
}

Ensure (ad_connector, builder_rejects_changes_when_connection_exists)
{
  ad_connector_t connector;
  const gchar *host = "ad.example.org";

  connector = ad_connector_new ();
  assert_that (connector, is_not_null);

  connector->ldap_connection = (gvm_ldap_connection_t *) 0x1;
  assert_that (ad_connector_builder (connector, AD_CONNECTOR_OPT_HOST, host),
              is_equal_to (AD_CONNECTOR_CONNECTION_ERROR));

  connector->ldap_connection = NULL;
  ad_connector_free (connector);
}

/* ad_search_config_builder */

Ensure (ad_connector, search_config_builder_rejects_null_config)
{
  gint value = 1;

  assert_that (ad_search_config_builder (NULL,
                                         AD_SEARCH_CONFIG_OPT_PAGE_SIZE,
                                         &value),
               is_equal_to (AD_CONNECTOR_INVALID_VALUE));
}

Ensure (ad_connector, search_config_builder_validates_base_dn)
{
  ad_search_config_t config;
  const gchar *base_dn = "DC=example,DC=org";
  const gchar *empty = "";

  config = ad_search_config_new ();
  assert_that (config, is_not_null);

  assert_that (ad_search_config_builder (config,
                                         AD_SEARCH_CONFIG_OPT_BASE_DN,
                                         base_dn),
               is_equal_to (AD_CONNECTOR_OK));
  assert_that (config->base_dn, is_equal_to_string ("DC=example,DC=org"));

  assert_that (ad_search_config_builder (config,
                                         AD_SEARCH_CONFIG_OPT_BASE_DN,
                                         empty),
               is_equal_to (AD_CONNECTOR_INVALID_VALUE));

  ad_search_config_free (config);
}

Ensure (ad_connector, search_config_builder_validates_non_negative_numeric_options)
{
  ad_search_config_t config;
  gint negative = -1;
  gint page_size = 200;
  gint size_limit = 500;
  gint time_limit = 30;
  gint max_results = 1000;

  config = ad_search_config_new ();
  assert_that (config, is_not_null);

  assert_that (ad_search_config_builder (config,
                                         AD_SEARCH_CONFIG_OPT_PAGE_SIZE,
                                         &negative),
               is_equal_to (AD_CONNECTOR_INVALID_VALUE));
  assert_that (ad_search_config_builder (config,
                                         AD_SEARCH_CONFIG_OPT_SIZE_LIMIT,
                                         &negative),
               is_equal_to (AD_CONNECTOR_INVALID_VALUE));
  assert_that (ad_search_config_builder (config,
                                         AD_SEARCH_CONFIG_OPT_TIME_LIMIT,
                                         &negative),
               is_equal_to (AD_CONNECTOR_INVALID_VALUE));
  assert_that (ad_search_config_builder (config,
                                         AD_SEARCH_CONFIG_OPT_MAX_RESULTS,
                                         &negative),
               is_equal_to (AD_CONNECTOR_INVALID_VALUE));

  assert_that (ad_search_config_builder (config,
                                         AD_SEARCH_CONFIG_OPT_PAGE_SIZE,
                                         &page_size),
               is_equal_to (AD_CONNECTOR_OK));
  assert_that (config->page_size, is_equal_to (200));

  assert_that (ad_search_config_builder (config,
                                         AD_SEARCH_CONFIG_OPT_SIZE_LIMIT,
                                         &size_limit),
               is_equal_to (AD_CONNECTOR_OK));
  assert_that (config->ldap_size_limit, is_equal_to (500));

  assert_that (ad_search_config_builder (config,
                                         AD_SEARCH_CONFIG_OPT_TIME_LIMIT,
                                         &time_limit),
               is_equal_to (AD_CONNECTOR_OK));
  assert_that (config->ldap_time_limit, is_equal_to (30));

  assert_that (ad_search_config_builder (config,
                                         AD_SEARCH_CONFIG_OPT_MAX_RESULTS,
                                         &max_results),
               is_equal_to (AD_CONNECTOR_OK));
  assert_that (config->max_results, is_equal_to (1000));

  ad_search_config_free (config);
}

Ensure (ad_connector, search_config_builder_validates_scope_and_object_types)
{
  ad_search_config_t config;
  ad_connector_search_scope_t invalid_scope = (ad_connector_search_scope_t) 99;
  ad_connector_search_scope_t valid_scope = AD_CONNECTOR_SEARCH_SCOPE_SUBTREE;
  ad_object_type_t invalid_types_zero = (ad_object_type_t) 0;
  ad_object_type_t invalid_types_unknown =
    (ad_object_type_t) (AD_OBJECT_TYPE_ALL | (1 << 7));
  ad_object_type_t valid_types =
    (ad_object_type_t) (AD_OBJECT_TYPE_OU | AD_OBJECT_TYPE_GROUP);

  config = ad_search_config_new ();
  assert_that (config, is_not_null);

  assert_that (ad_search_config_builder (config,
                                         AD_SEARCH_CONFIG_OPT_SCOPE,
                                         &invalid_scope),
               is_equal_to (AD_CONNECTOR_INVALID_VALUE));
  assert_that (ad_search_config_builder (config,
                                         AD_SEARCH_CONFIG_OPT_SCOPE,
                                         &valid_scope),
               is_equal_to (AD_CONNECTOR_OK));
  assert_that (config->scope, is_equal_to (AD_CONNECTOR_SEARCH_SCOPE_SUBTREE));

  assert_that (ad_search_config_builder (config,
                                         AD_SEARCH_CONFIG_OPT_OBJECT_TYPES,
                                         &invalid_types_zero),
               is_equal_to (AD_CONNECTOR_INVALID_VALUE));
  assert_that (ad_search_config_builder (config,
                                         AD_SEARCH_CONFIG_OPT_OBJECT_TYPES,
                                         &invalid_types_unknown),
               is_equal_to (AD_CONNECTOR_INVALID_VALUE));
  assert_that (ad_search_config_builder (config,
                                         AD_SEARCH_CONFIG_OPT_OBJECT_TYPES,
                                         &valid_types),
               is_equal_to (AD_CONNECTOR_OK));
  assert_that (config->object_types,
               is_equal_to (AD_OBJECT_TYPE_OU | AD_OBJECT_TYPE_GROUP));

  ad_search_config_free (config);
}

Ensure (ad_connector, search_config_builder_handles_extra_attributes)
{
  ad_search_config_t config;
  const gchar *attrs = "memberOf,displayName";

  config = ad_search_config_new ();
  assert_that (config, is_not_null);

  assert_that (ad_search_config_builder (config,
                                         AD_SEARCH_CONFIG_OPT_EXTRA_ATTRIBUTES,
                                         attrs),
               is_equal_to (AD_CONNECTOR_OK));
  assert_that (config->extra_attributes,
               is_equal_to_string ("memberOf,displayName"));

  assert_that (ad_search_config_builder (config,
                                         AD_SEARCH_CONFIG_OPT_EXTRA_ATTRIBUTES,
                                         NULL),
               is_equal_to (AD_CONNECTOR_OK));
  assert_that (config->extra_attributes, is_null);

  ad_search_config_free (config);
}

Ensure (ad_connector, search_config_builder_handles_include_disabled)
{
  ad_search_config_t config;
  gboolean include_disabled = FALSE;

  config = ad_search_config_new ();
  assert_that (config, is_not_null);

  assert_that (ad_search_config_builder (
                 config,
                 AD_SEARCH_CONFIG_OPT_INCLUDE_DISABLED_COMPUTERS,
                 &include_disabled),
               is_equal_to (AD_CONNECTOR_OK));
  assert_that (config->include_disabled_computers, is_equal_to (FALSE));

  ad_search_config_free (config);
}

Ensure (ad_connector, search_config_builder_rejects_null_for_required_options)
{
  ad_search_config_t config;

  config = ad_search_config_new ();
  assert_that (config, is_not_null);

  assert_that (ad_search_config_builder (config,
                                         AD_SEARCH_CONFIG_OPT_BASE_DN,
                                         NULL),
               is_equal_to (AD_CONNECTOR_INVALID_VALUE));
  assert_that (ad_search_config_builder (config,
                                         AD_SEARCH_CONFIG_OPT_SCOPE,
                                         NULL),
               is_equal_to (AD_CONNECTOR_INVALID_VALUE));

  ad_search_config_free (config);
}

/* get_gvm_ldap_tls_mode */
Ensure (ad_connector, get_gvm_ldap_tls_mode_rejects_null)
{
  gvm_ldap_tls_mode_t tls_mode;

  ad_connector_t connector = ad_connector_new ();
  assert_that (connector, is_not_null);

  assert_that (get_gvm_ldap_tls_mode (NULL, &tls_mode),
              is_equal_to (AD_CONNECTOR_INVALID_VALUE));

  assert_that (get_gvm_ldap_tls_mode (connector, NULL),
              is_equal_to (AD_CONNECTOR_INVALID_VALUE));
  ad_connector_free (connector);
}

Ensure (ad_connector, get_gvm_ldap_tls_mode_maps_supported_modes)
{
  gvm_ldap_tls_mode_t tls_mode;
  ad_connector_tls_mode_t starttls = AD_CONNECTOR_TLS_STARTTLS;

  ad_connector_t connector = ad_connector_new ();
  assert_that (connector, is_not_null);

  assert_that (get_gvm_ldap_tls_mode (connector, &tls_mode),
              is_equal_to (AD_CONNECTOR_OK));
  assert_that (tls_mode, is_equal_to (GVM_LDAP_TLS_LDAPS));

  assert_that (ad_connector_builder (connector, AD_CONNECTOR_OPT_TLS_MODE,
                                     &starttls),
              is_equal_to (AD_CONNECTOR_OK));
  assert_that (get_gvm_ldap_tls_mode (connector, &tls_mode),
              is_equal_to (AD_CONNECTOR_OK));
  assert_that (tls_mode, is_equal_to (GVM_LDAP_TLS_STARTTLS));

  ad_connector_free (connector);
}

Ensure (ad_connector, get_gvm_ldap_tls_mode_rejects_unknown_mode)
{
  ad_connector_t connector = ad_connector_new ();
  gvm_ldap_tls_mode_t tls_mode;

  assert_that (connector, is_not_null);
  connector->tls_mode = (ad_connector_tls_mode_t) 99;

  assert_that (get_gvm_ldap_tls_mode (connector, &tls_mode),
               is_equal_to (AD_CONNECTOR_INVALID_VALUE));
  ad_connector_free (connector);
}

/* ad_connector_connect */
Ensure (ad_connector, connect_rejects_invalid_input_and_state)
{
  ad_connector_t connector = ad_connector_new ();
  assert_that (connector, is_not_null);

  assert_that (ad_connector_connect (NULL, "pw"),
               is_equal_to (AD_CONNECTOR_INVALID_VALUE));

  assert_that (ad_connector_connect (connector, NULL),
               is_equal_to (AD_CONNECTOR_INVALID_VALUE));

  assert_that (ad_connector_connect (connector, ""),
               is_equal_to (AD_CONNECTOR_INVALID_VALUE));

  assert_that (ad_connector_connect (connector, "pw"),
                                     is_equal_to (AD_CONNECTOR_INVALID_VALUE));

  connector->ldap_connection = (gvm_ldap_connection_t *) 0x88;
  assert_that (ad_connector_connect (connector, "pw"),
              is_equal_to (AD_CONNECTOR_CONNECTION_ERROR));

  connector->ldap_connection = NULL;
  ad_connector_free (connector);
}

Ensure (ad_connector, connect_rejects_unknown_tls_mode_before_open)
{
  ad_connector_t connector = ad_connector_new ();
  assert_that (connector, is_not_null);

  set_valid_connection_config (connector);
  connector->tls_mode = (ad_connector_tls_mode_t) 99;

  assert_that (ad_connector_connect (connector, "pw"),
              is_equal_to (AD_CONNECTOR_INVALID_VALUE));
  assert_that (stub_open_calls, is_equal_to (0));
  assert_that (stub_bind_calls, is_equal_to (0));

  ad_connector_free (connector);
}

Ensure (ad_connector, connect_maps_open_failures)
{
  ad_connector_t connector = ad_connector_new ();
  assert_that (connector, is_not_null);

  set_valid_connection_config (connector);

  stub_open_ret = GVM_LDAP_INVALID_VALUE;
  assert_that (ad_connector_connect (connector, "pw"),
              is_equal_to (AD_CONNECTOR_INVALID_VALUE));

  assert_that (stub_open_calls, is_equal_to (1));
  assert_that (stub_bind_calls, is_equal_to (0));

  reset_ldap_stubs ();
  set_valid_connection_config (connector);

  stub_open_ret = GVM_LDAP_INITIALIZE_ERROR;
  assert_that (ad_connector_connect (connector, "pw"),
               is_equal_to (AD_CONNECTOR_CONNECTION_ERROR));

  assert_that (stub_open_calls, is_equal_to (1));
  assert_that (stub_bind_calls, is_equal_to (0));

  ad_connector_free (connector);
}

Ensure (ad_connector, connect_handles_bind_failures_and_closes_connection)
{
  ad_connector_t connector = ad_connector_new ();
  assert_that (connector, is_not_null);

  set_valid_connection_config (connector);

  stub_bind_ret = GVM_LDAP_INVALID_VALUE;
  assert_that (ad_connector_connect (connector, "pw"),
              is_equal_to (AD_CONNECTOR_INVALID_VALUE));

  assert_that (stub_open_calls, is_equal_to (1));
  assert_that (stub_bind_calls, is_equal_to (1));
  assert_that (stub_close_calls, is_equal_to (1));
  assert_that (connector->ldap_connection, is_null);

  reset_ldap_stubs ();
  set_valid_connection_config (connector);

  stub_bind_ret = GVM_LDAP_BIND_ERROR;
  assert_that (ad_connector_connect (connector, "pw"),
              is_equal_to (AD_CONNECTOR_BIND_ERROR));

  assert_that (stub_open_calls, is_equal_to (1));
  assert_that (stub_bind_calls, is_equal_to (1));
  assert_that (stub_close_calls, is_equal_to (1));
  assert_that (connector->ldap_connection, is_null);

  ad_connector_free (connector);
}

Ensure (ad_connector, connect_succeeds_with_valid_configuration)
{
  ad_connector_t connector = ad_connector_new ();
  ad_connector_tls_mode_t starttls = AD_CONNECTOR_TLS_STARTTLS;
  gint port = 1389;
  assert_that (connector, is_not_null);

  set_valid_connection_config (connector);

  assert_that (ad_connector_builder (connector, AD_CONNECTOR_OPT_PORT, &port),
              is_equal_to (AD_CONNECTOR_OK));
  assert_that (ad_connector_builder (connector, AD_CONNECTOR_OPT_TLS_MODE, &starttls),
              is_equal_to (AD_CONNECTOR_OK));
  assert_that (ad_connector_connect (connector, "secret"),
              is_equal_to (AD_CONNECTOR_OK));

  assert_that (stub_open_calls, is_equal_to (1));
  assert_that (stub_bind_calls, is_equal_to (1));
  assert_that (stub_close_calls, is_equal_to (0));

  assert_that (connector->ldap_connection, is_equal_to (stub_open_connection));
  assert_that (stub_last_open_host, is_equal_to_string ("ad.example.org"));
  assert_that (stub_last_open_port, is_equal_to (1389));
  assert_that (stub_last_open_tls_mode, is_equal_to (GVM_LDAP_TLS_STARTTLS));
  assert_that (stub_last_open_network_timeout, is_equal_to (12));
  assert_that (stub_last_open_operation_timeout, is_equal_to (34));
  assert_that (stub_last_bind_dn, is_equal_to_string ("CN=svc,DC=example,DC=org"));
  assert_that (stub_last_bind_password, is_equal_to_string ("secret"));

  connector->ldap_connection = NULL;
  ad_connector_free (connector);
}

/* ad_ldap_entry_has_value */
Ensure (ad_connector, ad_ldap_entry_has_value_rejects_invalid_arguments)
{
  gvm_ldap_entry_t *entry = (gvm_ldap_entry_t *) 0x1;

  assert_that (ad_ldap_entry_has_value (NULL, "objectClass", "computer"),
              is_false);
  assert_that (ad_ldap_entry_has_value (entry, NULL, "computer"),
              is_false);
  assert_that (ad_ldap_entry_has_value (entry, "objectClass", NULL),
              is_false);
}

Ensure (ad_connector, ad_ldap_entry_has_value_returns_false_when_attribute_missing)
{
  gvm_ldap_entry_t *entry = (gvm_ldap_entry_t *) 0x1;

  assert_that (ad_ldap_entry_has_value (entry, "objectClass", "computer"),
              is_false);
}

Ensure (ad_connector, ad_ldap_entry_has_value_matches_case_insensitively)
{
  gvm_ldap_entry_t *entry = (gvm_ldap_entry_t *) 0x2;

  stub_set_entry_attr_values (entry, "objectClass", "top", "Computer", NULL);

  assert_that (ad_ldap_entry_has_value (entry, "objectClass", "computer"),
              is_true);
}

Ensure (ad_connector, ad_ldap_entry_has_value_scans_all_values)
{
  gvm_ldap_entry_t *entry = (gvm_ldap_entry_t *) 0x3;

  stub_set_entry_attr_values (entry, "objectClass", "top", "person", "group");

  assert_that (ad_ldap_entry_has_value (entry, "objectClass", "group"),
                                        is_true);
  assert_that (ad_ldap_entry_has_value (entry, "objectClass", "person"),
                                        is_true);
  assert_that (ad_ldap_entry_has_value (entry, "objectClass", "computer"),
                                        is_false);
}

/* entry_is_ou / entry_is_computer / entry_is_group */

Ensure (ad_connector, entry_is_ou_matches_object_class)
{
  gvm_ldap_entry_t *ou_entry = (gvm_ldap_entry_t *) 0x10;
  gvm_ldap_entry_t *non_ou_entry = (gvm_ldap_entry_t *) 0x11;

  stub_set_entry_attr_values (ou_entry, "objectClass",
                              "top", "organizationalUnit", NULL);
  stub_set_entry_attr_values (non_ou_entry, "objectClass",
                              "top", "group", NULL);

  assert_that (entry_is_ou (ou_entry), is_true);
  assert_that (entry_is_ou (non_ou_entry), is_false);
}

Ensure (ad_connector, entry_is_computer_matches_object_class)
{
  gvm_ldap_entry_t *computer_entry = (gvm_ldap_entry_t *) 0x20;
  gvm_ldap_entry_t *non_computer_entry = (gvm_ldap_entry_t *) 0x21;

  stub_set_entry_attr_values (computer_entry, "objectClass",
                              "top", "Computer", NULL);
  stub_set_entry_attr_values (non_computer_entry, "objectClass",
                              "top", "person", NULL);

  assert_that (entry_is_computer (computer_entry), is_true);
  assert_that (entry_is_computer (non_computer_entry), is_false);
}

Ensure (ad_connector, entry_is_group_matches_object_class)
{
  gvm_ldap_entry_t *group_entry = (gvm_ldap_entry_t *) 0x30;
  gvm_ldap_entry_t *non_group_entry = (gvm_ldap_entry_t *) 0x31;

  stub_set_entry_attr_values (group_entry, "objectClass",
                              "top", "GROUP", NULL);
  stub_set_entry_attr_values (non_group_entry, "objectClass",
                              "top", "computer", NULL);

  assert_that (entry_is_group (group_entry), is_true);
  assert_that (entry_is_group (non_group_entry), is_false);
}

/* get_parent_dn_from_dn */
Ensure (ad_connector, get_parent_dn_from_dn_gets_parent_dn)
{
  gchar *parent;

  parent = get_parent_dn_from_dn ("CN=Host01,OU=Computers,DC=example,DC=org");
  assert_that (parent, is_equal_to_string ("OU=Computers,DC=example,DC=org"));
  g_free (parent);

  parent = get_parent_dn_from_dn ("CN=Host\\,01, OU=Computers,DC=example,DC=org");
  assert_that (parent, is_equal_to_string ("OU=Computers,DC=example,DC=org"));
  g_free (parent);

  parent = get_parent_dn_from_dn ("DC=example");
  assert_that (parent, is_null);
}

Ensure (ad_connector, get_parent_dn_from_dn_returns_null_for_invalid_input)
{
  gchar *parent;

  parent = get_parent_dn_from_dn (NULL);
  assert_that (parent, is_null);

  parent = get_parent_dn_from_dn ("");
  assert_that (parent, is_null);
}

/* ad_object_from_ldap_entry */
Ensure (ad_connector, ad_object_from_ldap_entry_returns_null_for_unsupported_type)
{
  gvm_ldap_entry_t *entry = (gvm_ldap_entry_t *) 0x40;
  gchar *attrs[] = { "memberOf", NULL };
  ad_object_t *object;

  stub_last_entry_dn = g_strdup ("CN=User1,OU=Users,DC=example,DC=org");
  stub_last_entry_name = g_strdup ("User1");
  stub_set_entry_attr_values (entry, "objectClass", "top", "person", NULL);

  object = ad_object_from_ldap_entry (entry, attrs);
  assert_that (object, is_null);
}

Ensure (ad_connector, ad_object_from_ldap_entry_builds_computer_object_with_attributes)
{
  gvm_ldap_entry_t *entry = (gvm_ldap_entry_t *) 0x41;
  gchar *attrs[] = { "memberOf", "dNSHostName", NULL };

  ad_object_t *object;
  GPtrArray *member_of;
  GPtrArray *dns;

  stub_last_entry_dn = g_strdup ("CN=PC1,OU=Computers,DC=example,DC=org");
  stub_last_entry_name = g_strdup ("PC1");
  stub_set_entry_attr_values (entry, "objectClass", "top", "computer", NULL);
  stub_set_entry_attr_values (entry, "memberOf",
                              "CN=G1,OU=Groups,DC=example,DC=org",
                              "CN=G2,OU=Groups,DC=example,DC=org",
                              NULL);
  stub_set_entry_attr_values (entry, "dNSHostName", "pc1.example.org", NULL, NULL);

  object = ad_object_from_ldap_entry (entry, attrs);

  assert_that (object, is_not_null);
  assert_that (object->type, is_equal_to (AD_OBJECT_TYPE_COMPUTER));
  assert_that (object->name, is_equal_to_string ("PC1"));
  assert_that (object->distinguished_name,
               is_equal_to_string ("CN=PC1,OU=Computers,DC=example,DC=org"));
  assert_that (object->parent_dn,
               is_equal_to_string ("OU=Computers,DC=example,DC=org"));

  member_of = g_hash_table_lookup (object->attributes, "memberOf");
  assert_that (member_of, is_not_null);
  assert_that (member_of->len, is_equal_to (2));

  dns = g_hash_table_lookup (object->attributes, "dNSHostName");
  assert_that (dns, is_not_null);
  assert_that (dns->len, is_equal_to (1));

  ad_object_free (object);
}

Ensure (ad_connector, ad_object_from_ldap_entry_returns_null_when_dn_or_name_missing)
{
  gvm_ldap_entry_t *entry_no_name = (gvm_ldap_entry_t *) 0x42;
  gvm_ldap_entry_t *entry_no_dn = (gvm_ldap_entry_t *) 0x43;
  gchar *attrs[] = { "memberOf", NULL };

  ad_object_t *object;

  stub_last_entry_dn = g_strdup ("CN=PC2,OU=Computers,DC=example,DC=org");
  stub_set_entry_attr_values (entry_no_name, "objectClass", "computer", NULL, NULL);
  object = ad_object_from_ldap_entry (entry_no_name, attrs);
  assert_that (object, is_null);

  stub_last_entry_dn = NULL;
  stub_last_entry_name = g_strdup ("PC3");
  stub_set_entry_attr_values (entry_no_dn, "objectClass", "computer", NULL, NULL);
  object = ad_object_from_ldap_entry (entry_no_dn, attrs);
  assert_that (object, is_null);
}

/* ad_search_ldap_entry_callback */
Ensure (ad_connector, search_entry_callback_rejects_null_context_or_callback)
{
  gvm_ldap_entry_t *entry = (gvm_ldap_entry_t *) 0x50;
  ad_search_context_t ctx = {0};

  assert_that (ad_search_ldap_entry_callback (entry, NULL),
               is_equal_to (GVM_LDAP_SEARCH_CALLBACK_ERROR));

  ctx.callback = NULL;
  assert_that (ad_search_ldap_entry_callback (entry, &ctx),
               is_equal_to (GVM_LDAP_SEARCH_CALLBACK_ERROR));
}

Ensure (ad_connector, search_entry_callback_continues_when_entry_cannot_be_converted)
{
  gvm_ldap_entry_t *entry = (gvm_ldap_entry_t *) 0x51;
  mock_callback_context_t cb_ctx = {0};
  ad_search_context_t ctx = {
    .max_results = 0,
    .emitted = 0,
    .truncated = FALSE,
    .attributes = NULL,
    .callback = mock_callback_continue,
    .user_data = &cb_ctx
  };

  stub_set_entry_attr_values (entry, "objectClass", "top", "person", NULL);
  stub_last_entry_dn = g_strdup ("CN=User1,OU=Users,DC=example,DC=org");
  stub_last_entry_name = g_strdup ("User1");

  assert_that (ad_search_ldap_entry_callback (entry, &ctx),
               is_equal_to (GVM_LDAP_SEARCH_CONTINUE));
  assert_that (ctx.emitted, is_equal_to (0));
  assert_that (ctx.truncated, is_false);
  assert_that (cb_ctx.calls, is_equal_to (0));
}

Ensure (ad_connector, search_entry_callback_stops_when_max_results_reached)
{
  gvm_ldap_entry_t *entry = (gvm_ldap_entry_t *) 0x52;
  mock_callback_context_t cb_ctx = {0};
  ad_search_context_t ctx = {
    .max_results = 1,
    .emitted = 1,
    .truncated = FALSE,
    .attributes = NULL,
    .callback = mock_callback_continue,
    .user_data = &cb_ctx
  };

  stub_set_entry_attr_values (entry, "objectClass", "top", "computer", NULL);
  stub_last_entry_dn = g_strdup ("CN=PC1,OU=Computers,DC=example,DC=org");
  stub_last_entry_name = g_strdup ("PC1");

  assert_that (ad_search_ldap_entry_callback (entry, &ctx),
               is_equal_to (GVM_LDAP_SEARCH_STOP));
  assert_that (ctx.truncated, is_true);
  assert_that (ctx.emitted, is_equal_to (1));
  assert_that (cb_ctx.calls, is_equal_to (0));
}

Ensure (ad_connector, search_entry_callback_emits_and_continues_on_callback_continue)
{
  gvm_ldap_entry_t *entry = (gvm_ldap_entry_t *) 0x53;
  mock_callback_context_t cb_ctx = {0};
  ad_search_context_t ctx = {
    .max_results = 0,
    .emitted = 0,
    .truncated = FALSE,
    .attributes = NULL,
    .callback = mock_callback_continue,
    .user_data = &cb_ctx
  };

  stub_set_entry_attr_values (entry, "objectClass", "top", "group", NULL);
  stub_last_entry_dn = g_strdup ("CN=Ops,OU=Groups,DC=example,DC=org");
  stub_last_entry_name = g_strdup ("Ops");

  assert_that (ad_search_ldap_entry_callback (entry, &ctx),
               is_equal_to (GVM_LDAP_SEARCH_CONTINUE));
  assert_that (ctx.emitted, is_equal_to (1));
  assert_that (cb_ctx.calls, is_equal_to (1));
  assert_that (ctx.truncated, is_false);
  assert_that (cb_ctx.calls, is_equal_to (1));
  assert_that (cb_ctx.last_type, is_equal_to (AD_OBJECT_TYPE_GROUP));
  assert_that (cb_ctx.last_name, is_equal_to_string ("Ops"));

  g_free (cb_ctx.last_name);
}

Ensure (ad_connector, search_entry_callback_maps_callback_error_and_invalid_return)
{
  gvm_ldap_entry_t *entry = (gvm_ldap_entry_t *) 0x54;
  mock_callback_context_t cb_ctx_error = {0};
  mock_callback_context_t cb_ctx_invalid = {0};
  ad_search_context_t ctx_error = {
    .max_results = 0,
    .emitted = 0,
    .truncated = FALSE,
    .attributes = NULL,
    .callback = mock_callback_error,
    .user_data = &cb_ctx_error
  };
  ad_search_context_t ctx_invalid = {
    .max_results = 0,
    .emitted = 0,
    .truncated = FALSE,
    .attributes = NULL,
    .callback = mock_callback_invalid_enum,
    .user_data = &cb_ctx_invalid
  };

  stub_set_entry_attr_values (entry, "objectClass", "top", "computer", NULL);
  stub_last_entry_dn = g_strdup ("CN=PC2,OU=Computers,DC=example,DC=org");
  stub_last_entry_name = g_strdup ("PC2");

  assert_that (ad_search_ldap_entry_callback (entry, &ctx_error),
               is_equal_to (GVM_LDAP_SEARCH_CALLBACK_ERROR));
  assert_that (ctx_error.emitted, is_equal_to (0));
  assert_that (cb_ctx_error.calls, is_equal_to (1));

  assert_that (ad_search_ldap_entry_callback (entry, &ctx_invalid),
               is_equal_to (GVM_LDAP_SEARCH_CALLBACK_ERROR));
  assert_that (ctx_invalid.emitted, is_equal_to (0));
  assert_that (cb_ctx_invalid.calls, is_equal_to (1));
}

/* ad_connector_build_search_filter */
Ensure (ad_connector, build_search_filter_returns_null_for_invalid_config)
{
  gchar *filter = ad_connector_build_search_filter (NULL);
  assert_that (filter, is_null);

  ad_search_config_t config = ad_search_config_new ();
  assert_that (config, is_not_null);

  config->object_types = 0;
  filter = ad_connector_build_search_filter (config);
  assert_that (filter, is_null);

  config->object_types = (ad_object_type_t) (AD_OBJECT_TYPE_ALL | (1 << 7));
  filter = ad_connector_build_search_filter (config);
  assert_that (filter, is_null);

  ad_search_config_free (config);
}

Ensure (ad_connector, build_search_filter_single_ou_clause)
{
  ad_search_config_t config = ad_search_config_new ();
  gchar *filter;

  assert_that (config, is_not_null);
  config->object_types = AD_OBJECT_TYPE_OU;

  filter = ad_connector_build_search_filter (config);
  assert_that (filter, is_equal_to_string (
    "(&(objectCategory=organizationalUnit)(objectClass=organizationalUnit))"));

  g_free (filter);
  ad_search_config_free (config);
}

Ensure (ad_connector, build_search_filter_single_computer_clause_enabled_and_disabled)
{
  ad_search_config_t config = ad_search_config_new ();
  gchar *filter;

  assert_that (config, is_not_null);
  config->object_types = AD_OBJECT_TYPE_COMPUTER;

  config->include_disabled_computers = TRUE;
  filter = ad_connector_build_search_filter (config);
  assert_that (filter, is_equal_to_string (
    "(&(objectCategory=computer)(objectClass=computer))"));
  g_free (filter);

  config->include_disabled_computers = FALSE;
  filter = ad_connector_build_search_filter (config);
  assert_that (filter, is_equal_to_string (
    "(&(objectCategory=computer)(objectClass=computer)"
    "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"));
  g_free (filter);

  ad_search_config_free (config);
}

Ensure (ad_connector, build_search_filter_single_group_clause)
{
  ad_search_config_t config = ad_search_config_new ();
  gchar *filter;

  assert_that (config, is_not_null);
  config->object_types = AD_OBJECT_TYPE_GROUP;

  filter = ad_connector_build_search_filter (config);
  assert_that (filter, is_equal_to_string (
    "(&(objectCategory=group)(objectClass=group))"));

  g_free (filter);
  ad_search_config_free (config);
}

Ensure (ad_connector, build_search_filter_combines_multiple_clauses_in_expected_order)
{
  ad_search_config_t config = ad_search_config_new ();
  gchar *filter;

  assert_that (config, is_not_null);

  config->object_types = (ad_object_type_t) (AD_OBJECT_TYPE_OU | AD_OBJECT_TYPE_GROUP);
  filter = ad_connector_build_search_filter (config);
  assert_that (filter, is_equal_to_string (
    "(|(&(objectCategory=organizationalUnit)(objectClass=organizationalUnit))"
    "(&(objectCategory=group)(objectClass=group)))"));
  g_free (filter);

  config->object_types = AD_OBJECT_TYPE_ALL;
  config->include_disabled_computers = FALSE;
  filter = ad_connector_build_search_filter (config);
  assert_that (filter, is_equal_to_string (
    "(|(&(objectCategory=organizationalUnit)(objectClass=organizationalUnit))"
    "(&(objectCategory=computer)(objectClass=computer)"
    "(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
    "(&(objectCategory=group)(objectClass=group)))"));
  g_free (filter);

  ad_search_config_free (config);
}

/* ad_connector_build_attributes */
Ensure (ad_connector, build_attributes_returns_null_for_null_config)
{
  gchar **attributes = ad_connector_build_attributes (NULL);

  assert_that (attributes, is_null);
}

Ensure (ad_connector, build_attributes_includes_core_and_type_specific_defaults)
{
  ad_search_config_t config;
  gchar **attributes;

  config = ad_search_config_new ();
  assert_that (config, is_not_null);

  attributes = ad_connector_build_attributes (config);
  assert_that (attributes, is_not_null);

  /* Core attributes */
  assert_that (attr_list_count (attributes, "objectClass"), is_equal_to (1));
  assert_that (attr_list_count (attributes, "objectCategory"), is_equal_to (1));
  assert_that (attr_list_count (attributes, "name"), is_equal_to (1));
  assert_that (attr_list_count (attributes, "description"), is_equal_to (1));
  assert_that (attr_list_count (attributes, "cn"), is_equal_to (1));
  /* Type-specific attributes from default object_types = AD_OBJECT_TYPE_ALL */
  assert_that (attr_list_count (attributes, "ou"), is_equal_to (1));
  assert_that (attr_list_count (attributes, "dNSHostName"), is_equal_to (1));
  assert_that (attr_list_count (attributes, "memberOf"), is_equal_to (1));

  g_strfreev (attributes);
  ad_search_config_free (config);
}

Ensure (ad_connector, build_attributes_adds_extra_unique_attributes)
{
  ad_search_config_t config;
  gchar **attributes;
  const gchar *extra = "memberOf, customAttr, CUSTOMATTR, ";

  config = ad_search_config_new ();
  assert_that (config, is_not_null);

  assert_that (ad_search_config_builder (config,
                                         AD_SEARCH_CONFIG_OPT_EXTRA_ATTRIBUTES,
                                         extra),
               is_equal_to (AD_CONNECTOR_OK));

  attributes = ad_connector_build_attributes (config);
  assert_that (attributes, is_not_null);

  assert_that (attr_list_count (attributes, "memberOf"), is_equal_to (1));
  assert_that (attr_list_count (attributes, "customAttr"), is_equal_to (1));

  g_strfreev (attributes);
  ad_search_config_free (config);
}

/* get_ldap_search_scope */
Ensure (ad_connector, get_ldap_search_scope_maps_known_values)
{
  assert_that (get_ldap_search_scope (AD_CONNECTOR_SEARCH_SCOPE_BASE),
               is_equal_to (GVM_LDAP_SCOPE_BASE));
  assert_that (get_ldap_search_scope (AD_CONNECTOR_SEARCH_SCOPE_ONELEVEL),
               is_equal_to (GVM_LDAP_SCOPE_ONELEVEL));
  assert_that (get_ldap_search_scope (AD_CONNECTOR_SEARCH_SCOPE_SUBTREE),
               is_equal_to (GVM_LDAP_SCOPE_SUBTREE));
}

Ensure (ad_connector, get_ldap_search_scope_defaults_for_unknown_value)
{
  ad_connector_search_scope_t invalid_scope = (ad_connector_search_scope_t) 99;

  assert_that (get_ldap_search_scope (invalid_scope),
               is_equal_to (GVM_LDAP_SCOPE_ONELEVEL));
}

/* ad_connector_search_objects */
Ensure (ad_connector, search_objects_rejects_invalid_input_and_missing_connection)
{
  ad_connector_t connector = ad_connector_new ();
  ad_search_config_t config = ad_search_config_new ();

  assert_that (connector, is_not_null);
  assert_that (config, is_not_null);

  assert_that (ad_connector_search_objects (NULL, config,
                                            dummy_object_callback, NULL, NULL),
               is_equal_to (AD_CONNECTOR_INVALID_VALUE));
  assert_that (ad_connector_search_objects (connector, NULL,
                                            dummy_object_callback, NULL, NULL),
               is_equal_to (AD_CONNECTOR_INVALID_VALUE));
  assert_that (ad_connector_search_objects (connector, config,
                                            NULL, NULL, NULL),
               is_equal_to (AD_CONNECTOR_INVALID_VALUE));
  assert_that (ad_connector_search_objects (connector, config,
                                            dummy_object_callback, NULL, NULL),
               is_equal_to (AD_CONNECTOR_CONNECTION_ERROR));

  ad_search_config_free (config);
  ad_connector_free (connector);
}

Ensure (ad_connector, search_objects_returns_invalid_value_when_filter_or_params_fail)
{
  ad_connector_t connector = ad_connector_new ();
  ad_search_config_t config = ad_search_config_new ();

  assert_that (connector, is_not_null);
  assert_that (config, is_not_null);

  connector->ldap_connection = (gvm_ldap_connection_t *) 0x55;

  config->object_types = 0;
  assert_that (ad_connector_search_objects (connector, config,
                                            dummy_object_callback, NULL, NULL),
               is_equal_to (AD_CONNECTOR_INVALID_VALUE));

  config->object_types = AD_OBJECT_TYPE_ALL;
  stub_search_params_new_returns_null = TRUE;
  assert_that (ad_connector_search_objects (connector, config,
                                            dummy_object_callback, NULL, NULL),
               is_equal_to (AD_CONNECTOR_INVALID_VALUE));

  connector->ldap_connection = NULL;
  ad_search_config_free (config);
  ad_connector_free (connector);
}

Ensure (ad_connector, search_objects_maps_ldap_return_codes_and_resets_result)
{
  ad_connector_t connector = ad_connector_new ();
  ad_search_config_t config = ad_search_config_new ();
  ad_object_search_result_t result = { .emitted = 99, .truncated = TRUE };

  assert_that (connector, is_not_null);
  assert_that (config, is_not_null);

  connector->ldap_connection = (gvm_ldap_connection_t *) 0x66;

  stub_search_paged_ret = GVM_LDAP_SUCCESS;
  assert_that (ad_connector_search_objects (connector, config,
                                            dummy_object_callback, NULL, &result),
               is_equal_to (AD_CONNECTOR_OK));
  assert_that (result.emitted, is_equal_to (0));
  assert_that (result.truncated, is_false);

  stub_search_paged_ret = GVM_LDAP_CALLBACK_ERROR;
  assert_that (ad_connector_search_objects (connector, config,
                                            dummy_object_callback, NULL, NULL),
               is_equal_to (AD_CONNECTOR_RESULT_ERROR));

  stub_search_paged_ret = GVM_LDAP_SEARCH_ERROR;
  assert_that (ad_connector_search_objects (connector, config,
                                            dummy_object_callback, NULL, NULL),
               is_equal_to (AD_CONNECTOR_SEARCH_ERROR));

  connector->ldap_connection = NULL;
  ad_search_config_free (config);
  ad_connector_free (connector);
}

/* Test suite */

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, ad_connector,
                         builder_rejects_null_connector);
  add_test_with_context (suite, ad_connector,
                         builder_rejects_empty_host_or_bind_dn);
  add_test_with_context (suite, ad_connector,
                         builder_validates_non_negative_timeouts);
  add_test_with_context (suite, ad_connector,
                         builder_allows_null_ca_cert_file);
  add_test_with_context (suite, ad_connector,
                         builder_rejects_changes_when_connection_exists);

  add_test_with_context (suite, ad_connector,
                         search_config_builder_rejects_null_config);
  add_test_with_context (suite, ad_connector,
                         search_config_builder_validates_base_dn);
  add_test_with_context (suite, ad_connector,
                         search_config_builder_validates_non_negative_numeric_options);
  add_test_with_context (suite, ad_connector,
                         search_config_builder_validates_scope_and_object_types);
  add_test_with_context (suite, ad_connector,
                         search_config_builder_handles_extra_attributes);
  add_test_with_context (suite, ad_connector,
                         search_config_builder_handles_include_disabled);
  add_test_with_context (suite, ad_connector,
                         search_config_builder_rejects_null_for_required_options);

  add_test_with_context (suite, ad_connector,
                         get_gvm_ldap_tls_mode_rejects_null);
  add_test_with_context (suite, ad_connector,
                         get_gvm_ldap_tls_mode_maps_supported_modes);
  add_test_with_context (suite, ad_connector,
                         get_gvm_ldap_tls_mode_rejects_unknown_mode);
  add_test_with_context (suite, ad_connector,
                         connect_rejects_invalid_input_and_state);
  add_test_with_context (suite, ad_connector,
                         connect_rejects_unknown_tls_mode_before_open);
  add_test_with_context (suite, ad_connector,
                         connect_maps_open_failures);
  add_test_with_context (suite, ad_connector,
                         connect_handles_bind_failures_and_closes_connection);
  add_test_with_context (suite, ad_connector,
                         connect_succeeds_with_valid_configuration);

  add_test_with_context (suite, ad_connector,
                         ad_ldap_entry_has_value_rejects_invalid_arguments);
  add_test_with_context (suite, ad_connector,
                         ad_ldap_entry_has_value_returns_false_when_attribute_missing);
  add_test_with_context (suite, ad_connector,
                         ad_ldap_entry_has_value_matches_case_insensitively);
  add_test_with_context (suite, ad_connector,
                         ad_ldap_entry_has_value_scans_all_values);

  add_test_with_context (suite, ad_connector,
                         entry_is_ou_matches_object_class);
  add_test_with_context (suite, ad_connector,
                         entry_is_computer_matches_object_class);
  add_test_with_context (suite, ad_connector,
                         entry_is_group_matches_object_class);

  add_test_with_context (suite, ad_connector,
                         get_parent_dn_from_dn_gets_parent_dn);
  add_test_with_context (suite, ad_connector,
                         get_parent_dn_from_dn_returns_null_for_invalid_input);

  add_test_with_context (suite, ad_connector,
                         ad_object_from_ldap_entry_returns_null_for_unsupported_type);
  add_test_with_context (suite, ad_connector,
                         ad_object_from_ldap_entry_builds_computer_object_with_attributes);
  add_test_with_context (suite, ad_connector,
                         ad_object_from_ldap_entry_returns_null_when_dn_or_name_missing);

  add_test_with_context (suite, ad_connector,
                         search_entry_callback_rejects_null_context_or_callback);
  add_test_with_context (suite, ad_connector,
                         search_entry_callback_continues_when_entry_cannot_be_converted);
  add_test_with_context (suite, ad_connector,
                         search_entry_callback_stops_when_max_results_reached);
  add_test_with_context (suite, ad_connector,
                         search_entry_callback_emits_and_continues_on_callback_continue);
  add_test_with_context (suite, ad_connector,
                         search_entry_callback_maps_callback_error_and_invalid_return);

  add_test_with_context (suite, ad_connector,
                         build_search_filter_returns_null_for_invalid_config);
  add_test_with_context (suite, ad_connector,
                         build_search_filter_single_ou_clause);
  add_test_with_context (suite, ad_connector,
                         build_search_filter_single_computer_clause_enabled_and_disabled);
  add_test_with_context (suite, ad_connector,
                         build_search_filter_single_group_clause);
  add_test_with_context (suite, ad_connector,
                         build_search_filter_combines_multiple_clauses_in_expected_order);

  add_test_with_context (suite, ad_connector,
                         build_attributes_returns_null_for_null_config);
  add_test_with_context (suite, ad_connector,
                         build_attributes_includes_core_and_type_specific_defaults);
  add_test_with_context (suite, ad_connector,
                         build_attributes_adds_extra_unique_attributes);

  add_test_with_context (suite, ad_connector,
                         get_ldap_search_scope_maps_known_values);
  add_test_with_context (suite, ad_connector,
                         get_ldap_search_scope_defaults_for_unknown_value);

  add_test_with_context (suite, ad_connector,
                         search_objects_rejects_invalid_input_and_missing_connection);
  add_test_with_context (suite, ad_connector,
                         search_objects_returns_invalid_value_when_filter_or_params_fail);
  add_test_with_context (suite, ad_connector,
                         search_objects_maps_ldap_return_codes_and_resets_result);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}