/* SPDX-FileCopyrightText: 2026 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "gvmldap.c"

#include <cgreen/cgreen.h>
#include <glib.h>

Describe (gvmldap);

static const gchar *mock_dn_to_return = NULL;
static struct berval **mock_values_to_return = NULL;
static int mock_ldap_str2dn_return_value = 0;
static int mock_ldap_set_option_return_value = LDAP_OPT_SUCCESS;
static int ldap_set_option_call_count = 0;
static int last_ldap_set_option_option = 0;

static struct berval **
make_mock_bervals (const gchar **values)
{
  int i;
  int count = 0;
  struct berval **bervals;

  if (values)
    {
      while (values[count] != NULL)
        count++;
    }

  bervals = g_malloc0 (sizeof (struct berval *) * (count + 1));

  for (i = 0; i < count; i++)
    {
      bervals[i] = g_malloc0 (sizeof (struct berval));
      bervals[i]->bv_len = strlen (values[i]);
      bervals[i]->bv_val = g_strndup (values[i], bervals[i]->bv_len);
    }

  bervals[count] = NULL;
  return bervals;
}

static void
free_mock_bervals (struct berval **values)
{
  int i;

  if (!values)
    return;

  for (i = 0; values[i] != NULL; i++)
    {
      g_free (values[i]->bv_val);
      g_free (values[i]);
    }

  g_free (values);
}

/* -------------------- Mock Functions -------------------- */

char *
ldap_get_dn (LDAP *ld, LDAPMessage *entry)
{
  (void) ld;
  (void) entry;

  if (!mock_dn_to_return)
    return NULL;

  return g_strdup (mock_dn_to_return);
}

void
ldap_memfree (void *p)
{
  g_free (p);
}

struct berval **
ldap_get_values_len (LDAP *ld, LDAPMessage *entry, const char *attr)
{
  (void) ld;
  (void) entry;
  (void) attr;
  return mock_values_to_return;
}

void
ldap_value_free_len (struct berval **vals)
{
  if (vals == mock_values_to_return)
    mock_values_to_return = NULL;

  free_mock_bervals (vals);
}

int
ldap_str2dn (LDAP_CONST char *str, LDAPDN *dn, unsigned flags)
{
  (void) str;
  (void) dn;
  (void) flags;

  return mock_ldap_str2dn_return_value;
}

int
ldap_set_option (LDAP *ld, int option, const void *invalue)
{
  (void) ld;
  (void) invalue;

  ldap_set_option_call_count++;
  last_ldap_set_option_option = option;

  return mock_ldap_set_option_return_value;
}

BeforeEach (gvmldap)
{
  mock_dn_to_return = NULL;
  mock_values_to_return = NULL;
  mock_ldap_str2dn_return_value = 0;
  mock_ldap_set_option_return_value = LDAP_OPT_SUCCESS;
  ldap_set_option_call_count = 0;
  last_ldap_set_option_option = 0;
}

AfterEach (gvmldap)
{
  mock_dn_to_return = NULL;
  mock_ldap_str2dn_return_value = 0;
  mock_ldap_set_option_return_value = LDAP_OPT_SUCCESS;
  ldap_set_option_call_count = 0;
  last_ldap_set_option_option = 0;

  if (mock_values_to_return)
    {
      free_mock_bervals (mock_values_to_return);
      mock_values_to_return = NULL;
    }
}

/* ldap_build_uri */

Ensure (gvmldap, ldap_build_uri_uses_defaults_for_starttls_and_ldaps)
{
  gchar *uri_starttls =
    ldap_build_uri ("ldap.example.org", 0, GVM_LDAP_TLS_STARTTLS);
  gchar *uri_ldaps = ldap_build_uri ("ldap.example.org", 0, GVM_LDAP_TLS_LDAPS);

  assert_that (uri_starttls, is_equal_to_string ("ldap://ldap.example.org:389"));
  assert_that (uri_ldaps, is_equal_to_string ("ldaps://ldap.example.org:636"));

  g_free (uri_starttls);
  g_free (uri_ldaps);
}

Ensure (gvmldap, ldap_build_uri_uses_given_port_and_formats_ipv6)
{
  gchar *uri_custom =
    ldap_build_uri ("ldap.example.org", 1389, GVM_LDAP_TLS_PLAINTEXT);
  gchar *uri_ipv6 =
    ldap_build_uri ("2001:db8::1", 1636, GVM_LDAP_TLS_LDAPS);
  gchar *uri_ipv6_bracketed =
    ldap_build_uri ("[2001:db8::1]", 1636, GVM_LDAP_TLS_LDAPS);

  assert_that (uri_custom, is_equal_to_string ("ldap://ldap.example.org:1389"));
  assert_that (uri_ipv6, is_equal_to_string ("ldaps://[2001:db8::1]:1636"));
  assert_that (uri_ipv6_bracketed,
               is_equal_to_string ("ldaps://[2001:db8::1]:1636"));

  g_free (uri_custom);
  g_free (uri_ipv6);
  g_free (uri_ipv6_bracketed);
}

/* gvm_ldap_entry_get_dn */

Ensure (gvmldap, gvm_ldap_entry_get_dn_returns_null_for_invalid_args)
{
  LDAP *ldap = (LDAP *) 0x1;
  LDAPMessage *entry = (LDAPMessage *) 0x1;

  assert_that (gvm_ldap_entry_get_dn (NULL, entry), is_null);
  assert_that (gvm_ldap_entry_get_dn (ldap, NULL), is_null);
}

Ensure (gvmldap, gvm_ldap_entry_get_dn_returns_dn)
{
  LDAP *ldap = (LDAP *) 0x1;
  LDAPMessage *entry = (LDAPMessage *) 0x1;
  gchar *dn;

  mock_dn_to_return = "cn=alice,dc=example,dc=org";

  dn = gvm_ldap_entry_get_dn (ldap, entry);

  assert_that (dn, is_not_null);
  assert_that (dn, is_equal_to_string ("cn=alice,dc=example,dc=org"));

  g_free (dn);
}

Ensure (gvmldap, gvm_ldap_entry_get_dn_returns_null_when_ldap_returns_null)
{
  LDAP *ldap = (LDAP *) 0x1;
  LDAPMessage *entry = (LDAPMessage *) 0x1;

  mock_dn_to_return = NULL;

  assert_that (gvm_ldap_entry_get_dn (ldap, entry), is_null);
}

/* gvm_ldap_entry_get_string */

Ensure (gvmldap, gvm_ldap_entry_get_string_returns_null_for_invalid_args)
{
  LDAP *ldap = (LDAP *) 0x1;
  LDAPMessage *entry = (LDAPMessage *) 0x1;

  assert_that (gvm_ldap_entry_get_string (NULL, entry, "cn"), is_null);
  assert_that (gvm_ldap_entry_get_string (ldap, NULL, "cn"), is_null);
  assert_that (gvm_ldap_entry_get_string (ldap, entry, NULL), is_null);
}

Ensure (gvmldap, gvm_ldap_entry_get_string_returns_first_attribute_value)
{
  LDAP *ldap = (LDAP *) 0x1;
  LDAPMessage *entry = (LDAPMessage *) 0x1;
  const gchar *values[] = {"alice", "bob", NULL};
  gchar *value;

  mock_values_to_return = make_mock_bervals (values);

  value = gvm_ldap_entry_get_string (ldap, entry, "cn");

  assert_that (value, is_not_null);
  assert_that (value, is_equal_to_string ("alice"));

  g_free (value);
}

Ensure (gvmldap, gvm_ldap_entry_get_string_returns_null_when_no_values)
{
  LDAP *ldap = (LDAP *) 0x1;
  LDAPMessage *entry = (LDAPMessage *) 0x1;

  mock_values_to_return = NULL;

  assert_that (gvm_ldap_entry_get_string (ldap, entry, "cn"), is_null);
}

/* gvm_ldap_entry_get_strings */

Ensure (gvmldap, gvm_ldap_entry_get_strings_returns_all_attribute_values)
{
  LDAP *ldap = (LDAP *) 0x1;
  LDAPMessage *entry = (LDAPMessage *) 0x1;
  const gchar *values[] = {"alice", "bob", NULL};
  GPtrArray *result;

  mock_values_to_return = make_mock_bervals (values);

  result = gvm_ldap_entry_get_strings (ldap, entry, "cn");

  assert_that (result, is_not_null);
  assert_that ((int) result->len, is_equal_to (2));
  assert_that ((gchar *) g_ptr_array_index (result, 0), is_equal_to_string ("alice"));
  assert_that ((gchar *) g_ptr_array_index (result, 1), is_equal_to_string ("bob"));

  g_ptr_array_free (result, TRUE);
}

Ensure (gvmldap, gvm_ldap_entry_get_strings_returns_null_for_no_values)
{
  LDAP *ldap = (LDAP *) 0x1;
  LDAPMessage *entry = (LDAPMessage *) 0x1;

  mock_values_to_return = NULL;

  assert_that (gvm_ldap_entry_get_strings (ldap, entry, "cn"), is_null);
}

Ensure (gvmldap, gvm_ldap_entry_get_strings_returns_null_for_empty_value_set)
{
  LDAP *ldap = (LDAP *) 0x1;
  LDAPMessage *entry = (LDAPMessage *) 0x1;
  const gchar *values[] = {NULL};
  GPtrArray *result;

  mock_values_to_return = make_mock_bervals (values);

  result = gvm_ldap_entry_get_strings (ldap, entry, "cn");

  assert_that (result, is_null);
}

/* gvm_ldap_search_params_new */

Ensure (gvmldap, gvm_ldap_search_params_new_rejects_invalid_input)
{
  gchar *attrs[] = {"cn", NULL};

  assert_that (
    gvm_ldap_search_params_new (NULL, LDAP_SCOPE_SUBTREE, "(uid=alice)", attrs,
                                0, 0, 0),
    is_null);
  assert_that (
    gvm_ldap_search_params_new ("dc=example,dc=org", LDAP_SCOPE_SUBTREE, NULL,
                                attrs, 0, 0, 0),
    is_null);
  assert_that (
    gvm_ldap_search_params_new ("dc=example,dc=org", LDAP_SCOPE_SUBTREE, "",
                                attrs, 0, 0, 0),
    is_null);
  assert_that (
    gvm_ldap_search_params_new ("dc=example,dc=org", -1, "(uid=alice)", attrs,
                                0, 0, 0),
    is_null);
}

Ensure (gvmldap, gvm_ldap_search_params_new_sets_defaults_and_duplicates_input)
{
  gchar **attrs = g_malloc0 (sizeof (gchar *) * 3);
  gvm_ldap_search_params_t *params;

  attrs[0] = g_strdup ("cn");
  attrs[1] = g_strdup ("mail");
  attrs[2] = NULL;

  params = gvm_ldap_search_params_new ("dc=example,dc=org", LDAP_SCOPE_SUBTREE,
                                       "(uid=alice)", attrs, 0, 0, 0);

  assert_that (params, is_not_null);
  assert_that (params->base_dn, is_equal_to_string ("dc=example,dc=org"));
  assert_that (params->scope, is_equal_to (LDAP_SCOPE_SUBTREE));
  assert_that (params->filter, is_equal_to_string ("(uid=alice)"));
  assert_that ((int) params->page_size, is_equal_to (GVM_LDAP_DEFAULT_PAGE_SIZE));
  assert_that ((int) params->size_limit, is_equal_to (0));
  assert_that ((int) params->timeout_seconds, is_equal_to (0));
  assert_that (params->attributes, is_not_null);
  assert_that (params->attributes[0], is_equal_to_string ("cn"));
  assert_that (params->attributes[1], is_equal_to_string ("mail"));
  assert_that (params->attributes[2], is_null);

  g_strfreev (attrs);
  gvm_ldap_search_params_free (params);
}

Ensure (gvmldap, gvm_ldap_search_params_new_sets_explicit_limits_and_timeouts)
{
  gvm_ldap_search_params_t *params;

  params = gvm_ldap_search_params_new ("dc=example,dc=org", LDAP_SCOPE_ONELEVEL,
                                       "(objectClass=person)", NULL, 50, 200, 10);

  assert_that (params, is_not_null);
  assert_that ((int) params->page_size, is_equal_to (50));
  assert_that ((int) params->size_limit, is_equal_to (200));
  assert_that ((int) params->timeout_seconds, is_equal_to (10));
  assert_that (params->attributes, is_null);

  gvm_ldap_search_params_free (params);
}

/* ldap_bind_dn_is_valid */

Ensure (gvmldap, ldap_bind_dn_is_valid_rejects_null_and_empty)
{
  assert_that (ldap_bind_dn_is_valid (NULL), is_false);
  assert_that (ldap_bind_dn_is_valid (""), is_false);
}

Ensure (gvmldap, ldap_bind_dn_is_valid_rejects_control_characters)
{
  assert_that (ldap_bind_dn_is_valid ("cn=alice,\nDC=example,DC=org"),
               is_false);
}

Ensure (gvmldap, ldap_bind_dn_is_valid_accepts_valid_dn)
{
  assert_that (ldap_bind_dn_is_valid ("cn=alice,DC=example,DC=org"), is_true);
}

Ensure (gvmldap, ldap_bind_dn_is_valid_accepts_user_at_domain)
{
  mock_ldap_str2dn_return_value = 1;
  assert_that (ldap_bind_dn_is_valid ("alice@example.org"), is_true);
}

Ensure (gvmldap, ldap_bind_dn_is_valid_accepts_domain_backslash_user)
{
  mock_ldap_str2dn_return_value = 1;
  assert_that (ldap_bind_dn_is_valid ("EXAMPLE\\alice"), is_true);
}

Ensure (gvmldap, ldap_bind_dn_is_valid_rejects_invalid_dn)
{
  mock_ldap_str2dn_return_value = 1;
  assert_that (ldap_bind_dn_is_valid ("@example.org"), is_false);
  assert_that (ldap_bind_dn_is_valid ("alice@"), is_false);
  assert_that (ldap_bind_dn_is_valid ("alice@@example.org"), is_false);

  assert_that (ldap_bind_dn_is_valid ("\\alice"), is_false);
  assert_that (ldap_bind_dn_is_valid ("EXAMPLE\\"), is_false);
  assert_that (ldap_bind_dn_is_valid ("EXAMPLE\\alice\\extra"), is_false);
}

/* ldap_set_timeout_option */

Ensure (gvmldap, ldap_set_timeout_option_does_not_set_timeout_for_zero)
{
  LDAP *ldap = (LDAP *) 0x1;
  int ret;

  ret = ldap_set_timeout_option (ldap, LDAP_OPT_NETWORK_TIMEOUT, 0);

  assert_that (ldap_set_option_call_count, is_equal_to (0));
  assert_that (ret, is_equal_to (LDAP_OPT_SUCCESS));
}

Ensure (gvmldap, ldap_set_timeout_option_sets_timeout_for_nonzero)
{
  LDAP *ldap = (LDAP *) 0x1;
  int ret;

  ret = ldap_set_timeout_option (ldap, LDAP_OPT_TIMEOUT, 7);

  assert_that (ldap_set_option_call_count, is_equal_to (1));
  assert_that (last_ldap_set_option_option, is_equal_to (LDAP_OPT_TIMEOUT));
  assert_that (ret, is_equal_to (LDAP_OPT_SUCCESS));
}

/* ldap_configure_tls */

Ensure (gvmldap, ldap_configure_tls_sets_tls_options_correctly_no_cert)
{
  LDAP *ldap = (LDAP *) 0x1;
  int ret;

  ret = ldap_configure_tls (ldap, NULL);

  assert_that (ldap_set_option_call_count, is_equal_to (2));
  assert_that (last_ldap_set_option_option, is_equal_to (LDAP_OPT_X_TLS_NEWCTX));
  assert_that (ret, is_equal_to (0));
}

Ensure (gvmldap, ldap_configure_tls_sets_tls_options_correctly_with_cert)
{
  LDAP *ldap = (LDAP *) 0x1;
  int ret;

  ret = ldap_configure_tls (ldap, "/path/to/cert");

  assert_that (ldap_set_option_call_count, is_equal_to (3));
  assert_that (last_ldap_set_option_option, is_equal_to (LDAP_OPT_X_TLS_NEWCTX));
  assert_that (ret, is_equal_to (0));
}

Ensure (gvmldap, ldap_configure_tls_handles_returns_error_for_invalid_input)
{
  int ret;

  ret = ldap_configure_tls (NULL, "/path/to/cert");

  assert_that (ldap_set_option_call_count, is_equal_to (0));
  assert_that (ret, is_equal_to (-1));
}

/* Test suite */

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, gvmldap,
                         ldap_build_uri_uses_defaults_for_starttls_and_ldaps);
  add_test_with_context (suite, gvmldap,
                         ldap_build_uri_uses_given_port_and_formats_ipv6);

  add_test_with_context (suite, gvmldap,
                         gvm_ldap_entry_get_dn_returns_null_for_invalid_args);
  add_test_with_context (
    suite, gvmldap, gvm_ldap_entry_get_dn_returns_dn);
  add_test_with_context (
    suite, gvmldap, gvm_ldap_entry_get_dn_returns_null_when_ldap_returns_null);

  add_test_with_context (
    suite, gvmldap, gvm_ldap_entry_get_string_returns_null_for_invalid_args);
  add_test_with_context (
    suite, gvmldap, gvm_ldap_entry_get_string_returns_first_attribute_value);
  add_test_with_context (
    suite, gvmldap, gvm_ldap_entry_get_string_returns_null_when_no_values);

  add_test_with_context (
    suite, gvmldap, gvm_ldap_entry_get_strings_returns_all_attribute_values);
  add_test_with_context (
    suite, gvmldap, gvm_ldap_entry_get_strings_returns_null_for_no_values);
  add_test_with_context (
    suite, gvmldap,
    gvm_ldap_entry_get_strings_returns_null_for_empty_value_set);

  add_test_with_context (
    suite, gvmldap, gvm_ldap_search_params_new_rejects_invalid_input);
  add_test_with_context (
    suite, gvmldap,
    gvm_ldap_search_params_new_sets_defaults_and_duplicates_input);
  add_test_with_context (
    suite, gvmldap,
    gvm_ldap_search_params_new_sets_explicit_limits_and_timeouts);

  add_test_with_context (
    suite, gvmldap, ldap_bind_dn_is_valid_rejects_null_and_empty);
  add_test_with_context (
    suite, gvmldap, ldap_bind_dn_is_valid_rejects_control_characters);
  add_test_with_context (
    suite, gvmldap, ldap_bind_dn_is_valid_accepts_valid_dn);
  add_test_with_context (
    suite, gvmldap, ldap_bind_dn_is_valid_accepts_user_at_domain);
  add_test_with_context (
    suite, gvmldap, ldap_bind_dn_is_valid_accepts_domain_backslash_user);
  add_test_with_context (
    suite, gvmldap, ldap_bind_dn_is_valid_rejects_invalid_dn);

  add_test_with_context (
    suite, gvmldap, ldap_set_timeout_option_does_not_set_timeout_for_zero);
  add_test_with_context (
    suite, gvmldap, ldap_set_timeout_option_sets_timeout_for_nonzero);

  add_test_with_context (
    suite, gvmldap, ldap_configure_tls_sets_tls_options_correctly_no_cert);
  add_test_with_context (
    suite, gvmldap, ldap_configure_tls_sets_tls_options_correctly_with_cert);
  add_test_with_context (
    suite, gvmldap, ldap_configure_tls_handles_returns_error_for_invalid_input);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}