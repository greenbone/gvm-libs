/* SPDX-FileCopyrightText: 2009-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "hosts.c"
#include "networking.h"

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>

Describe (hosts);
BeforeEach (hosts)
{
}
AfterEach (hosts)
{
}

/* make_hosts */

Ensure (hosts, gvm_hosts_new_never_returns_null)
{
  gvm_hosts_t *hosts;

  hosts = gvm_hosts_new ("");
  assert_that (hosts, is_not_null);
  gvm_hosts_free (hosts);

  hosts = gvm_hosts_new ("172.10.1.1");
  assert_that (hosts, is_not_null);
  gvm_hosts_free (hosts);

  hosts = gvm_hosts_new ("172.10.1.1/24");
  assert_that (hosts, is_not_null);
  gvm_hosts_free (hosts);
}

Ensure (hosts, gvm_get_host_type_returns_host_type_ipv4)
{
  assert_that (gvm_get_host_type ("192.168.0.4"), is_equal_to (HOST_TYPE_IPV4));
  assert_that (gvm_get_host_type ("1.1.1.1"), is_equal_to (HOST_TYPE_IPV4));
  assert_that (gvm_get_host_type ("0.0.0.0"), is_equal_to (HOST_TYPE_IPV4));
  assert_that (gvm_get_host_type ("255.255.255.255"),
               is_equal_to (HOST_TYPE_IPV4));
  assert_that (gvm_get_host_type ("10.1.1.1"), is_equal_to (HOST_TYPE_IPV4));
}

Ensure (hosts, gvm_get_host_type_returns_host_type_ipv6)
{
  assert_that (gvm_get_host_type ("::ffee"), is_equal_to (HOST_TYPE_IPV6));
  assert_that (gvm_get_host_type ("0001:1:1:1::1"),
               is_equal_to (HOST_TYPE_IPV6));
}

#define TEN "0123456789"
#define SIXTY TEN TEN TEN TEN TEN TEN
#define HUNDRED TEN TEN TEN TEN TEN TEN TEN TEN TEN TEN

Ensure (hosts, gvm_get_host_type_returns_host_type_hostname)
{
  assert_that (gvm_get_host_type ("www.greenbone.net"),
               is_equal_to (HOST_TYPE_NAME));
  assert_that (gvm_get_host_type ("www.example_underscore.net"),
               is_equal_to (HOST_TYPE_NAME));
  assert_that (gvm_get_host_type ("www.example-dash.net"),
               is_equal_to (HOST_TYPE_NAME));
  assert_that (gvm_get_host_type ("greenbone.net"),
               is_equal_to (HOST_TYPE_NAME));
  assert_that (gvm_get_host_type ("g"), is_equal_to (HOST_TYPE_NAME));
  assert_that (gvm_get_host_type ("123.com"), is_equal_to (HOST_TYPE_NAME));
  /* Lengths. */
  assert_that (gvm_get_host_type (SIXTY "123.short.enough.com"),
               is_equal_to (0));
  assert_that (gvm_get_host_type (SIXTY "." SIXTY "." SIXTY "." SIXTY "."
                                        "56789.com"),
               is_equal_to (0));
}

Ensure (hosts, gvm_get_host_type_returns_host_type_cidr_block)
{
  assert_that (gvm_get_host_type ("192.168.0.0/24"),
               is_equal_to (HOST_TYPE_CIDR_BLOCK));
  assert_that (gvm_get_host_type ("1.1.1.1/8"),
               is_equal_to (HOST_TYPE_CIDR_BLOCK));
  assert_that (gvm_get_host_type ("192.168.1.128/25"),
               is_equal_to (HOST_TYPE_CIDR_BLOCK));
  assert_that (gvm_get_host_type ("10.0.0.1/16"),
               is_equal_to (HOST_TYPE_CIDR_BLOCK));
  assert_that (gvm_get_host_type ("10.1.1.0/30"),
               is_equal_to (HOST_TYPE_CIDR_BLOCK));
}

Ensure (hosts, gvm_get_host_type_returns_host_type_cidr6_block)
{
  assert_that (gvm_get_host_type ("::ffee:1/64"),
               is_equal_to (HOST_TYPE_CIDR6_BLOCK));
  assert_that (gvm_get_host_type ("2001:db8::/78"),
               is_equal_to (HOST_TYPE_CIDR6_BLOCK));
  assert_that (gvm_get_host_type ("2001:db8:0000:0000:001f:ffff:ffff:1/1"),
               is_equal_to (HOST_TYPE_CIDR6_BLOCK));
}

Ensure (hosts, gvm_get_host_type_returns_host_type_range_short)
{
  assert_that (gvm_get_host_type ("192.168.10.1-9"),
               is_equal_to (HOST_TYPE_RANGE_SHORT));
  assert_that (gvm_get_host_type ("192.168.10.1-50"),
               is_equal_to (HOST_TYPE_RANGE_SHORT));
  assert_that (gvm_get_host_type ("192.168.10.1-255"),
               is_equal_to (HOST_TYPE_RANGE_SHORT));
  assert_that (gvm_get_host_type ("1.1.1.1-9"),
               is_equal_to (HOST_TYPE_RANGE_SHORT));
  assert_that (gvm_get_host_type ("1.1.1.1-50"),
               is_equal_to (HOST_TYPE_RANGE_SHORT));
  assert_that (gvm_get_host_type ("1.1.1.1-255"),
               is_equal_to (HOST_TYPE_RANGE_SHORT));
  assert_that (gvm_get_host_type ("255.255.255.1-9"),
               is_equal_to (HOST_TYPE_RANGE_SHORT));
  assert_that (gvm_get_host_type ("255.255.255.1-50"),
               is_equal_to (HOST_TYPE_RANGE_SHORT));
  assert_that (gvm_get_host_type ("255.255.255.1-255"),
               is_equal_to (HOST_TYPE_RANGE_SHORT));
}

Ensure (hosts, gvm_get_host_type_returns_host_type_range6_short)
{
  assert_that (gvm_get_host_type ("::ffee:1-fe50"),
               is_equal_to (HOST_TYPE_RANGE6_SHORT));
  assert_that (gvm_get_host_type ("2000::-ffff"),
               is_equal_to (HOST_TYPE_RANGE6_SHORT));
}

Ensure (hosts, gvm_get_host_type_returns_host_type_range_long)
{
  assert_that (gvm_get_host_type ("192.168.10.1-192.168.10.9"),
               is_equal_to (HOST_TYPE_RANGE_LONG));
  assert_that (gvm_get_host_type ("192.168.10.1-192.168.10.50"),
               is_equal_to (HOST_TYPE_RANGE_LONG));
  assert_that (gvm_get_host_type ("192.168.10.1-192.168.10.255"),
               is_equal_to (HOST_TYPE_RANGE_LONG));
  assert_that (gvm_get_host_type ("1.1.1.1-1.1.1.9"),
               is_equal_to (HOST_TYPE_RANGE_LONG));
  assert_that (gvm_get_host_type ("1.1.1.1-1.1.1.50"),
               is_equal_to (HOST_TYPE_RANGE_LONG));
  assert_that (gvm_get_host_type ("1.1.1.1-1.1.1.255"),
               is_equal_to (HOST_TYPE_RANGE_LONG));
  assert_that (gvm_get_host_type ("255.255.255.1-255.255.255.9"),
               is_equal_to (HOST_TYPE_RANGE_LONG));
  assert_that (gvm_get_host_type ("255.255.255.1-255.255.255.50"),
               is_equal_to (HOST_TYPE_RANGE_LONG));
  assert_that (gvm_get_host_type ("255.255.255.1-255.255.255.255"),
               is_equal_to (HOST_TYPE_RANGE_LONG));
}

Ensure (hosts, gvm_get_host_type_returns_host_type_range6_long)
{
  assert_that (
    gvm_get_host_type ("2001:db0::-2001:0dbf:ffff:ffff:ffff:ffff:ffff:ffff"),
    is_equal_to (HOST_TYPE_RANGE6_LONG));
  assert_that (gvm_get_host_type ("::1:200:7-::1:205:500"),
               is_equal_to (HOST_TYPE_RANGE6_LONG));
}

Ensure (hosts, gvm_get_host_type_returns_error)
{
  assert_that (gvm_get_host_type (""), is_equal_to (-1));
  assert_that (gvm_get_host_type ("."), is_equal_to (-1));

  /* Invalid chars. */
  assert_that (gvm_get_host_type ("a,b"), is_equal_to (-1));
  assert_that (gvm_get_host_type ("="), is_equal_to (-1));

  /* Numeric TLD. */
  assert_that (gvm_get_host_type ("a.123"), is_equal_to (-1));

  /* IP with too many parts. */
  assert_that (gvm_get_host_type ("192.168.10.1.1"), is_equal_to (-1));

  /* IP with numbers out of bounds. */
  assert_that (gvm_get_host_type ("256.168.10.1"), is_equal_to (-1));
  assert_that (gvm_get_host_type ("192.256.10.1"), is_equal_to (-1));
  assert_that (gvm_get_host_type ("192.168.256.1"), is_equal_to (-1));
  assert_that (gvm_get_host_type ("192.168.10.256"), is_equal_to (-1));
  assert_that (gvm_get_host_type ("192.168.10.855"), is_equal_to (-1));

  /* Lengths. */
  assert_that (gvm_get_host_type (SIXTY "1234.too.long.com"), is_equal_to (-1));
  assert_that (gvm_get_host_type (SIXTY "." SIXTY "." SIXTY "." SIXTY "."
                                        "567890.com"),
               is_equal_to (-1));
}

Ensure (hosts, gvm_hosts_new_with_max_returns_success)
{
  gvm_hosts_t *hosts;

  hosts = gvm_hosts_new_with_max ("127.0.0.1", 1);
  assert_that (hosts, is_not_null);
  gvm_hosts_free (hosts);

  hosts = gvm_hosts_new_with_max ("127.0.0.1", 2000);
  assert_that (hosts, is_not_null);
  gvm_hosts_free (hosts);

  hosts = gvm_hosts_new_with_max ("127.0.0.1,127.0.0.2", 2);
  assert_that (hosts, is_not_null);
  gvm_hosts_free (hosts);

  hosts = gvm_hosts_new_with_max ("127.0.0.1, 127.0.0.2", 2);
  assert_that (hosts, is_not_null);
  gvm_hosts_free (hosts);
}

Ensure (hosts, gvm_hosts_new_with_max_returns_error)
{
  /* Host error. */
  assert_that (gvm_hosts_new_with_max ("a.123", 2), is_null);

  /* More than max_hosts hosts. */
  assert_that (gvm_hosts_new_with_max ("127.0.0.1, 127.0.0.2", 1), is_null);

  /* Wrong separator. */
  assert_that (gvm_hosts_new_with_max ("127.0.0.1 127.0.0.2", 2), is_null);
  assert_that (gvm_hosts_new_with_max ("127.0.0.1|127.0.0.2", 2), is_null);
}

Ensure (hosts, gvm_hosts_new_with_max_handles_range_edge_cases)
{
  gvm_hosts_t *max_ipv4_host =
    gvm_hosts_new_with_max ("255.255.255.255-255.255.255.255", 10);
  assert_that (max_ipv4_host, is_not_null);
  assert_that (max_ipv4_host->count, is_equal_to (1));
  gvm_hosts_free (max_ipv4_host);

  gvm_hosts_t *max_ipv6_host =
    gvm_hosts_new_with_max ("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
                            "-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
                            10);
  assert_that (max_ipv6_host, is_not_null);
  assert_that (max_ipv6_host->count, is_equal_to (1));
  gvm_hosts_free (max_ipv6_host);
}

// This is a macro so the line number below is clear on failure.
#define ASSERT_HOST_EQUALS(hosts_var, i, string)                               \
  {                                                                            \
    gchar *value;                                                              \
                                                                               \
    value = gvm_host_value_str (hosts_var->hosts[i]);                          \
    assert_true_with_message (g_strcmp0 (value, string) == 0,                  \
                              "Expected %s->hosts[%d] to be %s but it was %s", \
                              G_STRINGIFY (hosts_var), i, string, value);      \
    g_free (value);                                                            \
  }

static int
host_value_eq (gvm_host_t *host, gchar *string)
{
  int ret;
  gchar *value;

  value = gvm_host_value_str (host);
  ret = g_strcmp0 (value, string);
  g_free (value);
  return ret;
}

Ensure (hosts, gvm_hosts_move_host_to_end)
{
  gvm_hosts_t *hosts = NULL;
  gvm_host_t *host = NULL;
  int totalhosts;
  size_t current;

  hosts = gvm_hosts_new ("192.168.0.0/28");

  ASSERT_HOST_EQUALS (hosts, 0, "192.168.0.1");
  ASSERT_HOST_EQUALS (hosts, 1, "192.168.0.2");
  ASSERT_HOST_EQUALS (hosts, 2, "192.168.0.3");
  ASSERT_HOST_EQUALS (hosts, 3, "192.168.0.4");
  ASSERT_HOST_EQUALS (hosts, 4, "192.168.0.5");
  ASSERT_HOST_EQUALS (hosts, 5, "192.168.0.6");
  ASSERT_HOST_EQUALS (hosts, 6, "192.168.0.7");
  ASSERT_HOST_EQUALS (hosts, 7, "192.168.0.8");
  ASSERT_HOST_EQUALS (hosts, 8, "192.168.0.9");
  ASSERT_HOST_EQUALS (hosts, 9, "192.168.0.10");
  ASSERT_HOST_EQUALS (hosts, 10, "192.168.0.11");
  ASSERT_HOST_EQUALS (hosts, 11, "192.168.0.12");
  ASSERT_HOST_EQUALS (hosts, 12, "192.168.0.13");
  ASSERT_HOST_EQUALS (hosts, 13, "192.168.0.14");

  // Get first host
  host = gvm_hosts_next (hosts);

  totalhosts = gvm_hosts_count (hosts);
  assert_that (totalhosts, is_equal_to (14));

  while (host_value_eq (host, "192.168.0.9"))
    {
      host = gvm_hosts_next (hosts);
    }
  assert_that (host_value_eq (host, "192.168.0.9"), is_equal_to (0));

  current = hosts->current;
  gvm_hosts_move_current_host_to_end (hosts);
  assert_that (hosts->current, is_equal_to (current - 1));

  host = gvm_hosts_next (hosts);
  assert_that (host_value_eq (host, "192.168.0.10"), is_equal_to (0));
  assert_that (host_value_eq (hosts->hosts[totalhosts - 1], "192.168.0.9"),
               is_equal_to (0));

  ASSERT_HOST_EQUALS (hosts, 0, "192.168.0.1");
  ASSERT_HOST_EQUALS (hosts, 1, "192.168.0.2");
  ASSERT_HOST_EQUALS (hosts, 2, "192.168.0.3");
  ASSERT_HOST_EQUALS (hosts, 3, "192.168.0.4");
  ASSERT_HOST_EQUALS (hosts, 4, "192.168.0.5");
  ASSERT_HOST_EQUALS (hosts, 5, "192.168.0.6");
  ASSERT_HOST_EQUALS (hosts, 6, "192.168.0.7");
  ASSERT_HOST_EQUALS (hosts, 7, "192.168.0.8");
  ASSERT_HOST_EQUALS (hosts, 8, "192.168.0.10");
  ASSERT_HOST_EQUALS (hosts, 9, "192.168.0.11");
  ASSERT_HOST_EQUALS (hosts, 10, "192.168.0.12");
  ASSERT_HOST_EQUALS (hosts, 11, "192.168.0.13");
  ASSERT_HOST_EQUALS (hosts, 12, "192.168.0.14");
  ASSERT_HOST_EQUALS (hosts, 13, "192.168.0.9");

  gvm_hosts_free (hosts);
}

#define ASSERT_SLIST_HOST_EQUALS(list_var, index, host_str) \
  assert_that (g_slist_nth_data (list_var, index),          \
               is_equal_to_string (host_str));

Ensure (hosts, gvm_hosts_allowed_only_handles_noop)
{
  gvm_hosts_t *hosts = NULL;
  GSList *removed = NULL;

  // NULL allow_hosts and deny_hosts
  hosts = gvm_hosts_new ("192.168.0.1,192.168.0.2,192.168.0.3");
  removed = gvm_hosts_allowed_only (hosts, NULL, NULL);

  assert_that (gvm_hosts_count (hosts), is_equal_to (3));
  ASSERT_HOST_EQUALS (hosts, 0, "192.168.0.1");
  ASSERT_HOST_EQUALS (hosts, 1, "192.168.0.2");
  ASSERT_HOST_EQUALS (hosts, 2, "192.168.0.3");
  assert_that (removed, is_null);

  g_slist_free_full (removed, g_free);
  gvm_hosts_free (hosts);

  // NULL allow_hosts and deny_hosts
  hosts = gvm_hosts_new ("192.168.0.1,192.168.0.2,192.168.0.3");
  removed = gvm_hosts_allowed_only (hosts, NULL, NULL);

  assert_that (gvm_hosts_count (hosts), is_equal_to (3));
  ASSERT_HOST_EQUALS (hosts, 0, "192.168.0.1");
  ASSERT_HOST_EQUALS (hosts, 1, "192.168.0.2");
  ASSERT_HOST_EQUALS (hosts, 2, "192.168.0.3");
  assert_that (removed, is_null);

  g_slist_free_full (removed, g_free);
  gvm_hosts_free (hosts);

  // Empty allow_hosts and deny_hosts strings
  hosts = gvm_hosts_new ("192.168.0.1,192.168.0.2,192.168.0.3");
  removed = gvm_hosts_allowed_only (hosts, "", "");

  assert_that (gvm_hosts_count (hosts), is_equal_to (3));
  ASSERT_HOST_EQUALS (hosts, 0, "192.168.0.1");
  ASSERT_HOST_EQUALS (hosts, 1, "192.168.0.2");
  ASSERT_HOST_EQUALS (hosts, 2, "192.168.0.3");
  assert_that (removed, is_null);

  g_slist_free_full (removed, g_free);
  gvm_hosts_free (hosts);
}

Ensure (hosts, gvm_hosts_allowed_only_handles_deny)
{
  gvm_hosts_t *hosts = NULL;
  GSList *removed = NULL;

  // deny_hosts with NULL allow_hosts
  hosts = gvm_hosts_new ("192.168.0.1,192.168.0.2,192.168.0.3");
  removed = gvm_hosts_allowed_only (hosts, "192.168.0.2", NULL);

  assert_that (gvm_hosts_count (hosts), is_equal_to (2));
  ASSERT_HOST_EQUALS (hosts, 0, "192.168.0.1");
  ASSERT_HOST_EQUALS (hosts, 1, "192.168.0.3");
  assert_that (g_slist_length (removed), is_equal_to (1));
  ASSERT_SLIST_HOST_EQUALS (removed, 0, "192.168.0.2");

  g_slist_free_full (removed, g_free);
  gvm_hosts_free (hosts);

  // deny_hosts with empty allow_hosts string
  hosts = gvm_hosts_new ("192.168.0.1,192.168.0.2,192.168.0.3");
  removed = gvm_hosts_allowed_only (hosts, "192.168.0.2", "");
  assert_that (gvm_hosts_count (hosts), is_equal_to (2));
  ASSERT_HOST_EQUALS (hosts, 0, "192.168.0.1");
  ASSERT_HOST_EQUALS (hosts, 1, "192.168.0.3");
  assert_that (g_slist_length (removed), is_equal_to (1));
  ASSERT_SLIST_HOST_EQUALS (removed, 0, "192.168.0.2");

  g_slist_free_full (removed, g_free);
  gvm_hosts_free (hosts);
}

Ensure (hosts, gvm_hosts_allowed_only_handles_allow)
{
  gvm_hosts_t *hosts = NULL;
  int totalhosts;
  GSList *removed = NULL;

  // allow_hosts with NULL deny_hosts
  hosts = gvm_hosts_new ("192.168.0.1,192.168.0.2,192.168.0.3");
  removed = gvm_hosts_allowed_only (hosts, NULL, "192.168.0.3");

  totalhosts = gvm_hosts_count (hosts);
  assert_that (totalhosts, is_equal_to (1));
  ASSERT_HOST_EQUALS (hosts, 0, "192.168.0.3");
  assert_that (g_slist_length (removed), is_equal_to (2));
  ASSERT_SLIST_HOST_EQUALS (removed, 1, "192.168.0.1");
  ASSERT_SLIST_HOST_EQUALS (removed, 0, "192.168.0.2");

  g_slist_free_full (removed, g_free);
  gvm_hosts_free (hosts);

  // allow_hosts with empty deny_hosts string
  hosts = gvm_hosts_new ("192.168.0.1,192.168.0.2,192.168.0.3");
  removed = gvm_hosts_allowed_only (hosts, "", "192.168.0.3");

  totalhosts = gvm_hosts_count (hosts);
  assert_that (totalhosts, is_equal_to (1));
  ASSERT_HOST_EQUALS (hosts, 0, "192.168.0.3");
  assert_that (g_slist_length (removed), is_equal_to (2));
  ASSERT_SLIST_HOST_EQUALS (removed, 1, "192.168.0.1");
  ASSERT_SLIST_HOST_EQUALS (removed, 0, "192.168.0.2");

  g_slist_free_full (removed, g_free);
  gvm_hosts_free (hosts);
}

Ensure (hosts, gvm_hosts_allowed_only_handles_both)
{
  gvm_hosts_t *hosts = NULL;
  int totalhosts;
  GSList *removed = NULL;

  // Both allow_hosts and deny_hosts
  // Deny should have higher priority than allow
  hosts = gvm_hosts_new ("192.168.0.1,192.168.0.2,192.168.0.3");
  removed =
    gvm_hosts_allowed_only (hosts, "192.168.0.2", "192.168.0.2,192.168.0.3");

  totalhosts = gvm_hosts_count (hosts);
  assert_that (totalhosts, is_equal_to (1));
  ASSERT_HOST_EQUALS (hosts, 0, "192.168.0.3");
  assert_that (g_slist_length (removed), is_equal_to (2));
  ASSERT_SLIST_HOST_EQUALS (removed, 1, "192.168.0.1");
  ASSERT_SLIST_HOST_EQUALS (removed, 0, "192.168.0.2");

  g_slist_free_full (removed, g_free);
  gvm_hosts_free (hosts);
}

Ensure (hosts, gvm_hosts_reverse_moves_hosts)
{
  gvm_hosts_t *empty_hosts = NULL;
  gvm_hosts_t *single_host = NULL;
  gvm_hosts_t *odd_hosts = NULL;
  gvm_hosts_t *even_hosts = NULL;

  empty_hosts = gvm_hosts_new ("");
  gvm_hosts_reverse (empty_hosts);
  assert_that (empty_hosts->count, is_equal_to (0));
  gvm_hosts_free (empty_hosts);

  single_host = gvm_hosts_new ("192.168.0.1");
  gvm_hosts_reverse (single_host);
  assert_that (single_host->count, is_equal_to (1));
  ASSERT_HOST_EQUALS (single_host, 0, "192.168.0.1");
  gvm_hosts_free (single_host);

  odd_hosts = gvm_hosts_new ("192.168.0.1,192.168.0.2,192.168.0.3");
  gvm_hosts_reverse (odd_hosts);
  assert_that (odd_hosts->count, is_equal_to (3));
  ASSERT_HOST_EQUALS (odd_hosts, 0, "192.168.0.3");
  ASSERT_HOST_EQUALS (odd_hosts, 1, "192.168.0.2");
  ASSERT_HOST_EQUALS (odd_hosts, 2, "192.168.0.1");
  gvm_hosts_free (odd_hosts);

  even_hosts =
    gvm_hosts_new ("192.168.0.1,192.168.0.2,192.168.0.3,192.168.0.4");
  gvm_hosts_reverse (even_hosts);
  assert_that (even_hosts->count, is_equal_to (4));
  ASSERT_HOST_EQUALS (even_hosts, 0, "192.168.0.4");
  ASSERT_HOST_EQUALS (even_hosts, 1, "192.168.0.3");
  ASSERT_HOST_EQUALS (even_hosts, 2, "192.168.0.2");
  ASSERT_HOST_EQUALS (even_hosts, 3, "192.168.0.1");
  gvm_hosts_free (even_hosts);
}

/* Test suite. */

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, hosts, gvm_hosts_new_never_returns_null);
  add_test_with_context (suite, hosts,
                         gvm_get_host_type_returns_host_type_ipv4);
  add_test_with_context (suite, hosts,
                         gvm_get_host_type_returns_host_type_ipv6);
  add_test_with_context (suite, hosts,
                         gvm_get_host_type_returns_host_type_hostname);
  add_test_with_context (suite, hosts,
                         gvm_get_host_type_returns_host_type_cidr_block);
  add_test_with_context (suite, hosts,
                         gvm_get_host_type_returns_host_type_cidr6_block);
  add_test_with_context (suite, hosts,
                         gvm_get_host_type_returns_host_type_range_short);
  add_test_with_context (suite, hosts,
                         gvm_get_host_type_returns_host_type_range6_short);
  add_test_with_context (suite, hosts,
                         gvm_get_host_type_returns_host_type_range_long);
  add_test_with_context (suite, hosts,
                         gvm_get_host_type_returns_host_type_range6_long);
  add_test_with_context (suite, hosts, gvm_get_host_type_returns_error);

  add_test_with_context (suite, hosts, gvm_hosts_new_with_max_returns_error);
  add_test_with_context (suite, hosts, gvm_hosts_new_with_max_returns_success);
  add_test_with_context (suite, hosts,
                         gvm_hosts_new_with_max_handles_range_edge_cases);

  add_test_with_context (suite, hosts, gvm_hosts_move_host_to_end);

  add_test_with_context (suite, hosts, gvm_hosts_allowed_only_handles_noop);
  add_test_with_context (suite, hosts, gvm_hosts_allowed_only_handles_deny);
  add_test_with_context (suite, hosts, gvm_hosts_allowed_only_handles_allow);
  add_test_with_context (suite, hosts, gvm_hosts_allowed_only_handles_both);

  add_test_with_context (suite, hosts, gvm_hosts_reverse_moves_hosts);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
