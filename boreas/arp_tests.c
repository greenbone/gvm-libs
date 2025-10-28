/* SPDX-FileCopyrightText: 2025 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "arp.c"

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>

// Mock for libnet_name2addr4
uint32_t
__wrap_libnet_name2addr4 (libnet_t *l, char *, uint8_t);
uint32_t
__wrap_libnet_name2addr4 (libnet_t *l, char *host_name, uint8_t use_name)
{
  return (uint32_t) mock (l, host_name, use_name);
}

Describe (arp);
BeforeEach (arp)
{
  // Reset static variables before each test
  libnet = NULL;
}

AfterEach (arp)
{
}

/* strip_newline */

Ensure (arp, strip_newline_removes_trailing_newlines)
{
  char test_str[20] = "test\n\n";
  strip_newline (test_str);
  assert_that (test_str, is_equal_to_string ("test"));
}

Ensure (arp, strip_newline_handles_empty_string)
{
  char test_str[1] = "";
  strip_newline (test_str);
  assert_that (test_str, is_equal_to_string (""));
}

Ensure (arp, strip_newline_handles_string_without_newlines)
{
  char test_str[10] = "test";
  strip_newline (test_str);
  assert_that (test_str, is_equal_to_string ("test"));
}

/* xresolve */

Ensure (arp, xresolve_handles_broadcast_address)
{
  uint32_t addr = 0;
  int result = xresolve (NULL, "255.255.255.255", 0, &addr);
  assert_that (result, is_equal_to (1));
  assert_that (addr, is_equal_to (0xffffffff));
}

/* format_mac */

Ensure (arp, format_mac_formats_correctly)
{
  unsigned char mac[6] = {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc};
  char buf[128];
  char *result = format_mac (mac, buf, sizeof (buf));
  assert_that (result, is_equal_to_string ("12:34:56:78:9a:bc"));
}

Ensure (arp, format_mac_handles_ethnull)
{
  char buf[128];
  char *result = format_mac (ethnull, buf, sizeof (buf));
  assert_that (result, is_equal_to_string ("00:00:00:00:00:00"));
}

Ensure (arp, format_mac_handles_ethxmas)
{
  char buf[128];
  char *result = format_mac (ethxmas, buf, sizeof (buf));
  assert_that (result, is_equal_to_string ("ff:ff:ff:ff:ff:ff"));
}

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, arp, strip_newline_removes_trailing_newlines);
  add_test_with_context (suite, arp, strip_newline_handles_empty_string);
  add_test_with_context (suite, arp,
                         strip_newline_handles_string_without_newlines);
  add_test_with_context (suite, arp, xresolve_handles_broadcast_address);
  add_test_with_context (suite, arp, format_mac_formats_correctly);
  add_test_with_context (suite, arp, format_mac_handles_ethnull);
  add_test_with_context (suite, arp, format_mac_handles_ethxmas);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
