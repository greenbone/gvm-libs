/* SPDX-FileCopyrightText: 2019-2025 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "kb.c"

#include <cgreen/assertions.h>
#include <cgreen/cgreen.h>
#include <cgreen/constraint_syntax_helpers.h>
#include <cgreen/internal/c_assertions.h>
#include <cgreen/mocks.h>

#define TCP "tcp://"

Describe (kb);
BeforeEach (kb)
{
}

AfterEach (kb)
{
}

/* parse_port_of_addr */

Ensure (kb, parse_port_of_addr)
{
  const char *addr, *port;

  addr = TCP "xxx:5";
  port = parse_port_of_addr (addr, strlen (TCP));
  assert_that (port, is_equal_to_string ("5"));
}

Ensure (kb, parse_port_of_addr_missing)
{
  const char *addr, *port;

  addr = TCP "xxx";
  port = parse_port_of_addr (addr, strlen (TCP));
  assert_that (port, is_null);
}

Ensure (kb, parse_port_of_addr_v6)
{
  const char *addr, *port;

  addr = TCP "[2001:db8::1]:8080";
  port = parse_port_of_addr (addr, strlen (TCP));
  assert_that (port, is_equal_to_string ("8080"));
}

/* Test suite. */
int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, kb, parse_port_of_addr);
  add_test_with_context (suite, kb, parse_port_of_addr_missing);
  add_test_with_context (suite, kb, parse_port_of_addr_v6);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
