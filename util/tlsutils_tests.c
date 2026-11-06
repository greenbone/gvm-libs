/* SPDX-FileCopyrightText: 2009-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "tlsutils.c"

#include <cgreen/assertions.h>
#include <cgreen/cgreen.h>
#include <cgreen/constraint_syntax_helpers.h>
#include <cgreen/internal/c_assertions.h>
#include <cgreen/mocks.h>

Describe (tlsutils);
BeforeEach (tlsutils)
{
}
AfterEach (tlsutils)
{
}

/* gvm_x509_format_from_data */

Ensure (tlsutils, fmt_detects_pem)
{
  const char *pem = "-----BEGIN CERTIFICATE-----\nMIIB\n";
  gnutls_x509_crt_fmt_t fmt;

  fmt = gvm_x509_format_from_data (pem, strlen (pem));
  assert_that (fmt, is_equal_to (GNUTLS_X509_FMT_PEM));
}

Ensure (tlsutils, fmt_detects_der)
{
  const guchar der[] = {0x30, 0x82, 0x00, 0x01, 0x00};
  gnutls_x509_crt_fmt_t fmt;

  fmt = gvm_x509_format_from_data ((const char *) der, sizeof (der));
  assert_that (fmt, is_equal_to (GNUTLS_X509_FMT_DER));
}

Ensure (tlsutils, fmt_respects_length)
{
  const char *data = "xx-----BEGIN ";
  gnutls_x509_crt_fmt_t fmt;

  fmt = gvm_x509_format_from_data (data, 2);
  assert_that (fmt, is_equal_to (GNUTLS_X509_FMT_DER));
}

/* gvm_base64_to_gnutls_datum */

Ensure (tlsutils, base64_decodes)
{
  gnutls_datum_t datum;
  int ret;

  ret = gvm_base64_to_gnutls_datum ("aGVsbG8=", &datum);
  assert_that (ret, is_equal_to (GNUTLS_E_SUCCESS));
  assert_that ((int) datum.size, is_equal_to (5));
  assert_that (memcmp (datum.data, "hello", 5), is_equal_to (0));
  gnutls_free (datum.data);
}

Ensure (tlsutils, base64_rejects_invalid)
{
  gnutls_datum_t datum;
  int ret;

  ret = gvm_base64_to_gnutls_datum ("@@not-base64@@", &datum);
  assert_that (ret, is_not_equal_to (GNUTLS_E_SUCCESS));
  if (datum.data)
    gnutls_free (datum.data);
}

/* Test suite. */

int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, tlsutils, fmt_detects_pem);
  add_test_with_context (suite, tlsutils, fmt_detects_der);
  add_test_with_context (suite, tlsutils, fmt_respects_length);
  add_test_with_context (suite, tlsutils, base64_decodes);
  add_test_with_context (suite, tlsutils, base64_rejects_invalid);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
