/* SPDX-FileCopyrightText: 2019-2025 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "serverutils.c"

#include <cgreen/assertions.h>
#include <cgreen/cgreen.h>
#include <cgreen/constraint_syntax_helpers.h>
#include <cgreen/internal/c_assertions.h>
#include <cgreen/mocks.h>

Describe (serverutils);
BeforeEach (serverutils)
{
}

AfterEach (serverutils)
{
}

static void
chk (int ret)
{
  assert_that (ret, is_equal_to (GNUTLS_E_SUCCESS));
}

/* server_new_gnutls_set */

Ensure (serverutils, server_new_gnutls_set)
{
  int ret;
  unsigned len;
  gnutls_session_t session;
  gnutls_certificate_credentials_t cred;
  gnutls_x509_privkey_t pkey;
  gnutls_x509_crt_t cert, *certs;
  gnutls_datum_t pkey_data, cert_data;
  unsigned char serial[] = {0x99, 0x99, 0x99, 0x99};

  // Setup credential.

  chk (gnutls_certificate_allocate_credentials (&cred));

  chk (gnutls_x509_privkey_init (&pkey));
  chk (gnutls_x509_privkey_generate (pkey, GNUTLS_PK_RSA, 2048, 0));

  chk (gnutls_x509_crt_init (&cert));
  chk (gnutls_x509_crt_set_key (cert, pkey));

  chk (gnutls_x509_crt_set_version (cert, 3));
  chk (gnutls_x509_crt_set_serial (cert, serial, sizeof (serial)));
  chk (gnutls_x509_crt_set_dn_by_oid (cert, GNUTLS_OID_X520_COMMON_NAME, 0,
                                      "Eg", strlen ("Eg")));
  chk (gnutls_x509_crt_set_issuer_dn (cert, "CN=Self-Signed Certificate", 0));

  chk (gnutls_x509_crt_set_activation_time (cert, time (NULL)));
  chk (gnutls_x509_crt_set_expiration_time (cert,
                                            time (NULL) + 365 * 24 * 60 * 60));

  chk (gnutls_x509_crt_sign2 (cert, cert, pkey, GNUTLS_DIG_SHA256, 0));

  chk (gnutls_init (&session, GNUTLS_CLIENT));

  chk (gnutls_x509_privkey_export2 (pkey, GNUTLS_X509_FMT_PEM, &pkey_data));
  chk (gnutls_x509_crt_export2 (cert, GNUTLS_X509_FMT_PEM, &cert_data));

  chk (gnutls_certificate_set_x509_key_mem (cred, &cert_data, &pkey_data,
                                            GNUTLS_X509_FMT_PEM));

  // Setup session with credential.

  ret = server_new_gnutls_set (GNUTLS_CLIENT, "NORMAL", &session, &cred);
  assert_that (ret, is_equal_to (0));

  // Confirm that credential was set.

  chk (gnutls_certificate_get_x509_crt (cred, 0, &certs, &len));
  assert_that (len, is_equal_to (1));
  assert_that (gnutls_x509_crt_equals (cert, certs[0]), is_true);

  // Clean up.

  gnutls_free (pkey_data.data);
  gnutls_free (cert_data.data);
  gnutls_x509_crt_deinit (cert);
  for (unsigned i = 0; i < len; i++)
    gnutls_x509_crt_deinit (certs[i]);
  gnutls_free (certs);
  gnutls_x509_privkey_deinit (pkey);
  gnutls_certificate_free_credentials (cred);
}

/* Test suite. */
int
main (int argc, char **argv)
{
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, serverutils, server_new_gnutls_set);

  if (argc > 1)
    return run_single_test (suite, argv[1], create_text_reporter ());

  return run_test_suite (suite, create_text_reporter ());
}
