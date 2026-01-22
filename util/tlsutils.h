/* SPDX-FileCopyrightText: 2009-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file tlsutils.h
 * @brief TLS certificate utilities headers.
 */

#ifndef _GVM_UTIL_TLSUTILS_H
#define _GVM_UTIL_TLSUTILS_H

#include <glib.h>
#include <gnutls/gnutls.h>
#include <gnutls/pkcs12.h>

gnutls_x509_crt_fmt_t
gvm_x509_format_from_data (const char *, size_t);

int
gvm_base64_to_gnutls_datum (const char *, gnutls_datum_t *);

void
gvm_x509_cert_list_free (gnutls_x509_crt_t *certs, unsigned int certs_count);

gchar *
gvm_x509_privkey_to_pem (gnutls_x509_privkey_t privkey);

gchar *
gvm_x509_cert_list_to_pem (gnutls_x509_crt_t *certs, unsigned int certs_count);

gchar *
gvm_x509_crl_to_pem (gnutls_x509_crl_t crl);

int
gvm_pkcs12_to_pem (gnutls_pkcs12_t pkcs12, const char *passphrase,
                   gchar **privkey_out, gchar **cert_chain_out,
                   gchar **extra_certs_out, gchar **crl_out);

#endif /* not _GVM_UTIL_TLSUTILS_H */
