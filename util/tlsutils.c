/* SPDX-FileCopyrightText: 2009-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file tlsutils.c
 * @brief TLS certificate utilities.
 */

#include "tlsutils.h"

#include <string.h>

#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "libgvm util"

/**
 * @brief Try to determine the format (DER or PEM) of a x509 certificate.
 *
 * @param[in]  cert_data  The certificate data.
 * @param[in]  cert_len   Length of the certificate data.
 *
 * @return The GnuTLS x509 certificate type.
 */
gnutls_x509_crt_fmt_t
gvm_x509_format_from_data (const char *cert_data, size_t cert_len)
{
  static const gchar *begin_str = "-----BEGIN ";
  if (g_strstr_len (cert_data, cert_len, begin_str))
    return GNUTLS_X509_FMT_PEM;
  else
    return GNUTLS_X509_FMT_DER;
}

/**
 * @brief Decode a Base64 string to the contents of a gnutls_datum_t
 *
 * @param[in]     encoded         The Base64 data as a NUL-terminated string
 * @param[in,out] decoded_datum   The datum struct to decode to.
 *
 * @return The return code from gnutls_base64_decode2
 */
int
gvm_base64_to_gnutls_datum (const char *encoded, gnutls_datum_t *decoded_datum)
{
  gnutls_datum_t encoded_datum;
  decoded_datum->data = NULL;
  decoded_datum->size = 0;
  encoded_datum.data = (unsigned char *) encoded;
  encoded_datum.size = strlen (encoded);

  return gnutls_base64_decode2 (&encoded_datum, decoded_datum);
}

/**
 * @brief Frees a list of X509 certificates.
 *
 * @param[in]  certs        The cerificate list to free.
 * @param[in]  certs_count  The number of certificates in the list.
 */
void
gvm_x509_cert_list_free (gnutls_x509_crt_t *certs, unsigned int certs_count)
{
  if (certs == NULL)
    return;
  for (unsigned int i = 0; i < certs_count; i++)
    gnutls_x509_crt_deinit (certs[i]);
  gnutls_free (certs);
}

/**
 * @brief Export a GnuTLS x509 private key as a PEM formatted string.
 *
 * @param[in]  privkey  The private key to export.
 *
 * @return The private key as a PEM string, or NULL on error.
 */
gchar *
gvm_x509_privkey_to_pem (gnutls_x509_privkey_t privkey)
{
  gchar *pem_str = NULL;
  int ret;
  gnutls_datum_t export_datum = {.data = NULL, .size = 0};

  ret =
    gnutls_x509_privkey_export2 (privkey, GNUTLS_X509_FMT_PEM, &export_datum);
  if (ret)
    g_warning ("%s: Error exporting private key: %s", __func__,
               gnutls_strerror (ret));
  else
    pem_str = g_strdup ((const char *) export_datum.data);

  gnutls_free (export_datum.data);

  return pem_str;
}

/**
 * @brief Export a GnuTLS x509 cerificate list as a PEM formatted string.
 *
 * @param[in]  certs        The array of certificates to export
 * @param[in]  certs_count  The number of certificates to export
 *
 * @return  The certificates as a PEM string, or NULL on error.
 */
gchar *
gvm_x509_cert_list_to_pem (gnutls_x509_crt_t *certs, unsigned int certs_count)
{
  int ret;
  GString *certs_string = g_string_new ("");
  for (unsigned int i = 0; i < certs_count; i++)
    {
      gnutls_x509_crt_t cert;
      gnutls_datum_t export_datum = {.data = NULL, .size = 0};

      cert = certs[i];
      ret = gnutls_x509_crt_export2 (cert, GNUTLS_X509_FMT_PEM, &export_datum);
      if (ret)
        {
          g_warning ("%s: Error exporting certificate: %s", __func__,
                     gnutls_strerror (ret));
        }
      else
        g_string_append_printf (certs_string, "%s\n",
                                (char *) export_datum.data);
      gnutls_free (export_datum.data);
    }
  return g_string_free (certs_string, FALSE);
}

/**
 * @brief Export a GnuTLS x509 CRL as a PEM formatted string.
 *
 * @param[in]  crl        The certificate revocation list CRL
 *
 * @return  The certificates as a PEM string, or NULL on error.
 */
gchar *
gvm_x509_crl_to_pem (gnutls_x509_crl_t crl)
{
  gchar *crl_str = NULL;
  int ret;
  gnutls_datum_t export_datum = {.data = NULL, .size = 0};

  ret = gnutls_x509_crl_export2 (crl, GNUTLS_X509_FMT_PEM, &export_datum);
  if (ret)
    {
      g_warning ("%s: Error exporting CRL: %s", __func__,
                 gnutls_strerror (ret));
    }
  else
    crl_str = g_strdup ((char *) export_datum.data);

  gnutls_free (export_datum.data);
  return crl_str;
}

/**
 * @brief Convert GnuTLS PKCS12 data to a PEM formatted string.
 *
 * @param[in]  pkcs12           PKCS12 data to get data from
 * @param[in]  passphrase       Passphrase to decrypt PKCS12 data
 * @param[out] privkey_out      Optional private key output
 * @param[out] cert_chain_out   Optional certificate chain output
 * @param[out] extra_certs_out  Optional extra certificates output
 * @param[out] crl_out          Optional CRL output
 *
 * @return 0 success or a GnuTLS error code if decryption or parsing fails.
 */
int
gvm_pkcs12_to_pem (gnutls_pkcs12_t pkcs12, const char *passphrase,
                   gchar **privkey_out, gchar **cert_chain_out,
                   gchar **extra_certs_out, gchar **crl_out)
{
  gnutls_x509_privkey_t privkey;
  gnutls_x509_crt_t *chain_certs, *extra_certs;
  gnutls_x509_crl_t crl;
  unsigned int chain_certs_count, extra_certs_count;
  int ret;

  if (privkey_out)
    *privkey_out = NULL;
  if (cert_chain_out)
    *cert_chain_out = NULL;
  if (extra_certs_out)
    *extra_certs_out = NULL;
  if (crl_out)
    *crl_out = NULL;

  chain_certs = extra_certs = NULL;

  gnutls_x509_privkey_init (&privkey);
  gnutls_x509_crl_init (&crl);
  ret = gnutls_pkcs12_simple_parse (pkcs12, passphrase, &privkey, &chain_certs,
                                    &chain_certs_count, &extra_certs,
                                    &extra_certs_count, &crl, 0);
  if (ret != GNUTLS_E_SUCCESS)
    {
      gnutls_x509_privkey_deinit (privkey);
      gnutls_x509_crl_deinit (crl);
      return ret;
    }

  if (privkey_out && privkey)
    *privkey_out = gvm_x509_privkey_to_pem (privkey);

  gnutls_x509_privkey_deinit (privkey);

  if (cert_chain_out && chain_certs_count)
    *cert_chain_out =
      gvm_x509_cert_list_to_pem (chain_certs, chain_certs_count);

  if (extra_certs_out && extra_certs_count)
    *extra_certs_out =
      gvm_x509_cert_list_to_pem (extra_certs, extra_certs_count);

  if (crl_out && crl)
    *crl_out = gvm_x509_crl_to_pem (crl);

  gvm_x509_cert_list_free (chain_certs, chain_certs_count);
  gvm_x509_cert_list_free (extra_certs, extra_certs_count);
  gnutls_x509_crl_deinit (crl);

  return GNUTLS_E_SUCCESS;
}
