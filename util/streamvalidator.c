/* SPDX-FileCopyrightText: 2025 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "streamvalidator.h"

#include "authutils.h"

#include <assert.h>
#include <gcrypt.h>
#include <glib.h>
#include <stdint.h>
#include <string.h>

/**
 * @file
 * @brief Data stream validation.
 */

/**
 * @brief Data stream validator structure.
 */
struct gvm_stream_validator
{
  gchar *expected_hash_str;  ///< Expected hash algorithm and hex string.
  gchar *expected_hash_hex;  ///< Expected hash value as hexadecimal string.
  int algorithm;             ///< The hash algorithm used.
  size_t expected_size;      ///< Expected amount of data to validate.
  size_t current_size;       ///< Current total amount of data received.
  gboolean size_enforced;    ///< TRUE enforce size checks; FALSE hash-only.
  gcry_md_hd_t gcrypt_md_hd; ///< gcrypt message digest handle.
};

/**
 * @brief Gets a string representation of a gvm_stream_validator_return_t
 *
 * @param[in]  value    The value to get a string representation of.
 *
 * @return Static string describing the return value
 *          or NULL if value is GVM_STREAM_VALIDATOR_OK.
 */
const char *
gvm_stream_validator_return_str (gvm_stream_validator_return_t value)
{
  switch (value)
    {
    case GVM_STREAM_VALIDATOR_INTERNAL_ERROR:
      return "internal error";
    case GVM_STREAM_VALIDATOR_OK:
      return NULL;
    case GVM_STREAM_VALIDATOR_DATA_TOO_SHORT:
      return "too short";
    case GVM_STREAM_VALIDATOR_DATA_TOO_LONG:
      return "too long";
    case GVM_STREAM_VALIDATOR_INVALID_HASH_SYNTAX:
      return "invalid hash syntax";
    case GVM_STREAM_VALIDATOR_INVALID_HASH_ALGORITHM:
      return "invalid or unsupported hash algorithm";
    case GVM_STREAM_VALIDATOR_INVALID_HASH_VALUE:
      return "invalid hash value";
    case GVM_STREAM_VALIDATOR_HASH_MISMATCH:
      return "hash does not match";
    default:
      return "unknown error";
    }
}

/**
 * @brief Allocate and initialize a checksum-only stream validator.
 *
 * @param[in]  expected_hash_str  Expected hash / checksum string consisting of
 *                               an algorithm name or OID as recognized by
 *                               gcrypt, followed by a colon and the
 *                               hex-encoded hash,
 *                               e.g. "md5:70165459812a0d38851a4a4c3e4124c9".
 * @param[out] validator_out      Pointer to output location of the newly
 * allocated validator.
 *
 * @return A gvm_stream_validator_return_t code indicating success or the
 *         reason of failure.
 *
 * @note Size is NOT enforced; callers who need exact-size validation must use
 *       gvm_stream_validator_with_size_new (..., expected_size, ...).
 */
gvm_stream_validator_return_t
gvm_stream_validator_new (const char *expected_hash_str,
                          gvm_stream_validator_t *validator_out)
{
  return gvm_stream_validator_with_size_new (
    expected_hash_str, GVM_STREAM_VALIDATOR_NO_SIZE, validator_out);
}

/**
 * @brief Allocate and initialize a new data stream validator.
 *
 * @param[in]  expected_hash_str  Expected hash / checksum string consisting of
 *                                an algorithm name or OID as recognized by
 *                                gcrypt, followed by a colon and the
 *                                hex-encoded hash,
 *                                e.g. "md5:70165459812a0d38851a4a4c3e4124c9".
 * @param[in]  expected_size  The number of bytes expected to be sent.
 *                            Pass (size_t)-1 to disable size enforcement
 *                            and validate by hash only.
 * @param[out] validator_out  Pointer to output location of the newly allocated
 *                             validator.
 *
 * @return A validator return code, returning a failure if the expected hash
 *         string is invalid or uses an unsupported algorithm.
 *
 * @note When size enforcement is enabled (expected_size != (size_t)-1),
 *       gvm_stream_validator_write() will return DATA_TOO_LONG if the stream
 *       exceeds the expected size, and gvm_stream_validator_end() will return
 *       DATA_TOO_SHORT if the stream ends early.
 */
gvm_stream_validator_return_t
gvm_stream_validator_with_size_new (const char *expected_hash_str,
                                    size_t expected_size,
                                    gvm_stream_validator_t *validator_out)
{
  assert (validator_out);

  static GRegex *hex_regex = NULL;
  gchar **parts = NULL;
  const char *algo_str = NULL;
  const char *hex_str = NULL;
  int algo;
  unsigned int expected_hex_len;
  gcry_md_hd_t gcrypt_md_hd;
  gboolean size_enforced = FALSE;
  size_t final_expected_size = 0;

  if (expected_hash_str == NULL)
    return GVM_STREAM_VALIDATOR_INVALID_HASH_SYNTAX;

  if (hex_regex == NULL)
    hex_regex = g_regex_new ("^(?:[0-9A-Fa-f][0-9A-Fa-f])+$", 0, 0, NULL);

  *validator_out = NULL;

  parts = g_strsplit (expected_hash_str, ":", 2);
  guint n = g_strv_length (parts);
  if (n != 2)
    {
      g_strfreev (parts);
      return GVM_STREAM_VALIDATOR_INVALID_HASH_SYNTAX;
    }
  algo_str = parts[0];
  hex_str = parts[1];

  if (expected_size != GVM_STREAM_VALIDATOR_NO_SIZE)
    {
      final_expected_size = expected_size;
      size_enforced = TRUE;
    }
  else
    {
      final_expected_size = 0;
      size_enforced = FALSE;
    }

  algo = gcry_md_map_name (algo_str);
  if (algo == GCRY_MD_NONE || gcry_md_test_algo (algo))
    {
      g_strfreev (parts);
      return GVM_STREAM_VALIDATOR_INVALID_HASH_ALGORITHM;
    }

  expected_hex_len = gcry_md_get_algo_dlen (algo) * 2;
  if (strlen (hex_str) != expected_hex_len
      || g_regex_match (hex_regex, hex_str, 0, NULL) == FALSE)
    {
      g_strfreev (parts);
      return GVM_STREAM_VALIDATOR_INVALID_HASH_VALUE;
    }

  gcrypt_md_hd = NULL;
  if (gcry_md_open (&gcrypt_md_hd, algo, 0))
    {
      g_strfreev (parts);
      return GVM_STREAM_VALIDATOR_INTERNAL_ERROR;
    }

  *validator_out = g_malloc0 (sizeof (struct gvm_stream_validator));
  (*validator_out)->algorithm = algo;
  (*validator_out)->expected_size = final_expected_size;
  (*validator_out)->size_enforced = size_enforced;
  (*validator_out)->expected_hash_str = g_strdup (expected_hash_str);
  (*validator_out)->expected_hash_hex = g_strdup (hex_str);
  (*validator_out)->gcrypt_md_hd = gcrypt_md_hd;
  (*validator_out)->current_size = 0;

  g_strfreev (parts);
  return GVM_STREAM_VALIDATOR_OK;
}

/**
 * @brief Rewind the validation state of a stream validator while keeping the
 *        expected hash and data size.
 *
 * @param[in]  validator  The validator to rewind.
 */
void
gvm_stream_validator_rewind (gvm_stream_validator_t validator)
{
  gcry_md_reset (validator->gcrypt_md_hd);
  validator->current_size = 0;
}

/**
 * @brief Free a stream validator and all of its fields.
 *
 * @param[in]  validator  The validator to free.
 */
void
gvm_stream_validator_free (gvm_stream_validator_t validator)
{
  gcry_md_close (validator->gcrypt_md_hd);
  g_free (validator->expected_hash_str);
  g_free (validator->expected_hash_hex);
  g_free (validator);
}

/**
 * @brief Write data to a validator, updating the hash state and current size.
 *
 * Will fail if the total data size exceeds the expected size.
 *
 * @param[in]  validator  The validator to handle the data
 * @param[in]  data       The data to write.
 * @param[in]  length     Length of the data.
 *
 * @return Validator return code, either a "success" or "too long".
 */
gvm_stream_validator_return_t
gvm_stream_validator_write (gvm_stream_validator_t validator, const char *data,
                            size_t length)
{
  if (validator->size_enforced)
    {
      if (length > validator->expected_size - validator->current_size)
        return GVM_STREAM_VALIDATOR_DATA_TOO_LONG;
    }

  gcry_md_write (validator->gcrypt_md_hd, data, length);
  validator->current_size += length;

  return GVM_STREAM_VALIDATOR_OK;
}

/**
 * @brief Signal the end of data input into a validator and produce the result
 *        of the validation.
 *
 * @param[in]  validator  The validator to signal the end of data input of.
 *
 * @return The validation result.
 */
gvm_stream_validator_return_t
gvm_stream_validator_end (gvm_stream_validator_t validator)
{
  unsigned char *actual_hash_bin;
  gchar *actual_hash_hex;

  if (validator->size_enforced)
    {
      if (validator->current_size < validator->expected_size)
        return GVM_STREAM_VALIDATOR_DATA_TOO_SHORT;

      if (validator->current_size > validator->expected_size)
        return GVM_STREAM_VALIDATOR_DATA_TOO_LONG;
    }

  actual_hash_bin =
    gcry_md_read (validator->gcrypt_md_hd, validator->algorithm);
  actual_hash_hex = digest_hex (validator->algorithm, actual_hash_bin);
  if (strcasecmp (validator->expected_hash_hex, actual_hash_hex))
    {
      g_free (actual_hash_hex);
      return GVM_STREAM_VALIDATOR_HASH_MISMATCH;
    }
  g_free (actual_hash_hex);

  return GVM_STREAM_VALIDATOR_OK;
}
