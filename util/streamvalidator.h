/* SPDX-FileCopyrightText: 2025 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _GVM_STREAMVALIDATOR_H
#define _GVM_STREAMVALIDATOR_H

#include <stdio.h>

/**
 * @file
 * @brief Data stream validation headers.
 */

typedef enum {
  /** An internal error ocurred. */
  GVM_STREAM_VALIDATOR_INTERNAL_ERROR = -1,
  /** Action successful / data is valid. */
  GVM_STREAM_VALIDATOR_OK = 0,
  /** Not enough data received. */
  GVM_STREAM_VALIDATOR_DATA_TOO_SHORT = 1,
  /** Too much data received. */
  GVM_STREAM_VALIDATOR_DATA_TOO_LONG,
  /** Syntax error in hash string (not using "algo:hex" format). */
  GVM_STREAM_VALIDATOR_INVALID_HASH_SYNTAX,
  /** Invalid or unsupported hash algorithm. */
  GVM_STREAM_VALIDATOR_INVALID_HASH_ALGORITHM,
  /** Hash value is not valid.
   *  (e.g. not hexadecimal or length does not match algorithm) */
  GVM_STREAM_VALIDATOR_INVALID_HASH_VALUE,
  /** Hash of received data does not match the expected hash */
  GVM_STREAM_VALIDATOR_HASH_MISMATCH
} gvm_stream_validator_return_t;

/**
 * @brief Pointer to an opaque stream validator data structure.
 */
typedef struct gvm_stream_validator* gvm_stream_validator_t;

const char *
gvm_stream_validator_return_str (gvm_stream_validator_return_t);

gvm_stream_validator_return_t
gvm_stream_validator_new (const char *, size_t, gvm_stream_validator_t*);

void
gvm_stream_validator_rewind (gvm_stream_validator_t);

void
gvm_stream_validator_free (gvm_stream_validator_t);

gvm_stream_validator_return_t
gvm_stream_validator_write (gvm_stream_validator_t, const char *, size_t);

gvm_stream_validator_return_t
gvm_stream_validator_end (gvm_stream_validator_t);

#endif /* not _GVM_STREAMVALIDATOR_H */
