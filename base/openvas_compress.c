/* openvas-libraries/base
 * $Id$
 * Description: Functions related to data compression (gzip format.)
 *
 * Authors:
 * Hani Benhabiles <hani.benhabiles@greenbone.net>
 *
 * Copyright:
 * Copyright (C) 2013 Greenbone Networks GmbH
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * or, at your option, any later version as published by the Free
 * Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "openvas_compress.h"


/**
 * @brief Compresses data in src buffer.
 *
 * @param[in]   src     Buffer of data to compress.
 * @param[in]   srclen  Length of data to compress.
 * @param[out]  dstlen  Length of compressed data.
 *
 * @return Pointer to compressed data if success, NULL otherwise.
 */
void *
openvas_compress (const void *src, uLong srclen, size_t *dstlen)
{
  void *buffer;
  uLong buflen = srclen * 2;
  int err;

  if (src == NULL || srclen <= 0 || dstlen == NULL)
    return NULL;

  /* For very small source buffers, compression result will be larger. */
  if (buflen < 20)
    buflen = 20;

  buffer = calloc (buflen, 1);
  if (buffer == NULL)
    return NULL;

  /* Compress */
  err = compress (buffer, &buflen, src, srclen);
  if (err != Z_OK)
    {
      free (buffer);
      return NULL;
    }

  *dstlen = buflen;
  return buffer;
}

/**
 * @brief Compresses a null-terminated string.
 *
 * @param[in]   str     Null-terminated string to compress.
 * @param[out]  dstlen  Length of compressed data.
 *
 * @return Pointer to compressed data if success, NULL otherwise.
 */
void *
openvas_compress_string (const char *str, uLong *dstlen)
{
  if (str == NULL || dstlen == NULL)
    return NULL;

  return openvas_compress (str, strlen (str) + 1, dstlen);
}

/**
 * @brief Uncompresses data in src buffer.
 *
 * @param[in]   src     Buffer of data to uncompress.
 * @param[in]   srclen  Length of data to uncompress.
 * @param[out]  dstlen  Length of uncompressed data.
 *
 * @return Pointer to uncompressed data if success, NULL otherwise.
 */
void *
openvas_uncompress (const void *src, uLong srclen, size_t *dstlen)
{
  void *buffer;
  uLong buflen = 2;

  if (src == NULL || srclen <= 0 || dstlen == NULL)
    return NULL;

  buffer = calloc (buflen, 1);
  if (buffer == NULL)
    return NULL;

  /* Uncompress */
  while (1)
    {
      int err = uncompress (buffer, &buflen, src, srclen);
      switch (err)
        {
          case Z_OK:
            *dstlen = buflen;
            return buffer;

          case Z_BUF_ERROR:
            free (buffer);
            buflen *= 2;
            buffer = calloc (buflen, 1);
            break;

          default:
            free (buffer);
            return NULL;
        }
    }

  return NULL;
}
