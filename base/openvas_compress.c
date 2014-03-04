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

/* For z_const to be defined as const. */
#if !defined(ZLIB_CONST)
#  define ZLIB_CONST
#endif

#include <zlib.h>
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
openvas_compress (const void *src, unsigned long srclen, unsigned long *dstlen)
{
  unsigned long buflen = srclen * 2;

  if (src == NULL || dstlen == NULL)
    return NULL;

  if (buflen < 30)
    buflen = 30;

  while (1)
    {
      int err;
      void *buffer;
      z_stream strm;

      /* Initialize deflate state */
      strm.zalloc = Z_NULL;
      strm.zfree = Z_NULL;
      strm.opaque = Z_NULL;
      strm.avail_in = srclen;
#ifdef z_const
      strm.next_in = src;
#else
      /* Workaround for older zlib. */
      strm.next_in = (void *) src;
#endif
      if (deflateInit (&strm, Z_DEFAULT_COMPRESSION) != Z_OK)
        return NULL;

      buffer = calloc (buflen, 1);
      if (buffer == NULL)
        {
          deflateEnd (&strm);
          return NULL;
        }
      strm.avail_out = buflen;
      strm.next_out = buffer;

      err = deflate (&strm, Z_SYNC_FLUSH);
      deflateEnd (&strm);
      switch (err)
        {
          case Z_OK:
          case Z_STREAM_END:
            if (strm.avail_out != 0)
              {
                *dstlen = strm.total_out;
                return buffer;
              }
            /* Fallthrough. */
          case Z_BUF_ERROR:
            free (buffer);
            buflen *= 2;
            break;

          default:
            free (buffer);
            return NULL;
        }
    }
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
openvas_uncompress (const void *src, unsigned long srclen,
                    unsigned long *dstlen)
{
  unsigned long buflen = srclen * 2;

  if (src == NULL || dstlen == NULL)
    return NULL;

  while (1)
    {
      int err;
      void *buffer;
      z_stream strm;

      /* Initialize inflate state */
      strm.zalloc = Z_NULL;
      strm.zfree = Z_NULL;
      strm.opaque = Z_NULL;
      strm.avail_in = srclen;
#ifdef z_const
      strm.next_in = src;
#else
      /* Workaround for older zlib. */
      strm.next_in = (void *) src;
#endif
      /*
       * From: http://www.zlib.net/manual.html
       * Add 32 to windowBits to enable zlib and gzip decoding with automatic header
       * detection.
       */
      if (inflateInit2 (&strm, 15 + 32) != Z_OK)
        return NULL;

      buffer = calloc (buflen, 1);
      if (buffer == NULL)
        {
          inflateEnd (&strm);
          return NULL;
        }
      strm.avail_out = buflen;
      strm.next_out = buffer;

      err = inflate (&strm, Z_SYNC_FLUSH);
      inflateEnd (&strm);
      switch (err)
        {
          case Z_OK:
          case Z_STREAM_END:
            if (strm.avail_out != 0)
              {
                *dstlen = strm.total_out;
                return buffer;
              }
            /* Fallthrough. */
          case Z_BUF_ERROR:
            free (buffer);
            buflen *= 2;
            break;

          default:
            free (buffer);
            return NULL;
        }
    }
}
