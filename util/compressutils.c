/* SPDX-FileCopyrightText: 2013-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/**
 * @file
 * @brief Functions related to data compression (gzip format.)
 */

/**
 * @brief For z_const to be defined as const.
 */
#if !defined(ZLIB_CONST)
#define ZLIB_CONST
#endif

#define _GNU_SOURCE

#include "compressutils.h"

#include <glib.h> /* for g_free, g_malloc0 */
#include <zlib.h> /* for z_stream, Z_NULL, Z_OK, Z_BUF_ERROR, Z_STREAM_END */

#undef G_LOG_DOMAIN
/**
 * @brief GLib logging domain.
 */
#define G_LOG_DOMAIN "libgvm util"

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
gvm_compress (const void *src, unsigned long srclen, unsigned long *dstlen)
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

      buffer = g_malloc0 (buflen);
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
          g_free (buffer);
          buflen *= 2;
          break;

        default:
          g_free (buffer);
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
gvm_uncompress (const void *src, unsigned long srclen, unsigned long *dstlen)
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
       * Add 32 to windowBits to enable zlib and gzip decoding with automatic
       * header detection.
       */
      if (inflateInit2 (&strm, 15 + 32) != Z_OK)
        return NULL;

      buffer = g_malloc0 (buflen);
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
          g_free (buffer);
          buflen *= 2;
          break;

        default:
          g_free (buffer);
          return NULL;
        }
    }
}

/**
 * @brief Compresses data in src buffer, gzip format compatible.
 *
 * @param[in]   src     Buffer of data to compress.
 * @param[in]   srclen  Length of data to compress.
 * @param[out]  dstlen  Length of compressed data.
 *
 * @return Pointer to compressed data if success, NULL otherwise.
 */
void *
gvm_compress_gzipheader (const void *src, unsigned long srclen,
                         unsigned long *dstlen)
{
  unsigned long buflen = srclen * 2;
  int windowsBits = 15;
  int GZIP_ENCODING = 16;

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

      if (deflateInit2 (&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                        windowsBits | GZIP_ENCODING, 8, Z_DEFAULT_STRATEGY)
          != Z_OK)
        return NULL;

      buffer = g_malloc0 (buflen);
      strm.avail_out = buflen;
      strm.next_out = buffer;

      err = deflate (&strm, Z_FINISH);
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
          g_free (buffer);
          buflen *= 2;
          break;

        default:
          g_free (buffer);
          return NULL;
        }
    }
}

/**
 * @brief Read decompressed data from a gzip file.
 * 
 * @param[in]  cookie       The gzFile to read from.
 * @param[in]  buffer       The buffer to output decompressed data to.
 * @param[in]  buffer_size  The size of the buffer.
 * 
 * @return The number of bytes read into the buffer.
 */
static ssize_t
gz_file_read (void *cookie, char *buffer, size_t buffer_size)
{
  gzFile gz_file = cookie;

  return gzread (gz_file, buffer, buffer_size);
}

/**
 * @brief Close a gzip file.
 * 
 * @param[in]  cookie       The gzFile to close.
 * 
 * @return 0 on success, other values on error (see gzclose() from zlib).
 */
static int
gz_file_close (void *cookie)
{
  gzFile gz_file = cookie;

  return gzclose (gz_file);;
}

/**
 * @brief Opens a gzip file as a FILE* stream for reading and decompression.
 *
 * @param[in]  path  Path to the gzip file to open.
 *
 * @return The FILE* on success, NULL otherwise.
 */
FILE *
gvm_gzip_open_file_reader (const char *path)
{
  static cookie_io_functions_t io_functions = {
    .read = gz_file_read,
    .write = NULL,
    .seek = NULL,
    .close = gz_file_close,
  };
  
  if (path == NULL)
    {
      return NULL;
    }

  gzFile gz_file = gzopen (path, "r");
  if (gz_file == NULL)
    {
      return NULL;
    }

  FILE *file = fopencookie (gz_file, "r", io_functions);
  return file;
}
