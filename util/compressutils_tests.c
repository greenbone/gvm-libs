/* SPDX-FileCopyrightText: 2019-2023 Greenbone AG
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "compressutils.c"

#include <cgreen/cgreen.h>
#include <cgreen/mocks.h>
#include <fcntl.h>

Describe (compressutils);
BeforeEach (compressutils)
{
}

AfterEach (compressutils)
{
}

Ensure (compressutils, can_compress_and_uncompress_without_header)
{
  const char *testdata = "TEST-12345-12345-TEST";

  unsigned long compressed_len = 0;
  char *compressed =
    gvm_compress (testdata, strlen (testdata) + 1, &compressed_len);
  assert_that (compressed_len, is_greater_than (0));
  assert_that (compressed, is_not_null);
  assert_that (compressed, is_not_equal_to_string (testdata));

  unsigned long uncompressed_len;
  char *uncompressed =
    gvm_uncompress (compressed, compressed_len, &uncompressed_len);
  assert_that (uncompressed_len, is_equal_to (strlen (testdata) + 1));
  assert_that (uncompressed, is_equal_to_string (testdata));
  g_free (compressed);
  g_free (uncompressed);
}

Ensure (compressutils, can_compress_and_uncompress_with_header)
{
  const char *testdata = "TEST-12345-12345-TEST";

  unsigned long compressed_len;
  char *compressed =
    gvm_compress_gzipheader (testdata, strlen (testdata) + 1, &compressed_len);
  assert_that (compressed_len, is_greater_than (0));
  assert_that (compressed, is_not_null);
  assert_that (compressed, is_not_equal_to_string (testdata));
  // Check for gzip magic number and deflate compression mode byte
  assert_that (compressed[0], is_equal_to ((char) 0x1f));
  assert_that (compressed[1], is_equal_to ((char) 0x8b));
  assert_that (compressed[2], is_equal_to (8));

  unsigned long uncompressed_len;
  char *uncompressed =
    gvm_uncompress (compressed, compressed_len, &uncompressed_len);
  assert_that (uncompressed_len, is_equal_to (strlen (testdata) + 1));
  assert_that (uncompressed, is_equal_to_string (testdata));
  g_free (compressed);
  g_free (uncompressed);
}

Ensure (compressutils, can_uncompress_using_reader)
{
  const char *testdata = "TEST-12345-12345-TEST";
  unsigned long compressed_len;
  char *compressed =
    gvm_compress_gzipheader (testdata, strlen (testdata) + 1, &compressed_len);

  char compressed_filename[35] = "/tmp/gvm_gzip_test_XXXXXX";
  int compressed_fd = mkstemp (compressed_filename);
  (void) !write (compressed_fd, compressed, compressed_len);
  close (compressed_fd);
  g_free (compressed);

  FILE *stream = gvm_gzip_open_file_reader (compressed_filename);
  assert_that (stream, is_not_null);

  gchar *uncompressed = g_malloc0 (30);
  (void) !fread (uncompressed, 1, 30, stream);
  assert_that (uncompressed, is_equal_to_string (testdata));
  g_free (uncompressed);

  assert_that (fclose (stream), is_equal_to (0));
}

Ensure (compressutils, can_uncompress_using_fd_reader)
{
  const char *testdata = "TEST-12345-12345-TEST";
  unsigned long compressed_len;
  char *compressed =
    gvm_compress_gzipheader (testdata, strlen (testdata) + 1, &compressed_len);

  char compressed_filename[35] = "/tmp/gvm_gzip_test_XXXXXX";
  int compressed_fd = mkstemp (compressed_filename);
  (void) !write (compressed_fd, compressed, compressed_len);
  close (compressed_fd);
  g_free (compressed);

  compressed_fd = open (compressed_filename, O_RDONLY);

  FILE *stream = gvm_gzip_open_file_reader_fd (compressed_fd);
  assert_that (stream, is_not_null);

  gchar *uncompressed = g_malloc0 (30);
  (void) !fread (uncompressed, 1, 30, stream);
  assert_that (uncompressed, is_equal_to_string (testdata));
  g_free (uncompressed);

  assert_that (fclose (stream), is_equal_to (0));
}

/* Test suite. */
int
main (int argc, char **argv)
{
  int ret;
  TestSuite *suite;

  suite = create_test_suite ();

  add_test_with_context (suite, compressutils,
                         can_compress_and_uncompress_without_header);
  add_test_with_context (suite, compressutils,
                         can_compress_and_uncompress_with_header);
  add_test_with_context (suite, compressutils, can_uncompress_using_reader);
  add_test_with_context (suite, compressutils, can_uncompress_using_fd_reader);

  if (argc > 1)
    ret = run_single_test (suite, argv[1], create_text_reporter ());
  else
    ret = run_test_suite (suite, create_text_reporter ());

  destroy_test_suite (suite);

  return ret;
}
