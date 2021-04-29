/* Copyright (C) 2020-2021 Greenbone Networks GmbH
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#include "passwordbasedauthentication.h"
// internal usage to have access to gvm_auth initialized to verify if
// initialization is needed
#include "authutils.c"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// UFC_crypt defines crypt_r when only when __USE_GNU is set
// this shouldn't affect other implementations
#define __USE_GNU
#include <crypt.h>

#ifndef CRYPT_GENSALT_OUTPUT_SIZE
#define CRYPT_GENSALT_OUTPUT_SIZE 192
#endif

#ifndef CRYPT_OUTPUT_SIZE
#define CRYPT_OUTPUT_SIZE 384
#endif

int
is_prefix_not_supported (const char *id)
{
  return strcmp ("$6$", id);
}

// we assume something else than libxcrypt > 3.1; like UFC-crypt
// libxcrypt sets a macro of crypt_gensalt_r to crypt_gensalt_rn
// therefore we could use that mechanism to figure out if we are on
// debian buster or newer.
#ifndef EXTERNAL_CRYPT_GENSALT_R

// used printables within salt
const char ascii64[64] =
  "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/* Tries to get BUFLEN random bytes into BUF; returns 0 on success. */
int
get_random (char *buf, size_t buflen)
{
  FILE *fp = fopen ("/dev/urandom", "r");
  int result = 0;
  if (fp == NULL)
    {
      result = -1;
      goto exit;
    }
  size_t nread = fread (buf, 1, buflen, fp);
  fclose (fp);
  if (nread < buflen)
    {
      result = -2;
    }

exit:
  return result;
}
/* Generate a string suitable for use as the setting when hashing a passphrase.
 * PREFIX controls which hash function will be used,
 * COUNT controls the computional cost of the hash,
 * RBYTES should point to NRBYTES bytes of random data.
 *
 * If PREFIX is a NULL pointer, the current best default is used; if RBYTES
 * is a NULL pointer, random data will be retrieved from the operating system
 * if possible.
 *
 * Teh generated setting string is written to OUTPUT, which is OUTPUT_SIZE long.
 * OUTPUT_SIZE must be at least CRYPT_GENSALT_OUTPUT_SIZE.
 *
 * */
char *
crypt_gensalt_r (const char *prefix, unsigned long count, const char *rbytes,
                 int nrbytes, char *output, int output_size)
{
  char *internal_rbytes = NULL;
  unsigned int written = 0, used = 0;
  unsigned long value = 0;
  if ((rbytes != NULL && nrbytes < 3) || output_size < 16
      || is_prefix_not_supported (prefix))
    {
      output[0] = '*';
      goto exit;
    }
  if (rbytes == NULL)
    {
      internal_rbytes = malloc (16);
      if (get_random (internal_rbytes, 16) != 0)
        {
          output[0] = '*';
          goto exit;
        }
      nrbytes = 16;
      rbytes = internal_rbytes;
    }
  written = snprintf (output, output_size, "%srounds=%lu$",
                      prefix == NULL ? PREFIX_DEFAULT : prefix, count);
  while (written + 5 < (unsigned int) output_size
         && used + 3 < (unsigned int) nrbytes && (used * 4 / 3) < 16)
    {
      value = ((unsigned long) rbytes[used + 0] << 0)
              | ((unsigned long) rbytes[used + 1] << 8)
              | ((unsigned long) rbytes[used + 2] << 16);
      output[written] = ascii64[value & 0x3f];
      output[written + 1] = ascii64[(value >> 6) & 0x3f];
      output[written + 2] = ascii64[(value >> 12) & 0x3f];
      output[written + 3] = ascii64[(value >> 18) & 0x3f];
      written += 4;
      used += 3;
    }
  output[written] = '\0';
exit:
  if (internal_rbytes != NULL)
    free (internal_rbytes);
  return output[0] == '*' ? 0 : output;
}

#endif

struct PBASettings *
pba_init (const char *pepper, unsigned int pepper_size, unsigned int count,
          char *prefix)
{
  unsigned int i = 0;
  struct PBASettings *result = NULL;
  if (pepper_size > MAX_PEPPER_SIZE)
    goto exit;
  if (prefix != NULL && is_prefix_not_supported (prefix))
    goto exit;
  result = malloc (sizeof (struct PBASettings));
  for (i = 0; i < MAX_PEPPER_SIZE; i++)
    result->pepper[i] = pepper != NULL && i < pepper_size ? pepper[i] : 0;
  result->count = count == 0 ? COUNT_DEFAULT : count;
  result->prefix = prefix == NULL ? PREFIX_DEFAULT : prefix;
exit:
  return result;
}

void
pba_finalize (struct PBASettings *settings)
{
  free (settings);
}
int
pba_is_phc_compliant (const char *setting)
{
  if (setting == NULL)
    {
      return 0;
    }
  return strlen (setting) > 1 && setting[0] == '$';
}

char *
pba_hash (struct PBASettings *setting, const char *password)
{
  char *result = NULL, *settings = NULL, *tmp, *rslt;
  int i;
  struct crypt_data *data = NULL;

  if (!setting || !password)
    goto exit;
  if (is_prefix_not_supported (setting->prefix) != 0)
    goto exit;
  settings = malloc (CRYPT_GENSALT_OUTPUT_SIZE);
  if (crypt_gensalt_r (setting->prefix, setting->count, NULL, 0, settings,
                       CRYPT_GENSALT_OUTPUT_SIZE)
      == NULL)
    goto exit;
  tmp = settings + strlen (settings) - 1;
  for (i = MAX_PEPPER_SIZE - 1; i > -1; i--)
    {
      if (setting->pepper[i] != 0)
        tmp[0] = setting->pepper[i];
      tmp--;
    }

  data = malloc (sizeof (struct crypt_data));
  rslt = crypt_r (password, settings, data);
  if (rslt == NULL)
    goto exit;
  result = malloc (CRYPT_OUTPUT_SIZE);
  memcpy (result, rslt, CRYPT_OUTPUT_SIZE);
  // remove pepper, by jumping to begin of applied pepper within result
  // and overridding it.
  tmp = result + (tmp - settings);
  for (i = 0; i < MAX_PEPPER_SIZE; i++)
    {
      tmp++;
      if (setting->pepper[i] != 0)
        tmp[0] = '0';
    }
exit:
  if (data != NULL)
    free (data);
  if (settings != NULL)
    free (settings);
  return result;
}

enum pba_rc
pba_verify_hash (const struct PBASettings *setting, const char *hash,
                 const char *password)
{
  char *cmp, *tmp = NULL;
  struct crypt_data *data = NULL;
  int i = 0;
  enum pba_rc result = ERR;
  if (!setting || !hash || !password)
    goto exit;
  if (is_prefix_not_supported (setting->prefix))
    goto exit;
  if (pba_is_phc_compliant (hash) != 0)
    {
      data = malloc (sizeof (struct crypt_data));
      // manipulate hash to reapply pepper
      tmp = malloc (CRYPT_OUTPUT_SIZE);
      memcpy (tmp, hash, CRYPT_OUTPUT_SIZE);
      cmp = strrchr (tmp, '$');
      for (i = MAX_PEPPER_SIZE - 1; i > -1; i--)
        {
          cmp--;
          if (setting->pepper[i] != 0)
            cmp[0] = setting->pepper[i];
        }
      cmp = crypt_r (password, tmp, data);
      if (strcmp (tmp, cmp) == 0)
        result = VALID;
      else
        result = INVALID;
    }
  else
    {
      // assume authutils hash handling
      // initialize gvm_auth utils if not already initialized
      if (initialized == FALSE && gvm_auth_init () != 0)
        {
          goto exit;
        }
      // verify result of gvm_authenticate_classic
      i = gvm_authenticate_classic (NULL, password, hash);
      if (i == 0)
        result = UPDATE_RECOMMENDED;
      else if (i == 1)
        result = INVALID;
    }
exit:
  if (data != NULL)
    free (data);
  if (tmp != NULL)
    free (tmp);
  return result;
}

