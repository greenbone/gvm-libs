/* Nessus Attack Scripting Language
 *
 * Copyright (C) 2002 - 2004 Tenable Network Security
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

/** @file
 * This file contains all the cryptographic functions NASL has.
 */

/* MODIFICATION: added definitions for implemention NTLMSSP features */

#include <gcrypt.h>
#include <glib.h>

#include "nasl_tree.h"
#include "nasl_global_ctxt.h"
#include "nasl_func.h"
#include "nasl_var.h"
#include "nasl_lex_ctxt.h"
#include "exec.h"
#include "nasl_crypto.h"
#include "hmacmd5.h"
#include "smb_crypt.h"
#include "nasl_debug.h"

#include "system.h"
#include <ctype.h>
#include <stdlib.h>
#include "strutils.h"
#include <assert.h>
#include "smb.h"
#include "smb_signing.h"
#include "ntlmssp.h"

#ifndef uchar
#define uchar unsigned char
#endif

#ifndef uint8
#define uint8 uint8_t
#endif

#ifndef uint32
#define uint32 uint32_t
#endif

/*-------------------[  Std. HASH ]-------------------------------------*/
static tree_cell *
nasl_gcrypt_hash (lex_ctxt * lexic, int algorithm, void *data, size_t datalen,
                  void *key, size_t keylen)
{
  gcry_md_hd_t hd;
  gcry_error_t err;
  tree_cell *retc;
  int dlen = gcry_md_get_algo_dlen (algorithm);

  if (data == NULL)
    return NULL;

  err = gcry_md_open (&hd, algorithm, key ? GCRY_MD_FLAG_HMAC : 0);
  if (err)
    {
      nasl_perror (lexic, "nasl_gcrypt_hash(): gcry_md_open failed: %s/%s\n",
                   gcry_strsource (err), gcry_strerror (err));
      return NULL;
    }

  if (key)
    {
      err = gcry_md_setkey (hd, key, keylen);
      if (err)
        {
          nasl_perror (lexic,
                       "nasl_gcrypt_hash():" " gcry_md_setkey failed: %s/%s\n",
                       gcry_strsource (err), gcry_strerror (err));
          return NULL;
        }
    }

  gcry_md_write (hd, data, datalen);

  retc = alloc_tree_cell (0, NULL);
  retc->type = CONST_DATA;
  retc->x.str_val = g_memdup (gcry_md_read (hd, algorithm), dlen + 1);
  retc->size = dlen;

  gcry_md_close (hd);

  return retc;
}

static tree_cell *
nasl_hash (lex_ctxt * lexic, int algorithm)
{
  char *data = get_str_var_by_num (lexic, 0);
  int len = get_var_size_by_num (lexic, 0);

  return nasl_gcrypt_hash (lexic, algorithm, data, len, NULL, 0);
}

tree_cell *
nasl_md2 (lex_ctxt * lexic)
{
  return nasl_hash (lexic, GCRY_MD_MD2);
}

tree_cell *
nasl_md4 (lex_ctxt * lexic)
{
  return nasl_hash (lexic, GCRY_MD_MD4);
}

tree_cell *
nasl_md5 (lex_ctxt * lexic)
{
  return nasl_hash (lexic, GCRY_MD_MD5);
}

tree_cell *
nasl_sha1 (lex_ctxt * lexic)
{
  return nasl_hash (lexic, GCRY_MD_SHA1);
}


tree_cell *
nasl_ripemd160 (lex_ctxt * lexic)
{
  return nasl_hash (lexic, GCRY_MD_RMD160);
}




/*-------------------[  HMAC ]-------------------------------------*/



static tree_cell *
nasl_hmac (lex_ctxt * lexic, int algorithm)
{
  char *data = get_str_local_var_by_name (lexic, "data");
  char *key = get_str_local_var_by_name (lexic, "key");
  int data_len = get_local_var_size_by_name (lexic, "data");
  int key_len = get_local_var_size_by_name (lexic, "key");

  return nasl_gcrypt_hash (lexic, algorithm, data, data_len, key, key_len);
}

tree_cell *
nasl_hmac_md2 (lex_ctxt * lexic)
{
  return nasl_hmac (lexic, GCRY_MD_MD2);
}

tree_cell *
nasl_hmac_md5 (lex_ctxt * lexic)
{
  return nasl_hmac (lexic, GCRY_MD_MD5);
}

tree_cell *
nasl_hmac_sha1 (lex_ctxt * lexic)
{
  return nasl_hmac (lexic, GCRY_MD_SHA1);
}

tree_cell *
nasl_hmac_ripemd160 (lex_ctxt * lexic)
{
  return nasl_hmac (lexic, GCRY_MD_RMD160);
}

/*-------------------[ Windows ]-------------------------------------*/
tree_cell *
nasl_get_sign (lex_ctxt * lexic)
{
  char *mac_key = (char *) get_str_var_by_name (lexic, "key");
  uint8_t *buf = (uint8_t *) get_str_var_by_name (lexic, "buf");
  int buflen = get_int_var_by_name (lexic, "buflen", -1);
  uint32 seq_num = get_int_var_by_name (lexic, "seq_number", -1);
  if (mac_key == NULL || buf == NULL || buflen == -1 || seq_num == -1)
    {
      nasl_perror (lexic,
                   "Syntax : get_sign(key:<k>, buf:<b>, buflen:<bl>, seq_number:<s>)\n");
      return NULL;
    }
  uint8_t calc_md5_mac[16];
  simple_packet_signature_ntlmssp ((uint8_t *) mac_key, buf, seq_num, calc_md5_mac);
  memcpy (buf + 18, calc_md5_mac, 8);
  char *ret = emalloc (buflen);
  bzero (ret, buflen);
  memcpy (ret, buf, buflen);
  tree_cell *retc;
  retc = alloc_tree_cell (0, NULL);
  retc->type = CONST_DATA;
  retc->size = buflen;
  retc->x.str_val = (char *) ret;
  return retc;
}

tree_cell *
nasl_ntlmv2_response (lex_ctxt * lexic)
{
  char *cryptkey = (char *) get_str_var_by_name (lexic, "cryptkey");
  char *user = (char *) get_str_var_by_name (lexic, "user");
  char *domain = (char *) get_str_var_by_name (lexic, "domain");
  unsigned char *ntlmv2_hash =
    (unsigned char *) get_str_var_by_name (lexic, "ntlmv2_hash");
  char *address_list = get_str_var_by_name (lexic, "address_list");
  int address_list_len = get_int_var_by_name (lexic, "address_list_len", -1);

  if (cryptkey == NULL || user == NULL || domain == NULL || ntlmv2_hash == NULL
      || address_list == NULL || address_list_len < 0)
    {
      nasl_perror (lexic,
                   "Syntax : ntlmv2_response(cryptkey:<c>, user:<u>, domain:<d>, ntlmv2_hash:<n>, address_list:<a>, address_list_len:<len>)\n");
      return NULL;
    }
  uint8_t lm_response[24];
  uint8_t nt_response[16 + 28 + address_list_len];
  uint8_t session_key[16];
  bzero (lm_response, sizeof (lm_response));
  bzero (nt_response, sizeof (nt_response));
  bzero (session_key, sizeof (session_key));

  ntlmssp_genauth_ntlmv2 (user, domain, address_list, address_list_len,
                          cryptkey, lm_response, nt_response, session_key,
                          ntlmv2_hash);
  tree_cell *retc;
  int lm_response_len = 24;
  int nt_response_len = 16 + 28 + address_list_len;
  int len = lm_response_len + nt_response_len + sizeof (session_key);
  char *ret = emalloc (len);
  memcpy (ret, lm_response, lm_response_len);
  memcpy (ret + lm_response_len, session_key, sizeof (session_key));
  memcpy (ret + lm_response_len + sizeof (session_key), nt_response,
          nt_response_len);
  retc = alloc_tree_cell (0, NULL);
  retc->type = CONST_DATA;
  retc->size = len;
  retc->x.str_val = ret;
  return retc;
}

tree_cell *
nasl_ntlm2_response (lex_ctxt * lexic)
{
  char *cryptkey = (char *) get_str_var_by_name (lexic, "cryptkey");
  char *password = get_str_var_by_name (lexic, "password");
  unsigned char *nt_hash =
    (unsigned char *) get_str_var_by_name (lexic, "nt_hash");

  if (cryptkey == NULL || password == NULL)
    {
      nasl_perror (lexic,
                   "Syntax : ntlm2_response(cryptkey:<c>, password:<p>, nt_hash:<n>)\n");
      return NULL;
    }

  uint8_t lm_response[24];
  uint8_t nt_response[24];
  uint8_t session_key[16];

  tree_cell *retc;
  ntlmssp_genauth_ntlm2 (password, lm_response, nt_response, session_key,
                         cryptkey, nt_hash);
  int len = sizeof (lm_response) + sizeof (nt_response) + sizeof (session_key);
  char *ret = emalloc (len);
  memcpy (ret, lm_response, sizeof (lm_response));
  memcpy (ret + sizeof (lm_response), nt_response, sizeof (nt_response));
  memcpy (ret + sizeof (lm_response) + sizeof (nt_response), session_key,
          sizeof (session_key));
  retc = alloc_tree_cell (0, NULL);
  retc->type = CONST_DATA;
  retc->size = len;
  retc->x.str_val = ret;
  return retc;
}

tree_cell *
nasl_ntlm_response (lex_ctxt * lexic)
{
  char *cryptkey = (char *) get_str_var_by_name (lexic, "cryptkey");
  char *password = get_str_var_by_name (lexic, "password");
  unsigned char *nt_hash =
    (unsigned char *) get_str_var_by_name (lexic, "nt_hash");
  int neg_flags = get_int_var_by_name (lexic, "neg_flags", -1);

  if (cryptkey == NULL || password == NULL || nt_hash == NULL || neg_flags < 0)
    {
      nasl_perror (lexic,
                   "Syntax : ntlm_response(cryptkey:<c>, password:<p>, nt_hash:<n>, neg_flags:<nf>)\n");
      return NULL;
    }

  uint8_t lm_response[24];
  uint8_t nt_response[24];
  uint8_t session_key[16];

  tree_cell *retc;

  ntlmssp_genauth_ntlm (password, lm_response, nt_response, session_key,
                        cryptkey, nt_hash, neg_flags);

  int len = sizeof (lm_response) + sizeof (nt_response) + sizeof (session_key);
  char *ret = emalloc (len);
  memcpy (ret, lm_response, sizeof (lm_response));
  memcpy (ret + sizeof (lm_response), nt_response, sizeof (nt_response));
  memcpy (ret + sizeof (lm_response) + sizeof (nt_response), session_key,
          sizeof (session_key));
  retc = alloc_tree_cell (0, NULL);
  retc->type = CONST_DATA;
  retc->size = len;
  retc->x.str_val = ret;
  return retc;
}

tree_cell *
nasl_keyexchg (lex_ctxt * lexic)
{
  char *cryptkey = (char *) get_str_var_by_name (lexic, "cryptkey");
  uint8_t *session_key = (uint8_t *) get_str_var_by_name (lexic, "session_key");
  unsigned char *nt_hash =
    (unsigned char *) get_str_var_by_name (lexic, "nt_hash");

  if (cryptkey == NULL || session_key == NULL || nt_hash == NULL)
    {
      nasl_perror (lexic,
                   "Syntax : keyexchg(cryptkey:<c>, session_key:<s>, nt_hash:<n> )\n");
      return NULL;
    }
  uint8_t new_sess_key[16];
  tree_cell *retc;
  uint8_t *encrypted_session_key = NULL;
  encrypted_session_key =
    ntlmssp_genauth_keyexchg (session_key, cryptkey, nt_hash,
                              (uint8_t *) & new_sess_key);
  int len = 16 + 16;
  char *ret = emalloc (len);
  memcpy (ret, new_sess_key, 16);
  memcpy (ret + 16, encrypted_session_key, 16);
  retc = alloc_tree_cell (0, NULL);
  retc->type = CONST_DATA;
  retc->size = len;
  retc->x.str_val = ret;
  return retc;
}

tree_cell *
nasl_ntlmv1_hash (lex_ctxt * lexic)
{
  const uchar *cryptkey = (uchar *) get_str_var_by_name (lexic, "cryptkey");
  char *password = get_str_var_by_name (lexic, "passhash");
  int pass_len = get_var_size_by_name (lexic, "passhash");
  unsigned char p21[21];
  tree_cell *retc;
  uchar *ret;

  if (cryptkey == NULL || password == NULL)
    {
      nasl_perror (lexic, "Syntax : ntlmv1_hash(cryptkey:<c>, passhash:<p>)\n");
      return NULL;
    }

  bzero (p21, sizeof (p21));
  memcpy (p21, password, pass_len < 16 ? pass_len : 16);

  ret = emalloc (24);

  E_P24 (p21, cryptkey, ret);
  retc = alloc_tree_cell (0, NULL);
  retc->type = CONST_DATA;
  retc->size = 24;
  retc->x.str_val = (char *) ret;

  return retc;
}

tree_cell *
nasl_nt_owf_gen (lex_ctxt * lexic)
{
  char *pass = get_str_var_by_num (lexic, 0);
  int pass_len = get_var_size_by_num (lexic, 0);
  char pwd[130];
  short upwd[130], *dst;
  short val;
  char *src;

  int i;

  if (pass_len < 0 || pass == NULL)
    {
      nasl_perror (lexic, "Syntax : nt_owf_gen(cryptkey:<c>, password:<p>)\n");
      return NULL;
    }

  dst = upwd;
  src = pass;
  for (i = 0; i < pass_len; i++)
    {
      val = *src;
#if __BYTE_ORDER == __BIG_ENDIAN
      *dst = val << 8;
#else
      *dst = val;
#endif
      dst++;
      src++;
      if (val == 0)
        break;
    }

  bzero (pwd, sizeof (pwd));
  memcpy (pwd, upwd, sizeof (pwd) < pass_len * 2 ? sizeof (pwd) : pass_len * 2);
  return nasl_gcrypt_hash (lexic, GCRY_MD_MD4, pwd,
                           pass_len * 2 > 128 ? 128 : pass_len * 2, NULL, 0);

}

tree_cell *
nasl_lm_owf_gen (lex_ctxt * lexic)
{
  char *pass = get_str_var_by_num (lexic, 0);
  int pass_len = get_var_size_by_num (lexic, 0);
  tree_cell *retc;
  uchar pwd[15];
  uchar p16[16];
  int i;

  if (pass_len < 0 || pass == NULL)
    {
      nasl_perror (lexic, "Syntax : nt_lm_gen(cryptkey:<c>, password:<p>)\n");
      return NULL;
    }

  bzero (pwd, sizeof (pwd));
  strncpy ((char *) pwd, pass, sizeof (pwd) - 1);
  for (i = 0; i < sizeof (pwd); i++)
    pwd[i] = toupper (pwd[i]);

  E_P16 (pwd, p16);

  retc = alloc_tree_cell (0, NULL);
  retc->type = CONST_DATA;
  retc->size = 16;
  retc->x.str_val = g_memdup (p16, 17);
  return retc;
}

tree_cell *
nasl_insert_hexzeros (lex_ctxt * lexic)
{
  const uchar *in = (uchar *) get_str_var_by_name (lexic, "in");
  int in_len = get_var_size_by_name (lexic, "in");
  char *src;
  smb_ucs2_t *out, *dst, val;
  int i;
  size_t byte_len;
  tree_cell *retc;
  if (in_len < 0 || in == NULL)
    {
      nasl_perror (lexic, "Syntax : insert_hexzeros(in:<i>)\n");
      return NULL;
    }

  byte_len = sizeof (smb_ucs2_t) * (strlen ((char *) in) + 1);
  out = emalloc (byte_len);
  dst = out;
  src = (char *) in;

  for (i = 0; i < in_len; i++)
    {
      val = *src;
      *dst = val;
      dst++;
      src++;
      if (val == 0)
        break;
    }


  /* We don't want null termination */
  byte_len = byte_len - 2;

  retc = alloc_tree_cell (0, NULL);
  retc->type = CONST_DATA;
  retc->size = byte_len;
  retc->x.str_val = (char *) out;
  return retc;
}

/* Does both the NTLMv2 owfs of a user's password */
tree_cell *
nasl_ntv2_owf_gen (lex_ctxt * lexic)
{
  const uchar *owf_in = (uchar *) get_str_var_by_name (lexic, "owf");
  int owf_in_len = get_var_size_by_name (lexic, "owf");
  char *user_in = get_str_var_by_name (lexic, "login");
  int user_in_len = get_var_size_by_name (lexic, "login");
  char *domain_in = get_str_var_by_name (lexic, "domain");
  int domain_len = get_var_size_by_name (lexic, "domain");
  char *src_user, *src_domain;
  smb_ucs2_t *user, *dst_user, val_user;
  smb_ucs2_t *domain, *dst_domain, val_domain;
  int i;
  size_t user_byte_len;
  size_t domain_byte_len;
  tree_cell *retc;
  uchar *kr_buf;
  HMACMD5Context ctx;

  if (owf_in_len < 0 || owf_in == NULL || user_in_len < 0 || user_in == NULL
      || domain_len < 0 || domain_in == NULL)
    {
      nasl_perror (lexic,
                   "Syntax : ntv2_owf_gen(owf:<o>, login:<l>, domain:<d>)\n");
      return NULL;
    }

  assert (owf_in_len == 16);

  user_byte_len = sizeof (smb_ucs2_t) * (strlen (user_in) + 1);
  user = emalloc (user_byte_len);
  dst_user = user;
  src_user = user_in;

  for (i = 0; i < user_in_len; i++)
    {
      val_user = *src_user;
      *dst_user = val_user;
      dst_user++;
      src_user++;
      if (val_user == 0)
        break;
    }

  domain_byte_len = sizeof (smb_ucs2_t) * (strlen (domain_in) + 1);
  domain = emalloc (domain_byte_len);
  dst_domain = domain;
  src_domain = domain_in;

  for (i = 0; i < domain_len; i++)
    {
      val_domain = *src_domain;
      *dst_domain = val_domain;

      dst_domain++;
      src_domain++;
      if (val_domain == 0)
        break;
    }

  strupper_w (user);
  strupper_w (domain);

  assert (user_byte_len >= 2);
  assert (domain_byte_len >= 2);

  /* We don't want null termination */
  user_byte_len = user_byte_len - 2;
  domain_byte_len = domain_byte_len - 2;

  kr_buf = emalloc (16);

  hmac_md5_init_limK_to_64 (owf_in, 16, &ctx);
  hmac_md5_update ((const unsigned char *) user, user_byte_len, &ctx);
  hmac_md5_update ((const unsigned char *) domain, domain_byte_len, &ctx);
  hmac_md5_final (kr_buf, &ctx);

  efree (&user);
  efree (&domain);

  retc = alloc_tree_cell (0, NULL);
  retc->type = CONST_DATA;
  retc->size = 16;
  retc->x.str_val = (char *) kr_buf;

  return retc;
}

tree_cell *
nasl_ntlmv2_hash (lex_ctxt * lexic)
{
  const uchar *server_chal = (uchar *) get_str_var_by_name (lexic, "cryptkey");
  int sc_len = get_var_size_by_name (lexic, "cryptkey");
  const uchar *ntlm_v2_hash = (uchar *) get_str_var_by_name (lexic, "passhash");
  int hash_len = get_var_size_by_name (lexic, "passhash");
  int client_chal_length = get_int_var_by_name (lexic, "length", -1);
  tree_cell *retc;
  unsigned char ntlmv2_response[16];
  unsigned char *ntlmv2_client_data = NULL;
  unsigned char *final_response;
  int i;

  if (sc_len < 0 || server_chal == NULL || hash_len < 0 || ntlm_v2_hash == NULL
      || client_chal_length < 0)
    {
      nasl_perror (lexic,
                   "Syntax : ntlmv2_hash(cryptkey:<c>, passhash:<p>, length:<l>)\n");
      return NULL;
    }

  /* NTLMv2 */

  /* We also get to specify some random data */
  ntlmv2_client_data = emalloc (client_chal_length);
  for (i = 0; i < client_chal_length; i++)
    ntlmv2_client_data[i] = rand () % 256;



  assert (hash_len == 16);
  /* Given that data, and the challenge from the server, generate a response */
  SMBOWFencrypt_ntv2_ntlmssp(ntlm_v2_hash, server_chal, 8, ntlmv2_client_data,
                      client_chal_length, ntlmv2_response);

  /* put it into nt_response, for the code below to put into the packet */
  final_response = emalloc (client_chal_length + sizeof (ntlmv2_response));
  memcpy (final_response, ntlmv2_response, sizeof (ntlmv2_response));
  /* after the first 16 bytes is the random data we generated above, so the server can verify us with it */
  memcpy (final_response + sizeof (ntlmv2_response), ntlmv2_client_data,
          client_chal_length);

  efree (&ntlmv2_client_data);

  retc = alloc_tree_cell (0, NULL);
  retc->type = CONST_DATA;
  retc->size = client_chal_length + sizeof (ntlmv2_response);
  retc->x.str_val = (char *) final_response;

  return retc;
}
