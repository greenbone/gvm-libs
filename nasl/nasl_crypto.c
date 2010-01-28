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
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

/** @file
 * This file contains all the cryptographic functions NASL has.
 */

#include <gcrypt.h>

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

#include "strutils.h"
#include <assert.h>


/*-------------------[  Std. HASH ]-------------------------------------*/
static tree_cell*
nasl_gcrypt_hash (lex_ctxt * lexic, int algorithm, void * data, size_t datalen,
                  void * key, size_t keylen)
{
  gcry_md_hd_t hd;
  gcry_error_t err;
  tree_cell * retc;
  int dlen = gcry_md_get_algo_dlen(algorithm);

  if (data == NULL)
    return NULL;

  err = gcry_md_open(&hd, algorithm, key ? GCRY_MD_FLAG_HMAC : 0);
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
          nasl_perror (lexic, "nasl_gcrypt_hash():"
                       " gcry_md_setkey failed: %s/%s\n",
                       gcry_strsource (err), gcry_strerror (err));
	  return NULL;
	}
    }

  gcry_md_write (hd, data, datalen);

  retc = alloc_tree_cell (0, NULL);
  retc->type = CONST_DATA;
  retc->x.str_val = nasl_strndup ((char *)gcry_md_read (hd, algorithm), dlen);
  retc->size = dlen;

  gcry_md_close (hd);

  return retc;
}

static tree_cell*
nasl_hash (lex_ctxt * lexic, int algorithm)
{
  char * data = get_str_var_by_num  (lexic, 0);
  int    len  = get_var_size_by_num (lexic, 0);

  return nasl_gcrypt_hash (lexic, algorithm, data, len, NULL, 0);
}

tree_cell *
nasl_md2(lex_ctxt * lexic)
{
  return nasl_hash(lexic, GCRY_MD_MD2);
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
  char * data = get_str_local_var_by_name (lexic, "data");
  char * key  = get_str_local_var_by_name (lexic, "key");
  int data_len = get_local_var_size_by_name (lexic, "data");
  int key_len  = get_local_var_size_by_name (lexic, "key");

  return nasl_gcrypt_hash (lexic, algorithm, data, data_len, key, key_len);
}

tree_cell *
nasl_hmac_md2(lex_ctxt * lexic)
{
  return nasl_hmac(lexic, GCRY_MD_MD2);
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
nasl_ntlmv1_hash(lex_ctxt * lexic)
{
  char * cryptkey = get_str_var_by_name(lexic, "cryptkey");
  char * password = get_str_var_by_name(lexic, "passhash");
  int pass_len  = get_var_size_by_name(lexic, "passhash");
  unsigned char p21[21];
  tree_cell * retc;
  char * ret;

  if (cryptkey == NULL || password == NULL )
   {
     nasl_perror(lexic, "Syntax : ntlmv1_hash(cryptkey:<c>, passhash:<p>)\n");
     return NULL;
   }

  bzero(p21, sizeof(p21));
  memcpy(p21, password, pass_len < 16 ? pass_len : 16);

  ret = emalloc(24);

  E_P24(p21, cryptkey, ret);
  retc = alloc_tree_cell(0, NULL);
  retc->type = CONST_DATA;
  retc->size  = 24;
  retc->x.str_val = ret;

  return retc;
}

tree_cell *
nasl_nt_owf_gen(lex_ctxt * lexic)
{
  char * pass = get_str_var_by_num(lexic, 0);
  int    pass_len = get_var_size_by_num(lexic, 0);
  char pwd[130];
  short upwd[130], * dst;
  short val;
  char * src;

  int i;

  if (pass_len < 0 || pass == NULL )
  {
    nasl_perror(lexic, "Syntax : nt_owf_gen(cryptkey:<c>, password:<p>)\n");
    return NULL;
  }

  dst = upwd;
  src = pass;
  for (i = 0 ; i < pass_len ; i ++)
   {
     val = *src;
#if __BYTE_ORDER == __BIG_ENDIAN
     *dst = val << 8;
#else
     *dst = val;
#endif
     dst ++;
     src ++;
     if(val == 0)
       break;
   }

  bzero(pwd, sizeof(pwd));
  memcpy(pwd, upwd, sizeof(pwd) < pass_len * 2 ? sizeof(pwd) :  pass_len * 2);
  return nasl_gcrypt_hash(lexic, GCRY_MD_MD4, pwd, pass_len * 2 > 128 ? 128 : pass_len * 2, NULL, 0);

}

tree_cell *
nasl_lm_owf_gen(lex_ctxt * lexic)
{
  char * pass = get_str_var_by_num(lexic, 0);
  int    pass_len = get_var_size_by_num(lexic, 0);
  tree_cell * retc;
  char pwd[15];
  char p16[16];
  int i;

  if (pass_len < 0 || pass == NULL )
   {
     nasl_perror(lexic, "Syntax : nt_lm_gen(cryptkey:<c>, password:<p>)\n");
     return NULL;
   }

  bzero(pwd, sizeof(pwd));
  strncpy(pwd, pass, sizeof(pwd) - 1);
  for(i=0;i<sizeof(pwd);i++)pwd[i] = toupper(pwd[i]);

  E_P16(pwd, p16);

  retc = alloc_tree_cell(0, NULL);
  retc->type = CONST_DATA;
  retc->size = 16;
  retc->x.str_val = nasl_strndup(p16, 16);
  return retc;
}

/* Does both the NTLMv2 owfs of a user's password */
tree_cell *
nasl_ntv2_owf_gen(lex_ctxt * lexic)
{
  char *owf_in = get_str_var_by_name(lexic, "owf");
  int  owf_in_len = get_var_size_by_name(lexic, "owf");
  char *user_in = get_str_var_by_name(lexic, "login");
  int  user_in_len = get_var_size_by_name(lexic, "login");
  char *domain_in = get_str_var_by_name(lexic, "domain");
  int  domain_len = get_var_size_by_name(lexic, "domain");
  char *src_user, *src_domain;
  smb_ucs2_t *user, *dst_user, val_user;
  smb_ucs2_t *domain, *dst_domain, val_domain;
  int i;
  size_t user_byte_len;
  size_t domain_byte_len;
  tree_cell * retc;
  char * kr_buf;
  HMACMD5Context ctx;

  if (owf_in_len<0 || owf_in == NULL || user_in_len<0 || user_in == NULL || domain_len<0 || domain_in==NULL)
  {
    nasl_perror(lexic, "Syntax : ntv2_owf_gen(owf:<o>, login:<l>, domain:<d>)\n");
    return NULL;
  }

  assert(owf_in_len==16);

  user_byte_len=sizeof(smb_ucs2_t)*(strlen(user_in)+1);
  user = emalloc(user_byte_len);
  dst_user = user;
  src_user = user_in;

  for (i = 0 ; i < user_in_len ; i ++)
   {
     val_user = *src_user;
     *dst_user = val_user;
     dst_user ++;
     src_user ++;
     if (val_user == 0)
       break;
   }

  domain_byte_len = sizeof(smb_ucs2_t)*(strlen(domain_in)+1);
  domain = emalloc(domain_byte_len);
  dst_domain = domain;
  src_domain = domain_in;

  for (i = 0 ; i < domain_len ; i ++)
   {
     val_domain = *src_domain;
     *dst_domain = val_domain;

     dst_domain ++;
     src_domain ++;
     if (val_domain == 0)
       break;
   }

  strupper_w(user);
  strupper_w(domain);

  assert(user_byte_len >= 2);
  assert(domain_byte_len >= 2);

  /* We don't want null termination */
  user_byte_len = user_byte_len - 2;
  domain_byte_len = domain_byte_len - 2;

  kr_buf = emalloc(16);

  hmac_md5_init_limK_to_64(owf_in, 16, &ctx);
  hmac_md5_update((const unsigned char *)user, user_byte_len, &ctx);
  hmac_md5_update((const unsigned char *)domain, domain_byte_len, &ctx);
  hmac_md5_final(kr_buf, &ctx);

  efree(&user);
  efree(&domain);

  retc = alloc_tree_cell(0, NULL);
  retc->type = CONST_DATA;
  retc->size  = 16;
  retc->x.str_val = kr_buf;

  return retc;
}

tree_cell *
nasl_ntlmv2_hash(lex_ctxt * lexic)
{
  char * server_chal = get_str_var_by_name(lexic, "cryptkey");
  int sc_len = get_var_size_by_name(lexic, "cryptkey");
  char * ntlm_v2_hash = get_str_var_by_name(lexic, "passhash");
  int hash_len  = get_var_size_by_name(lexic, "passhash");
  int client_chal_length = get_int_var_by_name(lexic, "length", -1);
  tree_cell * retc;
  unsigned char ntlmv2_response[16];
  unsigned char* ntlmv2_client_data=NULL;
  unsigned char* final_response;
  int i;

  if (sc_len<0 || server_chal == NULL || hash_len<0 || ntlm_v2_hash == NULL || client_chal_length<0)
   {
     nasl_perror(lexic, "Syntax : ntlmv2_hash(cryptkey:<c>, passhash:<p>, length:<l>)\n");
     return NULL;
   }

  /* NTLMv2 */

  /* We also get to specify some random data */
  ntlmv2_client_data = emalloc(client_chal_length);
  for (i=0;i<client_chal_length;i++)
    ntlmv2_client_data[i] = rand() % 256;



  assert(hash_len==16);
  /* Given that data, and the challenge from the server, generate a response */
  SMBOWFencrypt_ntv2(ntlm_v2_hash, server_chal, 8, ntlmv2_client_data, client_chal_length, ntlmv2_response);

  /* put it into nt_response, for the code below to put into the packet */
  final_response = emalloc(client_chal_length + sizeof(ntlmv2_response));
  memcpy(final_response, ntlmv2_response, sizeof(ntlmv2_response));
  /* after the first 16 bytes is the random data we generated above, so the server can verify us with it */
  memcpy(final_response + sizeof(ntlmv2_response), ntlmv2_client_data, client_chal_length);

  efree(&ntlmv2_client_data);

  retc = alloc_tree_cell(0, NULL);
  retc->type = CONST_DATA;
  retc->size  = client_chal_length + sizeof(ntlmv2_response);
  retc->x.str_val = final_response;

  return retc;
}
