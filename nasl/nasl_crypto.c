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
  * This file contains all the cryptographic functions NASL
  * has
  */
#include <includes.h>
#include <gcrypt.h>

#include "nasl_tree.h"
#include "nasl_global_ctxt.h"
#include "nasl_func.h"
#include "nasl_var.h"
#include "nasl_lex_ctxt.h"
#include "exec.h"  

#include "nasl_debug.h"

#include "strutils.h"
#include <assert.h>


/*-------------------[  Std. HASH ]-------------------------------------*/
static tree_cell*
nasl_gcrypt_hash(lex_ctxt * lexic, int algorithm, void * data, size_t datalen,
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
      nasl_perror(lexic, "nasl_gcrypt_hash(): gcry_md_open failed: %s/%s\n",
		  gcry_strsource(err), gcry_strerror(err));
      return NULL;
    }

  if (key)
    {
      err = gcry_md_setkey(hd, key, keylen);
      if (err)
	{
	  nasl_perror(lexic, "nasl_gcrypt_hash():"
		      " gcry_md_setkey failed: %s/%s\n",
		      gcry_strsource(err), gcry_strerror(err));
	  return NULL;
	}
    }

  gcry_md_write(hd, data, datalen);

  retc = alloc_tree_cell(0, NULL);
  retc->type = CONST_DATA;
  retc->x.str_val = nasl_strndup(gcry_md_read(hd, algorithm), dlen);
  retc->size = dlen;

  gcry_md_close(hd);

  return retc;
}

static tree_cell*
nasl_hash(lex_ctxt * lexic, int algorithm)
{
  char * data = get_str_var_by_num(lexic, 0);
  int    len  = get_var_size_by_num(lexic, 0);

  return nasl_gcrypt_hash(lexic, algorithm, data, len, NULL, 0);
}

tree_cell *
nasl_md4(lex_ctxt * lexic)
{
  return nasl_hash(lexic, GCRY_MD_MD4);
}

tree_cell *
nasl_md5(lex_ctxt * lexic)
{
  return nasl_hash(lexic, GCRY_MD_MD5);
}

tree_cell *
nasl_sha1(lex_ctxt * lexic)
{
  return nasl_hash(lexic, GCRY_MD_SHA1);
}


tree_cell *
nasl_ripemd160(lex_ctxt * lexic)
{
  return nasl_hash(lexic, GCRY_MD_RMD160);
}




/*-------------------[  HMAC ]-------------------------------------*/



static tree_cell *
nasl_hmac(lex_ctxt * lexic, int algorithm)
{
  char * data = get_str_local_var_by_name(lexic, "data");
  char * key  = get_str_local_var_by_name(lexic, "key");
  int data_len = get_local_var_size_by_name(lexic, "data");
  int  key_len = get_local_var_size_by_name(lexic, "key");

  return nasl_gcrypt_hash(lexic, algorithm, data, data_len, key, key_len);
}


tree_cell *
nasl_hmac_md5(lex_ctxt * lexic)
{
  return nasl_hmac(lexic, GCRY_MD_MD5);
}

tree_cell *
nasl_hmac_sha1(lex_ctxt * lexic)
{
  return nasl_hmac(lexic, GCRY_MD_SHA1);
}

tree_cell *
nasl_hmac_ripemd160(lex_ctxt * lexic)
{
  return nasl_hmac(lexic, GCRY_MD_RMD160);
}
