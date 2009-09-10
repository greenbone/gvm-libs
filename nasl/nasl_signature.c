/* OpenVAS-LibNASL
 *
 * Authors:
 * Bernhard Herzog <bernhard.herzog@intevation.de>
 *
 * Copyright:
 * Copyright (C) 2007 Intevation GmbH
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

#include <includes.h>

#include <stdlib.h>
#include <stdio.h>

#include "nasl_signature.h"

#include "nasl_tree.h"
#include "nasl_var.h"
#include "nasl_func.h"
#include "nasl_lex_ctxt.h"
#include "nasl_debug.h"

/**
 * @brief Returns pointer to freshly allocated and initialized openvas_certificate.
 * 
 * @param fingerpr ingerprint of certificate.
 * @param owner Certificate owners name.
 * @param istrusted Whether this certificate is trustworthy or not.
 * @param pubkey Full public key.
 * 
 * @return Pointer to fresh openvas_certificate.
 */
openvas_certificate*
openvas_certificate_new (char* fingerpr, char* owner, gboolean istrusted,
                         char* pubkey)
{
  openvas_certificate* cert = emalloc(sizeof(openvas_certificate));
  cert->fpr = fingerpr;
  cert->ownername = owner;
  cert->trusted = istrusted;
  cert->full_public_key = pubkey;
  return cert;
}

/**
 * Frees the openvas_certificate and all associated data.
 * 
 * @param cert Certificate which holds pointers to the data.
 */
void
openvas_certificate_free (openvas_certificate* cert)
{
  if(cert == NULL)
    return;
  if(cert->fpr != NULL)
    efree(& (cert->fpr) );
  if( cert->ownername != NULL)
    efree(& (cert->ownername) );
  if(cert->full_public_key != NULL)
    efree(& (cert->full_public_key) );
  efree(&cert);
}

/**
 * Prints an error message for errors returned by gpgme.
 * 
 * @param function Calling function name (debug info).
 * @param err The gpgme error that caused the problem.
 */
static void
print_gpgme_error (char *function, gpgme_error_t err)
{
  nasl_perror (NULL, "%s failed: %s/%s\n",
               function, gpgme_strsource(err), gpgme_strerror(err));
}

/**
 * @brief Checks whether the signature verification result contains at least one
 * @brief signature and whether all signatures are fully valid.
 *
 * The function returns 1 if all signatures are fully valid and 0 otherwise.
 *
 * @param result The verification result to examine.
 * 
 * @return 1 if signatures found and all are fully valid, 0 otherwise.
 */
static int
examine_signatures (gpgme_verify_result_t result)
{
  int num_sigs  = 0;
  int num_valid = 0;
  gpgme_signature_t sig;

  nasl_trace(NULL, "examine_signatures\n");

  sig = result->signatures;
  while (sig)
    {
      num_sigs += 1;

      if (nasl_trace_enabled())
	{
	  nasl_trace(NULL, "examine_signatures: signature #%d:\n", num_sigs);
	  nasl_trace(NULL, "examine_signatures:    summary: %d\n",
		     sig->summary);
	  nasl_trace(NULL, "examine_signatures:    validity: %d\n",
		     sig->validity);
	  nasl_trace(NULL, "examine_signatures:    status: %s\n",
		     gpg_strerror(sig->status));
	  nasl_trace(NULL, "examine_signatures:    timestamp: %ld\n",
		     sig->timestamp);
	  nasl_trace(NULL, "examine_signatures:    exp_timestamp: %ld\n",
		     sig->exp_timestamp);
	  nasl_trace(NULL, "examine_signatures:    fpr: %s\n", sig->fpr);
	}

      if (sig->summary & GPGME_SIGSUM_VALID)
	{
	  nasl_trace(NULL, "examine_signatures: signature is valid\n");
	  num_valid += 1;
	}
      else
	{
      	  nasl_trace(NULL, "examine_signatures: signature is invalid\n");
          /** @todo Early stop might be possible. Can return here. */
	}
      sig = sig->next;
    }

  return num_sigs > 0 && num_sigs == num_valid;
}

/**
 * Returns the name of the GnuPG home directory to use when checking
 * GnuPG signatures.  The return value is the value of the environment
 * variable OPENVAS_GPGHOME if it is set.  Otherwise it is the directory
 * openvas/gnupg under the sysconfdir that was set by configure (usually
 * $prefix/etc).  The return value has been created by estrdup and must
 * be deallocated by efree.
 * 
 * @return Custom path of the GnuPG home directory.
 */
static char *
determine_gpghome ()
{
  /** @todo Use glibs g_build_filename */
  char * default_dir = OPENVAS_SYSCONFDIR "/openvas/gnupg";
  char * envdir = getenv("OPENVAS_GPGHOME");

  return estrdup (envdir ? envdir : default_dir);
}

/**
 * Inits a gpgme context with the custom gpghome directory, protocol version
 * etc. Returns the context or NULL if an error occurred.
 * 
 * @return The gpgme_ctx_t to the context or NULL if an error occurred.
 */
gpgme_ctx_t
init_openvas_gpgme_ctx ()
{
  gpgme_error_t err;
  gpgme_ctx_t ctx = NULL;
  char * gpghome = determine_gpghome();

  /* Calls seem to be necessary for certain versions of gpgme (for
    initialization). Note that we could check the version number here, but do so
    in configure. */
  gpgme_check_version (NULL);
  err = gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP);

  if (err)
    {
      print_gpgme_error ("gpgme_engine_check_version", err);
    }

  if (!err)
    {
    err = gpgme_new(&ctx);
    if (err)
      {
        print_gpgme_error ("gpgme_new", err);
        if (ctx != NULL)
          gpgme_release (ctx);
        ctx = NULL;
      }
     }

  if (!err)
    {
    nasl_trace(NULL, "init_openvas_gpgme_ctx: setting homedir '%s'\n", gpghome);
    err = gpgme_ctx_set_engine_info(ctx, GPGME_PROTOCOL_OpenPGP, NULL,
                                    gpghome);
    if (err)
      {
        print_gpgme_error("gpgme_ctx_set_engine_info", err);
        if(ctx != NULL)
          gpgme_release(ctx);
        ctx = NULL;
      }
    }

  return ctx;
}

/**
 * Checks the detached OpenPGP signature of the file given by FILENAME.
 * The name of the signature file is derived from FILENAME by appending
 * ".asc".
 *
 * If a signature file exists and it contains only fully valid
 * signatures, the function returns 0.  If any of the signatures is not
 * valid or was made by an unknown or untrusted key, the function
 * returns 1.  If an error occurs or the file does not have a
 * corresponding detached signature the function returns -1.
 * 
 * @param filename Filename (e.g. 1.txt) for which to check signature (e.g.
                   1.txt.asc).
 * 
 * @return Zero, if files exists and all signatures are fully trusted. 1 if at 
 *         least one signature from invalid or untrusted key. -1 on missing file
 *         or error.
 */
int
nasl_verify_signature (const char* filename)
{
  int retcode = -1;
  char * sigfilename = NULL;
  gpgme_error_t err;
  gpgme_ctx_t ctx = init_openvas_gpgme_ctx();
  gpgme_data_t sig = NULL, text = NULL;

  if(ctx == NULL)
    {
      nasl_trace (NULL, "gpgme context could not be initialized.\n");
      goto fail;
    }

  nasl_trace (NULL, "nasl_verify_signature: loading scriptfile '%s'\n",
	      filename);

  err = gpgme_data_new_from_file(&text, filename, 1);
  if (err)
    {
      print_gpgme_error("gpgme_data_new_from_file", err);
      goto fail;
    }

  sigfilename = emalloc (strlen(filename) + 4 + 1);
  strcpy (sigfilename, filename); /* Flawfinder: ignore */
  strcat (sigfilename, ".asc");
  nasl_trace (NULL, "nasl_verify_signature: loading signature file '%s'\n",
              sigfilename);
  err = gpgme_data_new_from_file (&sig, sigfilename, 1);
  if (err)
    {
      /* If the file doesn't exist, fail without an error message
       * because an unsigned file is a very common and expected
       * condition */
      if (gpgme_err_code (err) != GPG_ERR_ENOENT)
        print_gpgme_error ("gpgme_data_new_from_file", err);
      else
        nasl_trace (NULL, "nasl_verify_signature: %s: %s\n",
                    sigfilename, gpgme_strerror(err));
      goto fail;
    }

  err = gpgme_op_verify (ctx, sig, text, NULL);
  nasl_trace (NULL, "nasl_verify_signature: gpgme_op_verify -> '%d'\n", err);
  if (err)
    {
      print_gpgme_error("gpgme_op_verify", err);
      goto fail;
    }

  if (examine_signatures (gpgme_op_verify_result(ctx)))
    retcode = 0;
  else
    retcode = 1;

 fail:
  gpgme_data_release(sig);
  gpgme_data_release(text);
  if(ctx != NULL)
    gpgme_release(ctx);
  efree(&sigfilename);

  return retcode;
}



/**
 * @brief Extracts fingerprints of signing public keys in a given signature file.
 *
 * Works like nasl_verify_signature, but always returns a string with the
 * fingerprints in it (NULL if error), even if the keys are not trusted.
 * 
 * @param filename Path to the signed file (e.g. /../check_killerapp.nasl).
 * 
 * @return A string with comma- separated fingerprints or NULL if error.
 * 
 * @see nasl_verify_signature( const char* filename )
 */
char*
nasl_extract_signature_fprs (const char* filename)
{
  char * sigfilename = NULL;
  gpgme_error_t err;
  gpgme_ctx_t ctx   = init_openvas_gpgme_ctx();
  gpgme_data_t sig  = NULL;
  gpgme_data_t text = NULL;
  gpgme_signature_t signature;
  /** @todo Once there was a size limitation for the cache.
    * It was removed since OpenVAS > 2.0 and this
    * fixed size here should eventually be replaced by dynamic solution. */
  char* key_fprs = emalloc( (3*48 + 3) *sizeof(char)); 
  key_fprs[0] = '\0';
  gboolean failed = FALSE;

  if ( ctx == NULL)
    {
    err = 0;
    failed = TRUE;
    }

  if(!err)
    {
    nasl_trace (NULL, "nasl_extract_signature_fprs: loading scriptfile '%s'\n",
               filename);
    err = gpgme_data_new_from_file (&text, filename, 1);
    if (err)
        {
          print_gpgme_error ("gpgme_data_new_from_file", err);
          failed = TRUE;
        }
    }

  if (!err)
    {
    sigfilename = emalloc (strlen(filename) + 4 + 1);
    strcpy (sigfilename, filename); /* Flawfinder: ignore */
    strcat (sigfilename, ".asc");

    nasl_trace(NULL, "nasl_extract_signature_fprs: loading signature file '%s'\n",
	       sigfilename);
    err = gpgme_data_new_from_file(&sig, sigfilename, 1);
    if (err)
      {
        /* If the file doesn't exist, fail without an error message
         * because an unsigned file is a very common and expected
         * condition */
        if (gpgme_err_code(err) != GPG_ERR_ENOENT)
          print_gpgme_error("gpgme_data_new_from_file", err);
        else
          nasl_trace(NULL, "nasl_extract_signature_fprs: %s: %s\n",
		   sigfilename, gpgme_strerror(err));
        failed = TRUE;
      }
    }

  if(!err)
    {
      err = gpgme_op_verify (ctx, sig, text, NULL);
      nasl_trace (NULL, "nasl_extract_signature_fprs: gpgme_op_verify -> '%d'\n", err);
      if (err)
        {
          print_gpgme_error("gpgme_op_verify", err);
          failed = TRUE;
        }
    }

  if (!err)
    {
    gpgme_verify_result_t result = gpgme_op_verify_result (ctx);

    signature = result->signatures;
    // Concatenate the fingerprints of the signatures in the sig (.asc) file.
    while (signature)
      {
        // Enough mem to store the new fingerprint (old + ',' + new + '\0')?
        if (strlen(key_fprs) + strlen(signature->fpr) < (3*48+1) )
          {
            // If already fingerprint(s) found, separate new one by ','.
            if (key_fprs[0] != '\0')
              {
                strcat (key_fprs,",");             /* RATS: ignore */
                strcat (key_fprs, signature->fpr); /* RATS: ignore */
              }
            // Else it is the first key found, copy it.
            else
              {
                strcpy (key_fprs, signature->fpr);
              }
          }
        else
          {
            printf ("Too much fingerprints for %s found. "
                    "Clients will see only parts of them.", filename);
            nasl_trace (NULL, "nasl_extract_signature_fprs: cropping fingerprints\n");
          }

        signature = signature->next;
      }
    }

  gpgme_data_release (sig);
  gpgme_data_release (text);
  if (ctx != NULL)
    gpgme_release(ctx);
  efree (&sigfilename);

  char* return_string = NULL;

  if (failed == FALSE)
     return_string = estrdup (key_fprs);

  efree (&key_fprs);
  return return_string;
}


/**
 * @brief Reads in a full public key.
 * The returned string will be ascii- armored.
 * 
 * @param ctx The gpgme context to work in.
 * @param fingerprint Fingerprint of the key to return.
 * 
 * @return The public key belonging to fingerprint in an emalloc'ed string 
 *         or NULL if an error occurred.
 */
char*
nasl_get_pubkey (gpgme_ctx_t ctx, char* fingerprint)
{
  gpgme_set_armor (ctx, 1);

  gpgme_error_t err;
  gpgme_data_t pkey;
  char* key_string = NULL;
  gpgme_data_new (&pkey);

  err = gpgme_data_set_encoding (pkey, GPGME_DATA_ENCODING_ARMOR);
  if (err)
    {
      print_gpgme_error("gpgme_data_set_encoding", err);
    }

  err = gpgme_op_export(ctx, fingerprint, 0, pkey);
  if (err)
    {
      print_gpgme_error("gpgme_op_export", err);
      gpgme_data_release(pkey);
      return NULL;
    }

  // Determine length of public key
  size_t key_length = gpgme_data_seek (pkey, 0, SEEK_END);

  // Public keys length must be >0
  if (key_length == -1)
    {
      nasl_trace (NULL, "gpgme couldn't find public key for %s.\n", fingerprint);
      gpgme_data_release (pkey);
      return NULL;
    }

  key_string = emalloc ((key_length + 1) * sizeof(char));

  // Rewind data
  if (gpgme_data_seek (pkey, 0, SEEK_SET) != 0)
    {
      nasl_trace (NULL, "gpgme couldn't deal with public key data "
                         "for %s.\n", fingerprint);
      gpgme_data_release (pkey);
      efree (&key_string);
      return NULL;
    }

  // Copy certificate into buffer
  size_t bytes_read = gpgme_data_read (pkey, key_string, key_length);
  if (bytes_read != key_length)
    {
      nasl_trace (NULL, "gpgme couldn't read all public key data "
                        "for %s.\n", fingerprint);
      gpgme_data_release (pkey);
      efree (&key_string);
      return NULL;
    }

  gpgme_data_release (pkey);

  if (err && key_string != NULL)
    efree (&key_string);

  return key_string;
}

/**
 * @brief Creates openvas_certificates for all certificates found in the
 * @brief (custom) gpg home directory
 * and returns a pointer to a GSList containing (pointers to) them.
 * 
 * Creation has to be done in two steps: First retrieve info like ownername and
 * trust level and then read in the full public key. The two steps have to
 * be done seperately because the two gpgme listing operations are exclusive.
 * 
 * @return Pointer to a GSList containing pointers to openvas_certificate structs.
 */
GSList*
nasl_get_all_certificates ()
{
  GSList* certificates = NULL;
  // Certificate retrieval
  gpgme_error_t err;
  gpgme_ctx_t ctx = init_openvas_gpgme_ctx();

  if ( ctx == NULL)
    {
      return NULL;
    }

  err = gpgme_op_keylist_ext_start(ctx, NULL, 0, 0);
  if (err)
    {
       nasl_trace(NULL, "otp_1_0_send_certificates: trouble finding gpgme keys %s.\n", strerror(err));
    }

  gpgme_key_t key = NULL;

  while (!err)
    {
       err = gpgme_op_keylist_next (ctx, &key);

       // No more keys
       if (key == NULL)
          break;
       // Other error
       if (err)
          {
            if (key != NULL)
              gpgme_key_release (key);
            print_gpgme_error ("gpgme_op_keylist_next", err);
            break;
          }

       openvas_certificate* cert = emalloc (sizeof (openvas_certificate));
       cert->fpr = estrdup (key->subkeys->fpr);
       cert->ownername = estrdup (key->uids->name);
       if (key->owner_trust == GPGME_VALIDITY_FULL || key->owner_trust == GPGME_VALIDITY_ULTIMATE)
          cert->trusted = TRUE;
       else
          cert->trusted = FALSE;

       certificates = g_slist_prepend (certificates, cert);
       gpgme_key_release (key);
    }

  // Fetch the full keys
  GSList* list = certificates;
  while (list != NULL && list->data != NULL)
    {
      openvas_certificate* cert = list->data;
      cert->full_public_key = nasl_get_pubkey (ctx, cert->fpr);
      list = g_slist_next (list);
    }

  gpgme_release(ctx);

  return certificates;
}
