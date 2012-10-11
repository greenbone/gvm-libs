/* openvas-libraries/nasl
 * $Id$
 * Description: Implementation of an API for X.509 certificates
 *
 * Authors:
 * Werner Koch <wk@gnupg.org>
 *
 * Copyright:
 * Copyright (C) 2012 Greenbone Networks GmbH
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * or, at your option, any later version as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

/**
 * @file nasl_cert.c
 *
 * @brief Implementation of an API for X.509 certificates
 *
 * This file contains the implementation of the cert_* NASL builtin
 * functions.
 */

#ifdef HAVE_LIBKSBA
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>
#include <glib/gstdio.h>

#include <ksba.h>

#include "system.h"             /* for emalloc */
#include "nasl_tree.h"
#include "nasl_global_ctxt.h"
#include "nasl_func.h"
#include "nasl_var.h"
#include "nasl_lex_ctxt.h"
#include "nasl_debug.h"

#include "nasl_cert.h"


#ifndef DIM
# define DIM(v)		     (sizeof(v)/sizeof((v)[0]))
# define DIMof(type,member)   DIM(((type *)0)->member)
#endif



/* This object is used to keep track of KSBA certificate objects.
   Because they are pointers they can't be mapped easily to the NASL
   type system.  Our solution is to track those objects here and clean
   up any left over context at the end of a script run.  We could use
   the undocumented "on_exit" feature but that one is not well
   implemented; thus we use explicit code in the interpreter for the
   cleanup.  The scripts are expected to close the objects, but as
   long as they don't open too many of them, the system will take care
   of it at script termination time.

   We associate each object with an object id, which is a global
   counter of this process.  An object id of 0 marks an unused table
   entry.
 */
struct object_desc_s;
typedef struct object_desc_s *object_desc_t;
struct object_desc_s
{
  object_desc_t next;
  int object_id;
  ksba_cert_t cert;
};

/* A linked list of all used certificate objects.  */
static object_desc_t object_list;



/* Return the next object id.  */
static int
next_object_id (void)
{
  static int last;
  static int wrapped;

 again:
  last++;
  /* Because we don't have an unsigned type, it is better to avoid
     negative values.  Thus if LAST turns negative we wrap around to
     the 1; this also avoids the verboten zero.  */
  if (last <= 0)
    {
      last = 1;
      wrapped = 1;
    }

  /* If the counter wrapped we need to check that we do not return an
     object id still in use.  We use a stupid simple retry algorithm;
     this could be improved, for example, by remembering gaps in the
     list of used ids.  This code part is anyway not easy to test
     unless we implement a test feature for this function.  */
  if (wrapped)
    {
      object_desc_t obj;

      for (obj = object_list; obj; obj = obj->next)
        if (obj->object_id == last)
          goto again;
    }
  return last;
}


/**
 * @brief Create a certificate object.
 * @naslfn{cert_open}
 *
 * Takes a string/data as unnamed argument and returns an identifier
 * used with the other cert functions.  The data is usually the BER
 * encoded certificate but the function will also try a PEM encoding
 * on failure to parse BER encoded one.
 *
 * @nasluparam
 *
 * - String/data object with the certificate.  Either binary or
 *   PEM encoded.
 *
 * @naslnparam
 *
 * - @a errorvar Name of a variable used on error to return an error
 *               description.
 *
 * @naslret An integer used as an id for the certificate; on error 0
 *          is returned.
 *
 * @param[in] lexic  Lexical context of the NASL interpreter.
 *
 * @return On success the function returns a tree-cell with a non-zero
 *         object identifier for use with other cert functions; zero is
 *         returned on error.
 */
tree_cell *
nasl_cert_open (lex_ctxt *lexic)
{
  gpg_error_t err;
  tree_cell *retc;
  const char *data;
  int datalen;
  ksba_reader_t reader;
  ksba_cert_t cert;
  object_desc_t obj;

  data = get_str_var_by_num (lexic, 0);
  if (!data || !(datalen = get_var_size_by_num (lexic, 0)))
    {
      fprintf (stderr, "No certificate passed to cert_open\n");
      return NULL;
    }

  err = ksba_reader_new (&reader);
  if (err)
    {
      fprintf (stderr, "Opening reader object failed: %s\n",
               gpg_strerror (err));
      return NULL;
    }
  err = ksba_reader_set_mem (reader, data, datalen);
  if (err)
    {
      fprintf (stderr, "ksba_reader_set_mem failed: %s\n",
               gpg_strerror (err));
      ksba_reader_release (reader);
      return NULL;
    }

  err = ksba_cert_new (&cert);
  if (err)
    {
      fprintf (stderr, "ksba_cert_new failed: %s\n", gpg_strerror (err));
      ksba_reader_release (reader);
      return NULL;
    }

  err = ksba_cert_read_der (cert, reader);
  if (err)
    {
      fprintf (stderr, "Certificate parsing failed: %s\n", gpg_strerror (err));
      /* FIXME: Try again this time assuming a PEM certificate.  */
      ksba_reader_release (reader);
      ksba_cert_release (cert);
      return NULL;
    }
  ksba_reader_release (reader);

  obj = g_try_malloc (sizeof *obj);
  if (!obj)
    {
      fprintf (stderr, "malloc failed in %s\n", __FUNCTION__);
      ksba_cert_release (cert);
      return NULL;
    }
  obj->object_id = next_object_id ();
  obj->cert = cert;
  obj->next = object_list;
  object_list = obj;

  /* Return the session id.  */
  retc = alloc_typed_cell (CONST_INT);
  retc->x.i_val = obj->object_id;
  return retc;
}


/**
 * @brief Release a certificate object.
 * @naslfn{cert_close}
 *
 * Takes a cert identifier as returned by cert_open and releases the
 * associated resources.

 * @nasluparam
 *
 * - Object id of the certificate.  0 acts as a NOP.
 *
 * @naslret none
 *
 * @param[in] lexic  Lexical context of the NASL interpreter.
 *
 * @return none
 */
tree_cell *
nasl_cert_close (lex_ctxt *lexic)
{
  int object_id;
  object_desc_t prevobj, obj;

  object_id = get_int_var_by_num (lexic, 0, -1);
  if (!object_id)
    return FAKE_CELL;
  if (object_id < 0)
    {
      fprintf (stderr, "Bad object id %d passed to cert_close\n", object_id);
      return FAKE_CELL;
    }

  for (prevobj = NULL, obj = object_list; obj; prevobj = obj, obj = obj->next)
    if (obj->object_id == object_id)
      break;
  if (!obj)
    {
      fprintf (stderr, "Unused object id %d passed to cert_close\n", object_id);
      return FAKE_CELL;
    }

  if (prevobj)
    prevobj->next = obj->next;
  else
    object_list = obj->next;

  ksba_cert_release (obj->cert);
  g_free (obj);

  return FAKE_CELL;
}


/**
 * @brief Query a certificate object.
 * @naslfn{cert_query}
 *
 * Takes a cert identifier as first unnamed argument and a command
 * string as second argument.  That commonis used to select specific
 * information from the certificate.  For certain commandss the named
 * argument @a idx is used as well.  Depending on this command the
 * return value may be a number, a string, or an array of strings.
 * Supported commands are:
 *
 * - @a serial The serial number of the certificate.  This is
 *             returned as a hex encoded string.
 *
 * - @a subject Returns the subject.  To query the subjectAltName the
 *               named parameters @a idx can be used.  If @a idx is
 *               used the return value is an array, with the first
 *               element giving the type of the altSubjectName and the
 *               second element the actual data.  Types may be one:
 *               "xxx", "xxx", "xxx".
 *
 * - @a not-before The notBefore time as UTC value in ISO time format
 *                 (e.g. "20120930T143521").
 *
 * - @a not-after  The notAfter time as UTC value in ISO time format
 *                 (e.g. "20280929T143520").
 *
 * - @a all Return all available information in a human readable
 *          format.
 *
 * @nasluparam
 *
 * - Object id of the certificate.
 *
 * - A string with the command to select what to return; see above.
 *
 * @naslnparam
 *
 * - @a idx Used by certain commands to select the n-th value of a set
 *    of values.  If not given 0 is assumed.
 *
 * @naslret A NASL type depending on the used command.  NULL is
 *          returned on error.
 *
 * @param[in] lexic  Lexical context of the NASL interpreter.
 *
 * @return none
 */
tree_cell *
nasl_cert_query (lex_ctxt *lexic)
{
  int object_id;
  object_desc_t obj;
  const char *command;
  int cmdidx;
  char *result;
  ksba_isotime_t isotime;
  tree_cell *retc;

  object_id = get_int_var_by_num (lexic, 0, -1);
  if (object_id <= 0)
    {
      fprintf (stderr, "Bad object id %d passed to cert_query\n", object_id);
      return NULL;
    }

  for (obj = object_list; obj; obj = obj->next)
    if (obj->object_id == object_id)
      break;
  if (!obj)
    {
      fprintf (stderr, "Unused object id %d passed to cert_query\n", object_id);
      return NULL;
    }

  /* Check that the command is a string.  */
  command = get_str_var_by_num (lexic, 1);
  if (!command || get_var_type_by_num (lexic, 1) != VAR2_STRING)
    {
      fprintf (stderr, "No proper command passed to cert_query\n");
      return NULL;
    }

  /* Get the index which defaults to 0.  */
  cmdidx = get_int_local_var_by_name (lexic, "idx", 0);

  /* Command dispatcher.  */
  retc = NULL;
  if (!strcmp (command, "serial"))
    {
      /* FIXME */
    }
  else if (!strcmp (command, "issuer"))
    {
      result = ksba_cert_get_issuer (obj->cert, cmdidx);
      if (!result)
        return NULL;

      retc = alloc_typed_cell (CONST_STR);
      retc->x.str_val = estrdup (result);
      retc->size = strlen (result);
    }
  else if (!strcmp (command, "subject"))
    {
      result = ksba_cert_get_subject (obj->cert, cmdidx);
      if (!result)
        return NULL;

      retc = alloc_typed_cell (CONST_STR);
      retc->x.str_val = estrdup (result);
      retc->size = strlen (result);
    }
  else if (!strcmp (command, "not-before"))
    {
      ksba_cert_get_validity (obj->cert, 0, isotime);
      retc = alloc_typed_cell (CONST_STR);
      retc->x.str_val = estrdup (isotime);
      retc->size = strlen (isotime);
    }
  else if (!strcmp (command, "not-after"))
    {
      ksba_cert_get_validity (obj->cert, 1, isotime);
      retc = alloc_typed_cell (CONST_STR);
      retc->x.str_val = estrdup (isotime);
      retc->size = strlen (isotime);
    }
  else if (!strcmp (command, "all"))
    {
      /* FIXME */
    }
  else
    {
      fprintf (stderr, "Unknown command '%s' passed to cert_query\n", command);
    }

  return retc;
}


#endif /*!HAVE_LIBSSH*/
