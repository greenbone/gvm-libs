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

/**
 * @file
 * This file contains all the functions that make the "glue" between
 * as NASL script and openvassd.
 * (script_*(), *kb*(), scanner_*())
 */

#include <ctype.h>              /* for isdigit */
#include <errno.h>              /* for errno */
#include <fcntl.h>              /* for open */
#include <stdlib.h>             /* for atoi */
#include <string.h>             /* for strcmp */
#include <sys/stat.h>           /* for stat */
#include <unistd.h>             /* for close */

#include <glib.h>

#include "comm.h"               /* for comm_send_status */
#include "kb.h"                 /* for KB_TYPE_INT */
#include "plugutils.h"          /* for plug_set_timeout */
#include "scanners_utils.h"     /* for getpts */
#include "system.h"             /* for estrdup */

#include "strutils.h"

#include "nasl_tree.h"
#include "nasl_global_ctxt.h"
#include "nasl_func.h"
#include "nasl_var.h"
#include "nasl_lex_ctxt.h"
#include "exec.h"

#include "nasl_debug.h"
#include "nasl_scanner_glue.h"

#ifndef NASL_DEBUG
#define NASL_DEBUG 0
#endif

/*------------------- Private utilities ---------------------------------*/

static int
isalldigit (char *str, int len)
{
  int i;
  char buf[1024];
  for (i = 0; i < len; i++)
    {
      if (!isdigit (str[i]))
        return 0;
    }

  snprintf (buf, sizeof (buf), "%d", atoi (str));       /* RATS: ignore */
  if (strcmp (buf, str) != 0)
    return 0;
  else
    return 1;
}



/*-------------------[ script_*() functions ]----------------------------*/

 /*
  * These functions are used when the script registers itself to openvas
  * scanner.
  */

tree_cell *
script_timeout (lex_ctxt * lexic)
{
  struct arglist *script_infos = lexic->script_infos;
  int to = get_int_var_by_num (lexic, 0, -65535);

  if (to == -65535)
    return FAKE_CELL;

  plug_set_timeout (script_infos, to ? to : -1);
  return FAKE_CELL;
}


tree_cell *
script_id (lex_ctxt * lexic)
{
  struct arglist *script_infos = lexic->script_infos;
  int id;

  id = get_int_var_by_num (lexic, 0, -1);
  if (id > 0)
    plug_set_id (script_infos, id);

  return FAKE_CELL;
}

tree_cell *
script_oid (lex_ctxt * lexic)
{
  struct arglist *script_infos = lexic->script_infos;
  char *oid = get_str_var_by_num (lexic, 0);
  if (oid != NULL)
    {
      plug_set_oid (script_infos, oid);
    }
  return FAKE_CELL;
}

/*
 * TODO: support multiple CVE entries
 */
tree_cell *
script_cve_id (lex_ctxt * lexic)
{
  struct arglist *script_infos = lexic->script_infos;
  char *cve = get_str_var_by_num (lexic, 0);
  int i;

  for (i = 0; cve != NULL; i++)
    {
      plug_set_cve_id (script_infos, cve);
      cve = get_str_var_by_num (lexic, i + 1);
    }

  return FAKE_CELL;
}

/*
 * TODO: support multiple bugtraq entries
 */
tree_cell *
script_bugtraq_id (lex_ctxt * lexic)
{
  struct arglist *script_infos = lexic->script_infos;
  char *bid = get_str_var_by_num (lexic, 0);
  int i;

  for (i = 0; bid != NULL; i++)
    {
      plug_set_bugtraq_id (script_infos, bid);
      bid = get_str_var_by_num (lexic, i + 1);
    }

  return FAKE_CELL;
}


tree_cell *
script_xref (lex_ctxt * lexic)
{
  struct arglist *script_infos = lexic->script_infos;
  char *name = get_str_var_by_name (lexic, "name");
  char *value = get_str_var_by_name (lexic, "value");


  if (value == NULL || name == NULL)
    {
      fprintf (stderr,
               "script_xref() syntax error - should be script_xref(name:<name>, value:<value>)\n");
      return FAKE_CELL;
    }

  plug_set_xref (script_infos, name, value);

  return FAKE_CELL;
}

tree_cell *
script_tag (lex_ctxt * lexic)
{
  struct arglist *script_infos = lexic->script_infos;
  char *name = get_str_var_by_name (lexic, "name");
  char *value = get_str_var_by_name (lexic, "value");

  if (value == NULL || name == NULL)
    {
      fprintf (stderr,
               "script_tag() syntax error - should be script_tag(name:<name>, value:<value>)\n");
      return FAKE_CELL;
    }

  plug_set_tag (script_infos, name, value);

  return FAKE_CELL;
}



/* UNUSED */
tree_cell *
script_see_also (lex_ctxt * lexic)
{
  nasl_perror (lexic, "Error - script_see_also() called\n");
  return FAKE_CELL;
}

typedef void (*script_register_func_t) (struct arglist *, const char *);

// TODO: This function can be elminiated (functionality back to script_name, etc)
// once all NASL scripts are being cleared of old I18N concept
static tree_cell *
script_elem (lex_ctxt * lexic, script_register_func_t script_register_func)
{
  struct arglist *script_infos = lexic->script_infos;
  char *str;

  str = get_str_local_var_by_name (lexic, "english");
  if (str == NULL)
    {
      str = get_str_var_by_num (lexic, 0);
      if (str == NULL)
        return FAKE_CELL;
    }

  script_register_func (script_infos, str);
  return FAKE_CELL;
}


tree_cell *
script_name (lex_ctxt * lexic)
{
  return (script_elem (lexic, plug_set_name));
}


tree_cell *
script_version (lex_ctxt * lexic)
{
  struct arglist *script_infos = lexic->script_infos;

  char *version = get_str_var_by_num (lexic, 0);
  if (version == NULL)
    {
      nasl_perror (lexic, "Argument error in function script_version()\n");
      nasl_perror (lexic, "Function usage is : script_version(<name>)\n");
      nasl_perror (lexic, "Where <name> is the name of another script\n");
    }

  else
    plug_set_version (script_infos, version);

  return FAKE_CELL;
}

tree_cell *
script_description (lex_ctxt * lexic)
{
  return (script_elem (lexic, plug_set_description));
}

tree_cell *
script_copyright (lex_ctxt * lexic)
{
  return (script_elem (lexic, plug_set_copyright));
}

tree_cell *
script_summary (lex_ctxt * lexic)
{
  return (script_elem (lexic, plug_set_summary));
}

tree_cell *
script_category (lex_ctxt * lexic)
{
  struct arglist *script_infos = lexic->script_infos;

  int category = get_int_var_by_num (lexic, 0, -1);

  if (category < 0)
    {
      nasl_perror (lexic, "Argument error in function script_category()\n");
      nasl_perror (lexic, "Function usage is : script_category(<category>)\n");
      return FAKE_CELL;
    }
  plug_set_category (script_infos, category);
  return FAKE_CELL;
}

tree_cell *
script_family (lex_ctxt * lexic)
{
  return (script_elem (lexic, plug_set_family));
}

tree_cell *
script_dependencie (lex_ctxt * lexic)
{
  struct arglist *script_infos = lexic->script_infos;
  char *dep = get_str_var_by_num (lexic, 0);
  int i;

  if (dep == NULL)
    {
      nasl_perror (lexic, "Argument error in function script_dependencie()\n");
      nasl_perror (lexic, "Function usage is : script_dependencie(<name>)\n");
      nasl_perror (lexic, "Where <name> is the name of another script\n");

      return FAKE_CELL;
    }

  for (i = 0; dep != NULL; i++)
    {
      dep = get_str_var_by_num (lexic, i);
      if (dep != NULL)
        plug_set_dep (script_infos, dep);
    }

  return FAKE_CELL;
}


tree_cell *
script_require_keys (lex_ctxt * lexic)
{
  struct arglist *script_infos = lexic->script_infos;

  char *keys = get_str_var_by_num (lexic, 0);
  int i;

  if (keys == NULL)
    {
      nasl_perror (lexic, "Argument error in function script_require_keys()\n");
      nasl_perror (lexic, "Function usage is : script_require_keys(<name>)\n");
      nasl_perror (lexic, "Where <name> is the name of a key\n");
      return FAKE_CELL;
    }

  for (i = 0; keys != NULL; i++)
    {
      keys = get_str_var_by_num (lexic, i);
      if (keys != NULL)
        plug_require_key (script_infos, keys);
    }

  return FAKE_CELL;
}

tree_cell *
script_mandatory_keys (lex_ctxt * lexic)
{
  struct arglist *script_infos = lexic->script_infos;

  char *keys = get_str_var_by_num (lexic, 0);
  int i;

  if (keys == NULL)
    {
      nasl_perror (lexic,
                   "Argument error in function script_mandatory_keys()\n");
      nasl_perror (lexic,
                   "Function usage is : script_mandatory_keys(<name>)\n");
      nasl_perror (lexic, "Where <name> is the name of a key\n");
      return FAKE_CELL;
    }

  for (i = 0; keys != NULL; i++)
    {
      keys = get_str_var_by_num (lexic, i);
      if (keys != NULL)
        plug_mandatory_key (script_infos, keys);
    }

  return FAKE_CELL;
}

tree_cell *
script_exclude_keys (lex_ctxt * lexic)
{
  struct arglist *script_infos = lexic->script_infos;

  int i;
  char *keys = get_str_var_by_num (lexic, 0);

  for (i = 0; keys != NULL; i++)
    {
      keys = get_str_var_by_num (lexic, i);
      if (keys != NULL)
        {
          plug_exclude_key (script_infos, keys);
        }
    }

  return FAKE_CELL;
}


tree_cell *
script_require_ports (lex_ctxt * lexic)
{
  struct arglist *script_infos = lexic->script_infos;
  char *port;
  int i;

  for (i = 0;; i++)
    {
      port = get_str_var_by_num (lexic, i);
      if (port != NULL)
        plug_require_port (script_infos, port);
      else
        break;
    }

  return FAKE_CELL;
}


tree_cell *
script_require_udp_ports (lex_ctxt * lexic)
{
  struct arglist *script_infos = lexic->script_infos;
  int i;
  char *port;

  for (i = 0;; i++)
    {
      port = get_str_var_by_num (lexic, i);
      if (port != NULL)
        plug_require_udp_port (script_infos, port);
      else
        break;
    }

  return FAKE_CELL;
}

tree_cell *
script_add_preference (lex_ctxt * lexic)
{
  char *name = get_str_local_var_by_name (lexic, "name");
  char *type = get_str_local_var_by_name (lexic, "type");
  char *value = get_str_local_var_by_name (lexic, "value");
  struct arglist *script_infos = lexic->script_infos;

  if (name == NULL || type == NULL || value == NULL)
    nasl_perror (lexic,
                 "Argument error in the call to script_add_preference()\n");
  else
    add_plugin_preference (script_infos, name, type, value);

  return FAKE_CELL;
}

tree_cell *
script_get_preference (lex_ctxt * lexic)
{
  struct arglist *script_infos = lexic->script_infos;
  tree_cell *retc;
  char *pref = get_str_var_by_num (lexic, 0);
  char *value;

  if (pref == NULL)
    {
      nasl_perror (lexic,
                   "Argument error in the function script_get_preference()\n");
      nasl_perror (lexic,
                   "Function usage is : pref = script_get_preference(<name>)\n");
      return FAKE_CELL;
    }

  value = get_plugin_preference (script_infos, pref);
  if (value != NULL)
    {
      retc = alloc_tree_cell (0, NULL);
      if (isalldigit (value, strlen (value)))
        {
          retc->type = CONST_INT;
          retc->x.i_val = atoi (value);
        }
      else
        {
          retc->type = CONST_DATA;
          retc->size = strlen (value);
          retc->x.str_val = estrdup (value);
        }
      return retc;
    }
  else
    return FAKE_CELL;
}

tree_cell *
script_get_preference_file_content (lex_ctxt * lexic)
{
  struct arglist *script_infos = lexic->script_infos;
  tree_cell *retc;
  char *pref = get_str_var_by_num (lexic, 0);
  char *value;
  char *content;
  int contentsize = 0;

  if (pref == NULL)
    {
      nasl_perror (lexic,
                   "Argument error in the function script_get_preference()\n");
      nasl_perror (lexic,
                   "Function usage is : pref = script_get_preference_file_content(<name>)\n");
      return NULL;
    }

  value = get_plugin_preference (script_infos, pref);
  if (value == NULL)
    return NULL;

  content = get_plugin_preference_file_content (script_infos, value);
  if (content == NULL)
    return FAKE_CELL;
  contentsize = get_plugin_preference_file_size (script_infos, value);
  if (content <= 0)
    {
      nasl_perror (lexic,
                   "script_get_preference_file_content: could not get size of file from preference %s\n",
                   pref);
      return NULL;
    }

  retc = alloc_tree_cell (0, NULL);
  retc->type = CONST_DATA;
  retc->size = contentsize;
  retc->x.str_val = content;

  return retc;
}


tree_cell *
script_get_preference_file_location (lex_ctxt * lexic)
{
  struct arglist *script_infos = lexic->script_infos;
  tree_cell *retc;
  char *pref = get_str_var_by_num (lexic, 0);
  const char *value, *local;
  int len;

  /* Getting the local file name is not dangerous, but
   * only signed scripts can access files uploaded by the user */
  if (check_authenticated (lexic) < 0)
    {
      nasl_perror (lexic,
                   "script_get_preference_file_location: script is not authenticated!\n");
      return NULL;
    }

  if (pref == NULL)
    {
      nasl_perror (lexic,
                   "script_get_preference_file_location: no preference name!\n");
      return NULL;
    }

  value = get_plugin_preference (script_infos, pref);
  if (value == NULL)
    {
      nasl_perror (lexic,
                   "script_get_preference_file_location: could not get preference %s\n",
                   pref);
      return NULL;
    }
  local = get_plugin_preference_fname (script_infos, value);
  if (local == NULL)
    return NULL;

  len = strlen (local);
  retc = alloc_typed_cell (CONST_DATA);
  retc->size = len;
  retc->x.str_val = emalloc (len + 1);
  memcpy (retc->x.str_val, local, len + 1);

  return retc;
}

/* Are safe checks enabled ? */
tree_cell *
safe_checks (lex_ctxt * lexic)
{
  struct arglist *script_infos = lexic->script_infos;
  struct arglist *prefs = arg_get_value (script_infos, "preferences");
  char *value;
  tree_cell *retc = alloc_tree_cell (0, NULL);

  retc->type = CONST_INT;
  value = arg_get_value (prefs, "safe_checks");
  if ((value && !strcmp (value, "yes")))
    {
      retc->x.i_val = 1;
    }
  else
    retc->x.i_val = 0;

  return retc;
}

tree_cell *
scan_phase (lex_ctxt * lexic)
{
  struct arglist *script_infos = lexic->script_infos;
  struct arglist *globals = arg_get_value (script_infos, "globals");
  char *value;
  tree_cell *retc = alloc_tree_cell (0, NULL);

  retc->type = CONST_INT;
  value = arg_get_value (globals, "network_scan_status");
  if (value)
    {
      if (strcmp (value, "busy") == 0)
        retc->x.i_val = 1;
      else
        retc->x.i_val = 2;
    }
  else
    retc->x.i_val = 0;

  return retc;
}

tree_cell *
network_targets (lex_ctxt * lexic)
{
  struct arglist *script_infos = lexic->script_infos;
  struct arglist *globals = arg_get_value (script_infos, "globals");
  char *value;
  tree_cell *retc;

  value = arg_get_value (globals, "network_targets");
  retc = alloc_typed_cell (CONST_DATA);
  if (value)
    {
      retc->x.str_val = strdup (value);
      retc->size = strlen (value);
    }
  else
    return NULL;

  return retc;
}

/*--------------------[ KB ]---------------------------------------*/

#define SECRET_KB_PREFIX	"Secret/"

tree_cell *
get_kb_list (lex_ctxt * lexic)
{
  struct arglist *script_infos = lexic->script_infos;
  struct kb_item **kb = plug_get_kb (script_infos);
  char *kb_mask = get_str_var_by_num (lexic, 0);
  tree_cell *retc;
  int num_elems = 0;
  nasl_array *a;
  struct kb_item *res, *top;

  if (kb_mask == NULL)
    {
      nasl_perror (lexic, "get_kb_list() usage : get_kb_list(<NameOfItem>)\n");
      return NULL;
    }

  if (kb == NULL)
    {
      return NULL;
    }

  retc = alloc_tree_cell (0, NULL);
  retc->type = DYN_ARRAY;
  retc->x.ref_val = a = emalloc (sizeof (nasl_array));

  top = res = kb_item_get_pattern (kb, kb_mask);

  while (res != NULL)
    {
      anon_nasl_var v;
      bzero (&v, sizeof (v));

      if (lexic->authenticated
          || strncmp (res->name, SECRET_KB_PREFIX,
                      sizeof (SECRET_KB_PREFIX) - 1) != 0)
        {
          if (res->type == KB_TYPE_INT)
            {
              v.var_type = VAR2_INT;
              v.v.v_int = res->v.v_int;
              add_var_to_array (a, res->name, &v);
              num_elems++;
            }
          else if (res->type == KB_TYPE_STR)
            {
              v.var_type = VAR2_DATA;
              v.v.v_str.s_val = (unsigned char *) res->v.v_str;
              v.v.v_str.s_siz = strlen (res->v.v_str);
              add_var_to_array (a, res->name, &v);
              num_elems++;
            }
        }
#if NASL_DEBUG > 0
      else
        nasl_perror (lexic, "get_kb_list: skipping protected KN entry %s\n",
                     res->name);
#endif
      res = res->next;
    }

  kb_item_get_all_free (top);

  if (num_elems == 0)
    {
      deref_cell (retc);
      return FAKE_CELL;
    }
  return retc;
}

tree_cell *
get_kb_item (lex_ctxt * lexic)
{
  struct arglist *script_infos = lexic->script_infos;

  char *kb_entry = get_str_var_by_num (lexic, 0);
  char *val;
  tree_cell *retc;
  int type;

  if (kb_entry == NULL)
    return NULL;

  if (!lexic->authenticated
      && strncmp (kb_entry, SECRET_KB_PREFIX,
                  sizeof (SECRET_KB_PREFIX) - 1) == 0)
    {
      nasl_perror (lexic,
                   "Untrusted script cannot read protected KB entry %s\n",
                   kb_entry);
      return NULL;
    }

  val = plug_get_key (script_infos, kb_entry, &type);


  if (val == NULL && type == -1)
    return NULL;


  retc = alloc_tree_cell (0, NULL);
  if (type == KB_TYPE_INT)
    {
      retc->type = CONST_INT;
      retc->x.i_val = GPOINTER_TO_SIZE (val);
      return retc;
    }
  else
    {
      retc->type = CONST_DATA;
      if (val != NULL)
        {
          retc->size = strlen (val);
          retc->x.str_val = estrdup (val);
        }
      else
        {
          retc->size = 0;
          retc->x.str_val = NULL;
        }
    }

  return retc;
}

/**
 * Instead of reading the local copy of the KB, we ask the upstream
 * father the "newest" value of a given KB item. This is especially useful
 * when dealing with shared sockets and SSH.
 */
tree_cell *
get_kb_fresh_item (lex_ctxt * lexic)
{
  struct arglist *script_infos = lexic->script_infos;

  char *kb_entry = get_str_var_by_num (lexic, 0);
  char *val;
  tree_cell *retc;
  int type;

  if (kb_entry == NULL)
    return NULL;

  if (!lexic->authenticated
      && strncmp (kb_entry, SECRET_KB_PREFIX,
                  sizeof (SECRET_KB_PREFIX) - 1) == 0)
    {
      nasl_perror (lexic,
                   "Untrusted script cannot read protected KB entry %s\n",
                   kb_entry);
      return NULL;
    }

  val = plug_get_fresh_key (script_infos, kb_entry, &type);


  if (val == NULL && type == -1)
    return NULL;

  retc = alloc_tree_cell (0, NULL);
  if (type == KB_TYPE_INT)
    {
      retc->type = CONST_INT;
      retc->x.i_val = GPOINTER_TO_SIZE (val);
      return retc;
    }
  else
    {
      retc->type = CONST_DATA;
      if (val != NULL)
        {
          retc->size = strlen (val);
          retc->x.str_val = val;        /* Do NOT estrdup() the value, since plug_get_fresh_key() allocated the memory already */
        }
      else
        {
          retc->size = 0;
          retc->x.str_val = NULL;
        }
    }

  return retc;
}

tree_cell *
replace_kb_item (lex_ctxt * lexic)
{
  struct arglist *script_infos = lexic->script_infos;
  char *name = get_str_local_var_by_name (lexic, "name");
  int type = get_local_var_type_by_name (lexic, "value");

  if (name == NULL)
    {
      nasl_perror (lexic, "Syntax error with replace_kb_item() [null name]\n",
                   name);
      return FAKE_CELL;
    }

  if (!lexic->authenticated
      && strncmp (name, SECRET_KB_PREFIX, sizeof (SECRET_KB_PREFIX) - 1) == 0)
    {
      nasl_perror (lexic, "Only signed scripts can set a Secret/ KB entry\n");
      return FAKE_CELL;
    }

  if (type == VAR2_INT)
    {
      int value = get_int_local_var_by_name (lexic, "value", -1);
      if (value != -1)
        plug_replace_key (script_infos, name, ARG_INT,
                          GSIZE_TO_POINTER (value));
      else
        nasl_perror (lexic,
                     "Syntax error with replace_kb_item(%s) [value=-1]\n",
                     name);
    }
  else
    {
      char *value = get_str_local_var_by_name (lexic, "value");
      if (value == NULL)
        {
          nasl_perror (lexic,
                       "Syntax error with replace_kb_item(%s) [null value]\n",
                       name);
          return FAKE_CELL;
        }
      plug_replace_key (script_infos, name, ARG_STRING, value);
    }

  return FAKE_CELL;
}

tree_cell *
set_kb_item (lex_ctxt * lexic)
{
  struct arglist *script_infos = lexic->script_infos;
  char *name = get_str_local_var_by_name (lexic, "name");
  int type = get_local_var_type_by_name (lexic, "value");

  if (name == NULL)
    {
      nasl_perror (lexic, "Syntax error with set_kb_item() [null name]\n",
                   name);
      return FAKE_CELL;
    }

  if (!lexic->authenticated
      && strncmp (name, SECRET_KB_PREFIX, sizeof (SECRET_KB_PREFIX) - 1) == 0)
    {
      nasl_perror (lexic, "Only signed scripts can set a Secret/ KB entry\n");
      return FAKE_CELL;
    }


  if (type == VAR2_INT)
    {
      int value = get_int_local_var_by_name (lexic, "value", -1);
      if (value != -1)
        plug_set_key (script_infos, name, ARG_INT, GSIZE_TO_POINTER (value));
      else
        nasl_perror (lexic,
                     "Syntax error with set_kb_item() [value=-1 for name '%s']\n",
                     name);
    }
  else
    {
      char *value = get_str_local_var_by_name (lexic, "value");
      if (value == NULL)
        {
          nasl_perror (lexic,
                       "Syntax error with set_kb_item() [null value for name '%s']\n",
                       name);
          return FAKE_CELL;
        }
      plug_set_key (script_infos, name, ARG_STRING, value);
    }

  return FAKE_CELL;
}

/*------------------------[ Reporting a problem ]---------------------------*/


/**
 * Function is used when the script wants to report a problem back to openvassd.
 */
typedef void (*proto_post_something_t) (struct arglist *, int, const char *,
                                        const char *);
/**
 * Function is used when the script wants to report a problem back to openvassd.
 */
typedef void (*post_something_t) (struct arglist *, int, const char *);


static tree_cell *
security_something (lex_ctxt * lexic, proto_post_something_t proto_post_func,
                    post_something_t post_func)
{
  struct arglist *script_infos = lexic->script_infos;

  char *proto = get_str_local_var_by_name (lexic, "protocol");
  char *data = get_str_local_var_by_name (lexic, "data");
  int port = get_int_local_var_by_name (lexic, "port", -1);
  char *dup = NULL;

  if (data != NULL)
    {
      int len = get_local_var_size_by_name (lexic, "data");
      int i;

      dup = nasl_strndup (data, len);
      for (i = 0; i < len; i++)
        if (dup[i] == 0)
          dup[i] = ' ';
    }

  if ((arg_get_value (script_infos, "standalone")) != NULL)
    {
      if (data != NULL)
        fprintf (stdout, "%s\n", dup);
      else
        fprintf (stdout, "Success\n");
    }

  if (proto == NULL)
    proto = get_str_local_var_by_name (lexic, "proto");

  if (port < 0)
    port = get_int_var_by_num (lexic, 0, -1);

  if (dup != NULL)
    {
      if (proto == NULL)
        post_func (script_infos, port, dup);
      else
        proto_post_func (script_infos, port, proto, dup);

      efree (&dup);
      return FAKE_CELL;
    }

  if (proto == NULL)
    post_func (script_infos, port, NULL);
  else
    proto_post_func (script_infos, port, proto, NULL);

  return FAKE_CELL;
}

tree_cell *
security_hole (lex_ctxt * lexic)
{
  return security_something (lexic, proto_post_hole, post_hole);
}

tree_cell *
security_warning (lex_ctxt * lexic)
{
  return security_something (lexic, proto_post_info, post_info);
}

tree_cell *
security_note (lex_ctxt * lexic)
{
  return security_something (lexic, proto_post_note, post_note);
}

tree_cell *
log_message (lex_ctxt * lexic)
{
  return security_something (lexic, proto_post_log, post_log);
}

tree_cell *
debug_message (lex_ctxt * lexic)
{
  return security_something (lexic, proto_post_debug, post_debug);
}

tree_cell *
nasl_get_preference (lex_ctxt * lexic)
{
  tree_cell *retc;
  char *name, *value;
  struct arglist *script_infos, *prefs;


  script_infos = lexic->script_infos;
  prefs = arg_get_value (script_infos, "preferences");
  if (prefs == NULL)
    {
      nasl_perror (lexic, "get_preference: not preferences\n");
      return NULL;
    }
  name = get_str_var_by_num (lexic, 0);
  if (name == NULL)
    {
      nasl_perror (lexic, "get_preference: no name\n");
      return NULL;
    }
  value = arg_get_value (prefs, name);
  if (value == NULL)
    return NULL;

  retc = alloc_typed_cell (CONST_DATA);
  retc->x.str_val = strdup (value);
  retc->size = strlen (value);
  return retc;
}

/*-------------------------[ Reporting an open port ]---------------------*/

/**
 * If the plugin is a port scanner, it needs to report the list of open
 * ports back to openvas scanner, and it also needs to know which ports are
 * to be scanned.
 */
tree_cell *
nasl_scanner_get_port (lex_ctxt * lexic)
{
  tree_cell *retc;
  int idx = get_int_var_by_num (lexic, 0, -1);
  struct arglist *script_infos = lexic->script_infos;
  struct arglist *prefs = arg_get_value (script_infos, "preferences");
  char *prange = arg_get_value (prefs, "port_range");
  static int num = 0;
  static u_short *ports = NULL;

  if (prange == NULL)
    return NULL;

  if (idx < 0)
    {
      nasl_perror (lexic, "Argument error in scanner_get_port()\n");
      nasl_perror (lexic, "Correct usage is : num = scanner_get_port(<num>)\n");
      nasl_perror (lexic,
                   "Where <num> should be 0 the first time you call it\n");
      return NULL;
    }

  if (ports == NULL)
    {
      ports = (u_short *) getpts (prange, &num);
      if (ports == NULL)
        {
          return NULL;
        }
    }

  if (idx >= num)
    {
      return NULL;
    }

  retc = alloc_tree_cell (0, NULL);
  retc->type = CONST_INT;
  retc->x.i_val = ports[idx];
  return retc;
}


tree_cell *
nasl_scanner_add_port (lex_ctxt * lexic)
{
  struct arglist *script_infos = lexic->script_infos;

  int port = get_int_local_var_by_name (lexic, "port", -1);
  char *proto = get_str_local_var_by_name (lexic, "proto");

  if (port >= 0)
    {
      scanner_add_port (script_infos, port, proto ? proto : "tcp");
    }

  return FAKE_CELL;
}

tree_cell *
nasl_scanner_status (lex_ctxt * lexic)
{
  int current = get_int_local_var_by_name (lexic, "current", -1);
  int total = get_int_local_var_by_name (lexic, "total", -1);
  struct arglist *script_infos = lexic->script_infos;
  struct arglist *hostdata = arg_get_value (script_infos, "HOSTNAME");

  if (current != -1 && total != -1)
    {
      struct arglist *globs = arg_get_value (script_infos, "globals");
      if (globs == NULL)
        return NULL;
      comm_send_status (globs, arg_get_value (hostdata, "NAME"), "portscan",
                        current, total);
    }
  return FAKE_CELL;
}



/*--------------------[ SHARED SOCKETS ]---------------------------------------*/

#define SECRET_SOCKET_PREFIX "Secret/"

tree_cell *
nasl_shared_socket_register (lex_ctxt * lexic)
{
  char *name = get_str_local_var_by_name (lexic, "name");
  int soc = get_int_local_var_by_name (lexic, "socket", -1);
  struct arglist *script_infos = lexic->script_infos;

  if (name == NULL || soc < 0)
    {
      fprintf (stderr,
               "Usage: shared_socket_register(name:<name>, socket:<soc>)\n");
      return NULL;
    }

  if (strncmp (name, SECRET_SOCKET_PREFIX, strlen (SECRET_SOCKET_PREFIX)) == 0
      && check_authenticated (lexic) < 0)
    return NULL;


  shared_socket_register (script_infos, soc, name);
  return FAKE_CELL;
}

tree_cell *
nasl_shared_socket_acquire (lex_ctxt * lexic)
{
  char *name = get_str_var_by_num (lexic, 0);
  int fd;
  tree_cell *retc;
  struct arglist *script_infos = lexic->script_infos;

  if (name == NULL)
    {
      fprintf (stderr, "Usage: shared_socket_acquire(<name>)\n");
      return NULL;
    }

  if (strncmp (name, SECRET_SOCKET_PREFIX, strlen (SECRET_SOCKET_PREFIX)) == 0
      && check_authenticated (lexic) < 0)
    return NULL;

  fd = shared_socket_acquire (script_infos, name);
  if (fd < 0)
    return NULL;
  retc = alloc_tree_cell (0, NULL);
  retc->type = CONST_INT;
  retc->x.i_val = fd;
  return retc;
}

tree_cell *
nasl_shared_socket_release (lex_ctxt * lexic)
{
  char *name = get_str_var_by_num (lexic, 0);
  struct arglist *script_infos = lexic->script_infos;

  if (name == NULL)
    {
      fprintf (stderr, "Usage: shared_socket_release(<name>)\n");
      return NULL;
    }

  if (strncmp (name, SECRET_SOCKET_PREFIX, strlen (SECRET_SOCKET_PREFIX)) == 0
      && check_authenticated (lexic) < 0)
    return NULL;

  shared_socket_release (script_infos, name);
  return NULL;
}

tree_cell *
nasl_shared_socket_destroy (lex_ctxt * lexic)
{
  char *name = get_str_var_by_num (lexic, 0);
  struct arglist *script_infos = lexic->script_infos;

  if (name == NULL)
    {
      fprintf (stderr, "Usage: shared_socket_release(<name>)\n");
      return NULL;
    }

  if (strncmp (name, SECRET_SOCKET_PREFIX, strlen (SECRET_SOCKET_PREFIX)) == 0
      && check_authenticated (lexic) < 0)
    return NULL;


  shared_socket_destroy (script_infos, name);
  return NULL;
}
