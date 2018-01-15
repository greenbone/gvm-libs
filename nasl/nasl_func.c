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

#include <search.h>             /* for qsort, lfind */
#include <stdlib.h>             /* for free */
#include <string.h>             /* for strcmp */

#include <glib.h>               /* for g_free */

#include "nasl_tree.h"
#include "nasl_global_ctxt.h"
#include "nasl_func.h"
#include "nasl_var.h"
#include "nasl_lex_ctxt.h"
#include "exec.h"

#include "nasl_debug.h"

/** @TODO consider glibs string hashing function g_strhash */
static int
hash_str (const char *s)
{
  return hash_str2 (s, FUNC_NAME_HASH);
}

/**
 * @brief This function climbs up in the context list and searches for a given
 * @brief function.
 */
static nasl_func *
get_func (lex_ctxt * ctxt, const char *name, int h)
{
  nasl_func *v;
  lex_ctxt *c;

  for (c = ctxt; c != NULL; c = c->up_ctxt)
    {
      for (v = c->functions[h]; v != NULL; v = v->next_func)
        if (v->func_name != NULL && strcmp (name, v->func_name) == 0)
          return v;
    }

  return NULL;
}

typedef int(*qsortcmp)(const void *, const void *);

nasl_func *
insert_nasl_func (lex_ctxt * lexic, const char *fname, tree_cell * decl_node)
{
  int h = hash_str (fname);
  int i;
  nasl_func *pf;
  tree_cell *pc;

  if (get_func (lexic, fname, h) != NULL)
    {
      nasl_perror (lexic,
                   "insert_nasl_func: function '%s' is already defined\n",
                   fname);
      return NULL;
    }
  pf = g_malloc0 (sizeof (nasl_func));
  pf->func_name = g_strdup (fname);

  if (decl_node != NULL && decl_node != FAKE_CELL)
    {
      for (pc = decl_node->link[0]; pc != NULL; pc = pc->link[0])
        if (pc->x.str_val == NULL)
          pf->nb_unnamed_args++;
        else
          pf->nb_named_args++;

      pf->args_names = g_malloc0 (sizeof (char *) * pf->nb_named_args);
      for (i = 0, pc = decl_node->link[0]; pc != NULL; pc = pc->link[0])
        if (pc->x.str_val != NULL)
          pf->args_names[i++] = g_strdup (pc->x.str_val);
      /* Sort argument names */
      qsort (pf->args_names, pf->nb_named_args, sizeof (pf->args_names[0]),
             (qsortcmp)strcmp);

      pf->block = decl_node->link[1];
      ref_cell (pf->block);
    }
  /* Allow variable number of arguments for user defined functions */
  if (decl_node != NULL)
    pf->nb_unnamed_args = 9999;

  pf->next_func = lexic->functions[h];
  lexic->functions[h] = pf;
  return pf;
}

tree_cell *
decl_nasl_func (lex_ctxt * lexic, tree_cell * decl_node)
{
  if (decl_node == NULL || decl_node == FAKE_CELL)
    {
      nasl_perror (lexic, "Cannot insert NULL or FAKE cell as function\n");
      return NULL;
    }

  if (insert_nasl_func (lexic, decl_node->x.str_val, decl_node) == NULL)
    return NULL;
  else
    return FAKE_CELL;
}

nasl_func *
get_func_ref_by_name (lex_ctxt * ctxt, const char *name)
{
  int h = hash_str (name);
  nasl_func *f;

  if ((f = get_func (ctxt, name, h)) != NULL)
    return f;
  else
    return NULL;
}

static int
stringcompare (const void *a, const void *b)
{
  char **s1 = (char **) a, **s2 = (char **) b;
  return strcmp (*s1, *s2);
}

extern FILE *nasl_trace_fp;

tree_cell *
nasl_func_call (lex_ctxt * lexic, const nasl_func * f, tree_cell * arg_list)
{
#if 0
  return FAKE_CELL;
#else
  int nb_u = 0, nb_n = 0, nb_a = 0;
  tree_cell *pc = NULL, *pc2 = NULL, *retc = NULL;
  lex_ctxt *lexic2 = NULL;
  char *trace_buf = NULL;
  char *temp_funname = NULL, *tmp_filename = NULL;
  int trace_buf_len = 0, tn;
#define TRACE_BUF_SZ	255

#if 0
  nasl_dump_tree (arg_list);
#endif

  /* 1. Create a new context */
  lexic2 = init_empty_lex_ctxt ();
  lexic2->script_infos = lexic->script_infos;
  lexic2->oid = lexic->oid;
  lexic2->recv_timeout = lexic->recv_timeout;
  lexic2->fct_ctxt = 1;

  if (nasl_trace_fp != NULL)
    {
      trace_buf = g_malloc0 (TRACE_BUF_SZ);
      tn = snprintf (trace_buf, TRACE_BUF_SZ, "Call %s(", f->func_name);
      if (tn > 0)
        trace_buf_len += tn;
    }

  if (!(f->flags & FUNC_FLAG_COMPAT))
    {
      for (pc = arg_list; pc != NULL; pc = pc->link[1])
        if (pc->x.str_val == NULL)
          nb_u++;
        else
          {
            size_t num = f->nb_named_args;
            if (lfind
                (&pc->x.str_val, f->args_names, &num, sizeof (char *),
                 stringcompare) != NULL)
              nb_n++;
          }

      if (nb_n + nb_u > f->nb_unnamed_args + f->nb_named_args)
        nasl_perror (lexic,
                     "Too many args for function '%s' [%dN+%dU > %dN+%dU]\n",
                     f->func_name, nb_n, nb_u, f->nb_unnamed_args,
                     f->nb_named_args);
      /*
       * I should look exactly how unnamed arguments works...
       * Or maybe I should remove this feature?
       */

      for (nb_u = 0, pc = arg_list; pc != NULL; pc = pc->link[1])
        {
#if 0
          pc2 = pc->link[0];
          ref_cell (pc2);
          do
            {
              pc22 = nasl_exec (lexic, pc2);
              deref_cell (pc2);
              pc2 = pc22;
            }
          while (!nasl_is_leaf (pc2));
#else
          pc2 = cell2atom (lexic, pc->link[0]);
#endif
          if (pc->x.str_val == NULL)
            {
              /* 2. Add unnamed (numbered) variables for unnamed args */
              if (add_numbered_var_to_ctxt (lexic2, nb_u, pc2) == NULL)
                goto error;
              nb_u++;
              if (nasl_trace_fp != NULL && trace_buf_len < TRACE_BUF_SZ)
                {
                  tn = snprintf (trace_buf + trace_buf_len,
                                 TRACE_BUF_SZ - trace_buf_len, "%s%d: %s",
                                 nb_a > 0 ? ", " : "", nb_u,
                                 dump_cell_val (pc2));
                  if (tn > 0)
                    trace_buf_len += tn;
                }
              nb_a++;
            }
          else
            {
              /* 3. and add named variables for named args */
              if (add_named_var_to_ctxt (lexic2, pc->x.str_val, pc2) == NULL)
                goto error;
              if (nasl_trace_fp != NULL && trace_buf_len < TRACE_BUF_SZ)
                {
                  tn = snprintf (trace_buf + trace_buf_len,
                                 TRACE_BUF_SZ - trace_buf_len, "%s%s: %s",
                                 nb_a > 0 ? ", " : "", pc->x.str_val,
                                 dump_cell_val (pc2));
                  if (tn > 0)
                    trace_buf_len += tn;
                }
              nb_a++;
            }
          deref_cell (pc2);
        }

      if (nasl_trace_fp != NULL)
        {
          if (trace_buf_len < TRACE_BUF_SZ)
            nasl_trace (lexic, "NASL> %s)\n", trace_buf);
          else
            nasl_trace (lexic, "NASL> %s ...)\n", trace_buf);
          g_free (trace_buf);
        }

      /* 4. Chain new context to old (lexic) */
      lexic2->up_ctxt = lexic;
      /* 5. Execute */
      tmp_filename = g_strdup (nasl_get_filename (NULL));
      nasl_set_filename (nasl_get_filename (f->func_name));
      if (f->flags & FUNC_FLAG_INTERNAL)
        {
          tree_cell *(*pf2) (lex_ctxt *) = f->block;
          retc = pf2 (lexic2);
        }
      else
        {
          temp_funname = g_strdup (nasl_get_function_name());
          nasl_set_function_name (f->func_name);
          retc = nasl_exec (lexic2, f->block);
          deref_cell (retc);
          retc = FAKE_CELL;
          nasl_set_function_name (temp_funname);
          g_free (temp_funname);
        }

      nasl_set_filename (tmp_filename);
      g_free (tmp_filename);
      if ((retc == NULL || retc == FAKE_CELL)
          && (lexic2->ret_val != NULL && lexic2->ret_val != FAKE_CELL))
        {
#if 0
          nasl_perror (lexic,
                       "nasl_func_call: nasl_exec(%s) returns NULL or FAKE value, but context disagrees. Fixing...\n",
                       f->func_name);
          nasl_dump_tree (retc);
#endif
          retc = lexic2->ret_val;
          ref_cell (retc);
        }

      if (nasl_trace_enabled ())
        nasl_trace (lexic, "NASL> Return %s: %s\n", f->func_name,
                    dump_cell_val (retc));
#if 1
      if (!nasl_is_leaf (retc))
        {
          nasl_perror (lexic,
                       "nasl_func_call: return value from %s is not atomic!\n",
                       f->func_name);
          nasl_dump_tree (retc);
        }
#endif

      free_lex_ctxt (lexic2);
      lexic2 = NULL;
      return retc;
    }


error:
  free_lex_ctxt (lexic2);
  return NULL;
#endif
}

tree_cell *
nasl_return (lex_ctxt * ctxt, tree_cell * retv)
{
  tree_cell *c;

  retv = cell2atom (ctxt, retv);
  if (retv == NULL)
    retv = FAKE_CELL;

  if (retv != FAKE_CELL && retv->type == REF_ARRAY)
    /* We have to "copy" it as the referenced array will be freed */
    {
      c = copy_ref_array (retv);
      deref_cell (retv);
      retv = c;
    }

  while (ctxt != NULL)
    {
      ctxt->ret_val = retv;
      ref_cell (retv);
      if (ctxt->fct_ctxt)
        break;
      ctxt = ctxt->up_ctxt;
    }
  /* Bug? Do not return NULL, as we may test it to break the control flow */
  deref_cell (retv);
  return FAKE_CELL;
}

static void
free_func (nasl_func * f)
{
  int i;

  if (! f) return;

  g_free (f->func_name);

  if (!(f->flags & FUNC_FLAG_INTERNAL))
    {
      for (i = 0; i < f->nb_named_args; i++)
        g_free (f->args_names[i]);
      g_free (f->args_names);
      deref_cell (f->block);
    }
  g_free (f);
}


void
free_func_chain (nasl_func * f)
{
  if (f == NULL)
    return;
  free_func_chain (f->next_func);
  free_func (f);
}
