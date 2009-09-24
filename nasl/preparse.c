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

#include "nasl_tree.h"
#include "nasl_global_ctxt.h"
#include "nasl_func.h"
#include "nasl_var.h"
#include "nasl_lex_ctxt.h"
#include "exec.h"
#include "nasl_regex.h"
#include "nasl_debug.h"

extern int naslparse (naslctxt *);

/**
 * @brief Parse a .nasl file anew.
 * 
 * Older comments suggest that this function was thought to load preparses if
 * the existed.
 * 
 * @return 0 on success, -1 on error.
 */
int
nasl_reload_or_parse (naslctxt* ctx, const char* name)
{
  if (init_nasl_ctx(ctx, name) < 0)
    return -1;

  if (naslparse(ctx))
    {
      fprintf(stderr, "\nParse error at or near line %d\n", ctx->line_nb);
      nasl_clean_ctx(ctx);
      return -1;
    }

  return 0;
}
