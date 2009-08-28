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

#include <includes.h>
#include <stdarg.h>

#include "nasl_tree.h"
#include "nasl_global_ctxt.h"
#include "nasl_func.h"
#include "nasl_var.h"
#include "nasl_lex_ctxt.h"
#include "exec.h"


extern FILE * nasl_trace_fp;



void nasl_perror(lex_ctxt * lexic, char * msg, ...)
{
 va_list param;
 char debug_message[4096];
 char *script_name = "", *p;
 
 va_start(param, msg);

 if( lexic != NULL )
 {
  script_name = arg_get_value(lexic->script_infos, "script_name");
  if(script_name == NULL)
   script_name = "";
 }
 
 vsnprintf(debug_message, sizeof(debug_message), msg, param);
 for (p = debug_message; *p != '\0'; p ++)
   ;
 if (p == debug_message || p[-1] != '\n')
   fprintf(stderr, "[%d](%s) %s\n",getpid(), script_name, debug_message); 
 else
   fprintf(stderr, "[%d](%s) %s",getpid(), script_name, debug_message); 
 va_end(param);
}


int nasl_trace_enabled()
{
 if( nasl_trace_fp == NULL )
   return 0;
 else 
  return 1;  
}


void nasl_trace(lex_ctxt * lexic, char * msg, ...)
{
 va_list param;
 char debug_message[4096];
 char *script_name = "", *p;
  
 if(nasl_trace_fp == NULL)
	 return;
 va_start(param, msg);
 
 if( lexic != NULL )
 {
  script_name = arg_get_value(lexic->script_infos, "script_name");
  if(script_name == NULL)
   script_name = "";
 }
 
 vsnprintf(debug_message, sizeof(debug_message), msg, param);
 for (p = debug_message; *p != '\0'; p ++)
   ;
 if (p == debug_message || p[-1] != '\n')
   fprintf(nasl_trace_fp, "[%d](%s) %s\n",getpid(), script_name, debug_message); 
 else
   fprintf(nasl_trace_fp, "[%d](%s) %s",getpid(), script_name, debug_message); 
 va_end(param);
}
