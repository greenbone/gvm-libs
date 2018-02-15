%pure-parser
%parse-param {naslctxt * parm}
%lex-param {naslctxt * parm}
%expect 1
%{
/* Nessus Attack Scripting Language version 2
 *
 * Copyright (C) 2002 - 2004 Michel Arboi and Renaud Deraison
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
 */

#define YYPARSE_PARAM parm
#define YYLEX_PARAM parm

#define LNB	(((naslctxt*)parm)->line_nb)

#include <ctype.h> /* for isalpha */
#include <pcap.h> /* for islocalhost */
#include <string.h> /* for strlen */
#include <sys/stat.h> /* for stat */

#include "nasl_tree.h"
#include "nasl_global_ctxt.h"
#include "nasl_func.h"
#include "nasl_var.h"
#include "nasl_lex_ctxt.h"
#include "nasl_debug.h"
#include "nasl_signature.h"

static void naslerror(naslctxt *, const char *);
#define YYERROR_VERBOSE
%}

%union {
  long int       num;
  char		*str;
  struct asciiz {
    char	*val;
    int		len;
  } data;
  tree_cell	*node;
}

%{
static int nasllex(YYSTYPE * lvalp, void * parm);
%}

%token IF
%token ELSE
%token EQ
%token NEQ
%token SUPEQ
%token INFEQ
%token OR
%token AND
%token MATCH
%token NOMATCH
%token REP
%token FOR
%token REPEAT
%token UNTIL
%token FOREACH
%token WHILE
%token BREAK
%token CONTINUE
%token FUNCTION
%token RETURN
%token INCLUDE
%token LOCAL
%token GLOBAL
%token PLUS_PLUS
%token MINUS_MINUS
%token L_SHIFT
%token R_SHIFT
%token R_USHIFT
%token EXPO

%token PLUS_EQ
%token MINUS_EQ
%token MULT_EQ
%token DIV_EQ
%token MODULO_EQ
%token L_SHIFT_EQ
%token R_SHIFT_EQ
%token R_USHIFT_EQ
%token RE_MATCH
%token RE_NOMATCH
%token ARROW

%token <str> IDENT
%token <data> STRING1
%token <str> STRING2

%token <num> INTEGER

%type <node> arg_list_1 arg_list arg
%type <node> arg_decl_1 arg_decl
%type <node> func_call func_decl
%type <node> instr instr_list instr_decl instr_decl_list simple_instr
%type <node> if_block block loop for_loop while_loop foreach_loop repeat_loop
%type <node> aff rep ret expr aff_func array_index array_elem lvalue var
%type <node> ipaddr post_pre_incr
%type <node> inc loc glob
%type <node> atom const_array list_array_data array_data simple_array_data

%type <str>  identifier string var_name

/* Priority of all operators */
%right '=' PLUS_EQ MINUS_EQ MULT_EQ DIV_EQ MODULO_EQ L_SHIFT_EQ R_SHIFT_EQ R_USHIFT_EQ
%left OR
%left AND
%nonassoc '<' '>' EQ NEQ SUPEQ INFEQ MATCH NOMATCH RE_MATCH RE_NOMATCH
%left '|'
%left '^'
%left '&'
%nonassoc R_SHIFT R_USHIFT L_SHIFT
%left '+' '-'
%left '*' '/' '%'
%nonassoc NOT
%nonassoc UMINUS BIT_NOT
%right EXPO
%nonassoc PLUS_PLUS MINUS_MINUS
%nonassoc ARROW

%start	tiptop

%%

tiptop: instr_decl_list
	{
	  ((naslctxt*)parm)->tree = $1;
	} ;

instr_decl_list: instr_decl
	{
	  $$ = alloc_tree_cell(LNB, NULL);
	  $$->type = NODE_INSTR_L;
	  $$->link[0] = $1;
	}
	| instr_decl instr_decl_list
	{
	  $$ = alloc_tree_cell(LNB, NULL);
	  $$->type = NODE_INSTR_L;
	  $$->link[0] = $1;
	  $$->link[1] = $2;
	};
instr_decl: instr | func_decl;

/* Function declaration */
func_decl: FUNCTION identifier '(' arg_decl ')' block
	{
          nasl_set_function_filename ($2);
	  $$ = alloc_tree_cell(LNB, $2);
	  $$->type = NODE_FUN_DEF;
	  $$->link[0] = $4;
	  $$->link[1] = $6;
	};

arg_decl: { $$ = NULL; } | arg_decl_1 { $$ = $1; };
arg_decl_1: identifier { $$ = alloc_tree_cell(LNB, $1); $$->type = NODE_DECL; }
	| identifier ',' arg_decl_1
	{
	  $$ = alloc_tree_cell(LNB, $1);
	  $$->type = NODE_DECL;
	  $$->link[0] = $3;
	};

/* Block */
block: '{' instr_list '}' { $$ = $2; } | '{' '}' { $$ = NULL; };
instr_list: instr
	| instr instr_list
	{
	  if ($1 == NULL)
	    $$ = $2;
	  else
	    {
	      $$ = alloc_tree_cell(LNB, NULL);
	      $$->type = NODE_INSTR_L;
	      $$->link[0] = $1;
	      $$->link[1] = $2;
	    }
	} ;

/* Instructions */
instr: simple_instr ';' { $$ = $1; } | block | if_block | loop ;

/* "simple" instruction */
simple_instr : aff | post_pre_incr | rep
	| func_call | ret | inc | loc | glob
	| BREAK {
	  $$ = alloc_tree_cell(LNB, NULL);
	  $$->type =  NODE_BREAK;
	}
	| CONTINUE {
	  $$ = alloc_tree_cell(LNB, NULL);
	  $$->type =  NODE_CONTINUE;
	}
	| /* nop */ { $$ = NULL; };

/* return */
ret: RETURN expr
	{
	  $$ = alloc_tree_cell(LNB, NULL);
	  $$->type =  NODE_RETURN;
	  $$->link[0] = $2;
	} |
	RETURN
	{
	  $$ = alloc_tree_cell(LNB, NULL);
	  $$->type =  NODE_RETURN;
	} ;

/* If block */
if_block: IF '(' expr ')' instr
	{
	  $$ = alloc_tree_cell(LNB, NULL);
	  $$->type = NODE_IF_ELSE;
	  $$->link[0] = $3; $$->link[1] = $5;
	}
	| IF '(' expr ')' instr ELSE instr
	{
	  $$ = alloc_tree_cell(LNB, NULL);
	  $$->type = NODE_IF_ELSE;
	  $$->link[0] = $3; $$->link[1] = $5; $$->link[2] = $7;
	};

/* Loops */
loop : for_loop | while_loop | repeat_loop | foreach_loop ;
for_loop : FOR '(' aff_func ';' expr ';' aff_func ')' instr
	{
	  $$ = alloc_tree_cell(LNB, NULL);
	  $$->type = NODE_FOR;
	  $$->link[0] = $3;
	  $$->link[1] = $5;
	  $$->link[2] = $7;
	  $$->link[3] = $9;
	} ;

while_loop : WHILE '(' expr ')' instr
	{
	  $$ = alloc_tree_cell(LNB, NULL);
	  $$->type = NODE_WHILE;
	  $$->link[0] = $3;
	  $$->link[1] = $5;
	} ;
repeat_loop : REPEAT instr UNTIL expr ';'
	{
	  $$ = alloc_tree_cell(LNB, NULL);
	  $$->type = NODE_REPEAT_UNTIL;
	  $$->link[0] = $2;
	  $$->link[1] = $4;
	} ;

foreach_loop : FOREACH identifier '(' expr ')'  instr
	{
	  $$ = alloc_tree_cell(LNB, $2);
	  $$->type = NODE_FOREACH;
	  $$->link[0] = $4;
	  $$->link[1] = $6;
	} ;

/* affectation or function call */
aff_func: aff | post_pre_incr | func_call | /*nop */ { $$ = NULL; };

/* repetition */
rep: func_call REP expr
	{
	  $$ = alloc_tree_cell(LNB, NULL);
	  $$->type = NODE_REPEATED;
	  $$->link[0] = $1;
	  $$->link[1] = $3;
	} ;

string : STRING1 { $$ = $1.val; } | STRING2 ;

/* include */
inc: INCLUDE '(' string ')'
	{
          char *tmp;
	  naslctxt	subctx;
	  int		x;

          subctx.always_authenticated = ((naslctxt*)parm)->always_authenticated;
          subctx.kb = ((naslctxt *) parm)->kb;
          x = init_nasl_ctx(&subctx, $3);
          $$ = NULL;
          tmp = g_strdup (nasl_get_filename (NULL));
          nasl_set_filename ($3);
          if (x >= 0)
            {
              if (! naslparse(&subctx))
                {
                  $$ = subctx.tree;
                }
              else
                nasl_perror(NULL, "%s: Parse error at or near line %d\n",
                        $3, subctx.line_nb);
	      g_free(subctx.buffer);
	      subctx.buffer = NULL;
	      fclose(subctx.fp);
	      subctx.fp = NULL;
	      g_free($3);
	    }
          else
            {
              g_free($3);
              g_free (tmp);
              return -2;
            }
          nasl_set_filename (tmp);
          g_free (tmp);
	} ;

/* Function call */
func_call: identifier '(' arg_list ')'
	{
	  $$ = alloc_tree_cell(LNB, $1);
	  $$->type = NODE_FUN_CALL;
	  $$->link[0] = $3;
	};

arg_list : arg_list_1 | { $$ = NULL; };
arg_list_1: arg | arg ',' arg_list_1
	{
	  $1->link[1] = $3;
	  $$ = $1;
	} ;

arg : expr
	{
	  $$ = alloc_tree_cell(LNB, NULL);
	  $$->type = NODE_ARG;
	  $$->link[0] = $1;
	}
	| identifier ':' expr
	{
	  $$ = alloc_tree_cell(LNB, $1);
	  $$->type = NODE_ARG;
	  $$->link[0] = $3;
	} ;

/* Affectation */
aff:	lvalue '=' expr
	{
	  $$ = alloc_expr_cell(LNB, NODE_AFF, $1, $3);
	}
	| lvalue PLUS_EQ expr { $$ = alloc_expr_cell(LNB, NODE_PLUS_EQ, $1, $3); }
	| lvalue MINUS_EQ expr  { $$ = alloc_expr_cell(LNB, NODE_MINUS_EQ, $1, $3); }
	| lvalue MULT_EQ expr { $$ = alloc_expr_cell(LNB, NODE_MULT_EQ, $1, $3); }
	| lvalue DIV_EQ expr  { $$ = alloc_expr_cell(LNB, NODE_DIV_EQ, $1, $3); }
	| lvalue MODULO_EQ expr  { $$ = alloc_expr_cell(LNB, NODE_MODULO_EQ, $1, $3); }
	| lvalue R_SHIFT_EQ expr { $$ = alloc_expr_cell(LNB, NODE_R_SHIFT_EQ, $1, $3); }
	| lvalue R_USHIFT_EQ expr { $$ = alloc_expr_cell(LNB, NODE_R_USHIFT_EQ, $1, $3); }
	| lvalue L_SHIFT_EQ expr { $$ = alloc_expr_cell(LNB, NODE_L_SHIFT_EQ, $1, $3); }
	;

lvalue:	identifier { $$ = alloc_tree_cell(LNB, $1); $$->type = NODE_VAR; } | array_elem ;

identifier:	IDENT | REP { $$ = strdup("x"); } ; /* => For "x" */

array_elem: identifier '[' array_index ']'
	{
	  $$ = alloc_tree_cell(LNB, $1);
	  $$->type = NODE_ARRAY_EL;
	  $$->link[0] = $3;
	} ;

array_index: expr ;

post_pre_incr:
   PLUS_PLUS lvalue { $$ = alloc_expr_cell(LNB, EXPR_INCR, NULL, $2); }
 | MINUS_MINUS lvalue {$$ = alloc_expr_cell(LNB, EXPR_DECR, NULL, $2); }
 | lvalue PLUS_PLUS { $$= alloc_expr_cell(LNB, EXPR_INCR, $1, NULL); }
 | lvalue MINUS_MINUS { $$= alloc_expr_cell(LNB, EXPR_DECR, $1, NULL); }
;

/* expression. We accepte affectations inside parenthesis */
expr: '(' expr ')' { $$ = $2; }
	| expr AND expr {  $$ = alloc_expr_cell(LNB, EXPR_AND, $1, $3); }
	| '!' expr %prec NOT {  $$ = alloc_expr_cell(LNB, EXPR_NOT, $2, NULL); }
	| expr OR expr { $$ = alloc_expr_cell(LNB, EXPR_OR, $1, $3); }
	| expr '+' expr { $$ = alloc_expr_cell(LNB, EXPR_PLUS, $1, $3); }
	| expr '-' expr { $$ = alloc_expr_cell(LNB, EXPR_MINUS, $1, $3); }
	| '-' expr %prec UMINUS { $$ = alloc_expr_cell(LNB, EXPR_U_MINUS, $2, NULL);}
	| '~' expr %prec BIT_NOT { $$ = alloc_expr_cell(LNB, EXPR_BIT_NOT, $2, NULL);}
	| expr '*' expr { $$ = alloc_expr_cell(LNB, EXPR_MULT, $1, $3); }
	| expr EXPO expr { $$ = alloc_expr_cell(LNB, EXPR_EXPO, $1, $3); }
	| expr '/' expr { $$ = alloc_expr_cell(LNB, EXPR_DIV, $1, $3); }
	| expr '%' expr { $$ = alloc_expr_cell(LNB, EXPR_MODULO, $1, $3); }
	| expr '&' expr { $$ = alloc_expr_cell(LNB, EXPR_BIT_AND, $1, $3); }
	| expr '^' expr { $$ = alloc_expr_cell(LNB, EXPR_BIT_XOR, $1, $3); }
	| expr '|' expr { $$ = alloc_expr_cell(LNB, EXPR_BIT_OR, $1, $3); }
	| expr R_SHIFT expr { $$ = alloc_expr_cell(LNB, EXPR_R_SHIFT, $1, $3); }
	| expr R_USHIFT expr { $$ = alloc_expr_cell(LNB, EXPR_R_USHIFT, $1, $3); }
	| expr L_SHIFT expr { $$ = alloc_expr_cell(LNB, EXPR_L_SHIFT, $1, $3); }
	| post_pre_incr
	| expr MATCH expr { $$ = alloc_expr_cell(LNB, COMP_MATCH, $1, $3); }
	| expr NOMATCH expr { $$ = alloc_expr_cell(LNB, COMP_NOMATCH, $1, $3); }
	| expr RE_MATCH string { $$ = alloc_RE_cell(LNB, COMP_RE_MATCH, $1, $3); }
	| expr RE_NOMATCH string { $$ = alloc_RE_cell(LNB, COMP_RE_NOMATCH, $1, $3); }
	| expr '<' expr { $$ = alloc_expr_cell(LNB, COMP_LT, $1, $3); }
	| expr '>' expr { $$ = alloc_expr_cell(LNB, COMP_GT, $1, $3); }
	| expr EQ expr  { $$ = alloc_expr_cell(LNB, COMP_EQ, $1, $3); }
	| expr NEQ expr { $$ = alloc_expr_cell(LNB, COMP_NE, $1, $3); }
	| expr SUPEQ expr { $$ = alloc_expr_cell(LNB, COMP_GE, $1, $3); }
	| expr INFEQ expr { $$ = alloc_expr_cell(LNB, COMP_LE, $1, $3); }
	| var | aff | ipaddr | atom | const_array ;


const_array:	'[' list_array_data ']' { $$ = make_array_from_elems($2); } ;

list_array_data: array_data { $$ = $1; }
	| array_data ',' list_array_data {
		$1->link[1] = $3; $$ = $1;
	};

array_data: simple_array_data {
	  $$ = alloc_typed_cell(ARRAY_ELEM);
	  $$->link[0] = $1;
	} | string ARROW simple_array_data {
	  $$ = alloc_typed_cell(ARRAY_ELEM);
	  $$->link[0] = $3;
	  $$->x.str_val = $1;
	} ;

atom:	INTEGER {  $$ = alloc_typed_cell(CONST_INT); $$->x.i_val = $1; }
	| STRING2 {
	  $$ = alloc_typed_cell(CONST_STR); $$->x.str_val = $1;
	  $$->size = strlen($1);
	}
	| STRING1 {
	  $$ = alloc_typed_cell(CONST_DATA); $$->x.str_val = $1.val;
	  $$->size = $1.len;
	} ;

simple_array_data: atom;

var:	var_name { $$ = alloc_tree_cell(LNB, $1); $$->type = NODE_VAR; }
	| array_elem | func_call;

var_name: identifier;

ipaddr: INTEGER '.' INTEGER '.' INTEGER '.' INTEGER
	{
	  char *s = g_strdup_printf ("%ld.%ld.%ld.%ld", $1, $3, $5, $7);
	  $$ = alloc_tree_cell(LNB, s);
	  $$->type = CONST_STR;
	  $$->size = strlen(s);
	};

/* Local variable declaration */
loc: LOCAL arg_decl
	{
	  $$ = alloc_tree_cell(LNB, NULL);
	  $$->type = NODE_LOCAL;
	  $$->link[0] = $2;
	};

/* Global variable declaration */
glob: GLOBAL arg_decl
	{
	  $$ = alloc_tree_cell(LNB, NULL);
	  $$->type = NODE_GLOBAL;
	  $$->link[0] = $2;
	};

%%

#include <stdio.h>
#include <stdlib.h>
#include "../misc/openvas_logging.h"
#include "../misc/prefs.h"
#include "../base/openvas_file.h"
#include <libgen.h>
#include <gcrypt.h>

static void
naslerror(naslctxt *parm, const char *s)
{
  fputs(s, stderr);
}

static GSList * inc_dirs = NULL;

/**
 * @brief Adds the given string as directory for searching for includes.
 *
 * @param dir  A directory path. This function will add a copy of this parameter
 *             to the list of include folders. This means the parameter can be
 *             freed elsewhere without affecting the list.
 *
 * @return  0 in case of success.
 *         -1 if the stat on the given directory path was unsuccessful.
 *         -2 if the given directory path was not a directory.
 */
int
add_nasl_inc_dir (const char * dir)
{
  if (dir == NULL)
    {
      return 0;
    }

  // Allow initialization with empty element
  if (*dir == '\0')
    {
      inc_dirs = g_slist_append (inc_dirs, g_strdup((gchar *)dir));
      return 0;
    }

  struct stat stat_buf;

  if (stat (dir, &stat_buf) != 0)
    return -1;

  if (S_ISDIR(stat_buf.st_mode) != 0)
    {
      inc_dirs = g_slist_append (inc_dirs, g_strdup((gchar *)dir));
      return 0;
    }
  else
    return -2;
}

/**
 * @brief Get the checksum of a file.
 *
 * @param[in]  filename     Path to file.
 * @param[in]  algorithm    1 for md5, 2 for sha256.
 *
 * @return checksum string, NULL otherwise.
 */
static char *
file_checksum (const char *filename, int algorithm)
{
  char *content = NULL, digest[128], *result;
  size_t len = 0, i, alglen;

  assert (algorithm == GCRY_MD_MD5 || algorithm == GCRY_MD_SHA256);
  if (!filename || !g_file_get_contents (filename, &content, &len, NULL))
    return NULL;

  gcry_md_hash_buffer (algorithm, digest, content, len);
  alglen = gcry_md_get_algo_dlen (algorithm);
  result = g_malloc0 (alglen * 2 + 1);
  for (i = 0; i < alglen; i++)
    snprintf (result + 2 * i, 3, "%02x", (unsigned char) digest[i]);
  g_free (content);

  return result;
}

static int checksum_algorithm = GCRY_MD_NONE;

static char checksum_file[2048];

static void
init_checksum_algorithm (void)
{
  const char *base = prefs_get ("plugins_folder");

  checksum_algorithm = GCRY_MD_SHA256;
  snprintf (checksum_file, sizeof (checksum_file), "%s/sha256sums", base);
  if (g_file_test (checksum_file, G_FILE_TEST_EXISTS))
    return;
  checksum_algorithm = GCRY_MD_MD5;
  snprintf (checksum_file, sizeof (checksum_file), "%s/md5sums", base);
  if (g_file_test (checksum_file, G_FILE_TEST_EXISTS))
    return;
  if (checksum_algorithm == GCRY_MD_NONE)
    {
      log_legacy_write ("No plugins checksums file");
      return;
    }
}

static void
load_checksums (kb_t kb)
{
  static int loaded = 0;
  const char *base, *prefix;
  FILE *file;

  if (loaded)
    return;
  loaded = 1;
  /* Verify checksum */
  base = prefs_get ("plugins_folder");
  if (nasl_verify_signature (checksum_file) != 0)
    {
      log_legacy_write ("Erroneous or missing signature for checksums file %s",
                        checksum_file);
      return;
    }

  /* Insert content into KB */
  file = fopen (checksum_file, "r");
  if (!file)
    {
      log_legacy_write ("%s: Couldn't read file %s", __FUNCTION__,
                        checksum_file);
      return;
    }
  if (checksum_algorithm == GCRY_MD_MD5)
    {
      kb_del_items (kb, "md5sums:*");
      prefix = "md5sums";
    }
  else
    {
      kb_del_items (kb, "sha256sums:*");
      prefix = "sha256sums";
    }
  while (1)
    {
      char buffer[2048], **splits;
      if (!fgets (buffer, sizeof (buffer), file))
        break;
      if (strstr (buffer, ".asc")
          || (!strstr (buffer, ".inc") && !strstr (buffer, ".nasl")))
        continue;
      splits = g_strsplit (buffer, "  ", -1);
      if (g_strv_length (splits) != 2)
        {
          log_legacy_write ("%s: Erroneous checksum entry %s", __FUNCTION__,
                            buffer);
          g_strfreev (splits);
          break;
        }
      splits[1][strlen (splits[1]) - 1] = '\0';
      if (strstr (splits[1], ".inc"))
        g_snprintf (buffer, sizeof (buffer), "%s:%s", prefix,
                    basename (splits[1]));
      else
        g_snprintf (buffer, sizeof (buffer), "%s:%s/%s", prefix, base,
                    splits[1]);
      kb_item_add_str (kb, buffer, splits[0]);
      g_strfreev (splits);
    }
  fclose (file);
}

/**
 * @brief Initialize a NASL context for a NASL file.
 *
 * @param pc   The NASL context handler.
 *
 * @param name The filename of the NASL script.
 *
 * @return    0  in case of success. Then, pc->fp is set with
 *               the respective file descriptor
 *            -1 if either the filename was not found/accessible
 *               or the signature verification failed (provided
 *               signature checking is enabled.
 *               Also, the pc->fp is set to NULL.
 *            In any case, various elements of pc are modified
 *            (initialized);
 */
int
init_nasl_ctx(naslctxt* pc, const char* name)
{
  char *full_name = NULL, key_path[2048], *checksum, *filename;
  GSList * inc_dir = inc_dirs; // iterator for include directories

  // initialize if not yet done (for openvas-server < 2.0.1)
  if (! inc_dirs) add_nasl_inc_dir("");

  pc->line_nb = 1;
  pc->tree = NULL;
  pc->buffer = g_malloc0 (80);
  pc->maxlen = 80;
  pc->fp = NULL;
  nasl_set_filename (name);
  while (inc_dir != NULL) {
    if (full_name)
      g_free (full_name);
    full_name = g_build_filename(inc_dir->data, name, NULL);

    if ((pc->fp = fopen(full_name, "r")) != NULL)
      break;

    inc_dir = g_slist_next(inc_dir);
  }

  if (! pc->fp) {
    log_legacy_write ("%s: Not able to open nor to locate it in include paths",
                      name);
    g_free(full_name);
    return -1;
  }

  if (pc->always_authenticated)
    {
      g_free(full_name);
      return 0;
    }
  /* Cache the checksum of signature verified files, so that commonly included
   * files are not verified multiple times per scan. */

  filename = full_name;
  if (strstr (full_name, ".inc"))
    filename = basename (full_name);
  init_checksum_algorithm ();
  if (checksum_algorithm == GCRY_MD_NONE)
    return -1;
  else if (checksum_algorithm == GCRY_MD_MD5)
    snprintf (key_path, sizeof (key_path), "md5sums:%s", filename);
  else if (checksum_algorithm == GCRY_MD_SHA256)
    snprintf (key_path, sizeof (key_path), "sha256sums:%s", filename);
  else
    abort ();
  checksum = kb_item_get_str (pc->kb, key_path);
  if (!checksum)
    load_checksums (pc->kb);
  checksum = kb_item_get_str (pc->kb, key_path);
  if (!checksum)
    {
      log_legacy_write ("No checksum for %s", full_name);
      g_free (full_name);
      return -1;
    }
  else
    {
      int ret;
      char *check = file_checksum (full_name, checksum_algorithm);
      ret = strcmp (check, checksum);
      if (ret)
        log_legacy_write ("checksum for %s not matching", full_name);
      g_free (full_name);
      g_free (checksum);
      g_free (check);
      return ret;
    }
}

void
nasl_clean_ctx(naslctxt* c)
{
#if 0
  nasl_dump_tree(c->tree);
#endif
  deref_cell(c->tree);
  g_free(c->buffer);
  c->buffer = NULL;
  if (c->fp)
    {
      fclose(c->fp);
      c->fp = NULL;
    }
}

enum lex_state {
  ST_START = 0,
  ST_SPACE,
  ST_IDENT,
  ST_ZERO,
  ST_ZEROX,
  ST_OCT,
  ST_DEC,
  ST_HEX,
  ST_COMMENT,
  ST_SUP,
  ST_INF,
  ST_SUP_EXCL,
  ST_STRING1,
  ST_STRING1_ESC,
  ST_STRING2,
  ST_PLUS,
  ST_MINUS,
  ST_MULT,
  ST_DIV,
  ST_MODULO,
  ST_R_SHIFT,
  ST_R_USHIFT,
  ST_L_SHIFT,
  ST_NOT,
  ST_EQ,
  ST_AND,
  ST_OR };

static int
mylex(lvalp, parm)
     YYSTYPE *lvalp;
     void	*parm;
{
  char		*p;
  naslctxt	*ctx = parm;
  FILE		*fp;
  int		c, st = ST_START, len, r;
  long int      x, i;

  if (!ctx)
    return -1;

  fp = ctx->fp;
  p = ctx->buffer;
  len = 0;

  while ((c = getc(fp)) != EOF)
    {
      if (c ==  '\n')
	ctx->line_nb ++;

      switch(st)
	{
	case ST_START:
	  if (c == '#')
	    st = ST_COMMENT;
	  else if (isalpha(c) || c == '_')
	    {
	      st = ST_IDENT;
	      *p++ = c;
	      len ++;
	    }
	  else if (isspace(c))
	    st = ST_SPACE;
	  else if (c == '0')
	    st = ST_ZERO;
	  else if (isdigit(c))
	    {
	      st = ST_DEC;
	      *p++ = c;
	      len ++;
	    }
	  else if (c == '\'')
	    st = ST_STRING1;
	  else if (c == '"')
	    st = ST_STRING2;
	  else if (c == '+')
	    st = ST_PLUS;
	  else if (c == '-')
	    st = ST_MINUS;
	  else if (c == '*')
	    st = ST_MULT;
	  else if (c == '/')
	    st = ST_DIV;
	  else if (c == '%')
	    st = ST_MODULO;
	  else if (c == '>')
	    st =  ST_SUP;
	  else if (c == '<')
	    st = ST_INF;
	  else if (c == '=')
	    st = ST_EQ;
	  else if (c == '|')
	    st = ST_OR;
	  else if (c == '!')
	    st = ST_NOT;
	  else if (c == '&')
	    st = ST_AND;
	  else
	    {
	      return c;
	    }
	  break;

	case ST_STRING2:
	  if (c == '"')
	    goto exit_loop;
	  *p++ = c;
	  len ++;
	  break;

	case ST_STRING1:
	  if (c == '\'')
	    goto exit_loop;
	  else if (c == '\\')
	    {
	      c = getc(fp);
	      switch (c)
		{
		case EOF:
		  nasl_perror(NULL, "Unfinished string\n");
		  goto exit_loop; /* parse error? */

		case '\n':	/* escaped end of line */
		  ctx->line_nb ++;
		  break;
		case '\\':
		  *p++ ='\\'; len ++;
		  break;
		case 'n':
		  *p++ = '\n'; len++;
		  break;
		case 'f':
		  *p++ = '\f'; len ++;
		  break;
		case 't':
		  *p++ = '\t'; len ++;
		  break;
		case 'r':
		  *p++ = '\r'; len++;
		  break;
		case 'v':
		  *p++ = '\v'; len ++;
		  break;
		case '"':
		  *p ++ = '"'; len ++;
		  break;
	  /* Not yet, as we do not return the length of the string */
		case '0':
		  *p++ = '\0'; len++;
		  break;
		case '\'':
		  *p++ = '\''; len++;
		  break;

		case 'x':
		  x = 0;
		  for (i = 0; i < 2; i ++)
		    {
		      c = getc(fp);
		      if (c == EOF)
			{
			  nasl_perror(NULL, "Unfinished \\x escape sequence (EOF)\n");
			  goto exit_loop;
			}
		      if (c == '\n')
			ctx->line_nb ++;

		      c = tolower(c);
		      if (c >= '0' && c <= '9')
			x = x * 16 + (c - '0');
		      else if (c >= 'a' && c <= 'f')
			x = x * 16 + 10 + (c - 'a');
		      else
			{
			  nasl_perror(NULL, "Unfinished \\x escape sequence\n");
			  ungetc(c, fp);
			  if (c == '\n')
			    ctx->line_nb --;
			  break;
			}
		    }
		  *p++ = x; len ++;
		  break;

		default:
		  nasl_perror(NULL, "Unknown escape sequence \\%c\n", c);
		  ungetc(c, fp);
		  if (c == '\n')
		    ctx->line_nb --;
		  goto exit_loop;
		}
	    }
	  else
	    {
	      *p++ = c;
	      len ++;
	    }
	  break;

	case ST_IDENT:
	  if (isalnum(c) || c == '_')
	    {
	      st = ST_IDENT;
	      *p++ = c;
	      len ++;
	    }
	  else
	    {
	      ungetc(c, fp);
	      if (c == '\n')
		ctx->line_nb --;
	      goto exit_loop;
	    }
	  break;

	case ST_ZERO:
	  if (c == 'x' || c == 'X')
	    st = ST_ZEROX;
	  else if (isdigit(c))
	    {
	      if (c <= '7')
		st = ST_OCT;
	      else
		st = ST_DEC;
	      *p ++ = c;
	      len ++;
	    }
	  else
	    {
	      ungetc(c, fp);
	      if (c == '\n')
		ctx->line_nb --;
	      goto exit_loop;
	    }
	  break;

	case ST_ZEROX:
	  if (isxdigit(c))
	    {
	      st = ST_HEX;
	      *p++ = c;
	      len ++;
	    }
	  else
	    {
	      /* This should be a parse error */
	      ungetc(c, fp);
	      if (c ==  '\n')
		ctx->line_nb --;
	      goto exit_loop;
	    }
	  break;

	case ST_OCT:
	  if (c >= '0')
	    {
	    if (c <= '7')
	      {
		*p++ = c;
		len ++;
		break;
	      }
	    else if (c <= '9')
	      {
		*p++ = c;
		len ++;
		st = ST_DEC;
		break;
	      }
	    }
	  ungetc(c, fp);
	  if (c ==  '\n')
	    ctx->line_nb --;
	  goto exit_loop;

	case ST_DEC:
	  if (isdigit(c))
	    {
	      *p++ = c;
	      len ++;
	    }
	  else
	    {
	      ungetc(c, fp);
	      if (c ==  '\n')
		ctx->line_nb --;
	      goto exit_loop;
	    }
	  break;

	case ST_HEX:
	  if (isxdigit(c))
	    {
	      *p++ = c;
	      len ++;
	    }
	  else
	    {
	      ungetc(c, fp);
	      if (c ==  '\n')
		ctx->line_nb --;
	      goto exit_loop;
	    }
	  break;

	case ST_SPACE:
	  if (! isspace(c))
	    {
	      ungetc(c, fp);
	      if (c ==  '\n')
		ctx->line_nb --;
	      st = ST_START;
	    }
	  break;

	case ST_COMMENT:
	  if (c == '\n')
	    st = ST_START;
	  break;

	case ST_SUP_EXCL:
	  if (c == '<')
	    return NOMATCH;
	  else
	    {
	      ungetc(c, fp);
	      if (c ==  '\n')
		ctx->line_nb --;
	      if (! isprint(c)) c = '.';
	      log_legacy_write ("lexer error: invalid token >!%c "
                                "parsed as >!< %c", c, c);
	      return NOMATCH;
	    }
	  break;

	case ST_SUP:
	  if (c == '=')
	    return SUPEQ;
	  else if (c == '<')
	    return MATCH;
	  else if (c == '>')
	    st = ST_R_SHIFT;
	  else if (c == '!')
	    st = ST_SUP_EXCL;
	  else
	    {
	      ungetc(c, fp);
	      if (c ==  '\n')
		ctx->line_nb --;
	      return '>';
	    }
	  break;

	case ST_INF:
	  if (c == '=')
	    return INFEQ;
	  else if (c == '<')
	    st = ST_L_SHIFT;
	  else
	    {
	      ungetc(c, fp);
	      if (c ==  '\n')
		ctx->line_nb --;
	      return '<';
	    }
	  break;

	case ST_R_SHIFT:
	  if (c == '=')
	    return R_SHIFT_EQ;
	  else if (c == '>')
	    st = ST_R_USHIFT;
	  else
	    {
	      ungetc(c, fp);
	      if (c ==  '\n')
		ctx->line_nb --;
	      return R_SHIFT;
	    }
	  /*NOTREACHED*/
	  break;

	case ST_R_USHIFT:
	  if (c == '=')
	    return R_USHIFT_EQ;
	  else
	    {
	      ungetc(c, fp);
	      if (c ==  '\n')
		ctx->line_nb --;
	      return R_USHIFT;
	    }
	  /*NOTREACHED*/
	  break;

	case ST_L_SHIFT:
	  if (c == '=')
	    return L_SHIFT_EQ;
	  else
	    {
	      ungetc(c, fp);
	      if (c ==  '\n')
		ctx->line_nb --;
	      return L_SHIFT;
	    }
	  /*NOTREACHED*/
	  break;

	case ST_AND:
	  if (c == '&')
	    return AND;
	  ungetc(c, fp);
	  if (c ==  '\n')
	    ctx->line_nb --;
	  return '&';

	case ST_OR:
	  if (c == '|')
	    return OR;
	  ungetc(c, fp);
	  if (c ==  '\n')
	    ctx->line_nb --;
	  return '|';

	case ST_NOT:
	  if (c == '=')
	    return NEQ;
	  else if (c == '~')
	    return RE_NOMATCH;
	  ungetc(c, fp);
	  if (c ==  '\n')
	    ctx->line_nb --;
	  return '!';

	case ST_EQ:
	  if (c == '=')
	    return EQ;
	  else if (c == '~')
	    return RE_MATCH;
	  else if (c == '>')
	    return ARROW;
	  ungetc(c, fp);
	  if (c ==  '\n')
	    ctx->line_nb --;
	  return '=';

	case ST_PLUS:
	  if (c == '+')
	    return PLUS_PLUS;
	  else if (c == '=')
	    return PLUS_EQ;

	  ungetc(c, fp);
	  if (c ==  '\n')
	    ctx->line_nb --;
	  return '+';

	case ST_MINUS:
	  if (c == '-')
	    return MINUS_MINUS;
	  else if (c == '=')
	    return MINUS_EQ;

	  ungetc(c, fp);
	  if (c ==  '\n')
	    ctx->line_nb --;
	  return '-';

	case ST_MULT:
	  if (c == '=')
	    return MULT_EQ;
	  else if (c == '*')
	    return EXPO;
	  ungetc(c, fp);
	  if (c ==  '\n')
	    ctx->line_nb --;
	  return '*';

	case ST_DIV:
	  if (c == '=')
	    return DIV_EQ;

	  ungetc(c, fp);
	  if (c ==  '\n')
	    ctx->line_nb --;
	  return '/';

	case ST_MODULO:
	  if (c == '=')
	    return MODULO_EQ;

	  ungetc(c, fp);
	  if (c ==  '\n')
	    ctx->line_nb --;
	  return '%';

	}

      if (len >= ctx->maxlen)
	{
	  int	offs = p - ctx->buffer;
	  char	*buf2;
	  ctx->maxlen += 80;
	  buf2 = g_realloc(ctx->buffer, ctx->maxlen + 1);
	  p = buf2 + offs;
	  ctx->buffer = buf2;
	}
    }

 exit_loop:
  ctx->buffer[len] = '\0';
  switch (st)
    {
    case ST_START:
    case ST_COMMENT:
    case ST_SPACE:
      return 0;

    case ST_STRING2:
      r = STRING2;
      lvalp->str = g_strdup(ctx->buffer);
      return r;

    case ST_STRING1:
      r = STRING1;
      lvalp->data.val = g_malloc0 (len+2);
      memcpy(lvalp->data.val, ctx->buffer, len+1);
      lvalp->data.len = len;
      return r;

    case ST_IDENT:
      if (strcmp(ctx->buffer, "if") == 0)
	r = IF;
      else if (strcmp(ctx->buffer, "else") == 0)
	r = ELSE;
      else if (strcmp(ctx->buffer, "for") == 0)
	r = FOR;
      else if (strcmp(ctx->buffer, "while") == 0)
	r = WHILE;
      else if (strcmp(ctx->buffer, "repeat") == 0)
	r = REPEAT;
      else if (strcmp(ctx->buffer, "until") == 0)
	r = UNTIL;
      else if (strcmp(ctx->buffer, "foreach") == 0)
	r = FOREACH;
      else if (strcmp(ctx->buffer, "function") == 0)
	r = FUNCTION;
      else if (strcmp(ctx->buffer, "return") == 0)
	r = RETURN;
      else if (strcmp(ctx->buffer, "x") == 0)
	r = REP;
      else if (strcmp(ctx->buffer, "include") == 0)
	r = INCLUDE;
      else if (strcmp(ctx->buffer, "break") == 0)
	r = BREAK;
      else if (strcmp(ctx->buffer, "continue") == 0)
	r = CONTINUE;
      else if (strcmp(ctx->buffer, "local_var") == 0)
	r = LOCAL;
      else if (strcmp(ctx->buffer, "global_var") == 0)
	r = GLOBAL;
      else
	{
	  r = IDENT;
	  lvalp->str = g_strdup(ctx->buffer);
	  return r;
	}
      return r;

    case ST_DEC:
      /* -123 is parsed as "-" and "123" so that we can write "4-2" without
       * inserting a white space after the minus operator
       * Note that strtoul would also work on negative integers */
      lvalp->num = x = strtoul(ctx->buffer, NULL, 10);
#if NASL_DEBUG > 1 && defined(ULONG_MAX) && defined(ERANGE)
      if (x == ULONG_MAX && errno == ERANGE)
	nasl_perror(NULL, "Integer overflow while converting %s at or near line %d\n", ctx->buffer, ctx->line_nb);
#endif
      return INTEGER;

    case ST_OCT:
      lvalp->num = x = strtoul(ctx->buffer, NULL, 8);
#if NASL_DEBUG > 1 && defined(ULONG_MAX) && defined(ERANGE)
      if (x == ULONG_MAX && errno == ERANGE)
	nasl_perror(NULL, "Integer overflow while converting %s at or near line %d\n", ctx->buffer, ctx->line_nb);
#endif
      return INTEGER;

    case ST_HEX:
      lvalp->num = x = strtoul(ctx->buffer, NULL, 16);
#if NASL_DEBUG > 1 && defined(ULONG_MAX)
      if (x == ULONG_MAX)
	nasl_perror(NULL, "Possible integer overflow while converting %s at or near line %d\n", ctx->buffer, ctx->line_nb);
#endif
      return INTEGER;

    case ST_ZEROX:
      nasl_perror(NULL, "Invalid token 0x parsed as 0 at line %d\n",
	      ctx->line_nb);
    case ST_ZERO:
      lvalp->num = 0;
      return INTEGER;
    default:
      abort();
    }
}

static int
nasllex(YYSTYPE * lvalp, void * parm)
{
  int	x = mylex (lvalp, parm);
  return x;
}

