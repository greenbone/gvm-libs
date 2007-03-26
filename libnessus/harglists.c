/*
 *  Copyright (c) Nessus Consulting S.A.R.L., 2000 - 2001
 *  Email: office@nessus.com
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Library General Public
 *  License as published by the Free Software Foundation; either
 *  version 2 of the License, or (at your option) any later version.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Library General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License 
 *  along with this library; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 *  $Id: harglists.c,v 1.37.2.1 2005/03/22 01:31:46 renaud Exp $
 *
 * Author: Jordan Hrycaj <jordan@mjh.teddy-net.com>
 *
 * Jordan re-wrote Renauds idea of an arglists management on top
 * of the hash list manager
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "hlst.h"

#define EXPORTING
#include <includes.h>
#include <errno.h>

#define __HARG_INTERNAL__
#include "harglists.h"

#ifdef HAVE__ALLOCA
#define alloca _alloca
#define HAVE_ALLOCA
#endif

/* set this flag if you want to dump create/destroy messages */
#undef HARG_CREATE_DEBUG

/* activates the lost-losts tracker functions harg_tracker_dunp()
   and harg_tracket_flush() */
#undef HARG_LIST_TRACKER

#define HARG_DEBUG 6 /* log level ranging [0..9] (9 is more output) */

/* ------------------------------------------------------------------------- *
 *                   private definitions: debugging stuff                    *
 * ------------------------------------------------------------------------- */

#ifdef HARG_DEBUG
# define IFDEBUG(cmd) cmd
# define XTAG(s) __FILE__ "(%u): " s ".\n", __LINE__
#else
# define IFDEBUG(cmd)
#endif

/* same as *HLOG, below but for debugging, call it  XPRINT (("problem", ..)) */
#define XPRINT(l,msg) IFDEBUG ({if ((l)<=dbglevel && xlog!=0)(*xlog) msg;})

/* log level dependent convenience macros */
#define XPRINT0(msg) XPRINT (0,msg)
#define XPRINT1(msg) XPRINT (1,msg)
#define XPRINT2(msg) XPRINT (2,msg)
#define XPRINT3(msg) XPRINT (3,msg)
#define XPRINT4(msg) XPRINT (4,msg)
#define XPRINT5(msg) XPRINT (5,msg)
#define XPRINT6(msg) XPRINT (6,msg)
#define XPRINT7(msg) XPRINT (7,msg)
#define XPRINT8(msg) XPRINT (8,msg)
#define XPRINT9(msg) XPRINT (9,msg)

/* ------------------------------------------------------------------------- *
 *                      private definitions                                  *
 * ------------------------------------------------------------------------- */

/* XMALLOC returns memory initialized to zero */
#define XMALLOC(x)  emalloc(x)
#define XFREE(x)    efree(&(x))

#define NEED_XREALLOC /* locally installed, no mem zero needed */
#define XREALLOC(x,n) xrealloc(x,n)

#ifdef DMALLOC
#undef NEED_XREALLOC
#undef XREALLOC
#define XREALLOC(x,n) realloc(x,n)
#endif


/* local on-the-stack memory allocation */
#ifdef HAVE_ALLOCA
# define XALLOCA(x)  alloca(x)
# define XDEALLOC(x) /* nothing */
#else
# define XALLOCA(x)  XMALLOC(x)
# define XDEALLOC(x) XFREE(x)
#endif

typedef /* data part for the data type, following */
struct _harg_aligned {
  union {
    char data [1]; 
    void  *ptr[1]; /* force alignment */
  } d;
} harg_aligned ;

typedef /* general data type record/slot */
struct _harg {
  hargtype_t type;
  unsigned   size;

  /* type ARG_STRING, ARG_STUCT data are stored as a data block
     of given size - all other data types are stored as (void*) */
  harg_aligned d;
  /* varable length, struct aligned  */
} harg;


typedef /* recursive list copying */
struct _copy_cb {
  harglst *trg;
  int    depth;  /* recursion depth */
} copy_cb ;


typedef /* call back function's state buffer */
struct _do_for_all_cb_state {
  void *state ;
  int (*cb_fn)(void*,void*,hargtype_t,unsigned,hargkey_t*) ;
} do_for_all_cb_state ;


typedef /* custum sort call back function descriptor */
struct _csts_desc {
  harglst *a;

  void *cmp_desc ;
  int (*cmp)(void*, harglst*,
	     hargkey_t  *left_key, hargtype_t  left_type,
	     hargkey_t *right_key, hargtype_t right_type);
} csts_desc ;



static void debug (const char *, long, long);

/* ------------------------------------------------------------------------- *
 *                       private variable                                    *
 * ------------------------------------------------------------------------- */



#ifdef HARG_LIST_TRACKER
static hlst *harg_tracker;
#endif

/* default logger */
static void (*xlog) (const char *, ...) = 0;
IFDEBUG (static int dbglevel = HARG_DEBUG);

/* ------------------------------------------------------------------------- *
 *                   private functions: helpers                              *
 * ------------------------------------------------------------------------- */

/* the memory size of the record containing the data block */
#define HARG_SIZE(   len) (sizeof (harg) - sizeof (harg_aligned) + (len))
#define HARG_RECSIZE(rec) HARG_SIZE((rec)->size)

/* get the byte offset of a field */
#define STRUCT_OFFSET(type, field) \
	((char*)(&((type*)0)->field)-(char*)0)

/* given a pointer to field "field" from a structure of type "type",
   get the structure pointer */
#define REVERT_FIELD_PTR(p, type, field)  \
	((type*)(((char*)p) - STRUCT_OFFSET (type,field)))

/* key length depending on the data type */
#define klen_by_type(t)  (is_ptrkey_type(t) ? sizeof (void*) : 0)

/* if enabled, compare ignoring remote bits */
#define falsify_given_type(s,t) \
        (is_specific_type (s) && get_local_type ((s)^(t)) != 0)

/* compare ignoring remote and ptr key bits */
#define verify_simple_type(s,t) (get_simple_type ((s)^(t)) == 0)

/* compare ignoring ptr key bits */
#define verify_yekrtp_type(s,t)  (get_yekrtp_type ((s)^(t)) == 0)

#ifdef NEED_XREALLOC
static void *
xrealloc
  (void       *p,
   unsigned size)
{
  void *q = realloc (p, size) ;
  if (q == 0) {
    /* on out of memory, let XMALLOC do the aborting job */
    q = XMALLOC (size) ;
    memcpy (q, p, size) ;
    XFREE (p) ;
    return q;
  }
  return q;
}
#endif /* NEED_XREALLOC */

#ifdef HARG_LIST_TRACKER
static void
harg_tracker_add
  (harglst *a)
{
  void **R;
  if (harg_tracker == 0 && (harg_tracker = create_hlst (100,0,0)) == 0)
    return ;
  if ((R = find_hlst (harg_tracker, (char*)&a, sizeof (void*))) == 0 &&
      (R = make_hlst (harg_tracker, (char*)&a, sizeof (void*))) == 0)
    return;
  *R = a;
}

static void
harg_tracker_delete
  (harglst *a)
{
  delete_hlst (harg_tracker, (char*)&a, sizeof (void*));
}

#else
#define harg_tracker_add(x)
#define harg_tracker_delete(x)
#endif


#ifdef  HARG_CREATE_DEBUG
#define HARG_DEBUG

static void
say_creating
  (void    *list,
   unsigned size)
{
  debug ("Creating harg -> 0x%lx{%u}", (long)list, size);
}

static void
say_closing
  (void    *list,
   unsigned flag)
{
  char f [200] = "Closing harg -> 0x%lx" ;
  int n = 0 ;
  if (flag & H_sREMOTE) 
    strcat (f, n ++ ? "|H_sREMOTE"  : ", flags=H_sREMOTE");
  if (flag & H_sWRTHRU) 
    strcat (f, n ++ ? "|H_sWRTHRU"  : ", flags=H_sWRTHRU");
  if (flag & H_sRECURSE)
    strcat (f, n ++ ? "|H_sRECURSE" : ", flags=H_sRECURSE");
  debug (f, (long)list, 0);
}

#else
#define say_creating(x,y)
#define say_closing(x,y)
#endif /* HARG_CREATE_DEBUG */

#ifdef HARG_DEBUG
static void
message
  (const char *s,
   const char *f,
   long        u,
   long        v,
   const char *t)
{
  fputs (s, stderr);
  fprintf (stderr, f, u, v);
  fputs (t, stderr);
# ifdef _WIN32
  fputc ('\r', stderr);
# endif 
  fputc ('\n', stderr);
}

static void
debug
  (const char *s,
   long        u,
   long        v)
{
  message ("DEBUG: ", s, u, v, ".");
}
#endif /* HARG_DEBUG */

static harg*
create_harg
  (hargtype_t type,
   void      *data,
   unsigned   size)
{
  harg *h ; 

  if (!is_blob_type (type) && size == 0)
    size = sizeof (void*);
  
  h = XMALLOC (HARG_SIZE (size));
  h->type = type ;
  h->size = size ;

  if (!is_blob_type (type)) {
    h->d.d.ptr [0] = data ;
    return h;
  }

  if (verify_simple_type (type, HARG_STRING) && size != 0)
    /* last character is '\0' */
    h->d.d.data [ -- size] = '\0' ;

  if (size != 0 && data != 0)
    memcpy (h->d.d.data, data, size);
  return h;
}

/* ------------------------------------------------------------------------- *
 *                   private functions: local call backs                     *
 * ------------------------------------------------------------------------- */

static void
clean_up
  (harglst     *a,
   harg     *data,
   hargkey_t *key,
   unsigned   len)
{
  /* last step, delete descriptor */
  if (data == 0) {
    if (a == 0) 
      return ;
    if (a->sorter != 0)
      XFREE (a->sorter) ;
    XFREE (a) ;
    return ;
  }
  /* recursively delete sublist */
  if (is_harglst_type (data->type) && 
      a != 0 && (a->destroy_mode & H_sRECURSE))
    harg_close_any (data->d.d.ptr [0], a->destroy_mode);
  
# ifdef ARG_ARGLIST
  else
    switch (data->type) {
    case HARG_ARGLIST:
    case HARG_PARGLIST:
      /* recursively delete sublist */
      if (a != 0 && (a->destroy_mode & H_sRECURSE))
	arg_free_all (data->d.d.ptr [0]);
    default:
    	break;	
    }
# endif

  XFREE (data);
}


static int 
do_for_all_cb
  (do_for_all_cb_state *s, 
   harg                *h,
   hargkey_t         *key, 
   unsigned           len)
{
  return (s->cb_fn) 
    (s->state, 
     is_blob_type (h->type) ?h->d.d.data :h->d.d.ptr [0],
     h->type, h->size, key);
}





static harg*
a_copy
  (copy_cb  *desc,
   harg     *data, /* from the source list */
   hargkey_t *key,
   unsigned   len)
{
  unsigned size ;
  harglst *a, *b, *c ;

  if (data == 0) { /* may happen, bootstrap also */
    errno = 0 ;
    return 0;
  }

  /* stupidly copying sensless data ?? */
  if (is_harglst_type (data->type) && (a = data->d.d.ptr [0]) != 0) {

    c = desc->trg ; /* == 0  on bootstrap level */

      if (++ desc->depth >= HLST_MAX_RDEPTH) {
	errno = ELOOP ;  /* recursion overflow ? */
	return 0;
      }
      /* recursively populate the sublist */    
      desc->trg =       /* mark it non-bootstrap level */
	b = XMALLOC (sizeof (harglst)) ;
      if ((b->x = copy_hlst 
	   (a->x, query_hlst_size (a->x),
	    (void*(*)(void*,void*,char*,unsigned))a_copy, desc,
	    (void (*)(void*,void*,char*,unsigned))clean_up, 0)) == 0) {
	int e = errno ;
	XFREE    (b);
	errno = e ;
	return 0;
      }

    -- desc->depth ;                     /* end recursion */
    if ((desc->trg = c) == 0)                  /* restore */
      return (harg*)b;      /* return value for bootstrap */
    
    /* local type applies, only */
    return create_harg (get_local_type (data->type), b, 0);
  }
  
  /* return a copy of the data block */
  size = HARG_RECSIZE (data);
  return memcpy (XMALLOC (size), data, size);
}


static int
__csts_cb /* custum sort call back function descriptor */
  (void *desc,
   const char  *left_key, unsigned  left_klen,
   const char *right_key, unsigned right_klen)
{
  harglst   *a = desc ;
  csts_desc *s = a->sorter ;

  harg  **left_R = (harg**)find_hlst (a->x,  left_key,  left_klen);
  harg **right_R = (harg**)find_hlst (a->x, right_key, right_klen);
  
  return (*s->cmp) 
    (s->cmp_desc, a,
     left_key,  get_local_type  ((*left_R)->type),
     right_key, get_local_type ((*right_R)->type));
}

/* ------------------------------------------------------------------------- *
 *               private functions: data tree dumper                         *
 * ------------------------------------------------------------------------- */

static void
do_newlevel
  (void)
{
  fputs ("\n", stderr);
}

static void
do_indent
  (int level)
{
  while (level -- > 0)
    fputs ("   ", stderr);
  fputs (" ", stderr);
}

static void
do_printf
  (const char *f,
   harg      **R,
   void       *a,
   int     flags,
   int     ptype,
   unsigned  arg)
{
  if (R != 0) {
    char *s = query_key_hlst ((void**)R) ;
    if (ptype)
      fprintf (stderr, "<0x%04X/%d> = ", (void*)s,(int)(s));
    else
      fprintf (stderr, "<%s> = ", s);
  } else {
    fprintf (stderr, "list");
  }
  fprintf (stderr, f, a, arg);
  fputs ("\n", stderr);
}


static void **
harg_walk_next_ptr
  (hargwalk *w)
{
  return next_hlst_search ((hsrch*)w) ;
}




static void
do_harg_dump
  (harglst *a,
   int  level)
{
  hargwalk *w ;
  harg **R, *r ;

  if(a == 0 || (w = harg_walk_init (a)) == 0) {
    do_printf ("-error; no such list!\n",0,0,0,0,0);
    return;
  } 

  while ((R = (harg**)harg_walk_next_ptr (w)) != 0) {
    int ptrky, flags = 0;
    do_indent (level);
    if ((r = *R) == 0) {
      do_printf ("Warning: NULL entry in list\n",0,0,0,0,0);
      continue ;
    }
    ptrky = (is_ptrkey_type (r->type) != 0);
    switch (get_simple_type (r->type)) {
    case HARG_STRING:
      do_printf ("\"%s\"",  R, (void*)r->d.d.data, flags, ptrky, 0);
      continue ;
    case HARG_BLOB:
      do_printf ("%#x[%u]", R, (void*)r->d.d.data, flags, ptrky, r->size);
      continue ;
#ifdef ARG_ARGLIST
    case HARG_ARGLIST:
      do_newlevel ();
      do_printf ("(old mode>) sublist ...", R, 0, flags, ptrky, 0);
      arg_dump (r->d.d.ptr [0], level+1);
      continue ;
#endif
    case HARG_HARG:
      /* do_newlevel (); */
      if (is_remote_type (r->type))
	do_printf ("remote sublist{%s} ...", R, r->d.d.ptr+1, flags, ptrky, 0);
      else
	do_printf ("sublist{%#x} ...", R, r->d.d.ptr [0], flags, ptrky, 0);
      do_harg_dump (r->d.d.ptr [0], level+1);
      continue ;
    case HARG_INT:
      do_printf ("%d",  R, r->d.d.ptr [0], flags, ptrky, 0);
      continue;
    default:
      do_printf ("*%#x", R, r->d.d.ptr [0], flags, ptrky, 0);
    }
  }
  harg_walk_stop (w);
}

/* ------------------------------------------------------------------------- *
 *                      private functions                                    *
 * ------------------------------------------------------------------------- */

static harg *
get_harg_entry
  (harglst      *a,
   const char *key,
   unsigned    len)
{
  harg **R, *r ;

  if (a == 0) { 
    errno = EINVAL; 
    return 0; 
  }
    if ((R = (harg**)find_hlst (a->x, key, len)) == 0)
      return 0;

  
  if ((r = *R) != 0)
    return r;
  /* zombie, should not happen, anyway */
  delete_hlst (a->x, key, len);
  errno = ENOENT ;
  return 0;
}








/* ------------------------------------------------------------------------- *
 *                 public functions: open/close management                   *
 * ------------------------------------------------------------------------- */

harglst*
harg_create 
  (unsigned size)
{
  harglst* h = XMALLOC (sizeof (harglst)) ;
  h->x = create_hlst 
    /* never returns NULL */
    (size, (void(*)(void*,void*,char*,unsigned))clean_up, h);
  say_creating (h, size);
  harg_tracker_add (h);
  return h ;
}


void
harg_close_any
  (harglst *a,
   int   flag)
{
  if (a == 0)
    return ;
  a->destroy_mode = flag ;
  say_closing (a,flag);
  harg_tracker_delete (a);
  destroy_hlst (a->x); /* implicitely frees a == call back descriptor */
}


harglst*
harg_dup
  (harglst*    a,
   unsigned size)
{
  copy_cb desc ;
  harg data ;

  /* sanity check */
  if (a == 0) {
    errno = EINVAL;
    return 0; 
  }

  desc.trg         = 0 ;
  desc.depth       = 0 ;
  data.type        = HARG_HARG ;
  data.d.d.ptr [0] = a ;

  return (harglst*)a_copy (&desc, &data, 0, 0);
}


/* ------------------------------------------------------------------------- *
 *               public functions: varable access - modify                   *
 * ------------------------------------------------------------------------- */

hargkey_t*
harg_addt
  (harglst      *a,
   hargkey_t  *key,
   hargtype_t type,
   int   overwrite,
   unsigned   size,
   void     *value)
{
  harg **R, *r ;

  /* depending on the key type get its length */
  int klen = klen_by_type (type);;

  /* sanity check */
  if (a == 0 || key == 0 ||
      size == 0 && ((value == 0) && is_blob_type (type) ||
		    verify_simple_type (type, HARG_BLOB))) {
    errno = EINVAL; 
    return 0;
  }

  if (verify_simple_type (type, HARG_STRING)) {
    if (size == 0) /* need a terminating '\0' */
      size = strlen (value) + 1 ;
    else
      size ++ ;
  }


    R = (harg**)find_hlst (a->x, key, klen);

  
  if (R != 0) {
    r = *R ;
    /* record exists, do we need to overwrite ? */
    if (!overwrite && type == r->type)
      return query_key_hlst ((void**)R);
    /* reuse the data block if the sizes did not change */
    if (r->size == size) {
      r->type = type ;
      if (type == HARG_STRING || type == HARG_BLOB) {
	if (size)
	  memcpy (r->d.d.data, value, size);
      } else {
	r->d.d.ptr [0] = value;
      }
      return query_key_hlst ((void**)R);
    }
    /* sizes have changed - reallocate but keep ID */
    *R = create_harg (type, value, size);
    XFREE (r);
    return query_key_hlst ((void**)R);
  }

  /* no such value - create anew */
  if ((R = (harg**)make_hlst (a->x, key, klen)) != 0) {
    *R = create_harg (type, value, size);
    return query_key_hlst ((void**)R);
  }
  /* cannot happen */

 
  return 0; 
}


int
harg_set_valuet
  (harglst      *a,
   hargkey_t  *key,
   hargtype_t type,
   unsigned   size,
   void     *value)
{
  harg **R, *r ;
  int klen = klen_by_type (type);

  /* sanity check */
  if (a == 0 || key == 0 ||
      size == 0 && (value == 0 && is_blob_type (type) ||
		    verify_simple_type (type, HARG_BLOB))) {
    errno = EINVAL; 
    return -1;
  }
  

    R = (harg**)find_hlst (a->x, key, klen);

  if ((r = *R) == 0) { /* zombie, should not happen, anyway */
    delete_hlst (a->x, key, klen);
    errno = ENOENT ;
    return -1;
  }
  if (falsify_given_type (type, (*R)->type)) {
    errno = EPERM;  /* not permitted */
    return -1;
  }
  if (is_blob_type (r->type) == 0) {
    r->d.d.ptr [0] = value ; /* the quick way */
    return 0;
  }
  if (verify_simple_type (r->type, HARG_STRING)) {
    if (size == 0) /* need a terminating '\0' */
      size = strlen (value) + 1 ;
    else
      size ++ ;
  }
  /* remains to any blob type */
  if (r->size != size) { /* reallocate that entry */
    *R = create_harg (r->type, value, size);
    XFREE (r);
    return 0;
  } 
  if (value != 0) {
    if (verify_simple_type (r->type, HARG_STRING))
      /* the string terminator may be on protected memory */
      r->d.d.data [-- size] = '\0' ;
    memcpy (r->d.d.data, value, size);
  }
  return 0;
}


int
harg_renamet
  (harglst       *a,
   hargkey_t   *key,
   hargtype_t  type,
   hargkey_t  *nkey,
   hargtype_t ntype)
{
  harg **S, **R, *r ;
  int same_keys, klen = klen_by_type (type);

  /* sanity check */
  if (a == 0) {
    errno = EINVAL; 
    return -1; 
  }


    R = (harg**)find_hlst (a->x, key, klen);


  if ((r = *R) == 0) { /* zombie, should not happen, anyway */
    delete_hlst (a->x, key, klen);
    errno = ENOENT ;
    return -1;
  }
  /* check for a specific source type */
  if (falsify_given_type (type, r->type)) {
    errno = EPERM ;
    return -1;
  }
  same_keys = 
    nkey == 0 || 
    (is_ptrkey_type  (type) && 
     is_ptrkey_type (ntype) &&
     memcmp (key, nkey, sizeof (void*)) == 0) ||
    (is_ptrkey_type  (type) == 0 && 
     is_ptrkey_type (ntype) == 0 &&
     strcmp (key, nkey) == 0)
    ? 1 
    : 0 
    ;
  if (r->type == ntype && same_keys)
    return 0 ; /* nothing to do */

  /* check target type groups */
  if (is_blob_type   (ntype) &&   is_blob_type (r->type) ||
      is_scalar_type (ntype) && is_scalar_type (r->type) ||
      is_specific_type (ntype) == 0) {
    if (same_keys == 0) {
      /* make new index */
      if ((S = (harg**)make_hlst (a->x, nkey, klen_by_type (ntype))) == 0)
	return -1;
      *S = *R;
      *R = 0;
      delete_hlst (a->x, key, klen);
    }
    if (is_specific_type (ntype))
      r->type = ntype ;
    return 0;
  }
  errno = EPERM;  /* not permitted */
  return -1 ;
}



int
harg_removet
  (harglst      *a,
   hargkey_t  *key,
   hargtype_t type)
{
  int klen = klen_by_type (type) ;
  harg **R = 0;

  /* sanity check */
  if (a == 0 || key == 0) { 
    errno = EINVAL; 
    return -1; 
  }


    if (is_specific_type (type) && 
	(R = (harg**)find_hlst (a->x, key, klen)) == 0) {
      errno = ENOENT ;  /* no such record */
      return -1 ;
    }


  if (R != 0 && *R != 0 && falsify_given_type (type, (*R)->type)) {
    errno = EPERM ;
    return -1;
  }
  return delete_hlst (a->x, key, klen);
}


/* ------------------------------------------------------------------------- *
 *               public functions: varable access - retrieve                 *
 * ------------------------------------------------------------------------- */

void * /* same as above, but with type check */
harg_get_valuet
  (harglst      *a,
   hargkey_t  *key,
   hargtype_t type)
{
  harg *r ;
  
  if ((r = get_harg_entry (a, key, klen_by_type (type))) == 0)
    return 0;

  /* check for strict type checking */
  if (falsify_given_type (type, r->type)) {
    errno = EPERM ;
    return 0;
  }
  return is_blob_type (r->type) ? r->d.d.data : r->d.d.ptr [0] ;
}


int
harg_inct
  (harglst      *a,
   hargkey_t  *key,
   hargtype_t type,
   incmode_t incop,
   int         inc)
{
  harg *r, **R ;
  int klen = klen_by_type (type);

  /* sanity check */
  if (a == 0) {
    errno = EINVAL;
    return -1; 
  }

  /* type may be 0, or HARG_ANY */
  type = is_ptrkey_type (type) ?HARG_PINT :HARG_INT ;
  

    R = (harg**)find_hlst (a->x, key, klen);


  /* no such entry, yet */
  if (R == 0 || (r = *R) == 0) { 
    if (inc_op_creates_record (incop)) {
      if (R == 0 && (R = (harg**)make_hlst (a->x, key, klen)) == 0)
	return -1;
      *R = create_harg (type, (void*)inc, sizeof (int));
      errno = 0;
      return (int)(*R)->d.d.ptr [0];
    }
    errno = ENOENT;
    return -1;
  }

  /* entry exists, already */
  if (!verify_simple_type (r->type, HARG_INT)) {
    errno = EPERM;
    return -1;
  }

  /* increment */
  if (inc_op_increments_record (incop)) {
    if (inc_op_wants_0_record (incop) && r->d.d.ptr [0] != 0) {
      errno = EEXIST;
      return -1;
    }
    r->d.d.ptr [0] = (void*)((int)(r->d.d.ptr [0]) + inc) ;
    return (int)r->d.d.ptr [0];
  }

  /* decrement */
  if (inc_op_notnegtv_record (incop) && (int)r->d.d.ptr [0] < inc) {
    errno = ERANGE;
    return -1;
  }
  if (inc_op_notpostv_record (incop) && (int)r->d.d.ptr [0] > inc) {
    errno = ERANGE;
    return -1;
  }
  if (inc_op_destroy0_record (incop) && (int)r->d.d.ptr [0] <= inc) {
    delete_hlst (a->x, key, klen);
    return errno = 0;
  }
  r->d.d.ptr [0] = (void*)((int)(r->d.d.ptr [0]) - inc) ;
  errno = 0 ;
  return (int)r->d.d.ptr [0];
}

void harg_sort(harglst *a) {
	sort_hlst(a->x);
}



int
harg_csort
  (harglst      *a,
   int (*fn)(void*, harglst*,
	     hargkey_t  *left_key, hargtype_t  left_type,
	     hargkey_t *right_key, hargtype_t right_type),
   void *fn_desc)
{
  csts_desc *s;

  if (a == 0) {
    errno = EINVAL; 
    return 0; 
  }
  if (fn == 0) {
    if (a->sorter == 0) {
      XFREE (a->sorter);
      a->sorter = 0;
    }
    return csort_hlst (a->x, 0, 0);
  }

  /* need some record space */
  if ((s = a->sorter) == 0)
    a->sorter = s = XMALLOC (sizeof (csts_desc));

  s->cmp      = fn ;
  s->cmp_desc = fn_desc;

  return csort_hlst (a->x, __csts_cb, a);
}


hargkey_t *
harg_get_ntht
  (harglst      *a,
   unsigned    inx,
   hargtype_t type)
{
  harg **R ;
  if (a == 0) {
    errno = EINVAL; 
    return 0; 
  }



    sort_hlst (a->x);
    if ((R = (harg**)inx_hlst (a->x, inx)) == 0)
      return 0 ;



  /* check for strict type cheking */
  if (falsify_given_type (type, (*R)->type)) {
    errno = EPERM ;
    return 0;
  }
  return query_key_hlst ((void**)R);    
}

hargtype_t
harg_get_typet
  (harglst      *a,
   hargkey_t  *key,
   hargtype_t type)
{
  harg *r = get_harg_entry (a, key, klen_by_type (type)) ;
  return r == 0
    ? 0 
    : get_local_type (r->type)
    ;
}

unsigned
harg_get_sizet
  (harglst *     a,
   hargkey_t  *key,
   hargtype_t type)
{
  harg *r = get_harg_entry (a, key, klen_by_type (type)) ;
  return r == 0 
    ? -1
    : (r->type & RHARG_ANY & RHARG_PANY) ? sizeof (void*) : r->size
    ;
}


/* ------------------------------------------------------------------------- *
 *               public functions: varable access - retrieve                 *
 * ------------------------------------------------------------------------- */

hargwalk*
harg_walk_init
  (harglst *a)
{
  if (a == 0) {
    errno = EINVAL; 
    return 0; 
  }


  return (hargwalk*)open_hlst_search (a->x);
}


hargkey_t*
harg_walk_nextT
(hargwalk        *w,
   hargtype_t *Type)
{
  harg **P ;
  if ((P =(harg**)harg_walk_next_ptr (w)) == 0)
    return 0;
  if (Type != 0)
    *Type = (*P)->type ;
  return query_key_hlst ((void**)P) ;
}


void
harg_walk_stop
  (hargwalk *w)
{
  close_hlst_search ((hsrch*)w);
}

int
harg_do
  (harglst    *a,
   int (*fn) (void *,void*,hargtype_t,unsigned,hargkey_t*),
   void *state)
{
  do_for_all_cb_state s ;
  if (a == 0) {
    errno = EINVAL; 
    return -1; 
  }

  s.state = state ;
  if ((s.cb_fn = fn) == 0) 
    return -1 ;

  
  return for_hlst_do 
    (a->x, (int(*)(void*,void*,char*,unsigned))do_for_all_cb, &s);
}


void
harg_dump
  (harglst *a)
{
  if (a == 0) return ;
  do_harg_dump (a, 0);
  /* hlst_statistics (a->x, 0, 0); not tested, yet */
}

void
harg_tracker_flush
  (void)
{
# ifdef HARG_LIST_TRACKER
  destroy_hlst (harg_tracker);
  harg_tracker = 0;
# endif
}

void
harg_tracker_dump
  (void)
{
# ifdef HARG_LIST_TRACKER
  void **R;
  int i = 0;
  sort_hlst (harg_tracker);
  while (R = inx_hlst (harg_tracker, i++))
    if (*R != 0) {
      fprintf (stderr, "{0x%lx} = ", (long)*R);
      do_harg_dump (*R, 0);
#     ifdef _WIN32
      fputc ('\r', stderr);
#     endif 
      fputc ('\n', stderr);
    }
# endif
}

void /* define a logger function */
  (*harg_logger(void(*f)(const char *, ...)))
     (const char *, ...)
{
  void (*g) (const char *, ...) ;
  g = xlog ;
  xlog = f ;
  return g ;
}

int
harg_debuglevel
  (int n)
{
  unsigned d = -1;
  IFDEBUG (d = dbglevel) ;
  IFDEBUG (dbglevel = n);
  return d;
}

/* ------------------------------------------------------------------------- *
 *                 source ends here                                          *
 * ------------------------------------------------------------------------- */
