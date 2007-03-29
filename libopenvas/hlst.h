/*
 *          Copyright (c) mjh-EDV Beratung, 1996-1999
 *     mjh-EDV Beratung - 63263 Neu-Isenburg - Rosenstrasse 12
 *          Tel +49 6102 328279 - Fax +49 6102 328278
 *                Email info@mjh.teddy-net.com
 *
 *       Author: Jordan Hrycaj <jordan@mjh.teddy-net.com>
 *
 *    $Id: hlst.h,v 1.12 2001/03/04 21:26:24 jordan Exp $ 
 *
 *   This library is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Library General Public
 *   License as published by the Free Software Foundation; either
 *   version 2 of the License, or (at your option) any later version.
 *
 *   This library is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *   Library General Public License for more details.
 *
 *   You should have received a copy of the GNU Library General Public
 *   License along with this library; if not, write to the Free
 *   Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 *
 *   HLST - a simple hash list
 */

#ifndef __HLST_H__
#define __HLST_H__

#ifdef ENABLE_RHLST
#define __RHLST_EXPORTS_H__
#include "rhlst.h"
#endif /* ENABLE_RHLST */

#ifdef __HLST_INTERNAL__
typedef 
struct _hsrch {			/* walk through the list */
  struct _hlst     *hlist ;	/* current hash list, to walk on */
  unsigned      bucket_id ;	/* current bucket */
  struct _hashqueue *ntry ;	/* pointer to the next entry */
  struct _hsrch     *next ;	/* more such entries */

# ifdef ENABLE_RHLST
  void (*clup)(void*)     ;	/* for remote list processing */
  void  *clup_state ;
# endif /* ENABLE_RHLST */

} hsrch ;

typedef
struct _hash_defs {		/* hash list parameters */
  unsigned  mod ;		/* number of buckets */
  unsigned  fac ;		/* shift by multiplication */
} hash_defs ;

#ifndef ENABLE_RHLST
typedef struct _rhlst {void* unused;} rlst;
#endif /* ENABLE_RHLST */

typedef 
struct _hlst {			/* hash list descriptor */
  struct _sorter *access;	/* there might be an index on that list */
  struct _rhlst *raccess;	/* extensions */
  int (*sorter_fn)(void*,const char*,unsigned,const char*,unsigned);
  void *sorter_desc ;		/* custom sort of the entries */
  void *clup_state ;
  void (*clup)			/* call back destructor for entries */
       (void*,void*,char*,unsigned);
  hash_defs       z ;		/* hash parameters for this list */
  struct _hsrch *walk ;		/* list: walk through the hash list */
  unsigned total_entries ;	/* number of entries in the list */
  void *bucket [1] ;		/* varable length array of buckets */
  /* varable length, pointer aligned  */
} hlst ;

#else
typedef struct _hlst  {char opaq;} hlst;
typedef struct _hsrch {char opaq;} hsrch;
#endif

#ifdef ENABLE_RHLST
#undef __RHLST_H__
#undef __RHLST_EXPORTS_H__
#include "rhlst.h"
#endif /* ENABLE_RHLST */

/* open/close management */
extern hlst *create_hlst 
  (unsigned estimated_size_hint, 

   /* this function is called when non-empty slots are removed, if the
      list is destroyed, the last call will be destroy(state,0,0,0). Apart
      from the last call, the detroy function will only be called with a
      non NULL item, */
   void (*destroy)(void *state, void* item, char* key, unsigned keylen), 
   void* state) ;

extern hlst *copy_hlst 
  (hlst *to_be_copied,
   /* leave the estimated_size_hint 0 to use the parameters from the
      list to_be_copied */
   unsigned estimated_size_hint, 

   /* The copy() function is called when an entry is to be copied and
      inserted into the copied slot - leave it empty to copy a list with
      keys but without inserted data, only. This function is only used for
      duplicating the list. Upon copy() returning NULL while errno set to
      a non-NULL value, copying is stopped and the partly allocated list
      is removed using destroy_hlst(). In this case, the copy_hlst() 
      function returns NULL while errno is set as passed from the copy() 
      function. */
   void *(*copy) (void *cpstate, void* item, char *key, unsigned keylen),
   void *cpstate,

   /* The destroy() function is called when non-empty slots are removed,
      if the list is destroyed, the last call will be destroy(state,0,0,0) 
      This function is registered, internally to be used later on.Apart
      from the last call, the detroy function will only be called with a
      non NULL item, */
   void (*destroy)(void *state, void* item, char* key, unsigned keylen), 
   void* state) ;

/* global factor to be applied internally to any estimated_size_hint */
extern unsigned compress_hlst_index (unsigned size_hint_percentage);

extern void destroy_hlst (hlst*);
extern void   flush_hlst 
   (hlst*,
    /* can have another destroy function, here, uses the default
       assigned in chreate_hlst, if the destroy argument is NULL */
    void (*destroy)(void*,void*,char*,unsigned), void*state);



/* find an existing slot, len == 0 means: key is ascii string */
extern void** find_hlst (hlst*, const char *key, unsigned len);

/* create a non existing slot, otherwise error
   len == 0 means: key is ascii string */
extern void** make_hlst (hlst*, const char *key, unsigned len);

/* delete slot (-1 == error), len == 0 means: key is ascii string */
extern int delete_hlst (hlst*, const char *key, unsigned len);


/* for a given (void**) ptr value as returned by {find|make}_hlst,
   retrieve the korresponding key and its length */
extern char    *query_key_hlst    (void **);
extern unsigned query_keylen_hlst (void **);

#ifdef ENABLE_RHLST
/* sets/returns a transaction number associated with the entry */
extern int query_tranum_hlst (void **);
extern int   set_tranum_hlst (void **, int);
#endif /* ENABLE_RHLST */

/* returns the number of elements in the argument list (might be NULL) */
extern unsigned query_hlst_size (hlst *);

/* applying a function fn () to all list elements */
extern int for_hlst_do
  (hlst *,
   /* if the argunemt function returns non 0 while the algorithm is running,
      the rest of the items not visited yet are skipped and for_hlst_do ()
      returns with the value passed by this function. */
   int (*fn)(void *state, void *, char *key, unsigned keylen),
   void *state) ;


/* searching step wise through all elements */
extern hsrch* open_hlst_search (hlst*) ;
extern void** next_hlst_search (hsrch*) ;
extern void  close_hlst_search (hsrch*) ;


/* sorter stuff */
extern void   sort_hlst (hlst*);
extern void  **inx_hlst (hlst*,unsigned);
extern void unsort_hlst (hlst*);

/* custom sort */
extern int csort_hlst
  (hlst*,
   /* custom comparison function for qsort */
   int (*)(void *desc,
	   const char  *left_key, unsigned  left_klen,
	   const char *right_key, unsigned right_klen),
   void *desc);


/* statistics etc. */
extern int  hlst_buckets (hlst*);
extern void hlst_statistics /* statistics, fn may be NULL to use the default */
  (hlst *h, void (*fn) (void*state, unsigned bucket_fill), void *state) ;

#endif /* __HLST_H__ */

