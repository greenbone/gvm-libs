/*
 *          Copyright (c) mjh-EDV Beratung, 1996-1999
 *     mjh-EDV Beratung - 63263 Neu-Isenburg - Rosenstrasse 12
 *          Tel +49 6102 328279 - Fax +49 6102 328278
 *                Email info@mjh.teddy-net.com
 *
 *       Author: Jordan Hrycaj <jordan@mjh.teddy-net.com>
 *
 *    $Id: hlst.c,v 1.33 2003/02/27 10:09:57 renaud Exp $ 
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
 *   HLST - a simple hash list manager
 */

#include <includes.h>

#define __HLST_INTERNAL__
#include "hlst.h"

#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

/* ------------------------------------------------------------------------- *
 *                      private definitions                                  *
 * ------------------------------------------------------------------------- */

/* XMALLOC returns memory initialized to zero */
#define XMALLOC(x) emalloc(x)
#define XFREE(x)   efree(&(x))

/* default number of hash buckets per list */
#define DEFAULT_BUCKETS 53

/* global factor to be applied internally to any estimated_size_hint */
#define DEFAULT_PERCENTAGE_COMPRESSOR 80

typedef
struct _sorter {
  int                  dirty ;
  unsigned              size ;
  struct _hashqueue *inx [1] ;
  /* varable length, pointer aligned  */
} sorter ;

typedef 
struct _hashqueue {		/* linked list of bucket entries */
  void           *contents;
  struct _hashqueue  *next;
  unsigned          keylen;	/* length of current key */
  int               locked;	/* currently visited my some hash walk */
  struct _sorter *backlink;	/* there might be an index on that list */
# ifdef ENABLE_RHLST
  int               tranum;	/* transaction id, used for caching */
# endif /* ENABLE_RHLST */
  char             key [1];	/* varable size key */
  /* varable length, pointer aligned  */
} hashqueue ;

/* get the byte offset of a field */
#define STRUCT_OFFSET(type, field) \
	((char*)(&((type*)0)->field)-(char*)0)

/* given a pointer to field "field" from a structure of type "type",
   get the structure pointer */
#define REVERT_FIELD_PTR(p, type, field)  \
	((type*)(((char*)p) - STRUCT_OFFSET (type,field)))

/* ------------------------------------------------------------------------- *
 *                      private variables                                    *
 * ------------------------------------------------------------------------- */

/* non-empty, 0-terminated sorted list in the first entry:
   possible table sizes and hash factors (rel prime to the table size) */

/* FIXME: parameters need to be double ckecked, here */
static const hash_defs hints [] = {
  { 11,   7},
  { 23,  11},
  { 53,  31},
  { 73,  37},
  {101,  40},
  {151,  43},
  {269,  97},
  {509, 101},
  {577, 107},
  {0,0}
};

static unsigned 
size_hint_percentage_compressor = DEFAULT_PERCENTAGE_COMPRESSOR ;

/* used for custum sorting -- not thread safe */
static void *sorter_desc ;
static int (*sorter_fn)(void*,const char*,unsigned,const char*,unsigned);

#ifdef USE_PTHREADS
/* some global sync for logging etc  -- make custum sorting thread safe */
static int glob_mutex_initialized = 0;
static pthread_mutex_t glob_mutex; 
#endif

/* ------------------------------------------------------------------------- *
 *               hashed index ank key length calculation                     *
 * ------------------------------------------------------------------------- */

/* make a hash from the argument key string */
#define _GET_HASH_AND_STRLEN( h, H, L, key) {	\
  const char *s = (key) ;			\
  (H) = *s ;					\
  (L) =  1 ;					\
  goto S; do {			                \
      (H) *= (h)->z.fac ; /* shift accu  */	\
      (H) +=        * s ; /* get char    */	\
      (L) ++            ; /* word length */	\
    S:(H) %= (h)->z.mod ; /* module size */	\
  } while (*s ++) ;				}

/* make a hash from a generic argument key of given length */
#define _GET_HASH( h, H, len, key) {		\
  const char *s = (key) ;			\
  int l = (len) ;				\
  (H)   =    *s ;				\
  goto T; do {					\
      (H) *= (h)->z.fac ; /* shift accu  */	\
      (H) +=     * ++ s ; /* get char    */	\
    T:(H) %= (h)->z.mod ; /* module size */	\
  } while (-- l);				}

/* combine that methods, above */
#define GET_HASH_AND_LEN( h, H, len, key)	\
  { if (len) _GET_HASH (h,H,len,key) else _GET_HASH_AND_STRLEN(h,H,len,key) }


#ifdef USE_PTHREADS
# define mutex_init(x)     pthread_mutex_init    (x, 0)
# define mutex_destroy(x)  pthread_mutex_destroy (x)
# define mutex_lock(x)     pthread_mutex_lock    (x)
# define mutex_unlock(x)   pthread_mutex_unlock  (x)
# define globally_lock()   _glob_lock ()
# define globally_unlock() mutex_unlock (&glob_mutex)
static void
_glob_lock
  (void)
{
  if (glob_mutex_initialized == 0) {
    mutex_init (&glob_mutex);
    glob_mutex_initialized = 1;
  }
  mutex_lock (&glob_mutex);
}
 #else
# define mutex_init(x)     /* empty */
# define mutex_lock(x)     /* empty */
# define mutex_unlock(x)   /* empty */
# define mutex_destroy(x)  /* empty */
# define globally_lock()   /* empty */
# define globally_unlock() /* empty */
#endif

/* ------------------------------------------------------------------------- *
 *                      private functions                                    *
 * ------------------------------------------------------------------------- */

#define XMCOPY(p,len) memcpy (XMALLOC (len), (p), (len))

static hashqueue **
find_bucket_ptr
  (hashqueue   **Q,
   const char *key,
   unsigned    len)
{
  hashqueue *q ;
  while (q = *Q, q != 0) {
    if (len == q->keylen && memcmp (q->key, key, len) == 0)
      return Q ;
    Q = &q->next ;
  }
  errno = ENOENT ;
  return 0;
}

/* qsort call back functions */
static int 
__comp
  (hashqueue**  left, 
   hashqueue** right)
{
  int n, min ;
  
  if ((min = (*left)->keylen) > (*right)->keylen)
    min = (*right)->keylen ;
  
  if ((n = memcmp ((*left)->key, (*right)->key, min)) != 0)
    return n;
  
  return (*left)->keylen - (*right)->keylen ;
}

static int 
__comp_custom
  (hashqueue**  left, 
   hashqueue** right)
{
  return (*sorter_fn) (sorter_desc,
		       (*left)->key,
		       (*left)->keylen,
		       (*right)->key,
		       (*right)->keylen);
}

/* ------------------------------------------------------------------------- *
 *                 public functions: open/close management                   *
 * ------------------------------------------------------------------------- */

hlst *
create_hlst
  (unsigned estimated_size_hint,
   void (*clup)(void*,void*,char*,unsigned),
   void *state)
{
  const hash_defs *hd = hints ;
  hlst *h ;

  if (estimated_size_hint == 0)
    estimated_size_hint = DEFAULT_BUCKETS ;
  
  /* adjust accoording to policy */
  estimated_size_hint *= size_hint_percentage_compressor ;
  estimated_size_hint /= 100 ;

  /* find appropriate list size, will stop at the last entry */
# ifdef _WIN32
  for (;;) {
    const hash_defs *hd1 = hd+1 ;
    if (hd1->mod == 0 || hd1->mod > estimated_size_hint)
      break ;
    ++ hd ;
  }
# else
  while (hd [1].mod != 0 && hd [1].mod <= estimated_size_hint)
    ++ hd ;
# endif

  h = XMALLOC (sizeof (hlst) + (hd->mod - 1) * sizeof (void*));
  h->z          =   *hd ;
  h->clup       =  clup ;
  h->clup_state = state ;
  return h;
}



hlst *
copy_hlst
  (hlst                     *h,
   unsigned estimated_size_hint,
   void *(*copy)(void*,void*,char*,unsigned),
   void           *cpstate,
   void (*clup)(void*,void*,char*,unsigned),
   void             *state)
{
  const hash_defs *hd = hints ;
  hlst *new ;
  unsigned i, copy_only ;
  
  /* sanity check */
  if (h == 0) {
    errno = EINVAL;
    return 0 ;
  }
  if (estimated_size_hint == 0)
    /* get default from list to copy */
    hd = &h->z ;

  else {
    /* adjust accoording to policy */
    estimated_size_hint *= size_hint_percentage_compressor ;
    estimated_size_hint /= 100 ;

    if (estimated_size_hint != h->z.mod) {
      /* find appropriate list size, will stop at the last entry */
#     ifdef _WIN32
      for (;;) {
	const hash_defs *hd1 = hd+1 ;
	if (hd1->mod == 0 || hd1->mod > estimated_size_hint)
	  break ;
	++ hd ;
      }
#     else
      while (hd [1].mod != 0 && hd [1].mod <= estimated_size_hint)
	++ hd ;
#     endif
    }
  }

  new = (copy_only = (hd->mod == h->z.mod && copy == 0)) == 0

    /* create a new list */
    ? XMALLOC (sizeof (hlst) + (hd->mod - 1) * sizeof (void*))

    /* in this case, we can simply copy blocks, later on */
    : XMCOPY (h, sizeof (hlst) + (h->z.mod - 1) * sizeof (void*))
    ;
  
  new->walk          =                0 ;
  new->clup          =             clup ;
  new->clup_state    =            state ;
  new->total_entries = h->total_entries ;
  
  /* we organize the new list while looping over the old one */
  for (i = 0; i < h->z.mod; i ++) {
    
    /* get hash queue */
    hashqueue *p = h->bucket [i] ;
    new->bucket [i] = 0 ;
 
    while (p != 0) {
      hashqueue *q ;
      void **Q ;
      
      if (copy_only) {

	/* copy entry */
	q = XMCOPY (p, sizeof (hashqueue) + p->keylen-1) ;
	q->locked = 0 ;

	/* link to bucket queue */	
	q->next         = ((hashqueue*)new->bucket [i]) ;
	new->bucket [i] = q ;

	/* get contents pointer */
	Q = &q->contents ;
	
      } else {

	/* create new entry */
	if ((Q = make_hlst ((hlst*)new, p->key, p->keylen)) == 0) {
	  fprintf (stderr, __FILE__ 
		   "(%d): [make_hlst() == 0] serious bug, "
		   "corrupt target list -- please report, aborting.\n",
		   __LINE__);
	  exit (2) ;
	}
      }
	
      if (copy != 0 && /* duplicate user contents */
	  (*Q = (*copy) (cpstate, p->contents, p->key, p->keylen)) == 0 &&
	  errno != 0) {
	int e = errno ;
	/* stop: clean up */
	destroy_hlst (new);
	errno = e ;
	return 0;
      }
      
      /* get next template */
      p = p->next ;
    }
  }
  
  return new ;
}


void 
flush_hlst 
  (hlst *h,
   void (*clup)(void*desc,void*,char*,unsigned),
   void*             desc)
{
  unsigned i;
  hsrch *s ;

  /* sanity check */
  if (h == 0) return ;

  if (clup == 0) {
    clup = h->clup ;
    desc = h->clup_state ;
  }
  /* remove sorter */
  if (h->access != 0) {
    XFREE (h->access);
    h->access = 0;
  }
  for (i = 0; i < h->z.mod; i ++) {
    /* do with this bucket */
    hashqueue *p, **P = (hashqueue**)h->bucket + i ;
    while ((p = *P) != 0) {
      /* unlink that node, so even circular sublists would not loop */
      *P = p->next ;
      if (clup != 0 && p->contents != 0)
	(*clup) (desc, p->contents, p->key, p->keylen);
      XFREE (p);
    }
  } /* for */

  /* cannot visit any node, anymore */
  for (s = h->walk; s != 0; s = s->next) {
    s->hlist = 0 ;      /* next_hlst_search() will stop, that way */
#   ifdef ENABLE_RHLST
    if (s->clup != 0) { /* clean up by call back as early as possible */
      (*s->clup)(s->clup_state);
      s->clup = 0 ;
    }
#   endif
  }
  /* statistics */
  h->total_entries = 0 ;
}


void 
destroy_hlst 
  (hlst *h)
{
  /* sanity check */
  if (h == 0) return ;

  flush_hlst (h, 0, 0);
  if (h->clup != 0) 
    (*h->clup) (h->clup_state,0,0,0);
  XFREE (h);
}

/* ------------------------------------------------------------------------- *
 *                 public functions: manipulate slots                        *
 * ------------------------------------------------------------------------- */

void** 
find_hlst
  (hlst         *h,
   const char *key,
   unsigned    len)
{
  hashqueue **Q;
  int inx ;

  /* sanity check */
  if (h == 0 || key == 0) {
    errno = EINVAL;
    return 0;
  }
  
  GET_HASH_AND_LEN (h, inx, len, key);

  if ((Q = find_bucket_ptr ((hashqueue**)h->bucket + inx, key, len)) != 0)
    return &(*Q)->contents ;

  errno = ENOENT;
  return 0;
}


void** 
make_hlst
  (hlst        *_h,
   const char *key,
   unsigned    len)
{
  hlst *h = (hlst *)_h ;
  hashqueue *q ;
  int inx ;

  /* sanity check */
  if (h == 0 || key == 0) {
    errno = EINVAL;
    return 0;
  }
  
  GET_HASH_AND_LEN (h, inx, len, key);

  /* cannot have duplicate entries */
  if (find_bucket_ptr ((hashqueue**)h->bucket + inx, key, len) != 0) {
    errno = EEXIST;
    return 0;
  }

  /* make entry */
  q = XMALLOC (sizeof (hashqueue) + len - 1);
  memcpy (q->key, key, q->keylen = len);

  /* link entry */
  q->next = h->bucket [inx] ;
  h->bucket [inx] = q ;

  /* statistics */
  h->total_entries ++ ;

  if (h->access != 0)
    /* mark the sorter ready for rebuilt */
    h->access->dirty = 1 ;

  /* always returns some pointer */
  return &q->contents ;
}


int
delete_hlst
  (hlst         *h, 
   const char *key,
   unsigned    len)
{
  hashqueue *q, **Q;
  hsrch *s;
  unsigned inx ;

  /* sanity check */
  if (h == 0 || key == 0) {
    errno = EINVAL;
    return -1;
  }
  
  GET_HASH_AND_LEN (h, inx, len, key);

  if ((Q = find_bucket_ptr ((hashqueue**)h->bucket + inx, key, len)) == 0) {
    errno = ENOENT ;
    return -1 ;
  }

  q = *Q ;

  if (q->locked) 
    /* cannot visit that node, anymore so update the walk decriptors */
    for (s = h->walk; s != 0; s = s->next)  
      if (s->ntry == q)		/* find find descriptor */
	s->ntry = q->next ;	/* visit successor, instead */

  /* set that index link idle */
  if (h->access != 0)
    if (q->backlink != 0) {
      *q->backlink->inx = 0 ;
      h->access->dirty = 1;
    }

  /* unlink */
  *Q = q->next ;

  /* statistics */
  h->total_entries -- ;

  if (h->clup != 0 && q->contents != 0) /* clean up call back */
    (*h->clup) (h->clup_state, q->contents, q->key, q->keylen);
  
  XFREE (q);
  return 0;
}

/* ------------------------------------------------------------------------- *
 *                 public functions: misc                                    *
 * ------------------------------------------------------------------------- */

/* global factor to be applied internally to any estimated_size_hint */
unsigned 
compress_hlst_index 
  (unsigned size_hint_percentage)
{
  unsigned o_index = size_hint_percentage_compressor ;
  if ((size_hint_percentage_compressor = size_hint_percentage) > 100)
    size_hint_percentage_compressor = 100 ;
  return o_index;
}

char *
query_key_hlst
  (void **t)
{
  if (t == 0) {
    errno = EINVAL;
    return 0;
  }
  return REVERT_FIELD_PTR (t, hashqueue, contents)->key ;
}

unsigned
query_keylen_hlst
  (void **t)
{
  if (t == 0) {
    errno = EINVAL;
    return 0;
  }
  return  REVERT_FIELD_PTR (t, hashqueue, contents)->keylen ;
}


#ifdef ENABLE_RHLST
int
query_tranum_hlst
  (void **t)
{
  if (t == 0) {
    errno = EINVAL;
    return 0;
  }
  errno = 0 ;
  return REVERT_FIELD_PTR (t, hashqueue, contents)->tranum ;
}

int
set_tranum_hlst
  (void **t,
   int    n)
{
  int last ;
  if (t == 0) {
    errno = EINVAL;
    return 0;
  }
  errno = 0 ;
  last = REVERT_FIELD_PTR (t, hashqueue, contents)->tranum ;
  REVERT_FIELD_PTR (t, hashqueue, contents)->tranum = n ;
  return last;
}
#endif /* ENABLE_RHLST */

unsigned
query_hlst_size
  (hlst *h)
{
  if (h == 0) {
    errno = EINVAL;
    return 0;
  }
  errno = 0 ;
  return h->total_entries ;
}


/* ------------------------------------------------------------------------- *
 *                 public functions: search that list, itemwise              *
 * ------------------------------------------------------------------------- */

hsrch* 
open_hlst_search 
 (hlst *h)
{
  hsrch *s ;

  /* sanity check */
  if (h == 0) {
    errno = EINVAL;
    return 0;
  }
  
  s = XMALLOC (sizeof (hsrch));
  s->hlist     =       h ;	/* current hash list, to walk on */
  s->bucket_id =      -1 ;
  s->ntry      =       0 ;	/* before the first entry */
  s->next      = h->walk ;	/* more such entries */

  h->walk = s ;
  return s;
}

void **
next_hlst_search 
  (hsrch *s)
{
  hlst *h ;
  void ** V ;

  /* sanity check */
  if (s == 0) {
    errno = EINVAL;
    return 0;
  }
  /* get the hash list */
  if ((h = s->hlist) == 0) {
    /* list has been flushed */
    errno = ENOENT ;
    return 0;
  }
  if (s->ntry != 0)
    s->ntry->locked -- ;	/* release that node */
  else
    do {			/* find next node */
      /* get bucket, check for end-of-list */
      if (++ s->bucket_id >= h->z.mod) {
	errno = 0;
	return 0 ;
      }
      s->ntry = h->bucket [s->bucket_id] ;
    } while (s->ntry == 0) ;
  
  /* get node contents as return value */
  V = &s->ntry->contents ;

  /* set to next value */
  if ((s->ntry = s->ntry->next) != 0)
    s->ntry->locked ++ ;    /* mark it visited */

  return V;
}


void
close_hlst_search
  (hsrch *s)
{
  hsrch **U, *u;
  /* sanity check */
  if (s == 0) return ;

  /* is this a stale walk descriptor? */
  if (s->hlist == 0) {
    XFREE (s);
    return ;
  }
  /* unlink current walk descriptor */
  U = &s->hlist->walk ;
  while (u = *U, u != 0) {
    if (u == s) {        /* find the link pointer for that record */
      if (u->ntry != 0)  /* release that particular node */
	u->ntry->locked -- ;
      *U = u->next ;     /* unlink the walk descriptor */
#     ifdef ENABLE_RHLST
      if (u->clup != 0)  /* clean up peripheral my call back fn */
	(*u->clup)(u->clup_state);
#     endif
      XFREE (u);         /* done */
      return ;
    }
    if (u->next == u) { /* XXXXXXXXXXXXX Grrr - should not happen (jh) */
      fprintf (stderr, 
	       "%s (%d): [u->next == u] serious bug -- please report\n",
	       __FILE__,
	       __LINE__);
      u->next = 0 ;
      return;
    }
    U = &u->next;	/* set to successor link */
  }
}


int
for_hlst_do
  (hlst     *h,
   int (*fn)(void*,void*,char*,unsigned),
   void *state)
{
  unsigned i ;
  int n ;
  
  /* sanity check */
  if (h == 0 || fn == 0) {
    errno = EINVAL;
    return -1;
  }
  /* looping over the buckets */
  for (i = 0; i < h->z.mod; i ++) {
    
    /* get hash queue */
    hashqueue *p = h->bucket [i] ;
    
    while (p != 0) {
      /* get next, the cb function could delete the current entry */
      hashqueue *q = p->next ;
      if ((n = (*fn) (state, p->contents, p->key, p->keylen)) < 0)
	return -1;
      if (n)
	return n;
      p = q ;
    }
  }
  
  return 0;
}

/* ------------------------------------------------------------------------- *
 *                 public functions: sorter index                            *
 * ------------------------------------------------------------------------- */

void
sort_hlst
  (hlst *h)
{
  unsigned i;
  hashqueue **ix ;
  int (*sorter_cb)(const void*,const void*);

  if (h == 0) return ;

  /* create an access array with entry pointers */
  if (h->access != 0) {
    /* nothing has changed, yet */
    if (h->access->dirty == 0)
      return ;
    XFREE (h->access) ;
  }
  h->access = XMALLOC 
    (sizeof (sorter) + (h->total_entries - 1) * sizeof (hashqueue*));
  h->access->size = h->total_entries ;

  /* link that array somehow to the list entries */
  ix = h->access->inx ;

  /* looping over the buckets */
  for (i = 0; i < h->z.mod; i ++) {
    
    /* looping over the hash queue */
    hashqueue *p = h->bucket [i] ;
    while (p != 0) {
      /* link into access array */
      * ix ++ = p ;
      /* get next */
      p = p->next ;
    }
  }

  /* check comparison function */
  if (h->sorter_fn != 0) {
    globally_lock () ; /* not thread safe, otherwise */
    sorter_fn   = h->sorter_fn   ;
    sorter_desc = h->sorter_desc ;
    sorter_cb   = (int(*)(const void*, const void*))__comp_custom ;
  } else {
    sorter_cb   = (int(*)(const void*, const void*))__comp ;
  }
  /* sort that access array */
  qsort (h->access->inx, h->total_entries, sizeof (hashqueue*), sorter_cb);
  
  if (h->sorter_fn != 0)
  {
    globally_unlock () ;
  }
}


int
csort_hlst
  (hlst *h,
   int (*fn)(void*,const char*,unsigned,const char*,unsigned),
   void *fn_desc)
{
  if (h == 0) {
    errno = EINVAL;
    return 0;
  }
  h->sorter_fn   = fn;
  h->sorter_desc = fn_desc;
  return 0;
}

void **
inx_hlst
  (hlst    *h,
   unsigned n)
{
  hashqueue *p ;

  if (h == 0) {
    errno = EINVAL;
    return 0;
  }
  if (h->access == 0) {
    errno = ESRCH;
    return 0;
  }
  if (n < h->access->size && (p = h->access->inx [n]) != 0)
    return &p->contents ;
  errno = ENOENT;
  return 0 ;
}


void
unsort_hlst
  (hlst *h)
{
  if (h == 0 || h->access == 0) return ;
  XFREE (h->access) ;
  h->access = 0;
}

/* ------------------------------------------------------------------------- *
 *                 public functions: statistics                              *
 * ------------------------------------------------------------------------- */

int
hlst_buckets
  (hlst *h)
{
  if (h == 0) {
    errno = EINVAL;
    return -1;
  }
  return h->z.mod;
}


typedef
struct _hstatistics {
  struct {
    unsigned busy, idle ;
    struct { unsigned entries, squares ; } sum ;
  } buckets ;
  struct {
    unsigned min, max ;
  } fill ;
} hstatistics ;


static void
__hstatistics_fn
 (hstatistics *state, 
  unsigned      fill)
{
  if (fill == 0) {
    state->buckets.idle ++ ;
    return ;
  }

  state->buckets.busy ++ ;  
  state->buckets.sum.entries += fill ;
  fill *= fill ;
  state->buckets.sum.squares += fill ;

  if (fill > state->fill.max)
    state->fill.max = fill ;

  if (fill < state->fill.min)
    state->fill.min = fill ;
}


void
hlst_statistics
  (hlst *h,
   void (*fn) (void*, unsigned),
   void *state)
{
  unsigned i, sum;
  float var, mu ;
  hstatistics hs;  

  /* sanity check */
  if (h == 0) return ;

  if (fn == 0) {
    fn = (void(*)(void*,unsigned))__hstatistics_fn ;
    hs.fill.min = -1 ;
    state = &hs ;
  }
  
  /* looping over the buckets */
  for (i = 0; i < h->z.mod; i ++) {
    
    /* get hash queue */
    hashqueue *p = h->bucket [i] ;
    unsigned   n = 0;
    
    while (p != 0)
      ++ n, p = p->next ;

    (*fn) (state, n);
  }

  if (fn != (void(*)(void*,unsigned))__hstatistics_fn) 
    return ;
 
  sum = hs.buckets.idle + hs.buckets.busy ;  
  if (hs.buckets.busy <= 1) {
    return ;
  }

  sum = hs.buckets.sum.entries + hs.buckets.idle ;
  fprintf (stderr, "Buckets: %u out of %u are busy, min/max fill: %u/%u\n",  
	   hs.buckets.busy, sum, hs.fill.min, hs.fill.max);
  
  /* busy buckets */
  mu  = hs.buckets.sum.entries / hs.buckets.busy ;
  var = hs.buckets.sum.squares / hs.buckets.busy  - mu * mu ;
  fprintf (stderr, "Busy statistics (mean/stddev): %f/%f\n", mu, var);

  /* all buckets */
  mu  = hs.buckets.sum.entries / sum ;
  var = hs.buckets.sum.squares / sum  - mu * mu ;
  fprintf (stderr, "Total statistics (mean/stddev): %f/%f\n", mu, var);
}
