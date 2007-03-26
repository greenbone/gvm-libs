/*
 * Nessus Development Header
 */

#ifndef NESSUSNT

#ifndef HAVE_MEMCPY
#define memcpy(d, s, n) bcopy ((s), (d), (n))
#define memmove(d, s, n) bcopy ((s), (d), (n))
#endif

#endif


#if !defined(HAVE_BZERO) || (HAVE_BZERO == 0)
#define bzero(s,z) memset(s,0,z)
#endif

#if !defined(HAVE_BCOPY) || (HAVE_BCOPY == 0)
#define bcopy(x,y,z) memcpy(y,x,z)
#endif



