/* OpenVAS
 * $Id$
 * Description: Undocumented module.
 *
 * Authors:
 * Renaud Deraison <deraison@nessus.org> (Original pre-fork development)
 *
 * Copyright:
 * Based on work Copyright (C) 1998 - 2003 Renaud Deraison
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef ___INCLUDES_H__
#define ___INCLUDES_H__
#undef WINDOWSNT
/*
 * OpenVAS system includes 
 */
#if defined(LINUX)
/* Bug 1388: to get memmem() prototype */
#define _GNU_SOURCE
#endif
#include <config.h>

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

#ifdef HAVE_LOCALE_H
#include <locale.h>
#endif


#ifndef WINDOWSNT
#if HAVE_UNISTD_H
#include <unistd.h>
#endif /* HAVE_UNISTD_H */

#ifdef linux
/* avoid symbol clash with librpcsvc.a(xmount.o) */
#define xdr_fhstatus xDr_fHsTaTuS
#endif
#endif /* WINDOWSNT */

#if defined(HAVE_STDLIB_H) || defined(WINDOWSNT)
#include <stdlib.h>
#endif

#if defined(HAVE_STDIO_H) || defined(WINDOWSNT)
#include <stdio.h>
#endif

#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_CTYPE_H
#include <ctype.h>
#endif

#ifndef WINDOWSNT
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif

#ifndef HAVE_UCBINCLUDE
#include <fcntl.h>
#else
/* Solaris */
#include "/usr/ucbinclude/fcntl.h"
#endif

#ifdef HAVE_MEMORY_H
#include <memory.h>
#endif

#if STDC_HEADERS && HAVE_STRING_H                                                       
#include <string.h>                                                    
#else                                                     
#ifndef HAVE_STRCHR                                                     
#define strchr index                                                   
#define strrchr rindex                                                
#endif /* not defined HAVE_STRCHR */                                                         
char *strchr (), *strrchr ();                 
#ifndef HAVE_MEMCPY
#define memcpy(d, s, n) bcopy ((s), (d), (n))                      
#define memmove(d, s, n) bcopy ((s), (d), (n))                        
#endif  /* not defined (HAVE_MEMCPY) */                                                         
#endif  /* STDC_HEADERS && HAVE_STRING_H */      

#endif /* not defined(WINDOWSNT) */


/* 
 * Unix specific includes  -- once more :)
 */
#ifndef WINDOWSNT

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif /* HAVE_STRINGS_H */

#include <netdb.h>
#include <sys/socket.h>

#ifdef HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#endif

#include <netinet/in.h>

#ifdef HAVE_SYS_UN_H
#include <sys/un.h>
#endif

#include <arpa/inet.h>
#include <signal.h>



#ifdef HAVE_DLFCN_H
#include <dlfcn.h>
#endif

                                          
#if HAVE_SYS_WAIT_H                                                     
#include <sys/wait.h>                                                
#endif                                                                

#ifndef WEXITSTATUS
#define WEXITSTATUS(stat_val) ((unsigned)(stat_val) >> 8)               
#endif                                                                

#ifndef WIFEXITED                                                        
#define WIFEXITED(stat_val) (((stat_val) & 255) == 0)                 
#endif    

#if TIME_WITH_SYS_TIME                                           
#include <sys/time.h>                                                
#include <time.h>                                               
#else                
#if HAVE_SYS_TIME_H
#include <sys/time.h> 
#else                                                                
#include <time.h>                                                  
#endif                                                                
#endif   

#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif


#include <sys/stat.h>


#ifdef HAVE_SYS_FILIO_H
#include <sys/filio.h>
#endif


#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#if HAVE_DIRENT_H                                                     
#include <dirent.h>
#define NAMLEN(dirent) strlen((dirent)->d_name)                 
#else                                                                  
#define dirent direct
#define NAMLEN(dirent) (dirent)->d_namlen                         
#if HAVE_SYS_NDIR_H                                                     
#include <sys/ndir.h>                                                  
#endif                                                             
#if HAVE_SYS_DIR_H
#include <sys/dir.h>                                                
#endif                                                               
#if HAVE_NDIR_H                                                         
#include <ndir.h>                                         
#endif            
#endif   



#ifdef WINDOWSNT
#define USE_NT_THREADS
#else
#ifndef USE_PTHREADS
#define USE_FORK_THREADS
#endif


#ifdef USE_PTHREADS
#if HAVE_PTHREAD_H
#include <pthread.h>
#else
#error "Your system is lacking pthread support"
#endif
#endif
#endif /* not defined(WINDOWSNT) */

#ifdef HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif

#ifdef HAVE_SEARCH_H
#include <search.h>
#endif

#ifdef BSD_BYTE_ORDERING
#define FIX(n) (n)
#define UNFIX(n) (n)
#else
#define FIX(n) htons(n)
#define UNFIX(n) ntohs(n)
#endif

#include <pcap.h>
#include <libopenvas.h>
#include <harglists.h>

#endif /* not defined(___INCLUDES_H) */


