/***************************************************************************
 * LPRng - An Extended Print Spooler System
 *
 * Copyright 1988-2002, Patrick Powell, San Diego, CA
 *     papowell@lprng.com
 * See LICENSE for conditions of use.
 * $Id: proctitle.h,v 1.1 2002/12/14 12:34:42 renaud Exp $
 ***************************************************************************/



#ifndef _PROCTITLE_H_
#define _PROCTITLE_H_ 1


#ifndef LINEBUFFER 
#define LINEBUFFER 4096
#endif

void initsetproctitle(int argc, char *argv[], char *envp[]);
/* VARARGS3 */
#if !defined(HAVE_SETPROCTITLE) || !defined(HAVE_SETPROCTITLE_DEF)
void setproctitle( const char *fmt, ... );
void proctitle( const char *fmt, ... );
#endif

/* PROTOTYPES */
#endif
