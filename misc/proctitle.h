/***************************************************************************
 * LPRng - An Extended Print Spooler System
 *
 * Copyright 1988-2002, Patrick Powell, San Diego, CA
 *     papowell@lprng.com
 * See LICENSE for conditions of use.
 * $Id: proctitle.h,v 1.1 2002/12/14 12:34:42 renaud Exp $
 ***************************************************************************/

/* The "LICENSE" file of LPRng states:

  "* You may use "LPRng" or "IFHP" under either the terms of the GNU
  GPL License or the Artistc License. These licenses are included
  below.  The licenses were obtained from the http://www.opensource.org
  web site on 28 Aug 2003".

  The included license is GNU General Public License Version 2.
*/

#ifndef _PROCTITLE_H_
#define _PROCTITLE_H_ 1

#ifndef LINEBUFFER
#define LINEBUFFER 4096
#endif

void initsetproctitle (int argc, char *argv[], char *envp[]);
void setproctitle (const char *fmt, ...);
void proctitle (const char *fmt, ...);

#endif
