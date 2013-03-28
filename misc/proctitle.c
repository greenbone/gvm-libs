/***************************************************************************
 * LPRng - An Extended Print Spooler System
 *
 * Copyright 1988-2002, Patrick Powell, San Diego, CA
 *     papowell@lprng.com
 * See LICENSE for conditions of use.
 ***************************************************************************/

/* The "LICENSE" file of LPRng states:

  "* You may use "LPRng" or "IFHP" under either the terms of the GNU
  GPL License or the Artistc License. These licenses are included
  below.  The licenses were obtained from the http://www.opensource.org
  web site on 28 Aug 2003".

  The included license is GNU General Public License Version 2.
*/


#include <stdio.h>
#include <string.h>
#include <stdarg.h>

#ifdef __linux__
#include "proctitle.h"
#include "system.h"

static char **Argv = NULL;      /* pointer to argument vector */
static char *LastArgv = NULL;   /* end of argv */
static char *MyName = NULL;


void
initsetproctitle (argc, argv, envp)
     int argc;
     char **argv;
     char **envp;
{
  register int i, envpsize = 0;
  extern char **environ;


  /*
   **  Move the environment so setproctitle can use the space at
   **  the top of memory.
   */

  for (i = 0; envp[i] != NULL; i++)
    envpsize += strlen (envp[i]) + 1;
  {
    char *s;
    environ = (char **) emalloc ((sizeof (char *) * (i + 1)) + envpsize + 1);
    s = ((char *) environ) + ((sizeof (char *) * (i + 1)));
    for (i = 0; envp[i] != NULL; i++)
      {
        strcpy (s, envp[i]);    /* RATS: ignore */
        environ[i] = s;
        s += strlen (s) + 1;
      }
  }
  environ[i] = NULL;
  MyName = estrdup (argv[0]);

  /*
   **  Save start and extent of argv for setproctitle.
   */

  Argv = argv;

  /*
   **  Determine how much space we can use for setproctitle.
   **  Use all contiguous argv and envp pointers starting at argv[0]
   */
  for (i = 0; i < argc; i++)
    {
      if (i == 0 || LastArgv + 1 == argv[i])
        LastArgv = argv[i] + strlen (argv[i]);
      else
        continue;
    }
  for (i = 0; envp[i] != NULL; i++)
    {
      if (LastArgv + 1 == envp[i])
        LastArgv = envp[i] + strlen (envp[i]);
      else
        continue;
    }
}


#define SPT_BUFSIZE 1024
#define SPT_PADCHAR '\0'

void
setproctitle (const char *fmt, ...)
{
  register int i;
  static char buf[SPT_BUFSIZE];
  static char buf2[SPT_BUFSIZE + 20];
  va_list param;

  /* print the argument string */
  va_start (param, fmt);
  vsnprintf (buf, sizeof (buf), fmt, param);
  va_end (param);

  snprintf (buf2, sizeof (buf2), "%s", buf); /* RATS: ignore */
  bzero (buf, sizeof (buf));
  strncpy (buf, buf2, sizeof (buf) - 1);

  i = strlen (buf);


  if (i > LastArgv - Argv[0] - 2)
    {
      i = LastArgv - Argv[0] - 2;
      buf[i] = '\0';
    }
  (void) strcpy (Argv[0], buf); /* RATS: ignore */
  {
    char *p;
    p = &Argv[0][i];
    while (p < LastArgv)
      *p++ = SPT_PADCHAR;
  }
  Argv[1] = NULL;
}



#else /* Not linux */

void
initsetproctitle (int argc, char **argv, char **envp)
{
  return;
}

void
setproctitle (const char *fmt, ...)
{
  return;
}
#endif
