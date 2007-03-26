
#include <includes.h>
#include <stdarg.h>
#ifndef HAVE_SETPROCTITLE
#ifdef __linux__
#include "proctitle.h"

 static char	**Argv = NULL;		/* pointer to argument vector */
 static char	*LastArgv = NULL;	/* end of argv */
 static char    *MyName = NULL;


 void initsetproctitle(argc, argv, envp)
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
		envpsize += strlen(envp[i]) + 1;
	{
	char *s;
	environ = (char **) emalloc((sizeof (char *) * (i + 1))+envpsize+1);
	s = ((char *)environ)+((sizeof (char *) * (i + 1)));
	for (i = 0; envp[i] != NULL; i++){
		strcpy(s,envp[i]);
		environ[i] = s;
		s += strlen(s)+1;
	}
	}
	environ[i] = NULL;
	MyName = estrdup(argv[0]);

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
		if (i==0 || LastArgv + 1 == argv[i])
			LastArgv = argv[i] + strlen(argv[i]);
		else
			continue;
	}
	for (i=0; envp[i] != NULL; i++)
	{
		if (LastArgv + 1 == envp[i])
			LastArgv = envp[i] + strlen(envp[i]);
		else
			continue;
	}
}


#define SPT_BUFSIZE 1024
#define SPT_PADCHAR '\0'

 void
 setproctitle (const char *fmt,...)
{
	register int i;
	static char buf[SPT_BUFSIZE]; 
        static char buf2[SPT_BUFSIZE+20];
	va_list param;
	 
    /* print the argument string */
    va_start(param, fmt);
#if HAVE_VNSPRINTF
    (void) vsnprintf(buf, sizeof(buf), fmt, param);
#else
    vsprintf(buf, fmt, param);
#endif
    va_end(param);

    snprintf(buf2, sizeof(buf2), "nessusd: %s", buf);
    bzero(buf, sizeof(buf));
    strncpy(buf, buf2, sizeof(buf) - 1);
   
    i = strlen(buf);


	if (i > LastArgv - Argv[0] - 2)
	{
		i = LastArgv - Argv[0] - 2;
		buf[i] = '\0';
	}
	(void) strcpy(Argv[0], buf);
	{ char *p;
	p = &Argv[0][i];
	while (p < LastArgv)
		*p++ = SPT_PADCHAR;
	}
	Argv[1] = NULL;
}



#else  /* Not linux */

void initsetproctitle(argc, argv, envp)
	int argc;
	char **argv;
	char **envp;
{
 return;
}

void
 setproctitle (const char *fmt,...)
{
 return;
}
#endif


#else /* the system has a setproctitle() call */

void initsetproctitle(argc, argv, envp)
	int argc;
	char **argv;
	char **envp;
{
 return;
}

#endif


