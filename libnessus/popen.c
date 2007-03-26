/*
 * Copyright (C) Michel Arboi 2002
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
 */

#include <includes.h>
#ifndef RLIM_INFINITY
#define RLIM_INFINITY (1024*1024*1024)
#endif

FILE*
nessus_popen4(const char* cmd, char *const args[], pid_t* ppid, int inice)
{
  int		fd, pipes[2];
  pid_t		son;
  FILE		*fp;

#if DEBUG
  int i;
  fprintf(stderr, "nessus_popen: running %s -", cmd);
  for (i = 0; args[i] != NULL; i ++)
    fprintf(stderr, " %s", args[i]);
  fputc('\n', stderr);
#endif
#if 0
  {
    char	buffer[1024], *p;
    int		n, sz = sizeof(buffer)-1;

    n = snprintf(buffer, sz, "%s", cmd);
    if (n > 0)
      {
	p = buffer + n; 
	sz -= n;
      }

    for (i = 0; args[i] != NULL && sz > 0; i ++)
      {
	n = snprintf(p, sz, " %s", args[i]);
	if (n > 0)
	  {
	    p = buffer + n; 
	    sz -= n;
	  }
      }
    *p ++ = '\0';
    log_write("nessus_popen: %s", buffer);
  }
#endif

 /* pipe() does not always work well on some OS */
  if (socketpair(AF_UNIX, SOCK_STREAM, 0, pipes) < 0)  
    {
      perror("socketpair");
      return NULL;
      /* filedes[0]  is  for  reading, filedes[1] is for writing. */
    }
  if ((son = fork()) < 0)
    {
      perror("fork");
      close(pipes[0]); close(pipes[1]);
      return NULL;
    }
  if (son == 0)
    {
      struct rlimit	rl;
      int i;
      
      /* Child process */

      if (inice)
	{
	  errno = 0;
	  /* Some systems returned the new nice value => it may be < 0 */
	  if (nice(inice) < 0 && errno)
	    perror("nice");
	}
      /* Memory usage: unlimited */
      rl.rlim_cur = rl.rlim_max = RLIM_INFINITY;
#ifdef RLIMIT_DATA
      if (setrlimit(RLIMIT_DATA, &rl) < 0) perror("RLIMIT_DATA");
#endif
#ifdef RLIMIT_RSS
      if (setrlimit(RLIMIT_RSS, &rl) < 0) perror("RLIMIT_RSS");
#endif
#ifdef RLIMIT_STACK
      if (setrlimit(RLIMIT_STACK, &rl) < 0) perror("RLIMIT_STACK");
#endif
      /* We could probably limit the CPU time, but to which value? */

      if ((fd = open("/dev/null", O_RDONLY)) < 0)
	{
	  perror("/dev/null");
	  exit(1);
	}
      close(0);
      if (dup2(fd, 0) < 0)
	{
	  perror("dup2");
	  exit(1);
	}
      close(fd);

      close(1);
      close(2);
      if (dup2(pipes[1], 1) < 0 ||
	  dup2(pipes[1], 2) < 0)
	{
	  /* Cannot print error as 2 is closed! */
	  exit(1);
	}
      /* 
       * Close all the fd's
       */
      for(i=3;i<256;i++)
      {
       close(i);
      }	
      signal(SIGTERM, _exit);
      signal(SIGPIPE, _exit);
      execvp(cmd, args);
      perror("execvp");
      _exit(1);
    }
  close(pipes[1]);
  if ((fp = fdopen(pipes[0], "r")) == NULL)
    {
      perror("fdopen");
      close(pipes[0]);
      return NULL;
    }

  if (ppid != NULL) *ppid = son;
  return fp;      
}

FILE*
nessus_popen(const char* cmd, char *const args[], pid_t* ppid)
{
  return nessus_popen4(cmd, args, ppid, 0);
}

int
nessus_pclose(FILE* fp, pid_t pid)
{
  if (pid > 0)
    if (waitpid(pid, NULL, WNOHANG) == 0)
      if (kill(pid, SIGTERM) >= 0)
	if (waitpid(pid, NULL, WNOHANG) == 0)
	  {
	    usleep(400);
	    (void) kill(pid, SIGKILL);
	    (void) waitpid(pid, NULL, WNOHANG);
	  }
  return fclose(fp);
}

/* Code taken from ptycall by Jordan Hrycaj */
ExtFunc	char**	append_argv(char **argv, char   *opt)
{
  int argc, n ;
  
  /* special case */
  if (opt == 0) {
    if (argv == 0) 
      (argv = emalloc(sizeof (char*))) [0] = 0 ;
    return argv ;
  }
  
  if (argv == 0) {
    argc = 1 ;
    argv = emalloc(2 * sizeof (char*));
  } else {

    /* calculate dim (argv) - 1 */
    argc = 0 ;
    while (argv [argc ++] != 0)
      ;

    /* append one more item */
    n = (++ argc) * sizeof (char*) ;
    argv = erealloc(argv, n) ;
    argv [-- argc] = 0 ;
  }

  /* append one duplicated item before the NULL entry */
  argv [-- argc] = estrdup(opt);
  return argv ;
}

ExtFunc	void	destroy_argv(char **argv)
{
  int argc ;
  if (argv == 0)
    return ;
  for (argc = 0; argv [argc] != 0; argc ++)
    efree (&argv [argc]) ;
  efree (&argv);
}
