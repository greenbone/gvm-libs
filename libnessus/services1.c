/* 
 * Copyright (C) 2002 Michel Arboi
 *
 * Some modifications (C) Tenable Network Security
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
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the Free
 * Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * TCP/IP service functions (getservent enhancement)
 */ 


#define EXPORTING
#include "includes.h"
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "services.h"

#ifndef MAP_FAILED
#define MAP_FAILED (void*)(-1)
#endif

/*
 * This file contains initialisation functions.
 * IMPORTANT ! Some options are defined in services.h
 */

struct my_svc {
  FILE		*fp;
  int		port;		/* 2 * port + proto_idx (0 = tcp, 1 = udp) */
  char		name[128];
  /* Debug */
  char		*filename;
  int		line;
};

static int
get_next_svc(struct my_svc *psvc)
{
  char		line[256], proto[32], *p;

 for (;;)
   {
     do
       {
	 if (fgets(line, sizeof(line), psvc->fp) == NULL)
	   {
	       fclose(psvc->fp);
	     return 0;
	   }
	 psvc->line ++;
       }
     while (line[0] == '#' || isspace(line[0]));

     for (p = line; ! isspace(*p) && *p != '\0'; p ++)
       ;
     if (*p == '\0')
       continue;
     *p = '\0';
     if (sscanf(p+1, "%d/%s", &psvc->port, proto) == 2
	 )
       {
	 psvc->port *= 2;
	 if (strcmp(proto, "udp") == 0)
	   psvc->port ++;
	 else if (strcmp(proto, "tcp") != 0)
	   continue;
	 psvc->name[sizeof(psvc->name) - 1] = '\0';
	 strncpy(psvc->name, line, sizeof(psvc->name) - 1);
	 return 1;
       }
   }
}

/*
 * Note: we do not take any lock, so this function should only be called
 * at Nessus startup
 */

ExtFunc int
nessus_init_svc()
{
  static int flag = 0;
  int		l, error_flag = 0, rebuild = 0;
#define N_SVC_F	5
  struct my_svc	svc[N_SVC_F];
  int		nf = 0, i, j, prev_p, prev_p_udp;
  FILE		*fpT = NULL, *fpU = NULL, *fpTXT = NULL;
  struct nessus_service	ness_svc;
  struct stat	st;
  time_t	t;

  bzero(&ness_svc, sizeof(ness_svc));

  if (flag)
    return 0;

  /* Verify files date */
  
  if (stat(NESSUS_SERVICES_TCP, &st) < 0)
    t = 0;
  else
    {
      int fd;
      char * buf;
     
      fd = open(NESSUS_SERVICES_TCP, O_RDONLY);
      if ( fd < 0 ) { perror("open "); rebuild ++; }
      else
       {
  	int len;
	len = (int)st.st_size;
        buf = mmap(NULL, len, PROT_READ, MAP_SHARED, fd, 0);
        if ( buf == MAP_FAILED || buf == NULL ){ perror("mmap "); rebuild ++; }
        else {
            struct nessus_service * s;
            s = (struct nessus_service*)(buf);
            if ( s->magic != SERVICES_MAGIC ) rebuild ++;
            munmap(buf, len);
           }
         close(fd);
	 fd = -1;
       }
      t = st.st_mtime;
      if (stat(NESSUS_SERVICES_UDP, & st) < 0)
	t = 0;
      else if ((unsigned)st.st_mtime < (unsigned)t)
	t = st.st_mtime;
    }
      
 if ( stat(NESSUS_SERVICES, &st) < 0 )
	{
	 fprintf(stderr, "**** %s could not be found. Install it and try again\n", NESSUS_SERVICES);
	 exit(1);
	}
  if (stat(NESSUS_SERVICES, &st) >= 0 && (unsigned)st.st_mtime > (unsigned)t)
    rebuild ++;
  
  if (! rebuild)
    return 0;

  /* fputs("Rebuilding Nessus services list\n", stderr); */

  for (i = 0; i < N_SVC_F; i ++)
    svc[i].line = 1;
  nf = 0;
  (void) mkdir(NESSUS_STATE_DIR, 0755);

  /*
   * Although our code is all right to parse /etc/services, we also
   * call getservent because the system may implement yellow pages or 
   * some other kind of database. getservent() is supposed to walk through it.
   */
  /* nessus-services file is supposed to be sorted */
  if ((svc[nf].fp = fopen(NESSUS_SERVICES, "r")) != NULL)
  {
    if (get_next_svc(&svc[nf]))
    {
      svc[nf].filename = NESSUS_SERVICES;
      nf ++;
    }
  }



  if (nf > 0)
    {
      if ((fpT = fopen(NESSUS_SERVICES_TCP, "w")) == NULL)
	{
	  perror(NESSUS_SERVICES_TCP);
	  error_flag ++;
	}
      else if ((fpU = fopen(NESSUS_SERVICES_UDP, "w")) == NULL)
	{
	  perror(NESSUS_SERVICES_UDP);
	  error_flag ++;
	}
      else if ((fpTXT = fopen(NESSUS_SERVICES_TXT, "w")) == NULL)
	{
	  perror(NESSUS_SERVICES_TXT);
	  error_flag ++;
	}
    }

  prev_p = prev_p_udp = -1;
  while (nf > 0 && ! error_flag)
    {
      for (j = 0, i = 1; i < nf; i ++)
	{
	  if (svc[i].port < svc[j].port)
	    j = i;
	}
      if ( ( svc[j].port % 2 == 0 && svc[j].port < prev_p     ) ||
           ( svc[j].port % 2 != 0 && svc[j].port < prev_p_udp ) ) 
	{
#if PANIC_THE_USER		
	  if (*svc[j].filename == '/') /* No warning on system base */
	  fprintf(stderr, "nessus_init_svc: %s is not sorted! Found %d/%s at the wrong place (line %d)\n",
		  svc[j].filename,
		  svc[j].port / 2, svc[j].port % 2 ? "udp" : "tcp",
		  svc[j].line);
#endif		  
	}
      else if ( (svc[j].port % 2 == 0 && svc[j].port != prev_p) || 
                (svc[j].port % 2 != 0 && svc[j].port != prev_p_udp) )
	{
	  if ( svc[j].port % 2 == 0 )
 	   prev_p = svc[j].port;
	  else
	   prev_p_udp = svc[j].port;

	  ness_svc.ns_port = svc[j].port / 2;
	  l = strlen(svc[j].name);
	  if (l > sizeof(ness_svc.ns_name) - 1)
	    l = sizeof(ness_svc.ns_name) - 1;
          ness_svc.magic = SERVICES_MAGIC;
	  memcpy(ness_svc.ns_name, svc[j].name, l);
	  memset(ness_svc.ns_name + l, 0, sizeof(ness_svc.ns_name) - l);
#ifdef ULTRA_VERBOSE_DEBUG
	  fprintf(stderr, "From %d: name=%s port=%d => %d\n",
		  j, ness_svc.ns_name, svc[j].port, ness_svc.ns_port);
#endif
	  if (svc[j].port % 2)
	    {
	      fprintf(fpTXT, "%s\t%d/udp\n", ness_svc.ns_name, ness_svc.ns_port);
	      if (fwrite(&ness_svc, sizeof(ness_svc), 1, fpU) < 1)
		{
		  perror("fwrite");
		  error_flag ++;
		}
	    }
	  else
	    {
	      fprintf(fpTXT, "%s\t%d/tcp\n", ness_svc.ns_name, ness_svc.ns_port);
	      if (fwrite(&ness_svc, sizeof(ness_svc), 1, fpT) < 1)
		{
		  perror("fwrite");
		  error_flag ++;
		}
	    }
	}
      if (! get_next_svc(&svc[j]))
	{
	  for (i = j; i < nf - 1; i ++)
	    svc[i] = svc[i+1];
	  nf --;
	}
    }

  if( fpTXT != NULL )(void) fclose(fpTXT);
  if ((fpT != NULL && fclose(fpT) < 0) || (fpU != NULL && fclose(fpU) < 0))
    {
      perror("fclose");
      error_flag ++;
    }

  if (error_flag)
    {
      for (i = 0; i < nf; i ++)
	if (svc[i].fp != NULL && svc[i].fp != (void*) 1)
	    fclose(svc[i].fp);
      unlink(NESSUS_SERVICES_TCP);
      unlink(NESSUS_SERVICES_UDP);
      unlink(NESSUS_SERVICES_TXT);
    }
  return error_flag ? -1 : 0;
}


