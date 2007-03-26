/* Nessuslib -- the Nessus Library
 * Copyright (C) 1998 - 2002 Renaud Deraison
 * SSL Support Copyright (C) 2001 Michel Arboi
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
 * Network Functions
 */ 

#define EXPORTING
#include <includes.h>
#include <stdarg.h>
#include "libnessus.h"
#include "network.h"
#include "resolve.h"
#include "ids_send.h"

#include <setjmp.h>

#ifdef HAVE_SSL
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#endif

#define TIMEOUT 20

#ifndef INADDR_NONE
#define INADDR_NONE 0xffffffff
#endif

extern int plug_get_port_transport(struct arglist*, int);
extern void plug_set_port_transport(struct arglist*, int, int);


/*----------------------------------------------------------------*
 * Low-level connection management                                *
 *----------------------------------------------------------------*/
 
/* Nessus "FILE" structure */
typedef struct {
 int fd;		/* socket number, or whatever */
 int transport;	/* "transport" layer code when stream is encapsultated. 
		 * Negative transport signals a free descriptor */
 int timeout;	  /* timeout, in seconds
		   * special values: -2 for default */
 int options;			/* Misc options - see libnessus.h */
  
 int port;			 
#ifdef HAVE_SSL
  SSL_CTX* 	ssl_ctx;	/* SSL context 	*/
  SSL_METHOD* 	ssl_mt;		/* SSL method   */
  SSL* 		ssl;		/* SSL handler  */
  int		last_ssl_err;	/* Last SSL error code */
#endif
 pid_t		pid;		/* Owner - for debugging only */

  char*		buf;		/* NULL if unbuffered */
  int		bufsz, bufcnt, bufptr;
  int 		last_err;
} nessus_connection;

/* 
 * The role of this offset is:
 * 1. To detect bugs when the program tries to write to a bad fd
 * 2. See if a fd is a real socket or a "nessus descriptor". This is a
 * quick & dirty hack and should be changed!!!
 */
#define NESSUS_FD_MAX 1024
#define NESSUS_FD_OFF 1000000

static nessus_connection connections[NESSUS_FD_MAX];

/*
 * Quick & dirty patch to run Nessus from behind a picky firewall (e.g.
 * FW/1 and his 'Rule 0'): Nessus will never open more than 1 connection at
 * a time.
 * Define NESSUS_CNX_LOCK, recompile and install nessus-library, and restart nessusd
 *
 * WARNING: waiting on the lock file may be long, so increase the default
 * script timeout or some scripts may be killed.
 */
#undef NESSUS_CNX_LOCK
/*#define NESSUS_CNX_LOCK	"/tmp/NessusCnx"*/

#ifdef NESSUS_CNX_LOCK
static int	lock_cnt = 0;
static int	lock_fd = -1;
#endif

/*
 * NESSUS_STREAM(x) is TRUE if <x> is a Nessus-ified fd
 */
#define NESSUS_STREAM(x) (((x - NESSUS_FD_OFF) < NESSUS_FD_MAX) && ((x - NESSUS_FD_OFF) >=0))


static void
renice_myself()
{
 static pid_t pid = 0;
 pid_t cpid = getpid();
 
 if( pid != cpid )
 {
  if(nice(0) >= 10)return;
  pid = cpid;
  nice(1);
 }
}
/*
 * Same as perror(), but prefixes the data by our pid
 */
static int 
nessus_perror(error)
 const char* error;
{
  fprintf(stderr, "[%d] %s : %s\n", getpid(), error, strerror(errno));
  return 0;
}

/*
 * Returns the amount of data waiting to be read in the socket
 * or -1 in case of an error (errno will be set)
 */
#if 0
static int data_left(soc)
 int soc;
{
 int len = 0;
 int ret = ioctl(soc, FIONREAD, &len);
 if (ret >= 0) {
  if(len <= 0)
   return 0;
  else 
   return len;
 }
 else {
  nessus_perror("ioctl(FIONREAD)");
  return -1;
 }
} /* data_left */
#endif

int
stream_get_err(fd)
 int fd;
{
 nessus_connection *p;
 
 if(!NESSUS_STREAM(fd))
    {
     errno = EINVAL;
     return -1;
    }
    
    
 p = &(connections[fd - NESSUS_FD_OFF]);
 return p->last_err;
}

/*
 * Returns a free file descriptor
 */
static int
get_connection_fd()
{
 int i;
 
 for ( i = 0; i < NESSUS_FD_MAX ; i++)
 {
  if(connections[i].transport <= 0) /* Not used */
  {
   bzero(&(connections[i]),  sizeof(connections[i]));
   connections[i].pid = getpid();
   return i + NESSUS_FD_OFF;
  }
 }
 fprintf(stderr, "[%d] %s:%d : Out of Nessus file descriptors\n", 
	 getpid(), __FILE__, __LINE__);
 errno = EMFILE;
 return -1;
}



static int
release_connection_fd(fd)
 int fd;
{
 nessus_connection *p;
 
 if(!NESSUS_STREAM(fd))
    {
     errno = EINVAL;
     return -1;
    }
    
    
 p = &(connections[fd - NESSUS_FD_OFF]);

 efree(&p->buf);

#ifdef HAVE_SSL
 if (p->ssl != NULL)
  SSL_free(p->ssl);
 if (p->ssl_ctx != NULL)
  SSL_CTX_free(p->ssl_ctx);
#endif

/* 
 * So far, fd is always a socket. If this is changed in the future, this
 * code shall be fixed
 */
if (p->fd >= 0)
 {
  if (shutdown(p->fd, 2) < 0)
    {
#if DEBUG_SSL > 1
    /*
     * It's not uncommon to see that one fail, since a lot of
     * services close the connection before we ask them to
     * (ie: http), so we don't show this error by default
     */
    nessus_perror("release_connection_fd: shutdown()");
#endif    
    }
  if (socket_close(p->fd)  < 0)
    nessus_perror("release_connection_fd: close()");
 }
 bzero(p, sizeof(*p));
 p->transport = -1; 
 return 0;
}

/* ******** Compatibility function ******** */

ExtFunc int
nessus_register_connection(s, ssl)
     int	s;
#ifdef HAVE_SSL
     SSL	*ssl;
#else
     void	*ssl;
#endif
{
  int			fd;
  nessus_connection	*p;

  if((fd = get_connection_fd()) < 0)
    return -1;
  p = connections + (fd - NESSUS_FD_OFF);
#ifdef HAVE_SSL 
  p->ssl_ctx = NULL;
  p->ssl_mt = NULL;		/* shall be freed elsewhere */
  p->ssl = ssl;			/* will be freed on close */
#endif  
  p->timeout = TIMEOUT;		/* default value */
  p->port = 0;			/* just used for debug */
  p->fd = s;
  p->transport = (ssl != NULL) ? NESSUS_ENCAPS_SSLv23 : NESSUS_ENCAPS_IP;
  p->last_err  = 0;
  return fd;
}

ExtFunc int
nessus_deregister_connection(fd)
 int fd;
{
 nessus_connection * p;
 if(!NESSUS_STREAM(fd))
 {
  errno = EINVAL;
  return -1;
 }
 
 p = connections +  (fd - NESSUS_FD_OFF);
 bzero(p, sizeof(*p));
 p->transport = -1; 
 return 0;
}

/*----------------------------------------------------------------*
 * High-level connection management                               *
 *----------------------------------------------------------------*/

static int __port_closed;

static int unblock_socket(int soc)
{
  int	flags =  fcntl(soc, F_GETFL, 0);
  if (flags < 0)
{
      nessus_perror("fcntl(F_GETFL)");
      return -1;
    }
  if (fcntl(soc, F_SETFL, O_NONBLOCK | flags) < 0)
    {
      nessus_perror("fcntl(F_SETFL,O_NONBLOCK)");
      return -1;
    }
  return 0;
}

static int block_socket(int soc)
{
  int	flags =  fcntl(soc, F_GETFL, 0);
  if (flags < 0)
    {
      nessus_perror("fcntl(F_GETFL)");
      return -1;
    }
  if (fcntl(soc, F_SETFL, (~O_NONBLOCK) & flags) < 0)
    {
      nessus_perror("fcntl(F_SETFL,~O_NONBLOCK)");
      return -1;
    }
  return 0;
}

/*
 * Initialize the SSL library (error strings and algorithms) and try
 * to set the pseudo random generator to something less silly than the
 * default value: 1 according to SVID 3, BSD 4.3, ISO 9899 :-(
 */

#ifdef HAVE_SSL
/* Adapted from stunnel source code */
ExtFunc
void sslerror2(txt, err)
     char	*txt;
     int	err;
{
  char string[120];

  ERR_error_string(err, string);
  fprintf(stderr, "[%d] %s: %s\n", getpid(), txt, string);
}

void
sslerror(txt)
     char	*txt;
{
  sslerror2(txt, ERR_get_error());
}
#endif

ExtFunc int
nessus_SSL_init(path)
     char	*path;		/* entropy pool file name */
{
#ifdef HAVE_SSL
  SSL_library_init();
  SSL_load_error_strings();

#ifdef HAVE_RAND_STATUS
  if (RAND_status() == 1)
    {
    /* The random generator is happy with its current entropy pool */
    return 0;
   }
#endif


  /*
   * Init the random generator
   *
   * OpenSSL provides nice functions for this job.
   * OpenSSL also ensures that each thread uses a different seed.
   * So this function should be called *before* forking.
   * Cf. http://www.openssl.org/docs/crypto/RAND_add.html#
   *
   * On systems that have /dev/urandom, SSL uses it transparently to seed 
   * its PRNG
   */

 
#if 0
  RAND_screen();	/* Only available under MSWin */
#endif

#ifdef EGD_PATH
  /*
   * We have the entropy gathering daemon.
   * However, OpenSSL automatically query it if it is not in some odd place
   */
  if(RAND_egd(EGD_PATH) > 0)
	  return 0;
#endif

   if (path != NULL)
    {
    (void) RAND_load_file(path, -1);
    RAND_write_file(path);
    }
   else
   {
    /*
     * Try with the default path
     */
    char path[1024];
    if(RAND_file_name(path, sizeof(path) - 1) == 0)
	    return -1;
    path[sizeof(path) - 1] = '\0';
    if(RAND_load_file(path, -1) < 0)
	    return -1;
    RAND_write_file(path);	
    return 0;
   } 
#endif
   return -1;
}

#ifdef HAVE_SSL
# if 0
ExtFunc void
nessus_print_SSL_certificate(cert)
     X509* cert;    
{
 BIO * b;
 BUF_MEM * bptr;
 char * ret = NULL;
 int	i;

 if(cert == NULL)
   return;

 b = BIO_new(BIO_s_mem());
 if(X509_print(b, cert) > 0)
   {
     BIO_get_mem_ptr(b, &bptr);
     printf("* Peer certificate *\n");
     for(i = 0; i < bptr->length; i ++)
       putchar(bptr->data[i]);
     printf("\n********************\n");
   }
 BIO_free(b);
}

ExtFunc void
nessus_print_peer_SSL_certificate(ssl)
     SSL* ssl;
{
  X509 * cert = SSL_get_peer_certificate(ssl);
  nessus_print_SSL_certificate(cert);
}
# endif
#endif


static int
nessus_SSL_password_cb(buf, size, rwflag, userdata)
     char *buf;
     int size;
     int rwflag;
     void *userdata;
{
  if (userdata != NULL)
    {
      buf[size - 1] = '\0';
      strncpy(buf, userdata, size - 1);
      return strlen(buf);
    }
  else
    {
#if DEBUG_SSL > 1
      fprintf(stderr, "nessus_SSL_password_cb: returning empty password\n");
#endif
      *buf = '\0';
      return 0;
    }
}

ExtFunc int
nessus_get_socket_from_connection(fd)
     int	fd;
{
  nessus_connection	*fp;

  if (!NESSUS_STREAM(fd))
    {
      fprintf(stderr,
	      "[%d] nessus_get_socket_from_connection: bad fd <%d>\n", getpid(), fd);
      fflush(stderr);
      return fd;
    }
  fp = connections + (fd - NESSUS_FD_OFF);
  if(fp->transport <= 0)
    {
      fprintf(stderr, "nessus_get_socket_from_connection: fd <%d> is closed\n", fd);
      return -1;
    }
  return fp->fd;
}


#ifdef HAVE_SSL
ExtFunc void
nessus_install_passwd_cb(ssl_ctx, pass)
     SSL_CTX	*ssl_ctx;
     char	*pass;
{
  SSL_CTX_set_default_passwd_cb(ssl_ctx, nessus_SSL_password_cb);
  SSL_CTX_set_default_passwd_cb_userdata(ssl_ctx, pass);
}

static int
open_SSL_connection(fp, timeout, cert, key, passwd, cert_names)
     nessus_connection	*fp;
     int		timeout;
     char		*cert, *key, *passwd; 
     STACK_OF(X509_NAME)	*cert_names;
{
  int		ret, err, d;
  time_t	tictac;
  fd_set	fdw, fdr;
  struct timeval	to;


  nessus_SSL_init(NULL);

  switch (fp->transport)
    {
    case NESSUS_ENCAPS_SSLv2:
      fp->ssl_mt = SSLv2_client_method();
      break;
    case NESSUS_ENCAPS_SSLv3:
      fp->ssl_mt = SSLv3_client_method();
      break;
    case NESSUS_ENCAPS_TLSv1:
      fp->ssl_mt = TLSv1_client_method();
      break;
    case NESSUS_ENCAPS_SSLv23:	/* Compatibility mode */
      fp->ssl_mt = SSLv23_client_method();
      break;
      
    default:
#if DEBUG_SSL > 0
      fprintf(stderr, "*Bug* at %s:%d. Unknown transport %d\n",
	      __FILE__, __LINE__, fp->transport);
#endif
      fp->ssl_mt = SSLv23_client_method();
      break;
    }

  if((fp->ssl_ctx = SSL_CTX_new(fp->ssl_mt)) == NULL)
    return -1;

  if (SSL_CTX_set_options(fp->ssl_ctx, SSL_OP_ALL) < 0)
    sslerror("SSL_CTX_set_options(SSL_OP_ALL)");

  if ((fp->ssl = SSL_new(fp->ssl_ctx)) == NULL)
    return -1;

  /* Client certificates should not be used if we are in SSLv2 */
  if (fp->transport != NESSUS_ENCAPS_SSLv2) {
  SSL_CTX_set_default_passwd_cb(fp->ssl_ctx, nessus_SSL_password_cb);
  SSL_CTX_set_default_passwd_cb_userdata(fp->ssl_ctx, passwd);

  if (cert != NULL)
    SSL_use_certificate_file(fp->ssl, cert, SSL_FILETYPE_PEM);
  if (key != NULL)
#if 1
    SSL_use_PrivateKey_file(fp->ssl, key, SSL_FILETYPE_PEM);
#else
    SSL_use_RSAPrivateKey_file(fp->ssl, key, SSL_FILETYPE_PEM);
#endif

    if (cert_names != NULL)
      SSL_CTX_set_client_CA_list(fp->ssl_ctx, cert_names);
    }

  unblock_socket(fp->fd);

  if(! (ret = SSL_set_fd(fp->ssl, fp->fd)))
    {
#if DEBUG_SSL > 0
      sslerror("SSL_set_fd");
#endif    
      return -1;
    }
    
  tictac = time(NULL);
  for (;;)
    {
  ret = SSL_connect(fp->ssl);
#if 0
      block_socket(fp->fd);
#endif
      if (ret > 0)
	return ret;

      fp->last_ssl_err = err = SSL_get_error(fp->ssl, ret);
      FD_ZERO(&fdr); FD_ZERO(&fdw);
      switch (err)
    {
	case SSL_ERROR_WANT_READ:
#if DEBUG_SSL > 2
	  fprintf(stderr, "SSL_Connect[%d]: SSL_ERROR_WANT_READ\n", getpid());
#endif
	  FD_SET(fp->fd, &fdr);
	  break;
	case SSL_ERROR_WANT_WRITE:
#if DEBUG_SSL > 2
	  fprintf(stderr, "SSL_Connect[%d]: SSL_ERROR_WANT_WRITE\n", getpid());
#endif	
	  FD_SET(fp->fd, &fdw);
	  break;
	default:
#ifdef DEBUG_SSL 
	  sslerror2("SSL_connect", err);
#endif
      	  return -1;
    }
     
      do
	{
	  d = tictac + timeout - time(NULL);
	  if (d <= 0)
	    {
	    fp->last_err = ETIMEDOUT;
	    return -1;
            }
	  to.tv_sec = d;
	  to.tv_usec = 0;
	  errno = 0;
	  if ((ret = select(fp->fd + 1, &fdr, &fdw, NULL, &to)) <= 0)
	    {
#if DEBUG_SSL > 1
	      nessus_perror("select");
#endif	
	    }
	}
      while (ret < 0 && errno == EINTR);
      if (ret <= 0)
	{
	fp->last_err = ETIMEDOUT;
	return -1;
        }
    }
  /*NOTREACHED*/
}
#endif


static void
set_ids_evasion_mode(args, fp)
     struct arglist	*args;
     nessus_connection	*fp;
{
 struct kb_item ** kb = plug_get_kb(args);
 char		*ids_evasion_split = kb_item_get_str(kb, "NIDS/TCP/split");
 char 		*ids_evasion_inject = kb_item_get_str(kb, "NIDS/TCP/inject");
 char 		*ids_evasion_short_ttl = kb_item_get_str(kb,"NIDS/TCP/short_ttl");
 char		*ids_evasion_fake_rst = kb_item_get_str(kb, "NIDS/TCP/fake_rst");
 int option = 0;
 
 
 /*
  * These first three options are mutually exclusive
  */
 if(ids_evasion_split != NULL && strcmp(ids_evasion_split, "yes") == 0)
 	option = NESSUS_CNX_IDS_EVASION_SPLIT;

 if(ids_evasion_inject != NULL && strcmp(ids_evasion_inject, "yes") == 0)
 	option = NESSUS_CNX_IDS_EVASION_INJECT;
 
 if(ids_evasion_short_ttl != NULL && strcmp(ids_evasion_short_ttl, "yes") == 0)
 	option = NESSUS_CNX_IDS_EVASION_SHORT_TTL;


 /*
  * This is not exclusive with the above
  */
 if(ids_evasion_fake_rst != NULL && strcmp(ids_evasion_fake_rst, "yes") == 0)
 	option |= NESSUS_CNX_IDS_EVASION_FAKE_RST;

 if(option)
   {
#ifdef SO_SNDLOWAT
     int		n = 1;
     (void) setsockopt(fp->fd, SOL_SOCKET, SO_SNDLOWAT, (void*)&n, sizeof(n));
#endif
     fp->options |= option;
   }
}

ExtFunc int
open_stream_connection(args, port, transport, timeout)
 struct arglist * args;
 unsigned int port;
 int transport, timeout;
{
 int			fd;
 nessus_connection * fp;
#ifdef HAVE_SSL
 char * cert   = NULL;
 char * key    = NULL;
 char * passwd = NULL;
 char * cafile = NULL;
 STACK_OF(X509_NAME)	*cert_names = NULL;
#endif

#if DEBUG_SSL > 2
 fprintf(stderr, "[%d] open_stream_connection: TCP:%d transport:%d timeout:%d\n",
       getpid(), port, transport, timeout);
#endif

 if(timeout == -2)
  timeout = TIMEOUT;
  
 switch(transport)
 {
  case NESSUS_ENCAPS_IP:
#ifdef HAVE_SSL
  case NESSUS_ENCAPS_SSLv2:
  case NESSUS_ENCAPS_SSLv23:
  case NESSUS_ENCAPS_SSLv3:
  case NESSUS_ENCAPS_TLSv1:
#endif 
   break;
  default:
   fprintf(stderr, "open_stream_connection(): unsupported transport layer %d\n",
   	transport);
   errno = EINVAL;
   return -1;
 }
 
 if((fd = get_connection_fd()) < 0)
  return -1;
 
 fp = &(connections[fd - NESSUS_FD_OFF]);
 
 
 fp->transport = transport;
 fp->timeout   = timeout;
 fp->port      = port;
 fp->last_err  = 0;
 set_ids_evasion_mode(args, fp);

 if(fp->options & NESSUS_CNX_IDS_EVASION_FAKE_RST)
   fp->fd = ids_open_sock_tcp(args, port, fp->options, timeout);
 else
   fp->fd = open_sock_tcp(args, port, timeout);
	
  if(fp->fd < 0)
	  goto failed;

 switch(transport)
 {
  case NESSUS_ENCAPS_IP:
    break;
#ifdef HAVE_SSL
  case NESSUS_ENCAPS_SSLv23:
  case NESSUS_ENCAPS_SSLv3:
  case NESSUS_ENCAPS_TLSv1:
    renice_myself();
    cert   = kb_item_get_str(plug_get_kb(args), "SSL/cert");
    key    = kb_item_get_str(plug_get_kb(args), "SSL/key");
    passwd = kb_item_get_str(plug_get_kb(args), "SSL/password");

    cafile = kb_item_get_str(plug_get_kb(args), "SSL/CA");

    if ((cafile != NULL) && cafile[0] != '\0')
      {
	cert_names = SSL_load_client_CA_file(cafile);
	if (cert_names == NULL)
	  {
	    char	msg[512];
	    snprintf(msg, sizeof(msg), "SSL_load_client_CA_file(%s)", cafile);
	    sslerror(msg);
	  }
     }
   
  case NESSUS_ENCAPS_SSLv2:
    /* We do not need a client certificate in this case */

    if (open_SSL_connection(fp, timeout, cert, key, passwd, cert_names) <= 0)
    goto failed;
  break;
#endif
 }
 
 return fd;

failed:
 release_connection_fd(fd);
 return -1;
}


ExtFunc int
open_stream_connection_unknown_encaps5(args, port, timeout, p, delta_t)
 struct arglist * args;
 unsigned int  port;
 int timeout, * p;
 int	*delta_t;		/* time, in micro-seconds */
{
 int fd;
 int i;
  struct timeval	tv1, tv2;
 static int encaps[] = {
#ifdef HAVE_SSL
   NESSUS_ENCAPS_SSLv2,
   NESSUS_ENCAPS_TLSv1,
   NESSUS_ENCAPS_SSLv3,
#endif
    NESSUS_ENCAPS_IP
  };
 
#if DEBUG_SSL > 2
 fprintf(stderr, "[%d] open_stream_connection_unknown_encaps: TCP:%d; %d\n",
	 getpid(), port,timeout);
#endif

 for (i = 0; i < sizeof(encaps) / sizeof(*encaps); i ++)
    {
      if (delta_t != NULL) (void) gettimeofday(&tv1, NULL);
   if ((fd = open_stream_connection(args, port, encaps[i], timeout)) >= 0)
     {
       *p = encaps[i];
#if DEBUG_SSL > 2
       fprintf(stderr, "[%d] open_stream_connection_unknown_encaps: TCP:%d -> transport=%d\n", getpid(), port, *p);
#endif
	  if (delta_t != NULL)
	    {
	      (void) gettimeofday(&tv2, NULL);
	      *delta_t = (tv2.tv_sec - tv1.tv_sec) * 1000000 + (tv2.tv_usec - tv1.tv_usec);
	    }
       return fd;
     }
   else if (__port_closed)
     {
#if DEBUG_SSL > 2
       fprintf(stderr, "[%d] open_stream_connection_unknown_encaps: TCP:%d -> closed\n", getpid(), port);
#endif
       return -1;
     }
    }
  return -1;
 }
 
ExtFunc int
open_stream_connection_unknown_encaps(args, port, timeout, p)
 struct arglist * args;
 unsigned int  port;
 int timeout, * p;
{
  return open_stream_connection_unknown_encaps5(args, port, timeout, p, NULL);
}


ExtFunc int
open_stream_auto_encaps(args, port, timeout)
 struct arglist * args;
 unsigned int     port;
 int              timeout;
{
 int trp = plug_get_port_transport(args, port);
 int fd;
 
 if(trp == 0)
 {
  if ((fd = open_stream_connection_unknown_encaps(args, port, timeout, &trp)) < 0)
   return -1;
  plug_set_port_transport(args, port, trp);
  return fd;
 }
 else
 {
  fd = open_stream_connection(args, port, trp, timeout);
  return fd;
 }
 /*NOTREACHED*/
}


#ifdef HAVE_SSL
ExtFunc SSL*
stream_get_ssl(fd)
     int	fd;
{
 nessus_connection * fp;
 if(!NESSUS_STREAM(fd))
    {
     errno = EINVAL;
     return NULL;
    }
  fp = &(connections[fd - NESSUS_FD_OFF]);
  if (fp->transport <= 0)
    return NULL;
  else
    return fp->ssl;
}

#endif

ExtFunc int
stream_set_timeout(fd, timeout)
 int fd;
 int timeout;
{
 int old;
 nessus_connection * fp;
 if(!NESSUS_STREAM(fd))
    {
     errno = EINVAL;
     return 0;
    }
  fp = &(connections[fd - NESSUS_FD_OFF]);
  old = fp->timeout;
  fp->timeout = timeout;
  return old;
}

ExtFunc int
stream_set_options(fd, reset_opt, set_opt)
     int	fd, reset_opt, set_opt;
{
 nessus_connection * fp;
 if(!NESSUS_STREAM(fd))
    {
     errno = EINVAL;
     return -1;
    }
  fp = &(connections[fd - NESSUS_FD_OFF]);
  fp->options &= ~reset_opt;
  fp->options |= set_opt;
  return 0;
}


static int 
read_stream_connection_unbuffered(fd, buf0, min_len, max_len)
 int fd;
 void* buf0;
 int min_len, max_len;
{
  int			ret, realfd, trp, t, err;
  int			total = 0, flag = 0, timeout = TIMEOUT, waitall = 0;
  unsigned char		* buf = (unsigned char*)buf0;
  nessus_connection	*fp = NULL;
  fd_set		fdr, fdw;
  struct timeval	tv;
  time_t		now, then;

  int		 	select_status;
 
#if 0
  fprintf(stderr, "read_stream_connection(%d, 0x%x, %d, %d)\n",
	  fd, buf, min_len, max_len);
#endif

  if (NESSUS_STREAM(fd))
    {
      fp = &(connections[fd - NESSUS_FD_OFF]);
      trp = fp->transport;
      realfd = fp->fd;
      fp->last_err = 0;
      if (fp->timeout != -2)
	timeout = fp->timeout;
    }
  else
    {
#if 0
      fprintf(stderr, "read_stream_connection[%d] : supposedly bad fd %d\n",
	      getpid(), fd);
#endif
      trp = NESSUS_ENCAPS_IP;
      if(fd < 0 || fd > 1024)
	      	{
			errno = EBADF;
			return -1;
		}
      realfd = fd;
    }

#ifndef INCR_TIMEOUT
# define INCR_TIMEOUT	1
#endif

#ifdef MSG_WAITALL
  if (min_len == max_len || timeout <= 0)
    waitall = MSG_WAITALL;
#endif

  if(trp == NESSUS_ENCAPS_IP)
    {
      for (t = 0; total < max_len && (timeout <= 0 || t < timeout); )
	{
	  tv.tv_sec = INCR_TIMEOUT; /* Not timeout! */
	  tv.tv_usec = 0;
	  FD_ZERO(&fdr);
	  FD_SET(realfd, &fdr);
	  if(select(realfd + 1, &fdr, NULL, NULL, timeout > 0 ? &tv : NULL) <= 0)
	    {
	      t += INCR_TIMEOUT;
	      /* Try to be smart */
	      if (total > 0 && flag) 
		return total;
	      else if (total >= min_len)
		flag ++;
	    }
	  else
	    {
	      errno = 0;
	      ret = recv(realfd, buf + total, max_len - total, waitall);
	      if (ret < 0)
		if (errno != EINTR)
                  {
		  fp->last_err = errno;
		  return total;
                  }
		else
		  ret = 0;
	      else if (ret == 0) /* EOF */
                {
                fp->last_err = EPIPE;
		return total;
                }
	      /*ret > 0*/
	      total += ret; 
	      if (min_len > 0 && total >= min_len)
		return total;
	      flag = 0;
	    }
	}
      if ( t >= timeout ) fp->last_err = ETIMEDOUT;
      return total;
    }

  switch(trp)
    {
      /* NESSUS_ENCAPS_IP was treated before with the non-Nessus fd */
#ifdef HAVE_SSL
    case NESSUS_ENCAPS_SSLv2:
    case NESSUS_ENCAPS_SSLv23:
    case NESSUS_ENCAPS_SSLv3:
    case NESSUS_ENCAPS_TLSv1:
# if DEBUG_SSL > 0
      if (getpid() != fp->pid)
	{
	  fprintf(stderr, "PID %d tries to use a SSL connection established by PID %d\n", getpid(), fp->pid);
	  errno = EINVAL;
	  return -1;
	}
# endif

      FD_ZERO(&fdr); FD_ZERO(&fdw);
      FD_SET(realfd, &fdr); FD_SET(realfd, &fdw); 
      now = then = time(NULL);
      for (t = 0; timeout <= 0 || t < timeout; t = now - then )
	{	
          now = time(NULL);
	  tv.tv_sec = INCR_TIMEOUT; tv.tv_usec = 0;
	  select_status = select ( realfd + 1, &fdr, &fdw, NULL, &tv );
          if ( select_status == 0 )
          {
      	   FD_ZERO(&fdr); FD_ZERO(&fdw);
      	   FD_SET(realfd, &fdr); FD_SET(realfd, &fdw); 
          }
	  else
	  if ( select_status > 0 )
	    {
	  ret = SSL_read(fp->ssl, buf + total, max_len - total);
	  if (ret > 0)
		{
	          total += ret;
		  FD_SET(realfd, &fdr);
		  FD_SET(realfd, &fdw); 
		}

	  if (total >= max_len)
	    return total;
	      if (ret <= 0)
		{
		  err = SSL_get_error(fp->ssl, ret);
		  FD_ZERO(&fdr); 
		  FD_ZERO(&fdw);
		  switch (err)
	   {
		    case SSL_ERROR_WANT_READ:
#if DEBUG_SSL > 2
		      fprintf(stderr, "SSL_read[%d]: SSL_ERROR_WANT_READ\n", getpid());
#endif
		      FD_SET(realfd, &fdr);
		      break;
		    case SSL_ERROR_WANT_WRITE:
#if DEBUG_SSL > 2
		      fprintf(stderr, "SSL_Connect[%d]: SSL_ERROR_WANT_WRITE\n", getpid());
#endif
		      FD_SET(realfd, &fdr);
		      FD_SET(realfd, &fdw);
		      break;

		    case SSL_ERROR_ZERO_RETURN:
#if DEBUG_SSL > 2
		      fprintf(stderr, "SSL_Connect[%d]: SSL_ERROR_ZERO_RETURN\n", getpid());
#endif
		      fp->last_err = EPIPE;
		      return total;

		    default:
#if DEBUG_SSL > 0
		      sslerror2("SSL_read", err);
#endif
		      fp->last_err = EPIPE;
		      return total;
		    }
		}
	    }

	    if (min_len <= 0)
	      {
		/* Be smart */
		if (total > 0 && flag)
		  return total;
		else
		  flag ++;
	      }
	  else if (total >= min_len)
		return total;
	}
      if ( t >= timeout ) fp->last_err = ETIMEDOUT;
      return total;
#endif
    default :
      if (fp->transport != -1 || fp->fd != 0)
	fprintf(stderr, "Severe bug! Unhandled transport layer %d (fd=%d)\n",
		fp->transport, fd);
      else
	fprintf(stderr, "read_stream_connection_unbuffered: fd=%d is closed\n", fd);
      errno = EINVAL;
      return -1;
    }
  /*NOTREACHED*/
}

ExtFunc int 
read_stream_connection_min(fd, buf0, min_len, max_len)
 int fd;
 void* buf0;
 int min_len, max_len;
{
  nessus_connection	*fp;

  if (NESSUS_STREAM(fd))
    {
      fp = &(connections[fd - NESSUS_FD_OFF]);
      if (fp->buf != NULL)
	{
	  int		l1, l2;

	  if (max_len == 1) min_len = 1; /* avoid "magic read" later */
	  l2 = max_len > fp->bufcnt ? fp->bufcnt : max_len;
	  if (l2 > 0)
	    {
	      memcpy(buf0, fp->buf + fp->bufptr, l2);
	      fp->bufcnt -= l2;
	      if (fp->bufcnt == 0)
		{
		  fp->bufptr = 0;
		  fp->buf[0] = '\0'; /* debug */
		}
	      else
		fp->bufptr += l2;
	      if (l2 >= min_len || l2 >= max_len)
		return l2;
	      max_len -= l2;
	      min_len -= l2;
	    }
	  if (min_len > fp->bufsz)
	    {
	      l1 = read_stream_connection_unbuffered(fd, (char*)buf0 + l2,
						     min_len, max_len);
	      if (l1 > 0)
		return l1 + l2;
	      else
		return l2;
	    }
	  /* Fill buffer */
	  l1 = read_stream_connection_unbuffered(fd, fp->buf, min_len, fp->bufsz);
	  if (l1 <= 0)
	    return l2;
	  
	  fp->bufcnt = l1;
	  l1 = max_len > fp->bufcnt ? fp->bufcnt : max_len;
	  memcpy((char*)buf0 + l2, fp->buf + fp->bufptr, l1);
	  fp->bufcnt -= l1;
	  if (fp->bufcnt == 0)
	    fp->bufptr = 0;
	  else
	    fp->bufptr += l1;
	  return l1 + l2;
	}
    }
  return read_stream_connection_unbuffered(fd, buf0, min_len, max_len);
}

ExtFunc int 
read_stream_connection(fd, buf0, len)
 int fd;
 void* buf0;
 int len;
{
 return read_stream_connection_min(fd, buf0, -1, len);
}

static int
write_stream_connection4(fd, buf0, n, i_opt) 
 int fd;
 void * buf0;
 int n;
 int	i_opt;
{
  int			err, ret, count;
 unsigned char* buf = (unsigned char*)buf0;
 nessus_connection * fp;
  fd_set		fdr, fdw;
  struct timeval	tv;
  int e;

 if(!NESSUS_STREAM(fd))
   {
#if DEBUG_SSL > 0
     fprintf(stderr, "write_stream_connection: fd <%d> invalid\n", fd);
# if 0
     abort();
# endif
#endif
     errno = EINVAL;
     return -1;
    }

 fp = &(connections[fd - NESSUS_FD_OFF]);
 fp->last_err = 0;
 
#if DEBUG_SSL > 8
 fprintf(stderr, "> write_stream_connection(%d, 0x%x, %d, 0x%x) \tE=%d 0=0x%x\n",
	 fd, buf, n, i_opt, fp->transport, fp->options);
#endif

 switch(fp->transport)
 {
  case NESSUS_ENCAPS_IP:
   for(count = 0; count < n;)
   {
     if ((fp->options & NESSUS_CNX_IDS_EVASION_SEND_MASK) != 0)
     {
      if(fp->options & NESSUS_CNX_IDS_EVASION_SPLIT)
       /* IDS evasion */
       ret = send(fp->fd, buf + count, 1, i_opt);
     else 
       /* i_opt ignored for ids_send */
     	ret = ids_send(fp->fd, buf + count, n - count, fp->options);
     }
     else
       ret = send(fp->fd, buf + count, n - count, i_opt);

    if(ret <= 0)
      {
       if ( ret < 0 ) fp->last_err = errno;
       else fp->last_err = EPIPE;
       break;
      }
     
     count += ret;
    }
    break;

#ifdef HAVE_SSL
  case NESSUS_ENCAPS_SSLv2:
  case NESSUS_ENCAPS_SSLv23:
  case NESSUS_ENCAPS_SSLv3:
  case NESSUS_ENCAPS_TLSv1:
      FD_ZERO(&fdr); FD_ZERO(&fdw); 
      FD_SET(fp->fd, & fdr); FD_SET(fp->fd, & fdw);

      /* i_opt ignored for SSL */
    for(count = 0; count < n;)
    { 
     ret = SSL_write(fp->ssl, buf + count, n - count);
	  if (ret > 0)
	    count += ret;
	  else
	    {
	      fp->last_ssl_err = err = SSL_get_error(fp->ssl, ret);
	      FD_ZERO(&fdw); FD_ZERO(&fdr); 
	      if (err == SSL_ERROR_WANT_WRITE)
		{
		  FD_SET(fp->fd, &fdw);
#if DEBUG_SSL > 2
		  fprintf(stderr, "SSL_write[%d]: SSL_ERROR_WANT_WRITE\n", getpid());
#endif    
     }
	      else if (err == SSL_ERROR_WANT_READ)
		{
#if DEBUG_SSL > 2
		  fprintf(stderr, "SSL_write[%d]: SSL_ERROR_WANT_READ\n", getpid());
#endif
		  FD_SET(fp->fd, &fdr);
		}
	      else
     { 
#if DEBUG_SSL > 0
		  sslerror2("SSL_write", err);
#endif      
		  fp->last_err = EPIPE;
  	break;
     }
	      if (fp->timeout >= 0)
		tv.tv_sec = fp->timeout;
     else 
		tv.tv_sec = TIMEOUT;

	      tv.tv_usec = 0;
 	      do {
 	      errno = 0;
	      e = select(fp->fd+1, &fdr, &fdw, NULL, &tv);
 	      } while ( e < 0 && errno == EINTR );

	    if ( e <= 0 )
		{
#if DEBUG_SSL > 0
		  nessus_perror("select");
#endif
		  fp->last_err = ETIMEDOUT;
		  break;
		}
	    }
     }
    break;
#endif
   default:
     if (fp->transport != -1 || fp->fd != 0)
       fprintf(stderr, "Severe bug! Unhandled transport layer %d (fd=%d)\n",
	       fp->transport, fd);
     else
       fprintf(stderr, "read_stream_connection_unbuffered: fd=%d is closed\n", fd);
     errno =EINVAL;
     return -1;
  }
  
  
  if(count == 0 && n > 0)
   return -1;
  else 
   return count;
}

ExtFunc int
write_stream_connection(fd, buf0, n) 
 int fd;
 void * buf0;
 int n;
{
  return write_stream_connection4(fd, buf0, n, 0);
}

ExtFunc int
nsend (fd, data, length, i_opt)
 int fd;
 void * data;
 int length, i_opt;
{
  int		n = 0;

 if(NESSUS_STREAM(fd))
 {
  if(connections[fd - NESSUS_FD_OFF].fd < 0)
   fprintf(stderr, "Nessus file descriptor %d closed ?!\n", fd);
  else 
    return write_stream_connection4(fd, data, length, i_opt);
 }
#if DEBUG_SSL > 1
 else
   fprintf(stderr, "nsend[%d]: fd=%d\n", getpid(), fd);
#endif
#if 0
   for (i = 0; i < NESSUS_FD_MAX; i ++)
     if (connections[i].fd == fd && connections[i].transport > 0)
       {
	 /* Fixing a severe bug! */
	 fprintf(stderr, "nsend: fd=%d used by Nessus FD %d\n",
		 fd, i + NESSUS_FD_OFF);
	 return write_stream_connection4(i + NESSUS_FD_OFF, data, length, i_opt);
       }
#endif
 /* Trying OS's send() */
   block_socket(fd);		/* ??? */
   do
 {
       struct timeval tv = {0,5};
       fd_set wr;
       int e;
       
       FD_ZERO(&wr);
       FD_SET(fd, &wr);
       
       errno = 0;
       e  = select(fd + 1, NULL, &wr, NULL, &tv);
       if ( e > 0 )
        n = os_send(fd, data, length, i_opt);
       else if ( e < 0 && errno == EINTR ) continue;
       else break;
     }
   while (n <= 0 && errno == EINTR);
   if (n < 0)
     fprintf(stderr, "[%d] nsend():send %s\n", getpid(), strerror(errno));
   return n;
 }
 
ExtFunc int
nrecv (fd, data, length, i_opt)
 int fd;
 void * data;
 int length, i_opt;
{
  int e;
#if DEBUG_SSL > 8
   fprintf(stderr, "nrecv: fd=%d len=%d\n", fd, length);
#endif
 if(NESSUS_STREAM(fd))
 {
  if(connections[fd - NESSUS_FD_OFF].fd < 0)
   fprintf(stderr, "Nessus file descriptor %d closed ?!\n", fd);
  else 
    return read_stream_connection(fd, data, length);
 }
 /* Trying OS's recv() 
  *
  * Do *NOT* use os_recv() here, as it will be blocking until the exact
  * amount of requested data arrives
  */
 block_socket(fd);
 do {
	e = recv(fd, data, length, i_opt);
 } while ( e < 0 && errno == EINTR );
 return e;
}
 

ExtFunc int
close_stream_connection(fd)
 int fd;
{
#if DEBUG_SSL > 2
 nessus_connection * fp;
 if(!NESSUS_STREAM(fd))
    {
     errno = EINVAL;
     return -1;
    }
  fp = &(connections[fd - NESSUS_FD_OFF]);
  fprintf(stderr, "close_stream_connection TCP:%d\n", fp->port);
#endif

  if(!NESSUS_STREAM(fd))	/* Will never happen if debug is on! */
   {
    if ( fd < 0 || fd > 1024 )
    {
	   errno = EINVAL;
	   return -1;
    }
   shutdown(fd, 2);
   return socket_close(fd);
   }
  else
   return release_connection_fd(fd);
}


ExtFunc int
get_encaps(fd)
 int fd;
{
 if(!NESSUS_STREAM(fd))
 {
   fprintf(stderr, "get_encaps() : bad argument\n");
   return -1;
 }
 return connections[fd - NESSUS_FD_OFF].transport;
}


 
ExtFunc const char *
get_encaps_name(code)
 int code;
{
 static char str[100];
 switch(code)
 {
  case NESSUS_ENCAPS_IP:
   return "IP";
  case NESSUS_ENCAPS_SSLv2:
    return "SSLv2";
  case NESSUS_ENCAPS_SSLv23:
    return "SSLv23";
  case NESSUS_ENCAPS_SSLv3:
    return "SSLv3";
  case NESSUS_ENCAPS_TLSv1:
    return "TLSv1";
  default:
   snprintf(str, sizeof(str), "[unknown transport layer - code %d (0x%x)]", code, code);
   return str;
 }
}

ExtFunc  const char *
get_encaps_through(code)
 int code;
{
 static char str[100];
 switch(code)
 {
  case NESSUS_ENCAPS_IP:
   return "";
  case NESSUS_ENCAPS_SSLv2:
  case NESSUS_ENCAPS_SSLv23:
  case NESSUS_ENCAPS_SSLv3:
  case NESSUS_ENCAPS_TLSv1:
    return " through SSL";
  default:
    snprintf(str, sizeof(str), " through unknown transport layer - code %d (0x%x)", code, code);
    return str;
 }
}

static int
open_socket(struct sockaddr_in *paddr, 
	    int port, int type, int protocol, int timeout)
{
  fd_set		fd_w;
  struct timeval	to;
  int			soc, x;
  int			opt;
  unsigned int opt_sz;

  __port_closed = 0;

  if ((soc = socket(AF_INET, type, protocol)) < 0)
    {
      nessus_perror("socket");
      return -1;
    }

  if (timeout == -2)
    timeout = TIMEOUT;

  if (timeout > 0)
    if (unblock_socket(soc) < 0)
      {
	closesocket(soc);
	return -1;
      }

  set_socket_source_addr(soc, 0);

#if defined NESSUS_CNX_LOCK
  if (lock_cnt == 0)
{
      lock_fd = open(NESSUS_CNX_LOCK, O_RDWR|O_CREAT);
      if (lock_fd < 0)
	nessus_perror(NESSUS_CNX_LOCK);
      else
	{
	  time_t	t1 = time(NULL), t2;
	  if (flock(lock_fd, LOCK_EX) < 0)
	    nessus_perror(NESSUS_CNX_LOCK);
	  else
	    {
	      lock_cnt ++;
	      t2 = time(NULL);
#if 1
	      if (t2 - t1 > 0)
		fprintf(stderr, "[%d] open_socket: " NESSUS_CNX_LOCK " locked in %d s\n", getpid(), t2 - t1);
#endif
	    }
	}
    }
  else
    {
#if 1
      fprintf(stderr, "[%d] open_socket: sleeping 1 second\n", getpid());
#endif
      sleep(1);
    }
#endif  
  
  if (connect(soc, (struct sockaddr*) paddr, sizeof(*paddr)) < 0)
    {
#if debug_SSL > 2
      nessus_perror("connect");
#endif
again:
      switch (errno)
	{
	case EINPROGRESS:
	case EAGAIN:
	  FD_ZERO(&fd_w);
	  FD_SET(soc, &fd_w);
	  to.tv_sec = timeout;
	  to.tv_usec = 0;
	  x = select(soc + 1, NULL, &fd_w, NULL, &to);
	  if (x == 0)
	    {
#if debug_SSL > 2
	      nessus_perror("connect->select: timeout");
#endif
	      socket_close(soc);
	      errno = ETIMEDOUT;
	      return -1;
	    }
	  else if (x < 0)
	    {
	      if ( errno == EINTR )
               {
 		 errno = EAGAIN;
		 goto again;
	       }
	      nessus_perror("select");
	      socket_close(soc);
	      return -1;
            }
 
	  opt = 0; opt_sz = sizeof(opt);
	  if (getsockopt(soc, SOL_SOCKET, SO_ERROR, &opt, &opt_sz) < 0)
	    {
	      nessus_perror("getsockopt");
	      socket_close(soc);
	      return -1;
	    }
	  if (opt == 0)
	    break;
#if DEBUG_SSL > 2
	  errno = opt;
	  nessus_perror("SO_ERROR");
#endif
	  /* no break; go on */	  
	default:
	  __port_closed = 1;
	  socket_close(soc);
	  return  -1;
	}
    }
  block_socket(soc);
  return soc;
}


ExtFunc 
int open_sock_opt_hn(hostname, port, type, protocol, timeout)
 const char * hostname; 
 unsigned int port; 
 int type;
 int protocol;
 int timeout;
{
 struct sockaddr_in addr;
  
  bzero((void*)&addr, sizeof(addr));
  addr.sin_family=AF_INET;
  addr.sin_port=htons((unsigned short)port);
  addr.sin_addr = nn_resolve(hostname);
  if (addr.sin_addr.s_addr == INADDR_NONE || addr.sin_addr.s_addr == 0)
    {
      fprintf(stderr, "open_sock_opt_hn: invalid socket address\n");
      return  -1;
    }
   
  return open_socket(&addr, port, type, protocol, timeout);
}


ExtFunc
int open_sock_tcp_hn(hostname, port)
 const char * hostname;
 unsigned int port;
{
  return open_sock_opt_hn(hostname, port, SOCK_STREAM, IPPROTO_TCP, TIMEOUT);
}



ExtFunc
int open_sock_tcp(args, port, timeout)
 struct arglist * args; 
 unsigned int port;
 int timeout;
{
  char name[32];
  int ret;
  int type;
  

  /*
   * If we timed out against this port in the past, there's no need
   * to scan it again
   */
  snprintf(name, sizeof(name), "/tmp/ConnectTimeout/TCP/%d", port);
  if ( plug_get_key ( args, name, &type ) ) 
	return -1;


  errno = 0;
  ret  = open_sock_option(args, port, SOCK_STREAM,IPPROTO_TCP, timeout);
  if ( ret < 0 && errno == ETIMEDOUT )
    plug_set_key( args, name, ARG_INT, (void*)1); 

  return ret;
}


ExtFunc
int open_sock_udp(args, port)
 struct arglist * args;
 unsigned int port;
{
  return open_sock_option(args, port, SOCK_DGRAM, IPPROTO_UDP, 0);
}


ExtFunc 
struct in_addr _socket_get_next_source_addr(struct in_addr * addr)
{
  static struct in_addr * src_addrs = NULL;
  static int current_src_addr = 0;
  static pid_t current_src_addr_pid = 0;
  static int num_addrs = 0;
  struct in_addr ret;
  pid_t mypid;
  
  if( current_src_addr < 0 )
  {
   ret.s_addr = INADDR_ANY;
   return ret;
  }
  
  
  
  if ( src_addrs == NULL && current_src_addr == 0 )
  {
    src_addrs = addr;
    if( src_addrs == NULL ) 
    {
     ret.s_addr = INADDR_ANY;
     current_src_addr = -1;
     return ret;
    }    	
   
   num_addrs = -1;
   while(src_addrs[++num_addrs].s_addr != 0 ) ;
  }
  
  
  mypid = getpid();
  if ( current_src_addr_pid != mypid )
   {
    current_src_addr_pid = mypid;
    current_src_addr = lrand48() % ( num_addrs ) ;
    if ( src_addrs[current_src_addr].s_addr == 0 ) current_src_addr = 0;
   }
  
  return src_addrs[current_src_addr];
}

ExtFunc
struct in_addr socket_get_next_source_addr()
{
 return _socket_get_next_source_addr(NULL);
}

ExtFunc 
int set_socket_source_addr(int soc, int port)
{ 
  struct sockaddr_in bnd;
  int opt = 1;  
  
  struct in_addr src = _socket_get_next_source_addr(NULL);
  
  if( src.s_addr == INADDR_ANY && port == 0 ) /* No need to bind() */
  	return 0;
   
  setsockopt(soc, SOL_SOCKET, SO_REUSEADDR, (void*)&opt, sizeof(int));
  bzero(&bnd, sizeof(bnd));
  
   
   
   bnd.sin_port = htons(port);
   bnd.sin_addr = src;
   bnd.sin_family = AF_INET;
  
  if( bind(soc, (struct sockaddr*)&bnd, sizeof(bnd)) < 0 )
  { 
   return -1;
  }
  
  return 0;
}

ExtFunc  void socket_source_init(struct in_addr * addr)
{
 (void) _socket_get_next_source_addr(addr);
}


ExtFunc
int open_sock_option(args, port, type, protocol, timeout)
 struct arglist * args;
 unsigned int port;
 int type;
 int protocol;
 int timeout;
{
  struct sockaddr_in addr;
  struct in_addr * t;

#if 0
  /* 
   * MA 2004-08-15: IMHO, as this is often (always?) tested in the NASL scripts
   * this should not be here. 
   * If it has to be somewhere else, I'd rather put it in libnasl (and add
   * a parameter to "force" the connection)
   */
  if(host_get_port_state(args, port)<=0)return(-1);
#endif
  bzero((void*)&addr, sizeof(addr));
  addr.sin_family=AF_INET;
  addr.sin_port=htons((unsigned short)port);
  t = plug_get_host_ip(args);
  if(!t)
  {
   fprintf(stderr, "ERROR ! NO ADDRESS ASSOCIATED WITH NAME\n");
   arg_dump(args, 0);
   return(-1);
  }
  addr.sin_addr = *t;
  if (addr.sin_addr.s_addr == INADDR_NONE)
    return(-1);
    
  return open_socket(&addr, port, type, protocol, timeout);
}


/* This function reads a text from the socket stream into the
   argument buffer, always appending a '\0' byte.  The return
   value is the number of bytes read, without the trailing '\0'.
 */


ExtFunc
int recv_line(soc, buf, bufsiz)
 int soc;
 char * buf;
 size_t bufsiz;
{
  int n, ret = 0;
  
  /*
   * Dirty SSL hack
   */
  if(NESSUS_STREAM(soc))
  {
   buf[0] = '\0';
   
   do
   {
    n = read_stream_connection_min (soc, buf + ret, 1, 1);
    switch (n)
    {
     case -1 :
       if(ret == 0)
        return -1;
       else 
        return ret;
       break;
     
     case 0:
       return ret;
       break;
      
      default :
      	ret ++;
    }
   }
   while (buf [ret-1] != '\0' && buf [ret-1] != '\n' && ret < bufsiz) ;
   
   if(ret > 0 )
   {
   if (buf[ret - 1] != '\0')
	{
	if ( ret < bufsiz ) 
		buf[ ret ] = '\0';
	else 
		buf [ bufsiz - 1 ] = '\0';
	}
   }
   return ret;  
  }
  else
  {
   fd_set rd;
   struct timeval tv;
   
   do
   {
      int e;
 again:
      errno = 0;
      FD_ZERO(&rd);
      FD_SET(soc, &rd);
      tv.tv_sec = 5;
      tv.tv_usec = 0;
      e = select(soc+1, &rd, NULL, NULL, &tv); 
      if( e < 0 && errno == EINTR) goto again;
      if( e > 0 )
      {
       n = recv(soc, buf + ret, 1, 0);
       switch(n)
       {
        case -1 :
	 if ( errno == EINTR ) continue;
	 if(ret == 0)
	  return -1;
	 else
	  return ret;
	 break;  
       case 0 :
         return ret;
       	 break;
       default:
         ret ++;	
       }
      } 
      else break;
      tv.tv_sec = 1;
      tv.tv_usec = 0;
    } while(buf[ret -1 ] != '\0' && buf[ret -1 ] != '\n' && ret < bufsiz);
    
    if(ret > 0)
    {
    if(buf[ret - 1] != '\0')
      {
	if ( ret < bufsiz )
	      	buf[ret] = '\0';
	else
		buf[bufsiz - 1] = '\0';
      }
    }
  }
  return ret;
} 

ExtFunc int
socket_close(soc)
int soc;
{
#if defined NESSUS_CNX_LOCK
  if (lock_cnt > 0)
    if (-- lock_cnt == 0)
      {
	if (flock(lock_fd, LOCK_UN) < 0)
	  nessus_perror(NESSUS_CNX_LOCK);
	if (close(lock_fd) < 0)
	  nessus_perror(NESSUS_CNX_LOCK);
	lock_fd = -1;
      }
#endif  
  return closesocket(soc);
}

/*
 * auth_printf()
 *
 * Writes data to the global socket of the thread
 */
ExtFunc void 
auth_printf(struct arglist * globals, char * data, ...)
{
  va_list param;
  char buffer[65535];
  
  bzero(buffer, sizeof(buffer));

  va_start(param, data);
  vsnprintf(buffer, sizeof(buffer) - 1, data, param);
  
  va_end(param);
  auth_send(globals, buffer);
}                    


ExtFunc void
auth_send(struct arglist * globals, char * data)
{
 int soc = (int)arg_get_value(globals, "global_socket");
 int confirm = (int)arg_get_value(globals, "confirm");
 int n = 0;
 int length;
 int sent = 0;

 if(soc < 0)
  return;

#ifndef NESSUSNT
 signal(SIGPIPE, _exit);
#endif
 length = strlen(data);
 while(sent < length)
 {
 n = nsend(soc, data+sent, length-sent, 0);
 if(n < 0)
 {
  if((errno == ENOMEM)
#ifdef ENOBUFS  
   ||(errno==ENOBUFS)
#endif   
   )
   n = 0;
  else
   {
   nessus_perror("nsend");
   goto out;
   }
 }
 else sent+=n;
 }
 
 if(confirm)
 {
  /*
   * If confirm is set, then we are a son
   * trying to report some message to our busy
   * father. So we wait until he told us he
   * took care of it
   */
  char n;
  read_stream_connection_min(soc, &n, 1, 1);
 }
out:
#ifndef NESSUSNT
  signal(SIGPIPE, SIG_IGN);
#else
 ;
#endif
}

/*
 * auth_gets()
 *
 * Reads data from the global socket of the thread
 */
ExtFunc char * 
auth_gets(globals, buf, bufsiz)
     struct arglist * globals;
     char * buf;
     size_t bufsiz;
{
  int soc = (int)arg_get_value(globals, "global_socket");
  int n;
  /* bzero(buf, bufsiz); */
  n = recv_line(soc, buf, bufsiz);
  if(n <= 0)
	  return NULL;
  
  return(buf);
}


/*
 * Select() routines
 */
 
ExtFunc int
stream_zero(set)
 fd_set * set;
{ 
 FD_ZERO(set);
 return 0;
}

ExtFunc int
stream_set(fd, set)
 int fd;
 fd_set * set;
{
 int soc = nessus_get_socket_from_connection(fd);
 if(soc >= 0)
  FD_SET(soc, set);
 return soc;
}

ExtFunc int
stream_isset(fd, set)
 int fd;
 fd_set * set;
{
 return FD_ISSET(nessus_get_socket_from_connection(fd), set);
}

ExtFunc int
fd_is_stream(fd)
     int	fd;
{
  return NESSUS_STREAM(fd);	/* Should probably be smarter... */
}


ExtFunc int 
stream_get_buffer_sz ( int fd )
{
  nessus_connection	*p;
  if (! NESSUS_STREAM(fd))
    return -1;
  p = &(connections[fd - NESSUS_FD_OFF]);
  return p->bufsz;
}


ExtFunc int
stream_set_buffer(fd, sz)
     int	fd, sz;
{
  nessus_connection	*p;
  char			*b;

  if (! NESSUS_STREAM(fd))
    return -1;

  p = &(connections[fd - NESSUS_FD_OFF]);
  if (sz < p->bufcnt)
      return -1;		/* Do not want to lose data */

  if (sz == 0)
    {
      efree(&p->buf);
      p->bufsz = 0;
      return 0;
    }
  else if (p->buf == 0)
    {
      p->buf = malloc(sz);
      if (p->buf == NULL)
	return -1;
      p->bufsz = sz;
      p->bufptr = 0;
      p->bufcnt = 0;
      return 0;
    }
  else
    {
      if (p->bufcnt > 0)
	{
	  memmove(p->buf, p->buf + p->bufptr, p->bufcnt);
	  p->bufptr = 0;
	}
      b = realloc(p->buf, sz);
      if (b == NULL)
	return -1;
      p->bufsz = sz;
      return 0;
    }
  /*NOTREACHED*/
}



/*------------------------------------------------------------------*/


int os_send(int soc, void * buf, int len, int opt )
{
 char * buf0 = (char*)buf;
 int e, n;
 for ( n = 0 ; n < len ; ) 
 {
  errno = 0;
  e = send(soc, buf0 + n , len -  n, opt);
  if ( e < 0 && errno == EINTR ) continue; 
  else if ( e <= 0 ) return -1;
  else n += e;
 }
 return n;
}

int os_recv(int soc, void * buf, int len, int opt )
{
 char * buf0 = (char*)buf;
 int e, n;
 for ( n = 0 ; n < len ; ) 
 {
  errno = 0;
  e = recv(soc, buf0 + n , len -  n, opt);
  if ( e < 0 && errno == EINTR ) continue; 
  else if ( e <= 0 ) return -1;
  else n += e;
 }
 return n;
}


/* 
 * internal_send() / internal_recv() :
 *
 * When processes are passing messages to each other, the format is
 * <length><msg>, with <length> being a long integer. The functions
 * internal_send() and internal_recv() encapsulate and decapsulate
 * the messages themselves. 
 */
int internal_send(int soc, char * data, int msg_type )
{
 int len;
 int e;
 int ack;
 fd_set rd;
 struct timeval tv;
 
 if ( data == NULL )
	data = "";

 e = os_send(soc, &msg_type, sizeof(len), 0 );
 if ( e < 0 ) return -1;

 if ( (msg_type & INTERNAL_COMM_MSG_TYPE_CTRL) == 0 )
  {
 len = strlen(data);

 e = os_send(soc, &len, sizeof(len), 0 );
 if ( e < 0 ) return -1;
 e = os_send(soc, data, len, 0 );
 if ( e < 0 ) return -1;
 }

 e = os_recv(soc, &ack, sizeof(ack), 0);
 if ( e < 0 ){
	fprintf(stderr, "internal_send->os_recv(%d): %s\n",soc, strerror(errno));
	return -1;
	}

 return 0;
}


int internal_recv(int soc, char ** data, int * data_sz, int * msg_type )
{
 int len = 0;
 int e;
 char * buf = *data;
 int    sz  = *data_sz;
 fd_set rd;
 struct timeval tv;
 int type;
 int ack;
 
 if ( buf == NULL )
 {
  sz = 65535;
  buf = emalloc ( sz );
 }

   
 e = os_recv(soc, &type, sizeof(type), 0 );
 if ( e < 0 ) goto error;

 if ( (type & INTERNAL_COMM_MSG_TYPE_CTRL) == 0 )
 {
 e = os_recv(soc, &len, sizeof(len), 0);
 if ( e < 0 ) goto error;
 
 if ( len >= sz )
 {
  sz = len + 1;
  buf = erealloc( buf, sz );
 }

 if ( len > 0 )
 {
 e = os_recv(soc, buf,len, 0);
 if ( e < 0 ) goto error;
 buf[len] = '\0';
 }

 if ( data != NULL )
 	*data = buf;
 if ( data_sz != NULL )
 	*data_sz = sz;
 }
 
 *msg_type = type;
 ack = INTERNAL_COMM_MSG_TYPE_CTRL | INTERNAL_COMM_CTRL_ACK;
 e = os_send(soc, &ack, sizeof(ack), 0);
 if ( e < 0 ) goto error;

 
 return len;
error:
 efree(&buf);
 *data = NULL;
 *data_sz = 0;
 return -1;
}


ExtFunc int stream_pending(int fd)
{
  nessus_connection * fp;
 if ( ! NESSUS_STREAM(fd) )
 {
  errno = EINVAL;
  return -1;
 }
 fp = &(connections[fd - NESSUS_FD_OFF]);

 if ( fp->bufcnt )
        return fp->bufcnt;
#ifdef HAVE_SSL
 else if ( fp->transport != NESSUS_ENCAPS_IP )
        return SSL_pending(fp->ssl);
#endif
 return 0;
}
