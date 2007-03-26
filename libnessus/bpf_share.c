/* Copyright (C) 2003 Renaud Deraison
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2,
 * as published by the Free Software Foundation
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

 

#include <includes.h>

#undef DEBUG_FORWARD
#undef DEBUG
#undef DEBUG_HIGH
#define NUM_CLIENTS 128
#define NUM_BPF_PER_CLIENT 5


#define BPF_SOCKET_PATH NESSUS_STATE_DIR"/nessus/bpf"
#define BPF_SERVER_PID_FILE NESSUS_STATE_DIR"/nessus/bpf_server.pid"

/*
 * The traditional pcap code is much more handy, so we'll try to use
 * it instead if our hack is not necessary
 */
#ifdef HAVE_DEV_BPFN 

#define CLNT_BUF_SIZ 1600


struct bpf_listener {
	int soc;
	char filter[512];
	char iface[128] ;
        int flag;
	struct bpf_program bpf_filter;
	};
	
struct bpf_pcap {
	pcap_t * pcap;
	char iface[128];
	struct bpf_program bpf_filter;
	struct bpf_pcap * next;
	};
	
struct bpf_client {
	int soc;
	int datalink;
	unsigned char *packet;
	};
	

/* Server-side */
static struct bpf_listener clients[NUM_CLIENTS];
static struct bpf_pcap * pcaps;

/* Client-side */
static struct bpf_client clnts[NUM_BPF_PER_CLIENT];


static void setbufsize(int soc)
{
 int optval = CLNT_BUF_SIZ * 40;
 if(setsockopt(soc, SOL_SOCKET, SO_SNDBUF, &optval, sizeof(optval)) < 0)
	perror("inc sndbuf");
 if(setsockopt(soc, SOL_SOCKET, SO_RCVBUF, &optval, sizeof(optval)) < 0)
	perror("inc sndbuf");
}

static void sigterm()
{
 unlink(BPF_SOCKET_PATH);
 _EXIT(0);
}
#ifdef DEBUG
 void dump_packet(char * p, int len)
{
 int i;
 printf("\n----\n");
 for(i=0;i<len;i+=16)
 {
  int j;
  for(j=0;j<16;j++)
  {
   printf("%.2x ", (unsigned char)p[j+i]);
   if(j %8 == 0)printf(" ");
  }
  printf("\n");
 }
}
#endif

/*------------------------------------------------------------------------*
 *				Server part 				  *
 *------------------------------------------------------------------------*/

int bpf_svr_close(int);


static struct bpf_pcap * add_pcap(char * iface, pcap_t * pcap)
{
 struct bpf_pcap * bpc;
 bpf_u_int32 netmask, network;
 
 
 if(pcap == NULL)
  return pcaps;
 bpc = malloc(sizeof(*bpc));
 bpc->pcap = pcap;
 strncpy(bpc->iface, iface, sizeof(bpc->iface) - 1);
 bpc->iface[sizeof(bpc->iface) - 1] = '\0';
 pcap_lookupnet(iface, &network, &netmask, 0);
 pcap_compile(pcap, &bpc->bpf_filter, "", 1, netmask); 
 bpc->next = pcaps;
 pcaps = bpc;
 return bpc;
}


static void rm_pcap(char * iface )
{
 struct bpf_pcap * bpc = pcaps, * prev = NULL;
 while( bpc != NULL )
 {
  if(strcmp(bpc->iface, iface) == 0)
	{
 	 struct bpf_pcap * next;
	 next = bpc->next;
	 pcap_close(bpc->pcap);
	 efree(&bpc);
	 if ( prev ) prev->next = next;
	 else pcaps = next;
	}
  prev = bpc;
  if ( bpc != NULL )
   bpc = bpc->next;
 }
}

static pcap_t * get_pcap(char * iface)
{
 struct bpf_pcap * bpc = pcaps;
 while( bpc != NULL )
 {
  if(strcmp(bpc->iface, iface) == 0)
   return bpc->pcap;
  bpc = bpc->next;
 }
 return NULL;
}

static pcap_t * new_pcap(char * iface)
{
 char errbuf[PCAP_ERRBUF_SIZE];
 bpf_u_int32 netmask, network;
 struct bpf_program filter_prog;
 char filter[] = "ip";
 pcap_t *  pcap;

 if(strcmp(iface, "lo") == 0 ||
    strcmp(iface, "lo0") == 0)return NULL;

 pcap = pcap_open_live(iface, 1500, 0, 1, errbuf);
 if(pcap == NULL)
  {
   fprintf(stderr, "new_pcap(%s) failed - %s\n", iface, errbuf);
   return NULL;
  }
  
  if(pcap_lookupnet(iface, &network, &netmask, 0) < 0)
 { 
   printf("pcap_lookupnet failed\n");
   pcap_close(pcap);
   return NULL;
 }
 
 if(pcap_compile(pcap, &filter_prog, filter, 1, netmask) < 0)
 {
  pcap_perror(pcap, "pcap_compile");
  pcap_close(pcap);
  return NULL;
 }
 
 if(pcap_setfilter(pcap, &filter_prog) < 0) 
 {
  pcap_perror(pcap, "pcap_setfilter\n");
  pcap_close(pcap);
  return NULL;
 }

 return pcap;
}





static pcap_t * bpf_add_pcap(char * iface)
{
 pcap_t * ret = get_pcap(iface);
 if(ret != NULL) 
  return ret;
 else 
   add_pcap(iface, new_pcap(iface));
   
 return get_pcap(iface);
}

 



static int bpf_recv_line(int soc, char * buf, int len)
{
 int r = 0;
 bzero(buf, len);
 for(;r<len;)
 {
 int e;
again: 
  e = recv(soc, &(buf[r]), 1, 0);
 if(e <= 0) {
    if(e < 0 && errno == EINTR)goto again;
    return e;
    }
 r ++;
 if(buf[r-1] == '\n'){
	return r;
	}
 }
 return r;
}

static int process(char * iface, u_char * p, int len)
{
 int i;
#ifdef DEBUG_HIGH
 printf("bpf_share: process()\n");
#endif 
 for(i=0;i<NUM_CLIENTS;i++)
 {
#ifdef DEBUG_HIGH 
if(clients[i].soc != 0)
  printf("%d) %d, %s %s %s\n", i, clients[i].soc, clients[i].iface, iface, clients[i].filter);
#endif  
  if(clients[i].soc > 0 && (strcmp(clients[i].iface, iface) == 0))
  {
   if(clients[i].filter[0] == '\0' || bpf_filter(clients[i].bpf_filter.bf_insns, p, len, len) != 0)
    {
    int e;
    int n;
    int lim;
    
#ifdef DEBUG_FORWARD 
    printf("Found packet that matches %s %d\n", clients[i].filter, i);
#endif        
#ifdef DEBUG    
    printf("bpf_share: forward data to %d\n", i);
#endif    
    n = 0;
    while( n != sizeof(len))
    {
     fd_set wr;
     struct timeval tv;
again:       
    FD_ZERO(&wr);
    FD_SET(clients[i].soc, &wr);
    tv.tv_sec = tv.tv_usec = 0;
    e = select(clients[i].soc + 1, NULL, &wr, NULL, &tv);
    if(e <= 0)
    {
     if(e < 0 && errno == EINTR)goto again;
     else break;
    }
    e = send(clients[i].soc, (char*)(&len)+n, sizeof(len)-n, 0);
    if(e <= 0)
    {
     if(e < 0 && errno == EINTR)goto again;
     if(errno != EPIPE)perror("bpf_share.c:process():send ");
     bpf_svr_close(i);
     goto endfor;
    }
    else n += e;
    }
    
    n = 0;
    
    if(len > CLNT_BUF_SIZ)
    	lim = CLNT_BUF_SIZ;
    else
        lim = len;
    
    
    while(n != lim)
    {
     fd_set wr;
    struct timeval tv;
again2:    
    FD_ZERO(&wr);
    FD_SET(clients[i].soc, &wr);
    tv.tv_sec = tv.tv_usec = 0;
    e = select(clients[i].soc + 1, NULL, &wr, NULL, &tv);
    if(e <= 0)
    {
     if(e < 0 && errno == EINTR)goto again2;
     else break;
    }

    e =  send(clients[i].soc, (char*)p + n, lim - n, 0);
    if(e <= 0)
     {
     if ( e < 0 && errno == EINTR )goto again2;
     
     if(errno != EPIPE)perror("bpf_share.c:process():send ");
     bpf_svr_close(i);
     goto endfor;
     }
    else n+=e;
    }
#ifdef DEBUG_FORWARD    
     printf("====>PACKET FORWARDED TO %d->%d\n", i, clients[i].soc);
#endif     
  endfor:
     ;
    }
  }
 }
 return 0;
}


static int mklistener()
{
 struct sockaddr_un addr;
 char name[] =  BPF_SOCKET_PATH;
 int soc;
 int one = 1;
 struct stat st;
 
 if(stat(name, &st) == 0)
 {
  unlink(name);
 }
 
 
 soc = socket(AF_UNIX, SOCK_STREAM, 0);
 if(soc < 0)
  return -1;
 
 bzero(&addr, sizeof(addr));
 addr.sun_family = AF_UNIX;
 bcopy(name, addr.sun_path, strlen(name));
 setsockopt(soc, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
 if(bind(soc, (struct sockaddr*)(&addr), sizeof(addr)) == -1)
 {
  perror("bpf_share.c:mklistener():bind ");
 }
 chmod(name, 0700);
 if(listen(soc, NUM_CLIENTS - 1) < 0)
  perror("bpf_share.c:mklistener():listen ");
 return soc;
}

static int add_client(int soc)
{
 int i;
 for(i=0;i<NUM_CLIENTS && clients[i].soc;i++);
 if(clients[i].soc)
 {
  fprintf(stderr, "bpf_share: Too many clients already.\n");
  close(soc);
  return -1;
 }
 
 clients[i].soc = soc;
 clients[i].filter[0] = '\0';
 clients[i].iface[0] = '\0';
#ifdef DEBUG 
 printf("Added client at index %d (%d)\n", i, clients[i].soc);
#endif
 return i;
}


static int read_clients()
{
 fd_set rd;
 int i;
 char buf[512];
 int max = -1;
 struct timeval tv = {0, 0};
 
 FD_ZERO(&rd);
 for(i=0;i<NUM_CLIENTS;i++)
 {
  if(clients[i].soc > 0)
  {
   FD_SET(clients[i].soc, &rd);
   if(clients[i].soc > max) max = clients[i].soc;
  }
 }
 
 if(max == -1)
 {
  usleep(50000);
  return 0;
 }
 
 if(select(max+1, &rd, NULL, NULL, &tv) > 0)
 {
  for(i=0;i<NUM_CLIENTS;i++)
  {
   if(clients[i].soc && FD_ISSET(clients[i].soc, &rd))
   {
    int n;
    
    n = bpf_recv_line(clients[i].soc, buf, sizeof(buf));
#ifdef DEBUG
    printf("Received %s\n", buf);
#endif    
    if(n <= 0)
    {
#ifdef DEBUG_FORWARD
     printf("Connection closed for %d\n", i);
#endif     
     /* connection was closed */
     bpf_svr_close(i);
    }
    else
    {
     if(clients[i].iface[0] == '\0')
     { 
       int dl; 
       int pcap_compile_failed = 0;
       pcap_t * pcap;
       bpf_u_int32 netmask, network;
       if(buf[0] != '\0')buf[strlen(buf) - 1 ] = '\0';
       clients[i].iface[sizeof(clients[i].iface) - 1] = '\0';
       strncpy(clients[i].iface, buf, sizeof(clients[i].iface) - 1);
       send(clients[i].soc, ".", 1, 0);
       
       
again:
       pcap = bpf_add_pcap(clients[i].iface);
       
     
       if(pcap != NULL)
       {
       dl = htonl(pcap_datalink(pcap));
       send(clients[i].soc, &dl, sizeof(dl), 0);
       n = bpf_recv_line(clients[i].soc, buf, sizeof(buf));
       if(buf[0] != '\0')buf[strlen(buf) - 1 ] = '\0';
       clients[i].filter[sizeof(clients[i].filter) - 1] = '\0';
       strncpy(clients[i].filter, buf, sizeof(clients[i].filter) - 1);
#ifdef DEBUG       
       printf("FILTER = %s (%s) %d\n", buf, clients[i].filter, i);
#endif       
       pcap_lookupnet(clients[i].iface, &network, &netmask, 0);
     /*  pcap_restart(NULL);    */    
       if ( pcap_compile(pcap, &clients[i].bpf_filter, buf, 1, netmask) 
< 0 )
	 {
	 if ( pcap_compile_failed == 0 )
		{
		 rm_pcap(clients[i].iface);
		 pcap_compile_failed++;
		 goto again;
		}
	  else {
	   fprintf(stderr, "pcap_compile(%s) failed\n", buf);
	   send(clients[i].soc, "e", 1, 0);
           }
	 }
        else 
	 clients[i].flag = 1;
      }
       else send(clients[i].soc, "e", 1, 0);
     }
    }
   }
  }
 }
 for(i=0;i<NUM_CLIENTS;i++)
 {
  if(clients[i].soc && clients[i].flag)
  {
     send(clients[i].soc, ",", 1, 0);
     clients[i].flag = 0;
  }
 }
 return 0;
}


static int add_clients(int soc)
{
 fd_set rd;
 struct timeval tv = {0,0};
 unsigned int clnt;
 
 FD_ZERO(&rd);
 FD_SET(soc, &rd);
 if(select(soc+1, &rd, &rd, &rd, &tv) > 0)
 {
  struct sockaddr_un soca;
  unsigned int len = sizeof(soca);
  clnt = accept(soc, (struct sockaddr*)&soca,&len); 
  if(clnt > 0)
  {
#ifdef DEBUG_FORWARD
   printf("New client!\n");
#endif     
   setbufsize(clnt);
   add_client(clnt);
   }
 }
 return 0;
}


static int pcaps_read()
{
 struct bpf_pcap * bpc = pcaps;
 
 if(bpc == NULL)usleep(50000);
 
 while(bpc != NULL)
 {
  u_char * p;
  struct pcap_pkthdr head;
  int count = 0;
again:  
  p = (u_char*)pcap_next(bpc->pcap, &head);
  if(p != NULL){
    process(bpc->iface, p, head.caplen);
    count ++;
    if ( count < 30 ) goto again;
   }
  bpc = bpc->next;
 }
 return 0;
}


int bpf_server()
{
 int i;
 int lst;
 int pid;
 int fd  = open(BPF_SERVER_PID_FILE, O_RDONLY);
 
 
 if ( fd >= 0 )
 {
  char buf[256];
  pid_t pid;
  read(fd, buf, sizeof(buf) - 1);
  buf[sizeof(buf) - 1] = 0;
  pid = atoi(buf);
  close(fd);
  if ( kill(pid, 0) == 0 ) return pid; /* Already running */
  else unlink(BPF_SERVER_PID_FILE);
 }
 
 
 for(i=0;i<NUM_CLIENTS;i++)bzero(&clients[i], sizeof(clients[i]));

 if((pid = fork()) == 0)
 {
  fd = open(BPF_SERVER_PID_FILE, O_CREAT|O_TRUNC|O_WRONLY, 0644);
  if ( fd >= 0 )
  {
   char buf[256];
   snprintf(buf, sizeof(buf), "%d", getpid());
   write(fd, buf, strlen(buf));
   close(fd);
  }
  signal(SIGPIPE, SIG_IGN);
  signal(SIGHUP, SIG_IGN);
  signal(SIGTERM, sigterm);
  setproctitle("bpf server"); 
  lst = mklistener();
  for(;;)
  {
   add_clients(lst);
   read_clients();
   pcaps_read();
   }
  }
 return pid;
}


int bpf_svr_close(int n)
{
 if(clients[n].soc) {
	shutdown(clients[n].soc, 2);
	close(clients[n].soc);
	}
 if(clients[n].bpf_filter.bf_insns != NULL)free(clients[n].bpf_filter.bf_insns);
 bzero(&clients[n], sizeof(clients[n]));
 return 0;
}

/*--------------------------------------------------------------------------*
 *			Client part 					    *
 *--------------------------------------------------------------------------*/
 


static int bpf_set_iface(int soc, char * iface)
{ 
 char buf[2]  = {0, 0};
 char snd[256];
 fd_set fds;
 struct timeval tv;
 int e;
 

 
 snprintf(snd, sizeof(snd), "%s\n", iface);
 
again:
 FD_ZERO(&fds);
 tv.tv_sec = 1; 
 tv.tv_usec = 0;
 FD_SET(soc, &fds);
 e = select(soc + 1, NULL, &fds, NULL, &tv);
 if ( e <= 0 )
 {
  if(e < 0 && errno == EINTR)goto again;
  else return -1;
 }
 
 e = send(soc, snd, strlen(snd), 0);
 if ( e <= 0 )
 {
  if ( e < 0 && errno == EINTR )goto again;
  else return -1;
 }
 
recv_again: 
 FD_ZERO(&fds);
 tv.tv_sec = 1; 
 tv.tv_usec = 0;
 FD_SET(soc, &fds);
 e = select(soc + 1, &fds, NULL, NULL, &tv);
 if ( e <= 0 )
 {
  if(e < 0 && errno == EINTR)goto recv_again;
  else return -1;
 }
 
 
 e = recv(soc, buf, 1, 0);
 if(e <= 0 )
 {
  if ( e < 0 && errno == EINTR ) goto recv_again;
  else return -1;
 }


 if(buf[0] == '.')
  {
  int dl;
  recv(soc, &dl, sizeof(dl), 0);
  dl = ntohl(dl);
  return dl;
  }
 else
  return -1;
}

static int bpf_set_filter(int soc, char * filter)
{
  char buf[2]  = {0, 0};
  char snd[1024];
  struct timeval tv;
  fd_set fds;
  int e;
  
  snprintf(snd, sizeof(snd), "%s\n", filter);
again:  
   FD_ZERO(&fds);
   tv.tv_sec = 1; 
   tv.tv_usec = 0;
   FD_SET(soc, &fds);
   e = select(soc + 1, NULL, &fds, NULL, &tv);
   if(e <= 0)
   {
    if ( e < 0 && errno == EINTR )goto again;
    else return -1;
   }
   
   e = send(soc, snd, strlen(snd), 0);
   if ( e <= 0 )
   { 
    if ( e < 0 && errno == EINTR ) goto again;
    else return -1;
   }
   
recv_again:  
   FD_ZERO(&fds);
   tv.tv_sec = 1; 
   tv.tv_usec = 0;
   FD_SET(soc, &fds);
   e = select(soc + 1, &fds, NULL, NULL, &tv);
   if(e <= 0)
   {
    if ( e < 0 && errno == EINTR )goto recv_again;
    else return -1;
   }
   
   e = recv(soc, buf, 1, 0);
   if ( e <= 0 )
   { 
    if ( e < 0 && errno == EINTR ) goto recv_again;
    else return -1;
   }

   
 
  if(buf[0] == ',')
   return 0;
  else
   return -1;
}


 
 
int bpf_open_live(char * iface, char * filter)
{
 int soc;
 struct sockaddr_un addr;
 int len = sizeof(addr);
 char name[] = BPF_SOCKET_PATH;
 char errbuf[PCAP_ERRBUF_SIZE];
 
 int i;
 
 for(i=0;i<NUM_BPF_PER_CLIENT && clnts[i].soc != 0;i++);
 
 if(clnts[i].soc != 0)
  return -1;
  
 
 if(iface == NULL)
  iface = pcap_lookupdev(errbuf); 
  
 
 soc = socket(AF_UNIX, SOCK_STREAM, 0);
  if(soc < 0)
  {
   perror("bpf_open_live():socket ");
   return -1;
  } 
 bzero(&addr, sizeof(addr));
 addr.sun_family = AF_UNIX;
 bcopy(name, addr.sun_path, strlen(name));
 setbufsize(soc);

 if(connect(soc, (struct sockaddr*)&addr, len) ==  -1 )
 { 
  perror("bpf_open_live():connect ");
  close(soc);
  return -1;
 }
 
 clnts[i].datalink = bpf_set_iface(soc, iface);
 if(clnts[i].datalink < 0 )
  {
  close(soc);
  bzero(&clnts[i], sizeof(clnts[i]));
  return -1;
  }
  
 if( bpf_set_filter(soc, filter) < 0)
 {
  close(soc);
  bzero(&clnts[i], sizeof(clnts[i]));
  return -1;
 }
 clnts[i].packet = emalloc(CLNT_BUF_SIZ);
 clnts[i].soc = soc;
 return i;
}


ExtFunc u_char* bpf_next_tv(int clnt, int * caplen, struct timeval * tv)
{
 fd_set rd;
 int soc;
 int lim;
 struct timeval tmp;
 int e;
 
 if(clnt < 0 )return NULL;
 
 soc = clnts[clnt].soc;
 if( soc <= 0 ){
    fprintf(stderr, "[%d] bpf_next_tv() : called on a closed bpf !\n", getpid());
    return NULL;
    }
 
 bzero(clnts[clnt].packet, CLNT_BUF_SIZ);

again: 
 errno = 0;
 tmp = *tv;
 
 
 FD_ZERO(&rd);
 FD_SET(soc, &rd);
#ifdef DEBUG 
 printf("(%d) bpf_next\n", getpid());
#endif 
 e = select(soc + 1, &rd, NULL, NULL, &tmp);
 if ( e < 0 && errno == EINTR)goto again;
 
 if(e > 0)
 {
  int n = 0;
  
#ifdef DEBUG  
  printf("(%d) Select(%d->%d)\n", getpid(), clnt, soc);
#endif  
  while(n != sizeof(*caplen))
  {
  char * x = (char*)caplen;
  int e;
recv_again:  
  e = recv(soc, x+n, sizeof(*caplen)-n, 0);
  if( e <= 0 )
   {
    if(e < 0 && errno == EINTR)goto recv_again;
    perror("bpf_next():recv ");
    bpf_close(clnt);
    return NULL;
   }
  else
   n += e;
  }
  
#ifdef DEBUG  
  printf("(%d) HEAD received (%d->%d)\n", getpid(), clnt, soc);
#endif  
 
  
 
  if( *caplen > CLNT_BUF_SIZ)
   lim = CLNT_BUF_SIZ;
  else
   lim = *caplen;
    
   
  n = 0;
  while(n != lim)
  {
  int e;
recv_again2:  
  e = recv(soc, &(clnts[clnt].packet[n]), lim-n, 0);
  if(e < 0 && errno == EINTR)goto recv_again2;
  
  if(e <= 0 ) 
   {
   bpf_close(clnt);
   return NULL;
   }
  else
   n+=e;
  }
#ifdef DEBUG
  dump_packet(clnts[clnt].packet, lim);
#endif  
  return clnts[clnt].packet;
 }
 return NULL;
}


ExtFunc u_char* bpf_next(int clnt, int * caplen)
{
 struct timeval tv = {0, 100000};
 return bpf_next_tv(clnt, caplen, &tv);
}

int bpf_datalink(int bpf)
{
 return clnts[bpf].datalink;
}



void bpf_close(int bpf)
{
 if(clnts[bpf].soc){
	shutdown(clnts[bpf].soc, 2);
	close(clnts[bpf].soc);
	}
 efree(&clnts[bpf].packet);       
 bzero(&clnts[bpf], sizeof(clnts[bpf]));
}

#else

static pcap_t * pcaps[NUM_CLIENTS];

	

int bpf_open_live(char * iface, char * filter)
{
 char errbuf[PCAP_ERRBUF_SIZE];
 pcap_t * ret;
 bpf_u_int32 netmask, network;
 struct bpf_program filter_prog;
 int i;
 
 for(i=0;i< NUM_CLIENTS && pcaps[i];i++);

 if(pcaps[i])
 {
  printf("no free pcap\n");
  return -1;
 }
  
 
 if(iface == NULL)
  iface = pcap_lookupdev(errbuf);
 
 ret = pcap_open_live(iface, 1500, 0, 1, errbuf);
 if(ret == NULL)
 {
    printf("%s\n", errbuf);	 
  return -1;
 }

 if(pcap_lookupnet(iface, &network, &netmask, 0) < 0)
 { 
   printf("pcap_lookupnet failed\n");
   pcap_close(ret);
   return -1;
 }
 
 if(pcap_compile(ret, &filter_prog, filter, 1, netmask) < 0)
 {
  pcap_perror(ret, "pcap_compile");
  pcap_close(ret);
  return -1;
 }
 
 if(pcap_setfilter(ret, &filter_prog) < 0) 
 {
  pcap_perror(ret, "pcap_setfilter\n");
  pcap_close(ret);
  return -1;
 }
 pcaps[i] = ret;
 return i;
}



u_char* bpf_next_tv(int bpf, int * caplen, struct timeval * tv)
{
  u_char * p = NULL;
  struct pcap_pkthdr head;
  struct timeval timeout, now;

  gettimeofday(&timeout, NULL);
  timeout.tv_sec += tv->tv_sec;
  timeout.tv_usec += tv->tv_usec;
  while ( timeout.tv_usec >= 1000000 ) {
        timeout.tv_sec ++;
        timeout.tv_usec -= 1000000;
  }
  
 do {
  p = (u_char*)pcap_next(pcaps[bpf], &head);
  *caplen  = head.caplen;
  if ( p != NULL ) break;
  gettimeofday(&now, NULL);
 } while ( !((now.tv_sec > timeout.tv_sec) ||
             (now.tv_sec == timeout.tv_sec && now.tv_usec >= timeout.tv_usec ) ));


 return p;
}


u_char* bpf_next(int bpf, int * caplen)
{
 struct timeval tv = {0, 100000};
 
 return bpf_next_tv(bpf, caplen, &tv);
}


int bpf_datalink(int bpf)
{
 return pcap_datalink(pcaps[bpf]);
}


void bpf_close(int bpf)
{
 pcap_close(pcaps[bpf]);
 pcaps[bpf] = NULL;
}


int bpf_server()
{
  return 0;
}
#endif /* HAVE_DEV_BPFN */



#undef __STANDALONE__
#ifdef __STANDALONE__
/*
 * This code tests our bpf sharer
 */
int main()
{
 printf("Hello human\n");
 bpf_server();

 
 
}
#endif
