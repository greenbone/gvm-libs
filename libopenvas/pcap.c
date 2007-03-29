/* Nessuslib -- the Nessus Library
 * Copyright (C) 1999 Renaud Deraison
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
 */

#include <includes.h>
#include <net/if.h>
#ifdef HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>
#endif
#include "network.h"


#define MAXROUTES 1024


struct interface_info {
    char name[64];
    struct in_addr addr;
};

struct interface_info *getinterfaces(int *howmany);




int is_local_ip(addr)
 struct in_addr addr;
{
 int ifaces;
 struct interface_info * ifs;
 int i;
 
 if ((ifs = getinterfaces(&ifaces)) == NULL) 
 	return -1;
 for(i=0;i<ifaces;i++)
 {
  bpf_u_int32 net, mask;
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_lookupnet(ifs[i].name, &net, &mask, errbuf);
  if((net & mask) == (addr.s_addr & mask))
  	return 1;
 }
 return 0;
}



/* 
 * We send an empty UDP packet to the remote host, and read back
 * its mac address. 
 *
 * (we should first interrogate the kernel's arp cache - we may
 * rely on libdnet in the future to do that)
 *
 * As a bonus, this function works well as a local ping
 *
 */
int 
get_mac_addr(addr, mac)
 struct in_addr addr;
 char ** mac;
{
 int soc = socket(AF_INET, SOCK_DGRAM, 0);
 struct sockaddr_in soca;
 int bpf;
 struct in_addr me;
 char * iface = routethrough(&addr, &me);
 char filter[255];
 char * src_host, * dst_host;
 unsigned char * packet;
 int len;
 
 *mac = NULL;
 if(soc < 0)
  return -1;
  
 src_host = estrdup(inet_ntoa(me));
 dst_host = estrdup(inet_ntoa(addr));
 snprintf(filter, sizeof(filter), "ip and (src host %s and dst host %s)",
 	src_host, dst_host);
 efree(&src_host);
 efree(&dst_host);
 
  
 bpf = bpf_open_live(iface, filter);
 if(bpf < 0)
  {
  close(soc);
  return -1;
  }
  
 /*
  * We only deal with ethernet
  */
 if(bpf_datalink(bpf) != DLT_EN10MB)
 {
  bpf_close(bpf);
  close(soc);
  return -1;
 }
 
 
 
 soca.sin_addr.s_addr = addr.s_addr;
 soca.sin_port = htons(9); /* or whatever */
 soca.sin_family = AF_INET;
 if(sendto(soc, NULL, 0, 0, (struct sockaddr*)&soca, sizeof(soca)) == 0)
 {
  packet = (unsigned char*)bpf_next(bpf, &len);
  if(packet)
  { 
   if(len >= get_datalink_size(bpf_datalink(bpf)))
   {
    int i;
    for(i=0;i<6;i++)
    	if(packet[i]!=0xFF)break;
    
    if(i == 6)
    {
     bpf_close(bpf);
     close(soc);
     return 1;
    }
    
    *mac = emalloc(22);
    snprintf(*mac, 22, "%.2x.%.2x.%.2x.%.2x.%.2x.%.2x",
    		(unsigned char)packet[0],
		(unsigned char)packet[1], 
		(unsigned char)packet[2],
		(unsigned char)packet[3],
		(unsigned char)packet[4],
		(unsigned char)packet[5]);
   bpf_close(bpf);
   close(soc);
   return 0;		
   }
  }
  else
  {
   bpf_close(bpf);
   close(soc);
   return 1;
  }
 }
 bpf_close(bpf);
 close(soc);
 return -1;
}


/*
 * Taken straight out of Fyodor's Nmap
 */

int ipaddr2devname( char *dev, int sz, struct in_addr *addr ) {
struct interface_info *mydevs;
int numdevs;
int i;
mydevs = getinterfaces(&numdevs);

if (!mydevs) return -1;

for(i=0; i < numdevs; i++) {
  if (addr->s_addr == mydevs[i].addr.s_addr) {
    dev[sz - 1] = '\0';
    strncpy(dev, mydevs[i].name, sz);
    return 0;
  }
}
return -1;
}

/* Tests whether a packet sent to  IP is LIKELY to route 
 through the kernel localhost interface */
int islocalhost(struct in_addr *addr) {
char dev[128];

  if(addr == NULL)
  	return -1;
	
  /* If it is 0.0.0.0 or starts with 127.0.0.1 then it is 
     probably localhost */
  if ((addr->s_addr & htonl(0xFF000000)) == htonl(0x7F000000))
    return 1;

  if (!addr->s_addr)
    return 1;

  /* If it is the same addy as a local interface, then it is
     probably localhost */

  if (ipaddr2devname(dev, sizeof(dev), addr) != -1)
    return 1;

  /* OK, so to a first approximation, this addy is probably not
     localhost */
  return 0;
}
int
get_datalink_size(datalink)
 int datalink;
{
 int offset = -1;
 switch(datalink) {
  case DLT_EN10MB: offset = 14; break;
  case DLT_IEEE802: offset = 22; break;
  case DLT_NULL: offset = 4; break;
  case DLT_SLIP:
#if (FREEBSD || OPENBSD || NETBSD || BSDI || DARWIN)
    offset = 16;
#else
    offset = 24; /* Anyone use this??? */
#endif
    break;
  case DLT_PPP: 
#if (FREEBSD || OPENBSD || NETBSD || BSDI || DARWIN)
    offset = 4;
#else
#ifdef SOLARIS
    offset = 8;
#else
    offset = 24; /* Anyone use this? */
#endif /* ifdef solaris */
#endif /* if freebsd || openbsd || netbsd || bsdi */
    break;
  case DLT_RAW: offset = 0; break;
  }
  return(offset);
}

int get_random_bytes(void *buf, int numbytes) {
static char bytebuf[2048];
static char badrandomwarning = 0;
static int bytesleft = 0;
int res;
int tmp;
struct timeval tv;
FILE *fp = NULL;
int i;
short *iptr;

if (numbytes < 0 || numbytes > 0xFFFF) return -1;

if (bytesleft == 0) {
  fp = fopen("/dev/urandom", "r");
  if (!fp) fp = fopen("/dev/random", "r");
  if (fp) {
    res = fread(bytebuf, 1, sizeof(bytebuf), fp);
    if (res != sizeof(bytebuf)) {    
      fclose(fp);
      fp = NULL;
    }      
    bytesleft = sizeof(bytebuf);
  }
  if (!fp) {  
    if (badrandomwarning == 0) {
      badrandomwarning++;
    }
    /* Seed our random generator */
    gettimeofday(&tv, NULL);
    srand((tv.tv_sec ^ tv.tv_usec) ^ getpid());

    for(i=0; i < sizeof(bytebuf) / sizeof(short); i++) {
      iptr = (short *) ((char *)bytebuf + i * sizeof(short));
      *iptr = rand();
    }
    bytesleft = (sizeof(bytebuf) / sizeof(short)) * sizeof(short);
    /*    ^^^^^^^^^^^^^^^not as meaningless as it looks  */
  } else fclose(fp);
}
if (numbytes <= bytesleft) { /* we can cover it */
  memcpy(buf, bytebuf + (sizeof(bytebuf) - bytesleft), numbytes);
  bytesleft -= numbytes;
  return 0;
}

/* We don't have enough */
memcpy(buf, bytebuf + (sizeof(bytebuf) - bytesleft), bytesleft);
tmp = bytesleft;
bytesleft = 0;
return get_random_bytes((char *)buf + tmp, numbytes - tmp);
}

struct interface_info *getinterfaces(int *howmany) {
  static struct interface_info mydevs[1024];
  int numinterfaces = 0;
  int sd;
  int len;
  char *p;
  char buf[10240];
  struct ifconf ifc;
  struct ifreq *ifr;
  struct sockaddr_in *sin;

    /* Dummy socket for ioctl */
    sd = socket(AF_INET, SOCK_DGRAM, 0);
    bzero(buf, sizeof(buf));
    if (sd < 0) printf("socket in getinterfaces");
    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sd, SIOCGIFCONF, &ifc) < 0) {
      printf("Failed to determine your configured interfaces!\n");
    }
    close(sd);
    ifr = (struct ifreq *) buf;
    if (ifc.ifc_len == 0) 
      printf("getinterfaces: SIOCGIFCONF claims you have no network interfaces!\n");
#ifdef HAVE_SOCKADDR_SA_LEN
    len = ifr->ifr_addr.sa_len;
#else
#ifdef HAVE_STRUCT_IFMAP
    len = sizeof(struct ifmap);
#else
    len = sizeof(struct sockaddr);
#endif
#endif
    for(; ifr && *((char *)ifr) && ((char *)ifr) < buf + ifc.ifc_len; 
	((*(char **)&ifr) +=  sizeof(ifr->ifr_name) + len )) {
      sin = (struct sockaddr_in *) &ifr->ifr_addr;
      memcpy(&(mydevs[numinterfaces].addr), (char *) &(sin->sin_addr), sizeof(struct in_addr));
      /* In case it is a stinkin' alias */
      if ((p = strchr(ifr->ifr_name, ':')))
	*p = '\0';
      strncpy(mydevs[numinterfaces].name, ifr->ifr_name, 63);
      mydevs[numinterfaces].name[63] = '\0';
      numinterfaces++;
      if (numinterfaces == 1023)  {      
	printf("My god!  You seem to have WAY too many interfaces!  Things may not work right\n");
	break;
      }
#if HAVE_SOCKADDR_SA_LEN
      /* len = MAX(sizeof(struct sockaddr), ifr->ifr_addr.sa_len);*/
      len = ifr->ifr_addr.sa_len;
#endif 
      mydevs[numinterfaces].name[0] = '\0';
  }
  if (howmany) *howmany = numinterfaces;
  return mydevs;
}


int getsourceip(struct in_addr *src, struct in_addr *dst) {
  int sd;
  struct sockaddr_in sock;
  unsigned int socklen = sizeof(struct sockaddr_in);
  unsigned short p1;
  
  
 
  
  *src = socket_get_next_source_addr(NULL);
  if ( src->s_addr != INADDR_ANY )
  {
   return 1;
  }
  

  get_random_bytes(&p1, 2);
  if (p1 < 5000) p1 += 5000;

  if ((sd = socket(AF_INET, SOCK_DGRAM, 0)) == -1)
    {perror("Socket troubles"); return 0;}
  sock.sin_family = AF_INET;
  sock.sin_addr = *dst;
  sock.sin_port = htons(p1);
  if (connect(sd, (struct sockaddr *) &sock, sizeof(struct sockaddr_in)) == -1)
    { perror("UDP connect()");
    close(sd);
    return 0;
    }
  bzero(&sock, sizeof(struct sockaddr_in));
  if (getsockname(sd, (struct sockaddr *)&sock, &socklen) == -1) {
    perror("getsockname");
    close(sd);
    return 0;
  }

  src->s_addr = sock.sin_addr.s_addr;
  close(sd);
  return 1; /* Calling function responsible for checking validity */
}

/* An awesome function to determine what interface a packet to a given
   destination should be routed through.  It returns NULL if no appropriate
   interface is found, oterwise it returns the device name and fills in the
   source parameter.   Some of the stuff is
   from Stevens' Unix Network Programming V2.  He had an easier suggestion
   for doing this (in the book), but it isn't portable :( */
   
   
/* An awesome function to determine what interface a packet to a given
   destination should be routed through.  It returns NULL if no appropriate
   interface is found, oterwise it returns the device name and fills in the
   source parameter.   Some of the stuff is
   from Stevens' Unix Network Programming V2.  He had an easier suggestion
   for doing this (in the book), but it isn't portable :( */
char *routethrough(struct in_addr *dest, struct in_addr *source) {
  static int initialized = 0;
  int i;
  struct in_addr addy;
  static enum { procroutetechnique, connectsockettechnique, guesstechnique } technique = procroutetechnique;
  char buf[10240];
  struct interface_info *mydevs;
  static struct myroute {
    struct interface_info *dev;
    unsigned long mask;
    unsigned long dest;
  } myroutes[MAXROUTES];
  int numinterfaces = 0;
  char *p, *endptr;
  char iface[64];
  static int numroutes = 0;
  FILE *routez;
  
  struct in_addr src = socket_get_next_source_addr(NULL);
  

  if (!dest) printf("ipaddr2devname passed a NULL dest address");

  if (!initialized) {  
    /* Dummy socket for ioctl */
    initialized = 1;
    mydevs = getinterfaces(&numinterfaces);

    /* Now we must go through several techniques to determine info */
    routez = fopen("/proc/net/route", "r");

    if (routez) {
      /* OK, linux style /proc/net/route ... we can handle this ... */
      /* Now that we've got the interfaces, we g0 after the r0ut3Z */
      
      fgets(buf, sizeof(buf), routez); /* Kill the first line */
      while(fgets(buf,sizeof(buf), routez)) {
	p = strtok(buf, " \t\n");
	if (!p) {
	  printf("Could not find interface in /proc/net/route line");
	  continue;
	}
	strncpy(iface, p, sizeof(iface));
	if ((p = strchr(iface, ':'))) {
	  *p = '\0'; /* To support IP aliasing */
	}
	p = strtok(NULL, " \t\n");
	endptr = NULL;
	myroutes[numroutes].dest = strtoul(p, &endptr, 16);
	if (!endptr || *endptr) {
	  printf("Failed to determine Destination from /proc/net/route");
	  continue;
	}
	for(i=0; i < 6; i++) {
	  p = strtok(NULL, " \t\n");
	  if (!p) break;
	}
	if (!p) {
	  printf("Failed to find field %d in /proc/net/route", i + 2);
	  continue;
	}
	endptr = NULL;
	myroutes[numroutes].mask = strtoul(p, &endptr, 16);
	if (!endptr || *endptr) {
	  printf("Failed to determine mask from /proc/net/route");
	  continue;
	}


#if TCPIP_DEBUGGING
	  printf("#%d: for dev %s, The dest is %lX and the mask is %lX\n", numroutes, iface, myroutes[numroutes].dest, myroutes[numroutes].mask);
#endif
	  for(i=0; i < numinterfaces; i++)
	    if (!strcmp(iface, mydevs[i].name)) {
	      myroutes[numroutes].dev = &mydevs[i];
	      break;
	    }
	  if (i == numinterfaces) 
	    printf("Failed to find interface %s mentioned in /proc/net/route\n", iface);
	  numroutes++;
	  if (numroutes >= MAXROUTES)
            {
	    printf("My god!  You seem to have WAY to many routes!\n");
            break;
            }
      }
      fclose(routez);
    } else {
      technique = connectsockettechnique;
    }
  } else {  
    mydevs = getinterfaces(&numinterfaces);
  }
  /* WHEW, that takes care of initializing, now we have the easy job of 
     finding which route matches */
  if (islocalhost(dest)) {
    if (source)
      source->s_addr = htonl(0x7F000001);
    /* Now we find the localhost interface name, assuming 127.0.0.1 is
       localhost (it damn well better be!)... */
    for(i=0; i < numinterfaces; i++) {    
      if (mydevs[i].addr.s_addr == htonl(0x7F000001)) {
	return mydevs[i].name;
      }
    }
    return NULL;
  }

  if (technique == procroutetechnique) {    
    for(i=0; i < numroutes; i++) {  
      if ((dest->s_addr & myroutes[i].mask) == myroutes[i].dest) {
	if (source) {
	  
	  if ( src.s_addr != INADDR_ANY )
	  	source->s_addr = src.s_addr;
	  else
	       source->s_addr = myroutes[i].dev->addr.s_addr; 
	}
	return myroutes[i].dev->name;      
      }
    }
  } else if (technique == connectsockettechnique) {
      if (!getsourceip(&addy, dest))
	return NULL;
      if (!addy.s_addr)  {  /* Solaris 2.4 */
        struct hostent *myhostent = NULL;
        char myname[MAXHOSTNAMELEN + 1];
#if defined(USE_PTHREADS) && defined(HAVE_GETHOSTBYNAME_R)
        int Errno = 0;
        char * buf = emalloc(4096);
        struct hostent * res = NULL;
        struct hostent * t = NULL;	
	
	myhostent = emalloc(sizeof(struct hostent));
#ifdef HAVE_SOLARIS_GETHOSTBYNAME_R
	 gethostbyname_r(myname, myhostent, buf, 4096, &Errno);
	 if(Errno){
	  	free(myhostent);
		myhostent = NULL;
		}
#else
         gethostbyname_r(myname, myhostent, buf, 4096, &res, &Errno);
         t = myhostent;
         myhostent = res;
#endif /* HAVE_SOLARIS_... */
	myhostent = res;
#else
	myhostent = gethostbyname(myname);
#endif /* USE_PTHREADS     */
        if (gethostname(myname, MAXHOSTNAMELEN) || 
           !myhostent)
	  printf("Cannot get hostname!  Try using -S <my_IP_address> or -e <interface to scan through>\n");
        memcpy(&(addy.s_addr), myhostent->h_addr_list[0], sizeof(struct in_addr));
#if defined(USE_PTHREADS) && defined(HAVE_GETHOSTBYNAME_R)
	if(myhostent)free(myhostent);
	free(buf);
#endif
      }

      /* Now we insure this claimed address is a real interface ... */
      for(i=0; i < numinterfaces; i++)
	if (mydevs[i].addr.s_addr == addy.s_addr) {
	  if (source) {
	    source->s_addr = addy.s_addr;	  
	  }
	  return mydevs[i].name;
	}  
      return NULL;
    } else 
      printf("I know sendmail technique ... I know rdist technique ... but I don't know what the hell kindof technique you are attempting!!!");
    return NULL;
}
