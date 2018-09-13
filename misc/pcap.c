/* OpenVAS Libraries
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
 * Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <netinet/in.h>
#include <resolv.h>
#include <pcap.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <ifaddrs.h>


#include "bpf_share.h"
#include "pcap_openvas.h"
#include "openvas_logging.h"
#include "network.h"
#include "support.h"

#define MAXROUTES 1024
/* MAXHOSTNAMELEN doesn't exist on some architectures like hurd i386 */
#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 64
#endif

struct interface_info
{
  char name[64];
  struct in_addr addr;
  struct in6_addr addr6;
  struct in6_addr mask;
};

struct myroute
{
  struct interface_info *dev;
  struct in6_addr dest6;
  unsigned long mask;
  unsigned long dest;
};

struct interface_info *getinterfaces (int *howmany);
struct interface_info *v6_getinterfaces (int *howmany);
int getipv6routes (struct myroute *myroutes, int *numroutes);

static void
ipv6addrmask (struct in6_addr *in6addr, int mask)
{
  int wordmask;
  int word;
  uint32_t *ptr;
  uint32_t addr;

  word = mask / 32;
  wordmask = mask % 32;
  ptr = (uint32_t *) in6addr;
  switch (word)
    {
    case 0:
      ptr[1] = ptr[2] = ptr[3] = 0;
      addr = ptr[0];
      addr = ntohl (addr) >> (32 - wordmask);
      addr = htonl (addr << (32 - wordmask));
      ptr[0] = addr;
      break;
    case 1:
      ptr[2] = ptr[3] = 0;
      addr = ptr[1];
      addr = ntohl (addr) >> (32 - wordmask);
      addr = htonl (addr << (32 - wordmask));
      ptr[1] = addr;
      break;
    case 2:
      ptr[3] = 0;
      addr = ptr[2];
      addr = ntohl (addr) >> (32 - wordmask);
      addr = htonl (addr << (32 - wordmask));
      ptr[2] = addr;
      break;
    case 3:
      addr = ptr[3];
      addr = ntohl (addr) >> (32 - wordmask);
      addr = htonl (addr << (32 - wordmask));
      ptr[3] = addr;
      break;
    }
}

int
v6_is_local_ip (struct in6_addr *addr)
{
  int ifaces;
  struct interface_info *ifs;
  int i;
  static struct myroute myroutes[MAXROUTES];
  int numroutes = 0;
  struct in6_addr in6addr;
#if TCPIP_DEBUGGING
  char addr1[INET6_ADDRSTRLEN];
  char addr2[INET6_ADDRSTRLEN];
#endif

  if ((ifs = v6_getinterfaces (&ifaces)) == NULL)
    return -1;

  if (IN6_IS_ADDR_V4MAPPED (addr))
    {
      for (i = 0; i < ifaces; i++)
        {
          bpf_u_int32 net, mask;
          char errbuf[PCAP_ERRBUF_SIZE];
          pcap_lookupnet (ifs[i].name, &net, &mask, errbuf);
          if ((net & mask) == (addr->s6_addr32[3] & mask))
            return 1;
        }
    }
  else
    {
      if (IN6_IS_ADDR_LINKLOCAL (addr))
        return 1;
      if (IN6_IS_ADDR_LOOPBACK (addr))
        return 1;
      if (getipv6routes (myroutes, &numroutes) == 0)
        {
          for (i = 0; i < numroutes; i++)
            {
              memcpy (&in6addr, addr, sizeof (struct in6_addr));
              ipv6addrmask (&in6addr, myroutes[i].mask);
#if TCPIP_DEBUGGING
              printf ("comparing addresses %s and %s\n",
                      inet_ntop (AF_INET6, &in6addr, addr1, sizeof (addr1)),
                      inet_ntop (AF_INET6, &myroutes[i].dest6, addr2,
                                 sizeof (addr2)));
#endif
              if (IN6_ARE_ADDR_EQUAL (&in6addr, &myroutes[i].dest6))
                {
                  return 1;
                }
            }
        }
    }
  return 0;
}

/**
 * @brief We send an empty UDP packet to the remote host, and read back its mac
 * @brief address.
 *
 * (we should first interrogate the kernel's arp cache - we may
 * rely on libdnet in the future to do that)
 *
 * As a bonus, this function works well as a local ping.
 */
int
v6_get_mac_addr (struct in6_addr *addr, char **mac)
{
  int soc;
  struct sockaddr_in soca;
  struct sockaddr_in6 soca6;
  int bpf;
  struct in6_addr me;
  struct in_addr inaddr;
  char *iface = v6_routethrough (addr, &me);
  char filter[255];
  char *src_host, *dst_host;
  unsigned char *packet;
  int len;
  char hostname[INET6_ADDRSTRLEN];

  if (IN6_IS_ADDR_V4MAPPED (addr))
    {
      soc = socket (AF_INET, SOCK_DGRAM, 0);
      *mac = NULL;
      if (soc < 0)
        return -1;

      inaddr.s_addr = me.s6_addr32[3];
      src_host = g_strdup (inet_ntoa (inaddr));
      inaddr.s_addr = addr->s6_addr32[3];
      dst_host = g_strdup (inet_ntoa (inaddr));
      snprintf (filter, sizeof (filter)-1, "ip and (src host %s and dst host %s)",
                src_host, dst_host);
      g_free (src_host);
      g_free (dst_host);

      bpf = bpf_open_live (iface, filter);
      if (bpf < 0)
        {
          close (soc);
          return -1;
        }

      /*
       * We only deal with ethernet
       */
      if (bpf_datalink (bpf) != DLT_EN10MB)
        {
          bpf_close (bpf);
          close (soc);
          return -1;
        }


      soca.sin_addr.s_addr = addr->s6_addr32[3];
      soca.sin_port = htons (9);        /* or whatever */
      soca.sin_family = AF_INET;
      if (sendto (soc, NULL, 0, 0, (struct sockaddr *) &soca, sizeof (soca)) !=
          0)
        {
          bpf_close (bpf);
          close (soc);
          return -1;
        }
    }
  else
    {
      soc = socket (AF_INET6, SOCK_DGRAM, 0);
      *mac = NULL;
      if (soc < 0)
        return -1;
      src_host =
        g_strdup (inet_ntop (AF_INET6, &me, hostname, sizeof (hostname)));
      dst_host =
        g_strdup (inet_ntop (AF_INET6, addr, hostname, sizeof (hostname)));
      snprintf (filter, sizeof (filter)-1,
                "ip6 and (src host %s and dst host %s)", src_host, dst_host);
      g_free (src_host);
      g_free (dst_host);


      bpf = bpf_open_live (iface, filter);
      if (bpf < 0)
        {
          close (soc);
          return -1;
        }

      /* We only deal with ethernet. */
      if (bpf_datalink (bpf) != DLT_EN10MB)
        {
          bpf_close (bpf);
          close (soc);
          return -1;
        }


      memcpy (&soca6.sin6_addr, addr, sizeof (struct in6_addr));
      soca6.sin6_port = htons (9);      /* or whatever */
      soca6.sin6_family = AF_INET6;
      if (sendto (soc, NULL, 0, 0, (struct sockaddr *) &soca6, sizeof (soca6))
          != 0)
        {
          bpf_close (bpf);
          close (soc);
          return -1;
        }
    }

  packet = (unsigned char *) bpf_next (bpf, &len);
  if (packet)
    {
      if (len >= get_datalink_size (bpf_datalink (bpf)))
        {
          int i;
          for (i = 0; i < 6; i++)
            if (packet[i] != 0xFF)
              break;

          if (i == 6)
            {
              bpf_close (bpf);
              close (soc);
              return 1;
            }

          *mac = g_malloc0 (23);
          snprintf (*mac, 22, "%.2x.%.2x.%.2x.%.2x.%.2x.%.2x",
                    (unsigned char) packet[0], (unsigned char) packet[1],
                    (unsigned char) packet[2], (unsigned char) packet[3],
                    (unsigned char) packet[4], (unsigned char) packet[5]);
          bpf_close (bpf);
          close (soc);
          return 0;
        }
    }
  else
    {
      bpf_close (bpf);
      close (soc);
      return 1;
    }
  return 1;                     /* keep the compiler happy */
}


/*
 * Taken straight out of Fyodor's Nmap
 */
int
v6_ipaddr2devname (char *dev, int sz, struct in6_addr *addr)
{
  struct interface_info *mydevs;
  int numdevs;
  int i;
  mydevs = v6_getinterfaces (&numdevs);
#if TCPIP_DEBUGGING
  char addr1[INET6_ADDRSTRLEN];
  char addr2[INET6_ADDRSTRLEN];
#endif

  if (!mydevs)
    return -1;

  for (i = 0; i < numdevs; i++)
    {
#if TCPIP_DEBUGGING
      printf ("comparing addresses %s and %s\n",
              inet_ntop (AF_INET6, addr, addr1, sizeof (addr1)),
              inet_ntop (AF_INET6, &mydevs[i].addr6, addr2, sizeof (addr2)));
#endif
      if (IN6_ARE_ADDR_EQUAL (addr, &mydevs[i].addr6))
        {
          dev[sz - 1] = '\0';
          strncpy (dev, mydevs[i].name, sz);
          return 0;
        }
    }
  return -1;
}

/*
 * Taken straight out of Fyodor's Nmap
 */
int
ipaddr2devname (char *dev, int sz, struct in_addr *addr)
{
  struct interface_info *mydevs;
  int numdevs;
  int i;
  mydevs = getinterfaces (&numdevs);

  if (!mydevs)
    return -1;

  for (i = 0; i < numdevs; i++)
    {
      if (addr->s_addr == mydevs[i].addr.s_addr)
        {
          dev[sz - 1] = '\0';
          strncpy (dev, mydevs[i].name, sz);
          return 0;
        }
    }
  return -1;
}

/**
 * @brief Tests whether a packet sent to IP is LIKELY to route through the
 * kernel localhost interface
 */
int
v6_islocalhost (struct in6_addr *addr)
{
  char dev[128];

  if (addr == NULL)
    return -1;

  if (IN6_IS_ADDR_V4MAPPED (addr))
    {
      /* If it is 0.0.0.0 or starts with 127.0.0.1 then it is
         probably localhost */
      if ((addr->s6_addr32[3] & htonl (0xFF000000)) == htonl (0x7F000000))
        return 1;

      if (!addr->s6_addr32[3])
        return 1;
    }

  if (IN6_IS_ADDR_LOOPBACK (addr))
    return 1;

  /* If it is the same addy as a local interface, then it is
     probably localhost */

  if (v6_ipaddr2devname (dev, sizeof (dev), addr) != -1)
    return 1;

  /* OK, so to a first approximation, this addy is probably not
     localhost */
  return 0;
}

/**
 * @brief Tests whether a packet sent to IP is LIKELY to route through the
 * kernel localhost interface
 */
int
islocalhost (struct in_addr *addr)
{
  char dev[128];

  if (addr == NULL)
    return -1;

  /* If it is 0.0.0.0 or starts with 127.0.0.1 then it is
     probably localhost */
  if ((addr->s_addr & htonl (0xFF000000)) == htonl (0x7F000000))
    return 1;

  if (!addr->s_addr)
    return 1;

  /* If it is the same addy as a local interface, then it is
     probably localhost */

  if (ipaddr2devname (dev, sizeof (dev), addr) != -1)
    return 1;

  /* OK, so to a first approximation, this addy is probably not
     localhost */
  return 0;
}

int
get_datalink_size (int datalink)
{
  int offset = -1;
  switch (datalink)
    {
    case DLT_EN10MB:
      offset = 14;
      break;
    case DLT_IEEE802:
      offset = 22;
      break;
    case DLT_NULL:
      offset = 4;
      break;
    case DLT_SLIP:
#if (FREEBSD || OPENBSD || NETBSD || BSDI || DARWIN)
      offset = 16;
#else
      offset = 24;              /* Anyone use this??? */
#endif
      break;
    case DLT_PPP:
#if (FREEBSD || OPENBSD || NETBSD || BSDI || DARWIN)
      offset = 4;
#else
#ifdef SOLARIS
      offset = 8;
#else
      offset = 24;              /* Anyone use this? */
#endif /* ifdef solaris */
#endif /* if freebsd || openbsd || netbsd || bsdi */
      break;
    case DLT_RAW:
      offset = 0;
      break;
    }
  return (offset);
}

int
get_random_bytes (void *buf, int numbytes)
{
  static char bytebuf[2048];
  static char badrandomwarning = 0;
  static int bytesleft = 0;
  int res;
  int tmp;
  struct timeval tv;
  FILE *fp = NULL;
  short *iptr;

  if (numbytes < 0 || numbytes > 0xFFFF)
    return -1;

  if (bytesleft == 0)
    {
      fp = fopen ("/dev/urandom", "r");
      if (!fp)
        fp = fopen ("/dev/random", "r");
      if (fp)
        {
          res = fread (bytebuf, 1, sizeof (bytebuf), fp);
          if (res != sizeof (bytebuf))
            {
              fclose (fp);
              fp = NULL;
            }
          bytesleft = sizeof (bytebuf);
        }
      if (!fp)
        {
          unsigned int i;

          if (badrandomwarning == 0)
            {
              badrandomwarning++;
            }
          /* Seed our random generator */
          gettimeofday (&tv, NULL);
          srand ((tv.tv_sec ^ tv.tv_usec) ^ getpid ());

          for (i = 0; i < sizeof (bytebuf) / sizeof (short); i++)
            {
              iptr = (short *) ((char *) bytebuf + i * sizeof (short));
              *iptr = rand ();
            }
          bytesleft = (sizeof (bytebuf) / sizeof (short)) * sizeof (short);
          /*    ^^^^^^^^^^^^^^^not as meaningless as it looks  */
        }
      else
        fclose (fp);
    }
  if (numbytes <= bytesleft)
    {                           /* we can cover it */
      memcpy (buf, bytebuf + (sizeof (bytebuf) - bytesleft), numbytes);
      bytesleft -= numbytes;
      return 0;
    }

  /* We don't have enough */
  memcpy (buf, bytebuf + (sizeof (bytebuf) - bytesleft), bytesleft);
  tmp = bytesleft;
  bytesleft = 0;
  return get_random_bytes ((char *) buf + tmp, numbytes - tmp);
}

struct interface_info *
v6_getinterfaces (int *howmany)
{
  struct sockaddr_in *saddr;
  struct sockaddr_in6 *s6addr;
  static struct interface_info mydevs[1024];
  int numinterfaces = 0;
  struct ifaddrs *ifaddr, *ifa;
  int family;

  if (getifaddrs (&ifaddr) == -1)
    {
      perror ("getifaddrs");
    }
  else
    {
      for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
        {
          if (ifa->ifa_addr == NULL)
              continue;

          family = ifa->ifa_addr->sa_family;
          if (family == AF_INET)
            {
              memcpy (mydevs[numinterfaces].name, ifa->ifa_name,
                      strlen (ifa->ifa_name));
              saddr = (struct sockaddr_in *) ifa->ifa_addr;
              mydevs[numinterfaces].addr6.s6_addr32[0] = 0;
              mydevs[numinterfaces].addr6.s6_addr32[1] = 0;
              mydevs[numinterfaces].addr6.s6_addr32[2] = htonl (0xffff);
              mydevs[numinterfaces].addr6.s6_addr32[3] = saddr->sin_addr.s_addr;
              saddr = (struct sockaddr_in *) ifa->ifa_netmask;
              mydevs[numinterfaces].mask.s6_addr32[0] = 0;
              mydevs[numinterfaces].mask.s6_addr32[1] = 0;
              mydevs[numinterfaces].mask.s6_addr32[2] = htonl (0xffff);
              mydevs[numinterfaces].mask.s6_addr32[3] = saddr->sin_addr.s_addr;
#ifdef TCPIP_DEBUGGING
              printf ("interface name is %s\n", ifa->ifa_name);
              printf ("\tAF_INET family\n");
              printf ("\taddress is %s\n", inet_ntoa (saddr->sin_addr));
              printf ("\tnetmask is %s\n", inet_ntoa (saddr->sin_addr));
#endif
              numinterfaces++;
            }
          else if (family == AF_INET6)
            {
              memcpy (mydevs[numinterfaces].name, ifa->ifa_name,
                      strlen (ifa->ifa_name));
              s6addr = (struct sockaddr_in6 *) ifa->ifa_addr;
              memcpy (&(mydevs[numinterfaces].addr6),
                      (char *) &(s6addr->sin6_addr), sizeof (struct in6_addr));
              s6addr = (struct sockaddr_in6 *) ifa->ifa_netmask;
              memcpy (&(mydevs[numinterfaces].mask),
                      (char *) &(s6addr->sin6_addr), sizeof (struct in6_addr));
              numinterfaces++;
#ifdef TCPIP_DEBUGGING
              printf ("\tAF_INET6 family\n");
              printf ("interface name is %s\n", ifa->ifa_name);
              printf ("\taddress is %s\n",
                      inet_ntop (AF_INET6, &s6addr->sin6_addr, ipaddr,
                                 sizeof (ipaddr)));
#endif
            }
          else
            {
#ifdef TCPIP_DEBUGGING
              printf ("\tfamily is %d\n", ifa->ifa_addr->sa_family);
#endif
            }
        }
      *howmany = numinterfaces;

      freeifaddrs (ifaddr);
    }
  return mydevs;
}

/**
 * @param[out] howmany Return location for the number of interfaces found
 *                     (might be NULL).
 */
struct interface_info *
getinterfaces (int *howmany)
{
  static struct interface_info mydevs[1024];
  int numinterfaces = 0;
  int sd;
  int len;
  char *p;
  char buf[10240];
  struct ifconf ifc;
  struct ifreq *ifr;
  struct sockaddr_in *sin;
  char *bufp;

  /* Dummy socket for ioctl. */
  sd = socket (AF_INET, SOCK_DGRAM, 0);
  bzero (buf, sizeof (buf));
  if (sd < 0)
    log_legacy_write ("socket in getinterfaces");

  ifc.ifc_len = sizeof (buf);
  ifc.ifc_buf = buf;
  if (ioctl (sd, SIOCGIFCONF, &ifc) < 0)
    log_legacy_write ("Failed to determine your configured interfaces!");

  close (sd);
  if (ifc.ifc_len == 0)
    log_legacy_write
     ("getinterfaces: SIOCGIFCONF claims you have no network interfaces!");

  len = sizeof (struct ifmap);

  for (bufp = buf; bufp && *bufp && (bufp < (buf + ifc.ifc_len));
       bufp += sizeof (ifr->ifr_name) + len)
    {
      ifr = (struct ifreq *) bufp;
      sin = (struct sockaddr_in *) &ifr->ifr_addr;
      memcpy (&(mydevs[numinterfaces].addr), (char *) &(sin->sin_addr),
              sizeof (struct in_addr));
      /* In case it is a stinkin' alias */
      if ((p = strchr (ifr->ifr_name, ':')))
        *p = '\0';
      strncpy (mydevs[numinterfaces].name, ifr->ifr_name, 63);
      mydevs[numinterfaces].name[63] = '\0';
      numinterfaces++;
      if (numinterfaces == 1023)
        {
          log_legacy_write
           ("You seem to have more than 1023 network interfaces."
            " Things may not work right.");
          break;
        }
      mydevs[numinterfaces].name[0] = '\0';
    }

  // If output parameter given, set value
  if (howmany)
    *howmany = numinterfaces;

  return mydevs;
}

int
v6_getsourceip (struct in6_addr *src, struct in6_addr *dst)
{
  int sd;
  struct sockaddr_in sock;
  struct sockaddr_in6 sock6;
  unsigned int socklen;
  unsigned short p1;

#ifdef TCPIP_DEBUGGING
  char name[INET6_ADDRSTRLEN];
#endif

  get_random_bytes (&p1, 2);
  if (p1 < 5000)
    p1 += 5000;

  if (IN6_IS_ADDR_V4MAPPED (dst))
    {
      if ((sd = socket (AF_INET, SOCK_DGRAM, 0)) == -1)
        {
          perror ("Socket troubles");
          return 0;
        }
      sock.sin_family = AF_INET;
      sock.sin_addr.s_addr = dst->s6_addr32[3];
      sock.sin_port = htons (p1);
      if (connect (sd, (struct sockaddr *) &sock, sizeof (struct sockaddr_in))
          == -1)
        {
          close (sd);
          return 0;
        }
      bzero (&sock, sizeof (struct sockaddr_in));
      socklen = sizeof (struct sockaddr_in);
      if (getsockname (sd, (struct sockaddr *) &sock, &socklen) == -1)
        {
          perror ("getsockname");
          close (sd);
          return 0;
        }


      src->s6_addr32[0] = 0;
      src->s6_addr32[1] = 0;
      src->s6_addr32[2] = htonl (0xffff);
      src->s6_addr32[3] = sock.sin_addr.s_addr;
#ifdef TCPIP_DEBUGGING
      printf ("source addrss is %s\n",
              inet_ntop (AF_INET6, src, name, sizeof (name)));
#endif
      close (sd);
    }
  else
    {
      if ((sd = socket (AF_INET6, SOCK_DGRAM, 0)) == -1)
        {
          perror ("Socket troubles");
          return 0;
        }
      sock6.sin6_family = AF_INET6;
      sock6.sin6_addr.s6_addr32[0] = dst->s6_addr32[0];
      sock6.sin6_addr.s6_addr32[1] = dst->s6_addr32[1];
      sock6.sin6_addr.s6_addr32[2] = dst->s6_addr32[2];
      sock6.sin6_addr.s6_addr32[3] = dst->s6_addr32[3];
      sock6.sin6_port = htons (p1);
      if (connect (sd, (struct sockaddr *) &sock6, sizeof (struct sockaddr_in6))
          == -1)
        {
          close (sd);
          return 0;
        }
      bzero (&sock6, sizeof (struct sockaddr_in6));
      socklen = sizeof (struct sockaddr_in6);
      if (getsockname (sd, (struct sockaddr *) &sock6, &socklen) == -1)
        {
          perror ("getsockname");
          close (sd);
          return 0;
        }

      src->s6_addr32[0] = sock6.sin6_addr.s6_addr32[0];
      src->s6_addr32[1] = sock6.sin6_addr.s6_addr32[1];
      src->s6_addr32[2] = sock6.sin6_addr.s6_addr32[2];
      src->s6_addr32[3] = sock6.sin6_addr.s6_addr32[3];
      memcpy (src, &sock6.sin6_addr, sizeof (struct in6_addr));
#ifdef TCPIP_DEBUGGING
      printf ("source addrss is %s\n",
              inet_ntop (AF_INET6, src, name, sizeof (name)));
#endif
      close (sd);
    }
  return 1;                     /* Calling function responsible for checking validity */
}

int
getsourceip (struct in_addr *src, struct in_addr *dst)
{
  int sd;
  struct sockaddr_in sock;
  unsigned int socklen = sizeof (struct sockaddr_in);
  unsigned short p1;

  get_random_bytes (&p1, 2);
  if (p1 < 5000)
    p1 += 5000;

  if ((sd = socket (AF_INET, SOCK_DGRAM, 0)) == -1)
    {
      perror ("Socket troubles");
      return 0;
    }
  sock.sin_family = AF_INET;
  sock.sin_addr = *dst;
  sock.sin_port = htons (p1);
  if (connect (sd, (struct sockaddr *) &sock, sizeof (struct sockaddr_in)) ==
      -1)
    {
      close (sd);
      return 0;
    }
  bzero (&sock, sizeof (struct sockaddr_in));
  if (getsockname (sd, (struct sockaddr *) &sock, &socklen) == -1)
    {
      perror ("getsockname");
      close (sd);
      return 0;
    }

  src->s_addr = sock.sin_addr.s_addr;
  close (sd);
  return 1;                     /* Calling function responsible for checking validity */
}

int
getipv4routes (struct myroute *myroutes, int *numroutes)
{
  struct interface_info *mydevs;
  int i;
  int numinterfaces;
  char buf[1024];
  char *p, *endptr;
  char iface[64];
  FILE *routez;
  unsigned long dest;
  struct in_addr inaddr;
  unsigned long mask;
  unsigned long ones;

  /* Dummy socket for ioctl */
  mydevs = v6_getinterfaces (&numinterfaces);

  /* Now we must go through several techniques to determine info */
  routez = fopen ("/proc/net/route", "r");

  if (routez)
    {
      /* OK, linux style /proc/net/route ... we can handle this ... */
      /* Now that we've got the interfaces, we g0 after the r0ut3Z */
      if (fgets (buf, sizeof (buf), routez) == NULL)  /* Kill the first line */
        {
          // /proc/net/route was empty or an error occurred.
          log_legacy_write ("Could not read from /proc/net/route");
          fclose (routez);
          return -1;
        }
      while (fgets (buf, sizeof (buf), routez))
        {
          p = strtok (buf, " \t\n");
          if (!p)
            {
              log_legacy_write ("Could not find interface in"
                                " /proc/net/route line");
              continue;
            }
          strncpy (iface, p, sizeof (iface));
          if ((p = strchr (iface, ':')))
            {
              *p = '\0';        /* To support IP aliasing */
            }
          p = strtok (NULL, " \t\n");
          endptr = NULL;
          dest = strtoul (p, &endptr, 16);
#ifdef TCPIP_DEBUGGING
          printf ("ipv4 dest is %s\n", p);
#endif
          if (!endptr || *endptr)
            {
              log_legacy_write ("Failed to determine Destination from"
                                " /proc/net/route");
              continue;
            }
          inaddr.s_addr = dest;
          myroutes[*numroutes].dest6.s6_addr32[0] = 0;
          myroutes[*numroutes].dest6.s6_addr32[1] = 0;
          myroutes[*numroutes].dest6.s6_addr32[2] = htonl (0xffff);
          myroutes[*numroutes].dest6.s6_addr32[3] = inaddr.s_addr;
          for (i = 0; i < 6; i++)
            {
              p = strtok (NULL, " \t\n");
              if (!p)
                break;
            }
          if (!p)
            {
              log_legacy_write ("Failed to find field %d in"
                                " /proc/net/route", i + 2);
              continue;
            }
          endptr = NULL;
          mask = strtoul (p, &endptr, 16);
          ones = 0;
          i = 0;
          while (mask & (1 << i++) && i < 32)
            ones++;
          myroutes[*numroutes].mask = ones + 96;
#ifdef TCPIP_DEBUGGING
          printf ("mask is %lu\n", myroutes[*numroutes].mask);
#endif
          if (!endptr || *endptr)
            {
              log_legacy_write ("Failed to determine mask from"
                                " /proc/net/route");
              continue;
            }


#if TCPIP_DEBUGGING
          printf ("#%d: for dev %s, The dest is %lX and the mask is %lX\n",
                  *numroutes, iface, myroutes[*numroutes].dest,
                  myroutes[*numroutes].mask);
#endif
          for (i = 0; i < numinterfaces; i++)
            if (!strcmp (iface, mydevs[i].name))
              {
                myroutes[*numroutes].dev = &mydevs[i];
                break;
              }
          if (i == numinterfaces)
            log_legacy_write
             ("Failed to find interface %s mentioned in /proc/net/route",
               iface);
          (*numroutes)++;
          if (*numroutes >= MAXROUTES)
            {
              log_legacy_write ("You seem to have WAY to many routes!");
              break;
            }
        }
      fclose (routez);
      return 0;
    }
  else
    return -1;
}

int
getipv6routes (struct myroute *myroutes, int *numroutes)
{
  struct interface_info *mydevs;
  int i, j;
  int len;
  struct in6_addr in6addr;
  char destaddr[100];
  int numinterfaces;
  char buf[1024];
  char *endptr;
  char iface[64];
  FILE *routez;
  char v6addr[INET6_ADDRSTRLEN];
  char *token;
  int cnt;

  /* Dummy socket for ioctl */
  mydevs = v6_getinterfaces (&numinterfaces);
  routez = fopen ("/proc/net/ipv6_route", "r");
  if (routez)
    {
      /* linux style /proc/net/ipv6_route ... we can handle this too... */
      while (fgets (buf, sizeof (buf), routez) != NULL)
        {
#if TCPIP_DEBUGGING
          printf ("%s\n", buf);
#endif
          token = strtok (buf, " \t\n");
          if (token)
            {
#if TCPIP_DEBUGGING
              printf ("first token is %s\n", token);
#endif
              strcpy (destaddr, token);
              len = strlen (destaddr);
              for (i = 0, j = 0; j < len; j++)
                {
                  v6addr[i++] = destaddr[j];
                  if (j % 4 == 3)
                    v6addr[i++] = ':';
                }
              v6addr[--i] = '\0';
#if TCPIP_DEBUGGING
              printf ("ipv6 dest is %s\n", v6addr);
#endif
              if (inet_pton (AF_INET6, v6addr, &in6addr) <= 0)
                {
                  log_legacy_write ("invalid ipv6 addressd");
                  continue;
                }
              memcpy (&myroutes[*numroutes].dest6, &in6addr,
                      sizeof (struct in6_addr));
            }
          token = strtok (NULL, " \t\n");
          if (token)
            {
              endptr = NULL;
              myroutes[*numroutes].mask = strtoul (token, &endptr, 16);
            }
          cnt = 7;
          while (cnt--)
            {
              token = strtok (NULL, " \t\n");
              if (!token)
                log_legacy_write ("getipv6routes error");
            }

          token = strtok (NULL, " \t\n");
          if (token)
            {
              strcpy (iface, token);
#ifdef _DEBUG
              printf ("name token is %s\n", token);
#endif
            }
          for (i = 0; i < numinterfaces; i++)
            if (!strcmp (iface, mydevs[i].name)
                && !IN6_IS_ADDR_V4MAPPED (&mydevs[i].addr6))
              {
                myroutes[*numroutes].dev = &mydevs[i];
                break;
              }
          if (i == numinterfaces)
            log_legacy_write
             ("Failed to find interface %s mentioned in /proc/net/route\n",
              iface);
          (*numroutes)++;
          if (*numroutes >= MAXROUTES)
            {
              log_legacy_write ("You seem to have WAY to many routes!");
              break;
            }
        }
      fclose (routez);
      return 0;
    }
  else
    {
      log_legacy_write ("Didn't find IPv6 routes");
      return -1;
    }
}

/** @brief An awesome function to determine what interface a packet to a given
 *  destination should be routed through.
 *
 * It returns NULL if no appropriate
 *  interface is found, oterwise it returns the device name and fills in the
 *   source parameter.   Some of the stuff is
 *  from Stevens' Unix Network Programming V2.  He had an easier suggestion
 *  for doing this (in the book), but it isn't portable :(
 */
char *
v6_routethrough (struct in6_addr *dest, struct in6_addr *source)
{
  static int initialized = 0;
  int i;
  struct in6_addr addy;
  static enum
  { procroutetechnique, connectsockettechnique, guesstechnique } technique =
    procroutetechnique;
  struct interface_info *mydevs;
  static struct myroute myroutes[MAXROUTES];
  int numinterfaces = 0;
  static int numroutes = 0;
  struct in6_addr in6addr;
#ifdef TCPIP_DEBUGGING
  char addr1[INET6_ADDRSTRLEN];
  char addr2[INET6_ADDRSTRLEN];
#endif
  struct in6_addr src;

  if (!dest)
    log_legacy_write ("ipaddr2devname passed a NULL dest address");

  if (IN6_IS_ADDR_V4MAPPED (dest))
    openvas_source_addr_as_addr6 (&src);
  else
    openvas_source_addr6 (&src);

  if (!initialized)
    {
      /* Dummy socket for ioctl */
      initialized = 1;
      mydevs = v6_getinterfaces (&numinterfaces);
      if (IN6_IS_ADDR_V4MAPPED (dest))
        {
          if (getipv4routes (myroutes, &numroutes) < 0)
            technique = connectsockettechnique;
        }
      else
        {
          if (getipv6routes (myroutes, &numroutes) < 0)
            technique = connectsockettechnique;
        }
    }
  else
    {
      mydevs = v6_getinterfaces (&numinterfaces);
    }
  /* WHEW, that takes care of initializing, now we have the easy job of
     finding which route matches */
  if (v6_islocalhost (dest))
    {
      if (source)
        {
          if (IN6_IS_ADDR_V4MAPPED (source))
            {
              source->s6_addr32[0] = 0;
              source->s6_addr32[1] = 0;
              source->s6_addr32[2] = htonl (0xffff);
              source->s6_addr32[3] = htonl (0x7F000001);
            }
          else
            {
              source->s6_addr32[0] = 0;
              source->s6_addr32[1] = 0;
              source->s6_addr32[2] = 0;
              source->s6_addr32[3] = htonl (1);
            }
        }
      /* Now we find the localhost interface name, assuming 127.0.0.1
         or ::1 is localhost (it damn well better be!)... */
      for (i = 0; i < numinterfaces; i++)
        {
          if (IN6_IS_ADDR_V4MAPPED (&mydevs[i].addr6))
            {
              if (mydevs[i].addr6.s6_addr32[3] == htonl (0x7F000001))
                return mydevs[i].name;
            }
          else
            {
              if (IN6_ARE_ADDR_EQUAL (&in6addr_any, &mydevs[i].addr6))
                return mydevs[i].name;
            }
        }
      return NULL;
    }

  if (technique == procroutetechnique)
    {
      for (i = 0; i < numroutes; i++)
        {
          memcpy (&in6addr, dest, sizeof (struct in6_addr));
          ipv6addrmask (&in6addr, myroutes[i].mask);
#if TCPIP_DEBUGGING
          printf ("comparing addresses %s and %s\n",
                  inet_ntop (AF_INET6, &in6addr, addr1, sizeof (addr1)),
                  inet_ntop (AF_INET6, &myroutes[i].dest6, addr2,
                             sizeof (addr2)));
#endif
          if (IN6_ARE_ADDR_EQUAL (&in6addr, &myroutes[i].dest6))
            {
              if (source)
                {
                  if (!IN6_ARE_ADDR_EQUAL (&src, &in6addr_any))
                    memcpy (source, &src, sizeof (struct in6_addr));
                  else
                    {
                      if (myroutes[i].dev != NULL)
                        {
#if TCPIP_DEBUGGING
                          printf ("copying address %s\n",
                                  inet_ntop (AF_INET6, &myroutes[i].dev->addr6,
                                             addr1, sizeof (addr1)));
                          printf ("dev name is %s\n", myroutes[i].dev->name);
#endif
                          memcpy (source, &myroutes[i].dev->addr6,
                                  sizeof (struct in6_addr));
                        }
                    }
                }
              return myroutes[i].dev->name;
            }
          technique = connectsockettechnique;
        }
    }
  if (technique == connectsockettechnique)
    {
      if (!v6_getsourceip (&addy, dest))
        return NULL;
      if (IN6_ARE_ADDR_EQUAL (&addy, &in6addr))
        {
          struct hostent *myhostent = NULL;
          char myname[MAXHOSTNAMELEN + 1];

          myhostent = gethostbyname (myname);
          if (gethostname (myname, MAXHOSTNAMELEN) || !myhostent)
            log_legacy_write ("Cannot get hostname!");
          if (myhostent->h_addrtype == AF_INET)
            {
              addy.s6_addr32[0] = 0;
              addy.s6_addr32[1] = 0;
              addy.s6_addr32[2] = htonl (0xffff);
              memcpy (&addy.s6_addr32[0], myhostent->h_addr_list[0],
                      sizeof (struct in6_addr));
            }
          else
            memcpy (&addy, myhostent->h_addr_list[0], sizeof (struct in6_addr));
        }

      /* Now we insure this claimed address is a real interface ... */
      for (i = 0; i < numinterfaces; i++)
        {
#ifdef TCPIP_DEBUGGING
          printf ("comparing addresses %s and %s\n",
                  inet_ntop (AF_INET6, &mydevs[i].addr6, addr1, sizeof (addr1)),
                  inet_ntop (AF_INET6, &addy, addr2, sizeof (addr2)));
#endif
          if (IN6_ARE_ADDR_EQUAL (&mydevs[i].addr6, &addy))
            {
              if (source)
                {
                  memcpy (source, &addy, sizeof (struct in6_addr));
                }
              return mydevs[i].name;
            }
        }
      return NULL;
    }
  else
    log_legacy_write ("%s: Provided technique is neither proc route nor"
                      " connect socket", __FUNCTION__);
  return NULL;
}

/** @brief An awesome function to determine what interface a packet to a given
 *  destination should be routed through.
 *
 * It returns NULL if no appropriate
 *  interface is found, oterwise it returns the device name and fills in the
 *   source parameter.   Some of the stuff is
 *  from Stevens' Unix Network Programming V2.  He had an easier suggestion
 *  for doing this (in the book), but it isn't portable :(
 */
char *
routethrough (struct in_addr *dest, struct in_addr *source)
{
  static int initialized = 0;
  int i;
  struct in_addr addy;
  static enum
  { procroutetechnique, connectsockettechnique, guesstechnique } technique =
    procroutetechnique;
  char buf[10240];
  struct interface_info *mydevs;
  static struct myroute
  {
    struct interface_info *dev;
    unsigned long mask;
    unsigned long dest;
  } myroutes[MAXROUTES];
  int numinterfaces = 0;
  char *p, *endptr;
  char iface[64];
  static int numroutes = 0;
  FILE *routez;
  long match = -1;
  unsigned long bestmatch = 0;

  struct in_addr src;

  openvas_source_addr (&src);
  if (!dest)
    log_legacy_write ("ipaddr2devname passed a NULL dest address");

  if (!initialized)
    {
      /* Dummy socket for ioctl */
      initialized = 1;
      mydevs = getinterfaces (&numinterfaces);

      /* Now we must go through several techniques to determine info */
      routez = fopen ("/proc/net/route", "r");

      if (routez)
        {
          /* OK, linux style /proc/net/route ... we can handle this ... */
          /* Now that we've got the interfaces, we g0 after the r0ut3Z */
          if (fgets (buf, sizeof (buf), routez) == NULL)  /* Kill the first line */
            log_legacy_write ("Could not read from /proc/net/route");
          while (fgets (buf, sizeof (buf), routez))
            {
              p = strtok (buf, " \t\n");
              if (!p)
                {
                  log_legacy_write ("Could not find interface in"
                                    " /proc/net/route line");
                  continue;
                }
              strncpy (iface, p, sizeof (iface));
              if ((p = strchr (iface, ':')))
                {
                  *p = '\0';    /* To support IP aliasing */
                }
              p = strtok (NULL, " \t\n");
              endptr = NULL;
              myroutes[numroutes].dest = strtoul (p, &endptr, 16);
              if (!endptr || *endptr)
                {
                  log_legacy_write
                   ("Failed to determine Destination from /proc/net/route");
                  continue;
                }
              for (i = 0; i < 6; i++)
                {
                  p = strtok (NULL, " \t\n");
                  if (!p)
                    break;
                }
              if (!p)
                {
                  log_legacy_write ("Failed to find field %d in"
                                    " /proc/net/route", i + 2);
                  continue;
                }
              endptr = NULL;
              myroutes[numroutes].mask = strtoul (p, &endptr, 16);
              if (!endptr || *endptr)
                {
                  log_legacy_write ("Failed to determine mask"
                                    " from /proc/net/route");
                  continue;
                }


#if TCPIP_DEBUGGING
              printf ("#%d: for dev %s, The dest is %lX and the mask is %lX\n",
                      numroutes, iface, myroutes[numroutes].dest,
                      myroutes[numroutes].mask);
#endif
              for (i = 0; i < numinterfaces; i++)
                if (!strcmp (iface, mydevs[i].name))
                  {
                    myroutes[numroutes].dev = &mydevs[i];
                    break;
                  }
              if (i == numinterfaces)
                log_legacy_write
                 ("Failed to find interface %s mentioned in /proc/net/route",
                  iface);
              numroutes++;
              if (numroutes >= MAXROUTES)
                {
                  log_legacy_write ("You seem to have WAY to many routes!");
                  break;
                }
            }
          fclose (routez);
        }
      else
        {
          technique = connectsockettechnique;
        }
    }
  else
    {
      mydevs = getinterfaces (&numinterfaces);
    }
  /* WHEW, that takes care of initializing, now we have the easy job of
     finding which route matches */
  if (islocalhost (dest))
    {
      if (source)
        source->s_addr = htonl (0x7F000001);
      /* Now we find the localhost interface name, assuming 127.0.0.1 is
         localhost (it damn well better be!)... */
      for (i = 0; i < numinterfaces; i++)
        {
          if (mydevs[i].addr.s_addr == htonl (0x7F000001))
            {
              return mydevs[i].name;
            }
        }
      return NULL;
    }

  if (technique == procroutetechnique)
    {
      for (i = 0; i < numroutes; i++)
        {
          if ((dest->s_addr & myroutes[i].mask) == myroutes[i].dest && myroutes[i].mask >= bestmatch)
            {
              if (source)
                {
                  if (src.s_addr != INADDR_ANY)
                    source->s_addr = src.s_addr;
                  else
                    source->s_addr = myroutes[i].dev->addr.s_addr;
                }
              match = i;
              bestmatch = myroutes[i].mask;
            }
        }
      if (match != -1)
          return myroutes[match].dev->name;
    }
  else if (technique == connectsockettechnique)
    {
      if (!getsourceip (&addy, dest))
        return NULL;
      if (!addy.s_addr)
        {                       /* Solaris 2.4 */
          struct hostent *myhostent = NULL;
          char myname[MAXHOSTNAMELEN + 1];
          myhostent = gethostbyname (myname);
          if (gethostname (myname, MAXHOSTNAMELEN) || !myhostent)
            log_legacy_write ("Cannot get hostname!");
          memcpy (&(addy.s_addr), myhostent->h_addr_list[0],
                  sizeof (struct in_addr));
        }

      /* Now we insure this claimed address is a real interface ... */
      for (i = 0; i < numinterfaces; i++)
        if (mydevs[i].addr.s_addr == addy.s_addr)
          {
            if (source)
              {
                source->s_addr = addy.s_addr;
              }
            return mydevs[i].name;
          }
      return NULL;
    }
  else
    log_legacy_write ("%s: Provided technique is neither proc route"
                      " nor connect socket", __FUNCTION__);
  return NULL;
}
