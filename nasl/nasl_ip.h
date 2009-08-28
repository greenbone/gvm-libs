#ifndef NESSUS_IP_H__

#include "config.h"

#ifdef HAVE_NETINET_IP_H
#include <netinet/ip.h>
#endif

#ifndef IP_RF
#define	IP_RF 0x8000			/* reserved fragment flag */
#endif

#ifndef IP_DF
#define	IP_DF 0x4000			/* dont fragment flag */
#endif

#ifndef IP_MF
#define	IP_MF 0x2000			/* more fragments flag */
#endif

#ifndef IP_OFFMASK
#define	IP_OFFMASK 0x1fff		/* mask for fragmenting bits */
#endif

#if !defined(HAVE_STRUCT_IP) || (HAVE_STRUCT_IP == 0)

#undef _IP_VHL

#define HAVE_STRUCT_IP 1
struct ip {
#if !WORDS_BIGENDIAN
	u_char	ip_hl:4,		/* header length */
		ip_v:4;			/* version */
#else
	 u_char	ip_v:4,			/* version */
		ip_hl:4;		/* header length */
#endif
	u_char	ip_tos;			/* type of service */
	u_short	ip_len;			/* total length */
	u_short	ip_id;			/* identification */
	u_short	ip_off;			/* fragment offset field */
	u_char	ip_ttl;			/* time to live */
	u_char	ip_p;			/* protocol */
	u_short	ip_sum;			/* checksum */
	struct	in_addr ip_src,ip_dst;	/* source and dest address */
};

#endif /* not defined(HAVE_STRUCT_IP) */

#ifdef HAVE_STRUCT_IP_CSUM
#define ip_sum ip_csum
#endif
#endif
