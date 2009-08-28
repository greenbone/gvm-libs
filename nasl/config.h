/* include/config.h.  Generated from config.h.in by configure.  */
/* Pkt_forge
 *
 * Copyright (C) 1999 Renaud Deraison
 * 
 * Please see PKT_LICENSE for the license details
 *
 */
 
#ifndef CONFIG_H__
#define CONFIG_H__

/*
 * Host specs.
 * 
 * Set this if you are running OpenBSD < 2.1 or all FreeBSD or
 * all netBSD, or BSDi < 3.0
 *
 * If you have run this script as root, then it should be correctly
 * set up
 *
 */
/* #undef BSD_BYTE_ORDERING */

/*
 * Set by AC_SYS_LARGEFILE, needed for gpgme key retrieval
 */
#define _FILE_OFFSET_BITS 64


#ifndef _CYGWIN_
/* #undef _CYGWIN_ */
#endif

#define STDC_HEADERS 1
#define HAVE_UNISTD_H 1
#define HAVE_ASSERT_H 1
/* #undef HAVE_FNMATCH */
#define HAVE_LSTAT 1
/* #undef HAVE_MMAP */
#define HAVE_BZERO 1
#define HAVE_BCOPY 1
#define HAVE_RAND 1
#define HAVE_POLL 1
#define HAVE_SELECT 1
#define HAVE_POLL_H 1
#define HAVE_GETTIMEOFDAY 1
/* #undef GETTIMEOFDAY_ONE_ARGUMENT */
/* #undef HAVE_TIMEVAL */
/* #undef HAVE_GETHRTIME */
#define HAVE_GETRUSAGE 1
#define HAVE_LONG_FILE_NAMES 1
#define HAVE_STRING_H 1
#define HAVE_STRINGS_H 1
#define HAVE_SYS_POLL_H 1
/* #undef HAVE_SYS_SOCKIO_H */
/* #undef HAVE_SYS_SOCKETIO_H */
#define HAVE_SYS_SOCKET_H 1
#define HAVE_SYS_PARAM_H 1
#define HAVE_NETDB_H 1
#define HAVE_ARPA_INET_H 1
#define HAVE_NETINET_TCP_H 1
#define HAVE_NET_IF_H 1
/* #undef HAVE_NETINET_TCPIP_H */
#define HAVE_NETINET_IN_H 1
#define HAVE_NETINET_IN_SYSTM_H 1
/* #undef HAVE_NETINET_IP_UDP_H */
/* #undef HAVE_NETINET_UDP_H */
/* #undef HAVE_NETINET_PROTOCOLS_H */
#define HAVE_NETINET_IP_H 1
#define HAVE_NETINET_IP_ICMP_H 1
/* #undef HAVE_NETINET_IP_TCP_H */
/* #undef HAVE_NETINET_PROTOCOLS_H */
#define HAVE_VSNPRINTF 1
#define HAVE_STRUCT_IP 1
#define HAVE_STRUCT_ICMP 1
#define HAVE_STRUCT_TCPHDR 1
#define HAVE_IP_HL 1
#define HAVE_TCPHDR_TH_OFF 1
/* #undef HAVE_TCPHDR_TH_X2_OFF */
#define HAVE_STRUCT_UDPHDR 1
#define HAVE_BSD_STRUCT_UDPHDR 1
/* #undef HAVE_ICMP_ICMP_LIFETIME */
#define HAVE_SYS_WAIT_H 1
#define HAVE_SYS_STAT_H 1
/* #undef HAVE_STAT_H */
#define TIME_WITH_SYS_TIME 1
/* #undef HAVE_SYS_TIME_H */
#define HAVE_SYS_IOCTL_H 1
#define HAVE_DIRENT_H 1
/* #undef HAVE_SYS_NDIR_H */
/* #undef HAVE_SYS_DIR_H */
/* #undef HAVE_NDIR_H */
#define HAVE_STRCHR 1
#define HAVE_MEMCPY 1
#define HAVE_MEMMOVE 1
#define HAVE_MEMMEM 1
#define HAVE_ALLOCA 1
#define HAVE_ALLOCA_H 1
#define HAVE_LOCALE_H 1
#define HAVE_PTHREAD_H 1
/* #undef HAVE_PTHREAD_CANCEL */
#define HAVE_DLFCN_H 1
#define HAVE_RPC_RPC_H 1
/* #undef WORDS_BIGENDIAN */
#define SIZEOF_SHORT 2
#define SIZEOF_INT 4
#define SIZEOF_LONG 4
/* #undef SIZEOF_UNSIGNED_INT */
/* #undef SIZEOF_UNSIGNED_LONG */
#define HAVE_MEMORY_H 1
/* #undef HAVE_ADDR2ASCII */
/* #undef HAVE_INET_NETA */
#define HAVE_SYS_UN_H 1
#define HAVE_CTYPE_H 1
#define HAVE_SYS_TYPES_H 1
#define HAVE_ERRNO_H 1
#define HAVE_PWD_H 1
#define HAVE_STDLIB_H 1
#define HAVE_STDIO_H 1
/* #undef HAVE_SYS_FILIO_H */
#define HAVE_SEARCH_H 1
/* #undef HAVE_XDR_MON */
/* #undef HAVE_SOCKADDR_SA_LEN */
#define HAVE_SYS_MMAN_H 1
#define HAVE_SIGACTION 1
#define HAVE_SIGNAL 1
#define HAVE_WAIT 1
#define HAVE_WAIT3 1
#define HAVE_WAIT4 1
#define HAVE_WAITPID 1

#define LINUX 1
/* #undef FREEBSD */
/* #undef OPENBSD */
/* #undef SOLARIS */
/* #undef SUNOS */
/* #undef BSDI */
/* #undef IRIX */
/* #undef NETBSD */

/* #undef HAVE_REGEX_SUPPORT */
#define HAVE_INET_ATON 1
/* #undef STUPID_SOLARIS_CHECKSUM_BUG */
/* #undef HAVE_STRUCT_IP_CSUM */
/* #undef HAVE_GETHOSTBYNAME_R */
/* #undef HAVE_SOLARIS_GETHOSTBYNAME_R */
/* #undef HAVE_SOLARIS_GETHOSTBYADDR_R */
/* #undef USE_SYSLOG */

/* #undef PCAP_RESTART */
/* #undef BROKEN_PTHREAD_CLEANUP_PUSH */

#define HAVE_LFIND 1
/* #undef HAVE_STRNDUP_ALREADY */

#define NESS_COMPILER   "(unknown)"
#define NESS_OS_NAME    "(unknown)"
#define NESS_OS_VERSION "(unknown)"


#endif
