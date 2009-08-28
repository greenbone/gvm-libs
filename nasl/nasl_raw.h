#ifndef NESSUS_RAW_H
#define NESSUS_RAW_H
#ifdef __linux__
#ifndef __BSD_SOURCE
#define __BSD_SOURCE
#endif

#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif

#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif
#endif

#include "nasl_ip.h"
#include "nasl_tcp.h"
#include "nasl_udp.h"
#include "nasl_icmp.h"

#endif
