/* OpenVAS
 * $Id$
 * Description: Base definitions for NTP.
 *
 * Authors:
 * Renaud Deraison <deraison@nessus.org> (Original pre-fork development)
 *
 * Copyright:
 * Based on work Copyright (C) 1998 Renaud Deraison
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _OPENVAS_NTP_H
#define _OPENVAS_NTP_H

#define OTP_10 100  /* OTP/1.0 */

/* Those marked a "deprecated" can be removed, once openvas-libraries
 * is branched for 1.1  */
typedef struct {
  int ntp_version; /*  NTP_VERSION, as defined in ntp.h */
  int ntp_11:1;    /*  TRUE, if we may use NTP 1.1 features; should
                       better be splitted into different capability
                       attributes, but this one simplifies the step
                       from NTP 1.1 to NTP 1.2. In the future we'll
                       use caps, I promise! :-) */
  int scan_ids:1;  /*  TRUE, if HOLE and INFO messages should
                       contain scan ID's. */
  int pubkey_auth:1; /* TRUE if the client wants to use public key
                        authentification */

  int md5_caching:1; /* TRUE if the client does not want us to send the
                        list of plugins directly, but just the md5 
                        hash instead */

  int plugins_version:1; /* TRUE if the client wants us to send the versions
                            of our plugins */
  int plugins_oid:1; /* the OID of the plugins along with their version */
  int dns:1; /* send the host name and host ip */
} ntp_caps;

#endif
