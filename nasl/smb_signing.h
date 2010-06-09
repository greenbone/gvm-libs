
#ifndef _SMB_SIGNING_H
#define _SMB_SIGNING_H

#include "md5.h"
#include "byteorder.h"
#include "smb.h"

#ifndef uchar
#define uchar unsigned char
#endif

#ifndef uint8
#define uint8 uint8_t
#endif

void simple_packet_signature_ntlmssp(uint8_t *mac_key, const uchar *buf, uint32 seq_number, unsigned char *calc_md5_mac);

#endif
