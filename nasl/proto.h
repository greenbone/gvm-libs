#include <time.h>
#include "smb.h"
/*implemented in genrand.c*/
void generate_random_buffer_ntlmssp( unsigned char *out, int len);
void set_need_random_reseed_ntlmssp();
/*implemented in time.c*/
void put_long_date_ntlmssp(char *p, time_t t);
void GetTimeOfDay_ntlmssp(struct timeval *tval);
/*implemented in iconv.c*/
size_t smb_iconv_ntlmssp(smb_iconv_t cd,
                 const char **inbuf, size_t *inbytesleft,
                 char **outbuf, size_t *outbytesleft);
smb_iconv_t smb_iconv_open_ntlmssp(const char *tocode, const char *fromcode);
int smb_iconv_close_ntlmssp (smb_iconv_t cd);
/*implemented in arc4.c*/
void smb_arc4_init_ntlmssp(unsigned char arc4_state_out[258], const unsigned char *key, size_t keylen);
void smb_arc4_crypt_ntlmssp(unsigned char arc4_state_inout[258], unsigned char *data, size_t len);
/*implemented in charcnv.c*/
size_t push_ascii_ntlmssp(void *dest, const char *src, size_t dest_len, int flags);
void lazy_initialize_conv_ntlmssp(void);
void init_iconv_ntlmssp(void);
