#include <time.h>
#include "smb.h"
/*implemented in genrand.c*/
void generate_random_buffer( unsigned char *out, int len);
void set_need_random_reseed();
/*implemented in time.c*/
void put_long_date(char *p, time_t t);
void GetTimeOfDay(struct timeval *tval);
/*implemented in iconv.c*/
size_t smb_iconv(smb_iconv_t cd,
                 const char **inbuf, size_t *inbytesleft,
                 char **outbuf, size_t *outbytesleft);
smb_iconv_t smb_iconv_open(const char *tocode, const char *fromcode);
int smb_iconv_close (smb_iconv_t cd);
/*implemented in arc4.c*/
void smb_arc4_init(unsigned char arc4_state_out[258], const unsigned char *key, size_t keylen);
void smb_arc4_crypt(unsigned char arc4_state_inout[258], unsigned char *data, size_t len);
/*implemented in charcnv.c*/
size_t push_ascii(void *dest, const char *src, size_t dest_len, int flags);
void lazy_initialize_conv(void);
void init_iconv(void);

