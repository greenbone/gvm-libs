#ifndef NASL_SMB_CRYPT_H
#define NASL_SMB_CRYPT_H


void E_P24(const uchar *p21, const uchar *c8, uchar *p24);
void E_P16(uchar *p14,uchar *p16);


int strupper_w(smb_ucs2_t *s);


void SMBOWFencrypt_ntv2(const uchar* kr, const uchar* srv_chal_data, int srv_chal_len, const uchar* cli_chal_data, int cli_chal_len, uchar resp_buf[16]);


#endif
