#ifndef MD5_H
#define MD5_H
#ifndef HEADER_MD5_H
/* Try to avoid clashes with OpenSSL */
#define HEADER_MD5_H 
#endif

/*
 * Note we duplicate the size tests in the unsigned
 * case as int32 may be a typedef from rpc/rpc.h
 */

#if !defined(uint32) && !defined(HAVE_UINT32_FROM_RPC_RPC_H)
#if (SIZEOF_INT == 4)
#define uint32 unsigned int
#elif (SIZEOF_LONG == 4)
#define uint32 unsigned long
#elif (SIZEOF_SHORT == 4)
#define uint32 unsigned short
#else
/* uggh - no 32 bit type?? probably a CRAY. just hope this works ... */
#define uint32 unsigned
#endif
#endif

struct MD5Context {
	uint32 buf[4];
	uint32 bits[2];
	unsigned char in[64];
};

void MD5Init(struct MD5Context *context);
void MD5Update(struct MD5Context *context, unsigned char const *buf,
	       unsigned len);
void MD5Final(unsigned char digest[16], struct MD5Context *context);

#endif /* !MD5_H */
