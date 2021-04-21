#ifndef _GVM_PASSWORDBASEDAUTHENTICATION_H
#define _GVM_PASSWORDBASEDAUTHENTICATION_H
#include <bits/types.h>

/* max amount of applied pepper */ 
#define MAX_PEPPER_SIZE 4
/* is used when count is 0 on init*/
#define COUNT_DEFAULT 20000
/* sha512 */
#define PREFIX_DEFAULT "$6$"

/**
 *
 * PBASettings is used by pba_hash to control SALT, HASH function and 
 * computional costs.
 *
 * */
struct PBASettings
{
  char pepper[MAX_PEPPER_SIZE]; /* is statically applied to the random salt */
  unsigned int count; /* controls the computational cost of the hash */
  char *prefix; /* controls which hash function will be used */
};
/** 
 * Intitializes PBASettings with given PEPPER, PREFIX, COUNT.
 *
 * PEPPER_SIZE must be lower or equal MAX_PEPPER_SIZE when PEPPER is set, when
 * PEPPER is a NULL pointer, no pepper will be used and PEPPER_SIZE is ignored.
 *
 * COUNT is set to COUNT_DEFAULT when it is 0, PREFIX is set to PREFIX_DEFAULT
 * when prefix is a nullpointer.
 *
 * Returns a pointer to PBASettings on success or NULL on failure.
 *
 * */
struct PBASettings *pba_init(const char *pepper, unsigned int pepper_size, unsigned int count, char *prefix);

/* return values for pba pba_verify_hash */
enum pba_rc {
    VALID, /* hash and password are correct */
    UPDATE_RECOMMENDED, /* password is correct but in an outdated format*/
    INVALID, /* password is incorrect */
    ERR, /* unexpected error */
};

/**
 * pba_hash tries to create a hash based SETTING and PASSWORD.
 * Returns a hash on success or a NULL pointer on failure
 */
char *pba_hash (struct PBASettings *setting, char *password);

/**
 * pba_verify_hash tries to create hash based on PASSWORD and settings found via
 * HASH and compares that with HASH.
 *
 * Returns VALID if HASH and PASSWORD are correct; 
 * UPDATE_RECOMMENDED when the HASH and PASSWORD are correct but based on a deprecated algorithm;
 * IVALID if HASH does not match PASSWORD;
 * ERR if an unexpected error occurs.
 */
enum pba_rc pba_verify_hash(const struct PBASettings *settings, const char *hash, const char *password);

void pba_finalize(struct PBASettings *settings);

#endif
