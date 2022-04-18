#ifndef _PPASS_H
#define _PPASS_H

/* The ppass_t object is not thread safe. It can be used only by a single thread at a time. Construct multiple objects or use syncronization if need to use those from multiple threads.
 *
 * Functions that do not require ppass_t object are thread safe.
 *
 * private key is an array of PPASS_PRIVATE_LEN unsigned chars
 * public key is an array of PPASS_PUBLIC_LEN unsigned chars
 *
 *
 */

#define PPASS_PRIVATE_LEN      32
#define PPASS_PUBLIC_LEN       33
#define PPASS_SIGNATURE_LEN    (PPASS_PRIVATE_LEN*2)
#define PPASS_IV_LEN           16
#define PPASS_HMAC_LEN         32
#define PPASS_SINGLE_SEED_BITS 11
#define PPASS_SEED_WORDS_CNT ((PPASS_PRIVATE_LEN*8+PPASS_SINGLE_SEED_BITS-1)/PPASS_SINGLE_SEED_BITS)

struct _ppass_t;

typedef struct _ppass_t ppass_t;

struct _ppass_encoder_t;

typedef struct _ppass_encoder_t ppass_encoder_t;

/* returns NULL on failure
 * generally only expected if case of memory allocation failure
 * mbedtls may also have cases when its random generator fails to initialize
 */
ppass_t *ppass_init(void);

void ppass_free(ppass_t *pp);

/* return 0 on success and -1 on failure
 * failure is generally never expected however officially the random number generation may fail
 */
int ppass_generate_private(ppass_t *pp, unsigned char *priv);

/* return 0 on success and -1 on failure (not expected) */
int ppass_public_from_private(ppass_t *pp, unsigned char *pub, const unsigned char *priv);

/* return 0 on success and -1 on failure (not expected) */
int ppass_invert_private(ppass_t *pp, unsigned char *inv_priv, const unsigned char *priv);

/* return 0 on success and -1 on failure (not expected) */
int ppass_mul(ppass_t *pp, unsigned char *res_pub, const unsigned char *pub, const unsigned char *priv);

/* generate private key from seed
 * seed is an array of PPASS_SEED_WORDS_CNT (24 if PPASS_PRIVATE_LEN is 32 and PPASS_SINGLE_SEED_BITS is 11) unsigned ints of which only the low PPASS_SINGLE_SEED_BITS are used
 */
void ppass_private_from_seed(unsigned char *priv, const unsigned int *seed);

/* generate seed from private key
 */
void ppass_seed_from_private(unsigned int *seed, const unsigned char *priv);

/* encrypt private key, not expected to fail generally
 * encrypted key length is the same as unencrypted length
 */
int ppass_encrypt_private(unsigned char *enc_priv, const unsigned char *priv, const char *pass);

/* decrypt private key, not expected to fail generally */
int ppass_decrypt_private(unsigned char *priv, const unsigned char *enc_priv, const char *pass);

/* sign data or any length with private key and provide signature of length PPASS_SIGNATURE_LEN
 * since any input data is technically valid, failure and returning of -1 is not expected in general
 */
int ppass_sign(ppass_t *pp, unsigned char *signature, const unsigned char *priv, const void *data, size_t datalen);

/* checks if signature is valid for data with pub's private key
 * returns 0 for valid signature
 *         1 for invalid signature
 *        -1 for any other failure
 *
 */
int ppass_verify(ppass_t *pp, const unsigned char *signature, const unsigned char *pub, const void *data, size_t datalen);

/* creates an encoder from a public key
 * return NULL on failure, which can generally only be memory allocation fail
 */
ppass_encoder_t *ppass_encoder_from_public(const unsigned char *pub);


/* creates an encoder from a password
 * return NULL on failure, which can generally only be memory allocation fail
 */
ppass_encoder_t *ppass_encoder_from_password(const char *pass);

/* frees an encoder object
 */
void ppass_free_encoder(ppass_encoder_t *enc);

/* encodes plain_data of length datalen and write them to enc_data, exactly datalen bytes are written, it is acceptable to have enc_data==plain_data so the data will be encoded in place
 * iv is populated with initialzation vector of length PPASS_IV_LEN
 * hmac is populated with authentication message of length PPASS_HMAC_LEN
 *
 * returns 0 on success and -1 on failure, that is not generally expected
 */
int ppass_encode_data(ppass_t *pp, ppass_encoder_t *enc, unsigned char *iv, unsigned char *hmac, unsigned char *enc_data, const unsigned char *plain_data, size_t datalen);

/* decodes enc_data of length datalen and write them to plain_data, exactly datalen bytes are written, it is acceptable to have enc_data==plain_data so the data will be decoded in place
 * iv is the initialzation vector of length PPASS_IV_LEN provided by ppass_encode_data
 * hmac is is the authentication message of length PPASS_HMAC_LEN provided by ppass_encode_data
 * returns 0 for success
 *         1 for invalid authentication message
 *        -1 for any other failure
 */
int ppass_decode_data(ppass_encoder_t *enc, unsigned char *plain_data, const unsigned char *iv, const unsigned char *hmac, const unsigned char *enc_data, size_t datalen);

/* Generates a key of a given `key_length` size from a passphrase `pass` as input via a PBKDF2 key derivation function using 30000 iterations.
 * On success the generated key is written to `key`.
 * returns 0 on success and -1 on failure, that is not generally expected
 * */
int ppass_generate_key_from_pass(unsigned char *key, const char *pass, uint32_t key_length);

#endif
