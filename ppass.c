#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include <mbedtls/md.h>
#include <mbedtls/aes.h>
#include <mbedtls/ecp.h>
#include <mbedtls/sha256.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/platform_util.h>
#include "ppass.h"

#define USE_CURVE MBEDTLS_ECP_DP_SECP256R1
#define AES_PASS_KEY_BITS 256
#define AES_KEY_LENGTH (AES_PASS_KEY_BITS / 8)
#define PBKDF2_ITERATIONS 30000

struct _ppass_t {
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context rnd;
  mbedtls_ecp_group grp;
  mbedtls_ecp_point pt;
  mbedtls_mpi grpA;
  mbedtls_mpi num;
};

struct _ppass_encoder_t {
  mbedtls_aes_context aes;
  unsigned char hmac_key[32];
};

/*
static void print_mpi(const mbedtls_mpi *m) {
  char buff[256];
  size_t len;
  mbedtls_mpi_write_string(m, 16, buff, sizeof(buff)-1, &len);
  buff[len]=0;
  printf("%d %lu %s\n", m->s, len, buff);
}
*/

ppass_t *ppass_init() {
  ppass_t *pp;
  pp=(ppass_t *)malloc(sizeof(struct _ppass_t));
  if (!pp)
    goto err0;
  mbedtls_entropy_init(&pp->entropy);
  mbedtls_ctr_drbg_init(&pp->rnd);
  if (mbedtls_ctr_drbg_seed(&pp->rnd, mbedtls_entropy_func, &pp->entropy, NULL, 0))
    goto err1;
  mbedtls_ecp_group_init(&pp->grp);
  if (mbedtls_ecp_group_load(&pp->grp, USE_CURVE))
    goto err1;
  mbedtls_mpi_init(&pp->num);
  mbedtls_mpi_init(&pp->grpA);
  mbedtls_ecp_point_init(&pp->pt);
  if (mbedtls_ecp_get_type(&pp->grp)!=MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS)
    goto err2;
  if (mbedtls_mpi_sub_int(&pp->grpA, &pp->grp.P, 3))
    goto err2;

  return pp;

err2:
  mbedtls_ecp_point_free(&pp->pt);
  mbedtls_mpi_free(&pp->num);
  mbedtls_mpi_free(&pp->grpA);
  mbedtls_ecp_group_free(&pp->grp);
err1:
  mbedtls_ctr_drbg_free(&pp->rnd);
  mbedtls_entropy_free(&pp->entropy);
  free(pp);
err0:
  return NULL;
}

void ppass_free(ppass_t *pp) {
  mbedtls_ecp_point_free(&pp->pt);
  mbedtls_mpi_free(&pp->num);
  mbedtls_mpi_free(&pp->grpA);
  mbedtls_ecp_group_free(&pp->grp);
  mbedtls_ctr_drbg_free(&pp->rnd);
  mbedtls_entropy_free(&pp->entropy);
  free(pp);
}

int ppass_generate_private(ppass_t *pp, unsigned char *priv) {
  mbedtls_mpi pr;
  mbedtls_mpi_init(&pr);
  if (mbedtls_mpi_random(&pr, 7, &pp->grp.N, mbedtls_ctr_drbg_random, &pp->rnd))
    goto err0;
  if (mbedtls_mpi_write_binary(&pr, priv, PPASS_PRIVATE_LEN))
    goto err0;
  mbedtls_mpi_free(&pr);
  return 0;
err0:
  mbedtls_mpi_free(&pr);
  return -1;
}

int ppass_public_from_private(ppass_t *pp, unsigned char *pub, const unsigned char *priv) {
  size_t len;
  if (mbedtls_mpi_read_binary(&pp->num, priv, PPASS_PRIVATE_LEN))
    return -1;
  if (mbedtls_ecp_mul(&pp->grp, &pp->pt, &pp->num, &pp->grp.G, mbedtls_ctr_drbg_random, &pp->rnd))
    return -1;
  if (mbedtls_ecp_point_write_binary(&pp->grp, &pp->pt, MBEDTLS_ECP_PF_COMPRESSED, &len, pub, PPASS_PUBLIC_LEN))
    return -1;
  if (len!=PPASS_PUBLIC_LEN)
    return -1;
  return 0;
}

int ppass_invert_private(ppass_t *pp, unsigned char *inv_priv, const unsigned char *priv) {
  int ret;
  mbedtls_mpi ip;
  if (mbedtls_mpi_read_binary(&pp->num, priv, PPASS_PRIVATE_LEN))
    return -1;
  mbedtls_mpi_init(&ip);
  if (!mbedtls_mpi_inv_mod(&ip, &pp->num, &pp->grp.N)) {
    ret=mbedtls_mpi_write_binary(&ip, inv_priv, PPASS_PRIVATE_LEN)?-1:0;
  } else {
    ret=-1;
  }
  mbedtls_mpi_free(&ip);
  return ret;
}

// no support for MBEDTLS_ECP_PF_COMPRESSED for import in mbedtls
int mbedtls_ecp_point_read_binary_compressed(ppass_t *pp, const mbedtls_ecp_group *grp, mbedtls_ecp_point *pt, const unsigned char *buf, size_t ilen) {
  mbedtls_mpi t1, t2, t3;
  if(mbedtls_ecp_get_type(grp)!=MBEDTLS_ECP_TYPE_SHORT_WEIERSTRASS)
    return -1;
  if (buf[0]!=0x02 && buf[0]!=0x03)
    return -1;
  if (mbedtls_mpi_read_binary(&pt->X, buf+1, ilen-1))
    return -1;
  if (mbedtls_mpi_lset(&pt->Z, 1))
    return -1;
  mbedtls_mpi_init(&t1);
  mbedtls_mpi_init(&t2);
  mbedtls_mpi_init(&t3);
  // x^3 mod P -> t3
  if (mbedtls_mpi_mul_mpi(&t1, &pt->X, &pt->X))
    goto err;
  if (mbedtls_mpi_mod_mpi(&t2, &t1, &grp->P))
    goto err;
  if (mbedtls_mpi_mul_mpi(&t1, &t2, &pt->X))
    goto err;
  if (mbedtls_mpi_mod_mpi(&t3, &t1, &grp->P))
    goto err;
  // a*x+b -> add to t3
  if (mbedtls_mpi_mul_mpi(&t1, &pp->grpA, &pt->X))
    goto err;
  if (mbedtls_mpi_mod_mpi(&t2, &t1, &grp->P))
    goto err;
  if (mbedtls_mpi_add_mpi(&t3, &t3, &t2))
    goto err;
  if (mbedtls_mpi_add_mpi(&t3, &t3, &grp->B))
    goto err;
  // result in t1
  if (mbedtls_mpi_mod_mpi(&t1, &t3, &grp->P))
    goto err;

  // sqrt(t1) -> t3
  if (mbedtls_mpi_add_int(&t2, &grp->P, 1))
    goto err;
  if (mbedtls_mpi_shift_r(&t2, 2))
    goto err;
  if (mbedtls_mpi_exp_mod(&t3, &t1, &t2, &grp->P, NULL))
    goto err;


  // result in t3, fix bit
  if (!(buf[0]&1)^!mbedtls_mpi_get_bit(&t3, 0)) {
    if (mbedtls_mpi_sub_mpi(&pt->Y, &grp->P, &t3))
      goto err;
  } else {
    if (mbedtls_mpi_copy(&pt->Y, &t3))
      goto err;
  }

  mbedtls_mpi_free(&t3);
  mbedtls_mpi_free(&t2);
  mbedtls_mpi_free(&t1);
  return 0;

err:
  mbedtls_mpi_free(&t3);
  mbedtls_mpi_free(&t2);
  mbedtls_mpi_free(&t1);
  return -1;
}

int ppass_mul(ppass_t *pp, unsigned char *res_pub, const unsigned char *pub, const unsigned char *priv) {
  mbedtls_ecp_point p;
  size_t len;
  if (mbedtls_mpi_read_binary(&pp->num, priv, PPASS_PRIVATE_LEN))
    return -1;
  mbedtls_ecp_point_init(&p);
  if (mbedtls_ecp_point_read_binary_compressed(pp, &pp->grp, &p, pub, PPASS_PUBLIC_LEN)) {
    mbedtls_ecp_point_free(&p);
    return -1;
  }
  if (mbedtls_ecp_mul(&pp->grp, &pp->pt, &pp->num, &p, mbedtls_ctr_drbg_random, &pp->rnd)) {
    mbedtls_ecp_point_free(&p);
    return -1;
  }
  mbedtls_ecp_point_free(&p);
  if (mbedtls_ecp_point_write_binary(&pp->grp, &pp->pt, MBEDTLS_ECP_PF_COMPRESSED, &len, res_pub, PPASS_PUBLIC_LEN))
    return -1;
  if (len!=PPASS_PUBLIC_LEN)
    return -1;
  return 0;
}

void ppass_private_from_seed(unsigned char *priv, const unsigned int *seed) {
  unsigned int i, j, bit;
  for (i=0; i<PPASS_PRIVATE_LEN; i++)
    priv[i]=0;
  for (i=0; i<PPASS_SEED_WORDS_CNT; i++)
    for (j=0; j<PPASS_SINGLE_SEED_BITS; j++) {
      bit=j+i*PPASS_SINGLE_SEED_BITS;
      if (bit>=PPASS_PRIVATE_LEN*8)
        break;
      priv[PPASS_PRIVATE_LEN-bit/8-1]|=((seed[i]>>j)&1)<<(bit%8);
    }
}

void ppass_seed_from_private(unsigned int *seed, const unsigned char *priv) {
  unsigned int i, j, bit;
  for (i=0; i<PPASS_SEED_WORDS_CNT; i++) {
    seed[i]=0;
    for (j=0; j<PPASS_SINGLE_SEED_BITS; j++) {
      bit=j+i*PPASS_SINGLE_SEED_BITS;
      if (bit>=PPASS_PRIVATE_LEN*8)
        break;
      seed[i]|=((priv[PPASS_PRIVATE_LEN-bit/8-1]>>(bit%8))&1)<<j;
    }
  }
}

int ppass_generate_key_from_pass(unsigned char *key, const char *pass, uint32_t key_length) {
  mbedtls_md_context_t ctx;
  static const char *salt = "pPass Salt for PBKDF2";
  mbedtls_md_init(&ctx);
  if (mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA512), 1))
    goto err0;
  if (mbedtls_pkcs5_pbkdf2_hmac(&ctx,
                                (const unsigned char *) pass, strlen(pass),
                                (const unsigned char *) salt, strlen(salt),
                                PBKDF2_ITERATIONS,
                                key_length, key))

    goto err0;
  mbedtls_md_free(&ctx);
  return 0;

    err0:
  mbedtls_md_free(&ctx);
  return -1;
}

/* Encoding random key with ECB is indeed safe
 */

int ppass_encrypt_private(unsigned char *enc_priv, const unsigned char *priv, const char *pass) {
  mbedtls_aes_context aes;
  unsigned char key[AES_PASS_KEY_BITS/8];
  unsigned int i;
  int ret;
  ret=-1;
  if (ppass_generate_key_from_pass(key, pass, AES_KEY_LENGTH))
    return -1;
  mbedtls_aes_init(&aes);
  if (mbedtls_aes_setkey_enc(&aes, key, AES_PASS_KEY_BITS))
    goto err0;
  for (i=0; i<PPASS_PRIVATE_LEN; i+=16)
    if (mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, priv+i, enc_priv+i))
      goto err0;
  ret=0;

err0:
  mbedtls_aes_free(&aes);
  mbedtls_platform_zeroize(key, sizeof(key));
  return ret;
}

int ppass_decrypt_private(unsigned char *priv, const unsigned char *enc_priv, const char *pass) {
  mbedtls_aes_context aes;
  unsigned char key[AES_PASS_KEY_BITS/8];
  unsigned int i;
  int ret;
  ret=-1;
  if (ppass_generate_key_from_pass(key, pass, AES_KEY_LENGTH))
    return -1;
  mbedtls_aes_init(&aes);
  if (mbedtls_aes_setkey_dec(&aes, key, AES_PASS_KEY_BITS))
    goto err0;
  for (i=0; i<PPASS_PRIVATE_LEN; i+=16)
    if (mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_DECRYPT, enc_priv+i, priv+i))
      goto err0;
  ret=0;

err0:
  mbedtls_aes_free(&aes);
  mbedtls_platform_zeroize(key, sizeof(key));
  return ret;
}

int ppass_sign(ppass_t *pp, unsigned char *signature, const unsigned char *priv, const void *data, size_t datalen) {
  unsigned char md[32];
  mbedtls_mpi r, s, p;
  int ret;
  if (mbedtls_sha256((const unsigned char *)data, datalen, md, 0))
    return -1;
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&s);
  mbedtls_mpi_init(&p);
  ret=-1;
  if (mbedtls_mpi_read_binary(&p, priv, PPASS_PRIVATE_LEN))
    goto err0;
  if (mbedtls_ecdsa_sign_det_ext(&pp->grp, &r, &s, &p, md, 32, MBEDTLS_MD_SHA256, mbedtls_ctr_drbg_random, &pp->rnd))
    goto err0;
  if (mbedtls_mpi_write_binary(&r, signature, PPASS_PRIVATE_LEN) ||
      mbedtls_mpi_write_binary(&s, signature+PPASS_PRIVATE_LEN, PPASS_PRIVATE_LEN))
    goto err0;
  ret=0;

err0:
  mbedtls_mpi_free(&p);
  mbedtls_mpi_free(&s);
  mbedtls_mpi_free(&r);
  return ret;
}

int ppass_verify(ppass_t *pp, const unsigned char *signature, const unsigned char *pub, const void *data, size_t datalen) {
  unsigned char md[32];
  mbedtls_mpi r, s;
  int ret;
  if (mbedtls_sha256((const unsigned char *)data, datalen, md, 0))
    return -1;
  if (mbedtls_ecp_point_read_binary_compressed(pp, &pp->grp, &pp->pt, pub, PPASS_PUBLIC_LEN))
    return -1;
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&s);
  ret=-1;
  if (mbedtls_mpi_read_binary(&r, signature, PPASS_PRIVATE_LEN))
    goto err0;
  if (mbedtls_mpi_read_binary(&s, signature+PPASS_PRIVATE_LEN, PPASS_PRIVATE_LEN))
    goto err0;

  switch (mbedtls_ecdsa_verify(&pp->grp, md, 32, &pp->pt, &r, &s)) {
    case 0:
      ret=0;
      break;
    case MBEDTLS_ERR_ECP_VERIFY_FAILED:
      ret=1;
      break;
    default:
      ret=-1;
      break;
  }

err0:
  mbedtls_mpi_free(&s);
  mbedtls_mpi_free(&r);
  return ret;
}

static int ppass_hmac_sha256(unsigned char *hmac, const unsigned char *key, size_t keylen,  const unsigned char *data, size_t datalen) {
  return mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), key, keylen, data, datalen, hmac)?-1:0;
}

static ppass_encoder_t *ppass_encoder_from_data(const unsigned char *data, size_t datalen) {
  static const char *aes_salt="ppass AES salt for encryption";
  static const char *hmac_salt="ppass HMAC salt for authentication";
  ppass_encoder_t *enc;
  unsigned char aeskey[32];
  enc=(ppass_encoder_t *)malloc(sizeof(ppass_encoder_t));
  if (!enc)
    return NULL;
  if (ppass_hmac_sha256(aeskey, (const unsigned char *)aes_salt, strlen(aes_salt), data, datalen))
    goto err0;
  if (ppass_hmac_sha256(enc->hmac_key, (const unsigned char *)hmac_salt, strlen(hmac_salt), data, datalen))
    goto err0;
  mbedtls_aes_init(&enc->aes);
  if (mbedtls_aes_setkey_enc(&enc->aes, aeskey, AES_PASS_KEY_BITS))
    goto err1;
  return enc;
err1:
  mbedtls_aes_free(&enc->aes);
err0:
  mbedtls_platform_zeroize(enc, sizeof(ppass_encoder_t));
  mbedtls_platform_zeroize(aeskey, sizeof(aeskey));
  free(enc);
  return NULL;
}

ppass_encoder_t *ppass_encoder_from_public(const unsigned char *pub) {
  return ppass_encoder_from_data(pub, PPASS_PUBLIC_LEN);
}

ppass_encoder_t *ppass_encoder_from_password(const char *pass) {
  unsigned char key[AES_PASS_KEY_BITS/8];
  if (ppass_generate_key_from_pass(key, pass, AES_KEY_LENGTH))
    return NULL;
  return ppass_encoder_from_data(key, sizeof(key));
}

void ppass_free_encoder(ppass_encoder_t *enc) {
  mbedtls_aes_free(&enc->aes);
  mbedtls_platform_zeroize(enc, sizeof(ppass_encoder_t));
  free(enc);
}

static int ppass_hmac_sha256_2(unsigned char *hmac, const unsigned char *key, size_t keylen, const unsigned char *data1, size_t datalen1, const unsigned char *data2, size_t datalen2) {
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  if (mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1))
    goto err0;
  if (mbedtls_md_hmac_starts(&ctx, key, keylen))
    goto err0;
  if (mbedtls_md_hmac_update(&ctx, data1, datalen1))
    goto err0;
  if (mbedtls_md_hmac_update(&ctx, data2, datalen2))
    goto err0;
  if (mbedtls_md_hmac_finish(&ctx, hmac))
    goto err0;
  mbedtls_md_free(&ctx);
  return 0;

err0:
  mbedtls_md_free(&ctx);
  return -1;
}

int ppass_encode_data(ppass_t *pp, ppass_encoder_t *enc, unsigned char *iv, unsigned char *hmac, unsigned char *enc_data, const unsigned char *plain_data, size_t datalen) {
  unsigned char counter[PPASS_IV_LEN], block[16];
  size_t off;
  if (mbedtls_ctr_drbg_random(&pp->rnd, counter, sizeof(counter)))
    return -1;
  memcpy(iv, counter, PPASS_IV_LEN);
  off = 0;
  if (mbedtls_aes_crypt_ctr(&enc->aes, datalen, &off, counter, block, plain_data, enc_data))
    return -1;
  if (ppass_hmac_sha256_2(hmac, enc->hmac_key, sizeof(enc->hmac_key), iv, PPASS_IV_LEN, enc_data, datalen))
    return -1;
  return 0;
}

int ppass_decode_data(ppass_encoder_t *enc, unsigned char *plain_data, const unsigned char *iv, const unsigned char *hmac, const unsigned char *enc_data, size_t datalen) {
  unsigned char hmacc[PPASS_HMAC_LEN], counter[PPASS_IV_LEN], block[16];
  size_t off;
  int i, r;
  if (ppass_hmac_sha256_2(hmacc, enc->hmac_key, sizeof(enc->hmac_key), iv, PPASS_IV_LEN, enc_data, datalen))
    return -1;
  for (i=0, r=0; i<PPASS_HMAC_LEN; i++)
    r+=hmacc[i]!=hmac[i];
  if (r)
    return 1;
  memcpy(counter, iv, PPASS_IV_LEN);
  off=0;
  if (mbedtls_aes_crypt_ctr(&enc->aes, datalen, &off, counter, block, enc_data, plain_data))
    return -1;
  return 0;
}



