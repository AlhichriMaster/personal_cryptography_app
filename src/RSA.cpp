#include "../include/RSA.h"
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/dsa.h>
#include <cstring>
#include <iostream>



int main()
{
  /* Create the context for generating the parameters */
  EVP_PKEY_CTX* pctx;
  EVP_PKEY* params = NULL;

  //Key pair generation:
  EVP_PKEY_CTX* kctx;
  EVP_PKEY* key = NULL;

  BIO* bio = nullptr;


  if(!(pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DSA, NULL))) goto err;
  if(!EVP_PKEY_paramgen_init(pctx)) goto err;

  if(!EVP_PKEY_CTX_ctrl(pctx, EVP_PKEY_DSA, EVP_PKEY_OP_PARAMGEN,
                        EVP_PKEY_CTRL_DSA_PARAMGEN_BITS, 2048, NULL)) goto err;

  if(!EVP_PKEY_paramgen(pctx, &params)) goto err;

  if( !(kctx = EVP_PKEY_CTX_new(params, NULL)) ) goto err;
  if(!EVP_PKEY_keygen_init(kctx)) goto err;
  if(!EVP_PKEY_keygen(kctx, &key)) goto err;

  bio = BIO_new_fp(stdout, BIO_NOCLOSE);
  EVP_PKEY_print_private(bio, key, 0, NULL);
  BIO_free(bio);

  EVP_PKEY_free(key);
  EVP_PKEY_free(params);
  EVP_PKEY_CTX_free(kctx);
  EVP_PKEY_CTX_free(pctx);

  return 0;

  err:
  std::cerr << "Error occurred during key generation" << std::endl;
  if(bio) BIO_free(bio);
  if(key) EVP_PKEY_free(key);
  if(params) EVP_PKEY_free(params);
  if(kctx) EVP_PKEY_CTX_free(kctx);
  if(pctx) EVP_PKEY_CTX_free(pctx);
  return -1;

}
