#ifndef _CRPT_H
#define _CRPT_H

#include <openssl/evp.h>
#include <openssl/err.h>
//#include <openssl/applink.c> // you may need this with some compilers due a bug

char *crpt_lastError()
{
  long error = ERR_get_error();
  return ERR_error_string(error, NULL);
}


int encrypt(unsigned char*plaintext, int plaintext_len, const unsigned char* key, const unsigned char* iv, unsigned char* ciphertext)
{
  EVP_CIPHER_CTX *ctx;
  int len;
  int ciphertxt_len;
  if(!(ctx = EVP_CIPHER_CTX_new())) return -1;

  //initialize the encryption operation
  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)) return -1;
  //provide the text to be encrypted
  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) return -1;
  ciphertxt_len = len;

  //finalize the encryption, may add extra bytes
  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) return -1;
  ciphertxt_len += len;
  //clean up
  EVP_CIPHER_CTX_free(ctx);
  return ciphertxt_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, const unsigned char *key, const unsigned char *iv, unsigned char *plaintext)
{
  EVP_CIPHER_CTX *ctx;
  int len;
  int plaintext_len;
  if(!(ctx = EVP_CIPHER_CTX_new())) return -1;
  //initialize the encryption operation
  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)) return -1;
  //provide the encrypted text to be decrypted
  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) return -1;
  plaintext_len = len;
  //finalize the encryption
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) return -1;
  plaintext_len += len;
  //finalize the decryption
  EVP_CIPHER_CTX_free(ctx);
  return plaintext_len;
}


#endif
