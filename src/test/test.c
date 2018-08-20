#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../crpt.h"


#define STR_OUT_OF_MEMORY "Out of memory!\n"
#define STR_ERROR_UD "Unknown error occurred!"



int main(int argc, char **argv)
{
  unsigned char key[] = {0xFC, 0xCB, 0x44, 0xEF, 0xAC, 0x12, 0x87, 0x71, 0x55, 0x21, 0xCC, 0x03, 0x11, 0x23, 0x33, 0x41, 0x57, 0x91, 0xee, 0xbb, 0x66, 0x37, 0xe3, 0xa1, 0x17, 0xc1, 0xd5, 0xf7, 0x81, 0xAE, 0x65, 0x89};
  unsigned char iv[] = {0x27, 0x11, 0xAD, 0x17, 0xF9, 0x1D, 0x77, 0x5A, 0x93, 0x7E, 0xF3, 0x71, 0x3C, 0x4F, 0x34, 0xCF};


  if(argc < 3 || (strcmp(argv[1], "-d")!= 0 && strcmp(argv[1], "-e") != 0)){
    printf("USAGE: %s -e/d <input>\n", argv[0]);
    exit(EXIT_FAILURE);
  }

  if(strcmp(argv[1], "-e") == 0){
    //encrypt ...
    int text_len = strlen(argv[2]);
    int cipher_len = text_len + EVP_MAX_BLOCK_LENGTH;//Add extra space EVP_MAX_BLOCK_LENGTH = 32byte = 256bit
    unsigned char *cipher_text = (unsigned char *) malloc(cipher_len * sizeof(unsigned char));
    if(!cipher_text){
      printf(STR_OUT_OF_MEMORY);
      exit(EXIT_FAILURE);
    }
    int out_len = encrypt((unsigned char*)argv[2], text_len, key, iv, cipher_text);
    if(out_len < 0){
      //encryption failed, try to get the error
      char *err = crpt_lastError();
      if(err)
	puts(err);
      else
	printf(STR_ERROR_UD);
      exit(EXIT_FAILURE);
    }
    int i;
    //print original text bytes
    printf("Plaint text:%s\nPlain text bytes:", argv[2]);
    for(i = 0; i < text_len; i++){
      printf("%02X", argv[2][i]);
    }
    printf("\n");
    //print the result
    printf("Result bytes:");
    for(i = 0; i < out_len; i++){
      printf("%02X", cipher_text[i]);
    }
    printf("\n");
  }
  else{
    //decrypt ...
    //we expect the input to be a hexadecimal string
    int text_len = strlen(argv[2]);
    if(text_len % 2 != 0){
      printf("Input error!\n");
      exit(EXIT_FAILURE);
    }
    int cipher_len = text_len/2 ;
    unsigned char *cipher_text = (unsigned char*) malloc(cipher_len * sizeof(unsigned char));
    if(!cipher_text){
      printf(STR_OUT_OF_MEMORY);
      exit(EXIT_FAILURE);
    }
    //convert the hexadecimal string into byte array
    char *pos = argv[2];
    size_t cnt;
    for(cnt = 0; cnt < cipher_len; cnt++){
      sscanf(pos, "%02X", &cipher_text[cnt]);
      pos +=2;
    }
    unsigned char *plain_text = (unsigned char*) malloc(cipher_len *sizeof(unsigned char));
    if(!plain_text){
      puts(STR_OUT_OF_MEMORY);
      exit(EXIT_FAILURE);
    }

    int out_len = decrypt(cipher_text, cipher_len, key, iv, plain_text);
    if(out_len < 0){
      char *err = crpt_lastError();
      if(err)
	printf("%s\n", err);
      else
	printf(STR_ERROR_UD);
    }
    plain_text[out_len] = '\0';
    printf("%s\n", (char *)plain_text);
  }
  
  
  
  return 0;
}

