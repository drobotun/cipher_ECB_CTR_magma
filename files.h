#ifndef FILES_H
#define FILES_H

#define PAD_MODE_1 0x01
#define PAD_MODE_2 0x02
#define PAD_MODE_3 0x03

#include "modes.h"

#define BUFF_SIZE (8*1024)

uint64_t get_size_file(FILE *f);

void
ECB_Encrypt_File(FILE *src, FILE *dst, uint8_t *key, uint64_t size, uint8_t pad_mode);

void
ECB_Decrypt_File(FILE *src, FILE *dst, uint8_t *key, uint64_t size);

void
CTR_Crypt_File(FILE *src, FILE *dst, uint8_t *init_vec, uint8_t *key, uint64_t size);


#endif // FILES_H
