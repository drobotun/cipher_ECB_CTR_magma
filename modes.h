#ifndef MODES_H
#define MODES_H

#include "magma_calc.h"

#define BLCK_SIZE 8

void
ECB_Encrypt(uint8_t *in_buf, uint8_t *out_buf, uint8_t *key, uint64_t size);

void
ECB_Decrypt(uint8_t *in_buf, uint8_t *out_buf, uint8_t *key, uint64_t size);

void
CTR_Crypt(uint8_t *init_vec, uint8_t *in_buf, uint8_t *out_buf, uint8_t *key, uint64_t size);


#endif // MODES_H
