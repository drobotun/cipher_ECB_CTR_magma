#ifndef MAGMA_CALC_H
#define MAGMA_CALC_H

#include <stdfix.h>
#include <stdint.h>
#include <string.h>
#include <malloc.h>
#include <stdio.h>

static unsigned char Pi[8][16]=
{
    {12,4,6,2,10,5,11,9,14,8,13,7,0,3,15,1},
    {6,8,2,3,9,10,5,12,1,14,4,7,11,13,0,15},
    {11,3,5,8,2,15,10,13,14,1,7,4,12,9,6,0},
    {12,8,2,1,13,4,15,6,7,0,10,5,3,14,9,11},
    {7,15,5,10,8,1,6,13,0,9,3,14,11,4,2,12},
    {5,13,15,6,9,2,12,10,11,7,8,1,4,3,14,0},
    {8,14,2,5,6,9,1,12,15,4,11,0,13,10,3,7},
    {1,7,14,13,0,5,8,3,4,15,10,6,9,12,11,2}
};

typedef uint8_t vect[4]; //блок размером 32 бита

vect iter_key[32]; //итерационные ключи шифрования

void
GOST_Magma_Expand_Key(const uint8_t *key);

void
GOST_Magma_Destroy_Key();

void
GOST_Magma_Encrypt(const uint8_t *blk, uint8_t *out_blk);

void
GOST_Magma_Decrypt(const uint8_t *blk, uint8_t *out_blk);

#endif // MAGMA_CALC_H
