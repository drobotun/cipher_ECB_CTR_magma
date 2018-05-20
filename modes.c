#include "modes.h"

static void
inc_ctr(uint8_t *ctr)
{
    int i;
    unsigned int internal = 0;
    uint8_t bit[BLCK_SIZE];
    memset(bit, 0x00, BLCK_SIZE);
    bit[0] = 0x01;
    for (i = 0; i < BLCK_SIZE; i++)
    {
        internal = ctr[i] + bit[i] + (internal >> 8);
        ctr[i] = internal & 0xff;
    }
}

static void
add_xor(const uint8_t *a, const uint8_t *b, uint8_t *c)
{
    int i;
    for (i = 0; i < BLCK_SIZE; i++)
        c[i] = a[i]^b[i];
}

void
ECB_Encrypt(uint8_t *in_buf, uint8_t *out_buf, uint8_t *key, uint64_t size)
{
    uint64_t num_blocks = size / BLCK_SIZE;
    uint8_t internal[BLCK_SIZE];
    uint64_t i;
    GOST_Magma_Expand_Key(key);
    for (i = 0; i < num_blocks; i++)
    {
        memcpy(internal, in_buf+i*BLCK_SIZE, BLCK_SIZE);
        GOST_Magma_Encrypt(internal, internal);
        memcpy(out_buf + i*BLCK_SIZE, internal, BLCK_SIZE);
    }
    GOST_Magma_Destroy_Key();
}

void
ECB_Decrypt(uint8_t *in_buf, uint8_t *out_buf, uint8_t *key, uint64_t size)
{
    uint64_t num_blocks = size / BLCK_SIZE;
    uint8_t internal[BLCK_SIZE];
    uint64_t i;
    GOST_Magma_Expand_Key(key);
    for (i = 0; i < num_blocks; i++)
    {
        memcpy(internal, in_buf + i*BLCK_SIZE, BLCK_SIZE);
        GOST_Magma_Decrypt(internal, internal);
        memcpy(out_buf + i*BLCK_SIZE, internal, BLCK_SIZE);
    }
    GOST_Magma_Destroy_Key();
}

void
CTR_Crypt(uint8_t *ctr, uint8_t *in_buf, uint8_t *out_buf, uint8_t *key, uint64_t size)
{
    uint64_t num_blocks = size / BLCK_SIZE;
    uint8_t gamma[BLCK_SIZE];
    uint8_t internal[BLCK_SIZE];

    uint64_t i;
    GOST_Magma_Expand_Key(key);
    for (i = 0; i < num_blocks; i++)
    {
        GOST_Magma_Encrypt(ctr, gamma);
        inc_ctr(ctr);
        memcpy(internal, in_buf + i*BLCK_SIZE, BLCK_SIZE);
        add_xor(internal, gamma, internal);
        memcpy(out_buf + i*BLCK_SIZE, internal, BLCK_SIZE);
        size = size - BLCK_SIZE;
    }
    if (size > 0)
    {
        GOST_Magma_Encrypt(ctr, gamma);
        inc_ctr(ctr);
        memcpy(internal, in_buf + i*BLCK_SIZE, size);
        add_xor(internal, gamma, internal);
        memcpy(out_buf + num_blocks*BLCK_SIZE, internal, size);
        size = 0;
    }
    GOST_Magma_Destroy_Key();
}
