#include "files.h"

uint64_t get_size_file(FILE *f)
{
    uint64_t size;
    fseek(f, 0, SEEK_END);
    size = ftell(f);
    fseek(f, 0, SEEK_SET);
    return size;
}

uint8_t
get_size_pad(uint64_t size, uint8_t pad_mode)
{
    if (pad_mode == PAD_MODE_1)
        if ((BLCK_SIZE - (size % BLCK_SIZE)) == BLCK_SIZE)
            return 0;

    if (pad_mode == PAD_MODE_3)
        if ((BLCK_SIZE - (size % BLCK_SIZE)) == BLCK_SIZE)
            return 0;

    return BLCK_SIZE - (size % BLCK_SIZE);
}

static void
set_padding(uint8_t *in_buf, uint8_t pad_size, uint64_t size, uint8_t pad_mode)
{
    if (pad_size > 0)
    {
        if (pad_mode == PAD_MODE_1)
            {
                uint64_t i;
                for (i = size; i < size + pad_size; i++)
                    in_buf[i] = 0x00;
            }

        if (pad_mode == PAD_MODE_2)
            {
                in_buf[size] = 0x80;
                uint64_t i;
                for (i = size + 1; i < size + pad_size; i++)
                    in_buf[i] = 0x00;
            }

        if (pad_mode == PAD_MODE_3)
            {
                in_buf[size] = 0x80;
                uint64_t i;
                for (i = size + 1; i < size + pad_size; i++)
                    in_buf[i] = 0x00;
            }
    }
}

void
ECB_Encrypt_File(FILE *src, FILE *dst, uint8_t *key, uint64_t size, uint8_t pad_mode)
{
    uint8_t *in_buf = malloc(BUFF_SIZE + BLCK_SIZE);
    uint8_t *out_buf = malloc(BUFF_SIZE + BLCK_SIZE);

    while (size)
    {
        if (size > BUFF_SIZE)
        {
            fread(in_buf, 1, BUFF_SIZE, src);
            ECB_Encrypt(in_buf, out_buf, key, BUFF_SIZE);
            fwrite(out_buf, 1, BUFF_SIZE, dst);
            size -= BUFF_SIZE;
        }
        else
        {
            fread(in_buf, 1, size, src);
            set_padding(in_buf, get_size_pad(size, pad_mode), size, pad_mode);
            ECB_Encrypt(in_buf, out_buf, key, size + get_size_pad(size, pad_mode));
            fwrite(out_buf, 1, size + get_size_pad(size, pad_mode), dst);
            size = 0;
        }
    }
}

void
ECB_Decrypt_File(FILE *src, FILE *dst, uint8_t *key, uint64_t size)
{
    uint8_t *in_buf = malloc(BUFF_SIZE);
    uint8_t *out_buf = malloc(BUFF_SIZE);

    while (size)
    {
        if (size > BUFF_SIZE)
        {
            fread(in_buf, 1, BUFF_SIZE, src);
            ECB_Decrypt(in_buf, out_buf, key, BUFF_SIZE);
            fwrite(out_buf, 1, BUFF_SIZE, dst);
            size -= BUFF_SIZE;
        }
        else
        {
            fread(in_buf, 1, size, src);
            ECB_Decrypt(in_buf, out_buf, key, size);
            fwrite(out_buf, 1, size, dst);
            size = 0;
        }
    }
}

void
CTR_Crypt_File(FILE *src, FILE *dst, uint8_t *init_vec, uint8_t *key, uint64_t size)
{
    uint8_t *in_buf = malloc(BUFF_SIZE);
    uint8_t *out_buf = malloc(BUFF_SIZE);
    uint8_t ctr[BLCK_SIZE];
    memset(ctr, 0x00, BLCK_SIZE);
    memcpy(ctr + BLCK_SIZE / 2, init_vec, BLCK_SIZE / 2);
    while (size)
    {
        if (size > BUFF_SIZE)
        {
            fread(in_buf, 1, BUFF_SIZE, src);
            CTR_Crypt(ctr, in_buf, out_buf, key, BUFF_SIZE);
            fwrite(out_buf, 1, BUFF_SIZE, dst);

            size -= BUFF_SIZE;
        }
        else
        {
            fread(in_buf, 1, size, src);
            CTR_Crypt(ctr, in_buf, out_buf, key, size);
            fwrite(out_buf, 1, size, dst);
            size = 0;
        }
    }
}
