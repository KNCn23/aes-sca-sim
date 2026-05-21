#ifndef AES_H
#define AES_H

#include <stdint.h>

#define AES_BLOCK_SIZE 16
#define AES_KEY_SIZE   16

void aes128_key_expand(const uint8_t key[16], uint8_t round_keys[176]);
void aes128_encrypt(const uint8_t key[16],
                    const uint8_t plaintext[16],
                    uint8_t ciphertext[16]);

extern const uint8_t AES_SBOX[256];

#endif
