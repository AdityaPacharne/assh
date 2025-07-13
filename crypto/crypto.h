#ifndef CRYPTO_H
#define CRYPTO_H

#include<tommath.h>
#include<cstdlib>

void fetch_value_of_generator(mp_int& generator);
void fetch_value_of_big_prime_number(mp_int& big_prime_number);
void generate_private_key(mp_int& private_key);
void generate_public_key(mp_int& private_key, mp_int& public_key);
size_t mp_to_buffer(mp_int& public_key, uint8_t* public_key_buffer);
mp_int buffer_to_mp(uint8_t* peer_public_key_buffer, int recv_size);
mp_int calculate_shared_key(mp_int& peer_public_key, mp_int& private_key);
void view_mp(mp_int& mp_tobe_viewed);

#endif
