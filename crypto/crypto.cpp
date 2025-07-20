#include<tommath.h>
#include<iostream>
#include<cstdlib>
#include "hashing/sha256.h"
#include "aes/aes.h"

#define BLOCK_SIZE 16

void fetch_value_of_generator(mp_int& generator){
    /*
     * Initializes a generator
     * Sets its value to 2 according to rfc 7919
     */
    mp_err generator_initialize = mp_init_i32(&generator, 2);
    if(generator_initialize != MP_OKAY){
        printf("Error initializing g: %s\n", mp_error_to_string(generator_initialize));
        exit(1);
    }
}

void fetch_value_of_big_prime_number(mp_int& big_prime_number) {
    /*
     * Initializes a big prime number for mod operator later in public key function
     * This big prime is taken from rfc 7919 and is stored in the environment variables
     */
    const char* p_env = "p_variable";
    const char* p_value = getenv(p_env);

    if(mp_init(&big_prime_number) != MP_OKAY){
        printf("Error initializing Big Prime\n");
    }

    mp_err reading_prime_from_env = mp_read_radix(&big_prime_number, p_value, 16);
    if(reading_prime_from_env != MP_OKAY){
        printf("Error reading Big Prime: %s\n", mp_error_to_string(reading_prime_from_env));
        exit(1);
    }
}

void generate_private_key(mp_int& private_key){
    /*
     * Intializes a private_key
     * Sets its value to a 64 digit random value
     */
    if(mp_init(&private_key) != MP_OKAY){
        printf("Error initializing private_key\n");
        exit(1);
    }

    mp_err private_key_random_initialize = mp_rand(&private_key, 64);
    if(private_key_random_initialize != MP_OKAY){
        printf("Error setting random value to private_key: %s\n", mp_error_to_string(private_key_random_initialize));
        exit(1);
    }
}

void generate_public_key(mp_int& private_key, mp_int& public_key){
    /*
     * Initializes a public_key
     * Store the output of equation ( g^a mod p ; where a is our private_key )
     */
    if(mp_init(&public_key) != MP_OKAY){
        printf("Error initializing public_key\n");
        exit(1);
    }

    mp_int generator;
    fetch_value_of_generator(generator);

    mp_int big_prime;
    fetch_value_of_big_prime_number(big_prime);

    mp_err public_key_exptmod_initialize = mp_exptmod(&generator, &private_key, &big_prime, &public_key);
    if(public_key_exptmod_initialize != MP_OKAY){
        printf("Error while calculating public_key: %s\n", mp_error_to_string(public_key_exptmod_initialize));
        exit(1);
    } 
    
    mp_clear(&generator);
    mp_clear(&big_prime);
}

size_t mp_to_buffer(mp_int& public_key, uint8_t* public_key_buffer){
    /*
     * Converts mp_int public key to a buffer of uint8_t for sending through sockets
     * Returns the number of bytes written in buffer
     */
    size_t public_key_maxlen = 256;
    size_t public_key_written;
    mp_err ubin_convert = mp_to_ubin(&public_key, public_key_buffer, public_key_maxlen, &public_key_written);
    if(ubin_convert != MP_OKAY){
        fprintf(stderr, "Error while converting mp public_key to buffer: %s\n", mp_error_to_string(ubin_convert));
        exit(1);
    }
    return public_key_written;
}

mp_int buffer_to_mp(uint8_t* peer_public_key_buffer, int recv_size){
    /*
     * Initializes peer_public_key
     * Converts the buffer to mp_int for further calculations
     */
    mp_int peer_public_key;
    if(mp_init(&peer_public_key) != MP_OKAY){
        fprintf(stderr, "Error while initializing peer_public_key\n"); 
        exit(1);
    }
    mp_err convert_to_ubin = mp_from_ubin(&peer_public_key, peer_public_key_buffer, recv_size);
    if(convert_to_ubin != MP_OKAY){
        fprintf(stderr, "Error while converting peer's public key: %s\n", mp_error_to_string(convert_to_ubin));
        exit(1);
    }
    return peer_public_key;
}

std::string calculate_symmetric_key(mp_int& peer_public_key, mp_int& private_key){
    /*
     * Creates and initializes shared_key
     * Calculated shared key by expt y^b where
     * y is peer_public_key and
     * b is private_key
     * thereby created shared_key = g^(ab) mod p
     */
    mp_int shared_key;
    if(mp_init(&shared_key) != MP_OKAY){
        fprintf(stderr, "Error while initializing shared_key\n");
        exit(1);
    }

    mp_int big_prime;
    fetch_value_of_big_prime_number(big_prime);
    mp_err shared_key_expt = mp_exptmod(&peer_public_key, &private_key, &big_prime, &shared_key);
    if(shared_key_expt != MP_OKAY){
        fprintf(stderr, "Error while calculating shared key: %s\n", mp_error_to_string(shared_key_expt));
        exit(1);
    }

    uint8_t shared_key_buffer[256];
    size_t shared_key_written = mp_to_buffer(shared_key, shared_key_buffer);
    const unsigned char* shared_key_char = reinterpret_cast<const unsigned char*>(shared_key_buffer);
    std::string symmetric_key = sha256(shared_key_char, shared_key_written);

    mp_clear(&big_prime);
    mp_clear(&shared_key);

    return symmetric_key;
}

void view_mp(mp_int& mp_tobe_viewed){
    /*
     * Prints the mp_int taken as input by converting it to buffer
     */
    char buffer[1024];
    size_t written;
    mp_err view_radix = mp_to_radix(&mp_tobe_viewed, buffer, 1024, &written, 16);
    if(view_radix != MP_OKAY){
        fprintf(stderr, "Error while converting to radix: %s\n", mp_error_to_string(view_radix));
    }
    printf("Radix: \n%s\n", buffer);
}

void counter_increment(unsigned char* cbuf) {
    for(int i = 16; i > 0; i--){
        if(++cbuf[i] != 0) break;
    }
}

std::string aes_ctr(std::string input, const std::string symmetric_key, const unsigned char* iv){
    /*
     * Uses aes ctr for encryption and decryption
     * It doesnt need 2 different functions
     * It takes input and symmetric_key as input
     * and 16 byte random number iv
     */
    int size = input.size();

    unsigned char* output_buffer = new unsigned char[size];

    aes_encrypt_ctx ctx = {};
    AES_RETURN aes_encrypt_initialize = aes_encrypt_key256(reinterpret_cast<const unsigned char*>(symmetric_key.c_str()), &ctx);
    if(aes_encrypt_initialize != 0){
        fprintf(stderr, "Error while initializing aes encrypt context\n");
    }

    /*AES_RETURN ctr_status = aes_ctr_crypt(const unsigned char *ibuf, unsigned char *obuf,*/
    /*        int len, unsigned char *cbuf, cbuf_inc ctr_inc, aes_encrypt_ctx ctx[1])*/

    unsigned char counter_buffer[16];
    memcpy(counter_buffer, iv, 16);

    AES_RETURN ctr_status = aes_ctr_crypt(reinterpret_cast<const unsigned char*>(input.c_str()), output_buffer, size, counter_buffer, counter_increment, &ctx);
    if(ctr_status != 0) std::cerr << "Error in ctr crypt\n";

    std::string output(reinterpret_cast<const char*>(output_buffer), size);
    delete[] output_buffer;

    return output;
}
