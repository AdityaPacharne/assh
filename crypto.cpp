#include<tommath.h>
#include<cstdlib>

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
