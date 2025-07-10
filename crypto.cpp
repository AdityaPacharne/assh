#include<tommath.h>
#include<iostream>

void fetchValueOfGenerator(mp_int& generator){
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

void fetchValueOfBigPrimeNumber(mp_int& bigPrimeNumber) {
    /*
     * Initializes a big prime number for mod operator later in public key function
     * This big prime is taken from rfc 7919 and is stored in the environment variables
     */
    const char* pENV = "pVariable";
    const char* pValue = getenv(pENV);

    if(mp_init(&bigPrimeNumber) != MP_OKAY){
        printf("Error initializing Big Prime\n");
    }

    mp_err readingPrimeFromENV = mp_read_radix(&bigPrimeNumber, pValue, 16);
    if(readingPrimeFromENV != MP_OKAY){
        printf("Error reading Big Prime: %s\n", mp_error_to_string(readingPrimeFromENV));
        exit(1);
    }
}

void generatePrivateKey(mp_int& private_key){
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

void generatePublicKey(mp_int& private_key, mp_int& public_key){
    /*
     * Initializes a public_key
     * Store the output of equation ( g^a mod p ; where a is our private_key )
     */
    if(mp_init(&public_key) != MP_OKAY){
        printf("Error initializing public_key\n");
        exit(1);
    }

    mp_int generator;
    fetchValueOfGenerator(generator);

    mp_int bigPrime;
    fetchValueOfBigPrimeNumber(bigPrime);

    mp_err public_key_exptmod_initialize = mp_exptmod(&generator, &private_key, &bigPrime, &public_key);
    if(public_key_exptmod_initialize != MP_OKAY){
        printf("Error while calculating public_key: %s\n", mp_error_to_string(public_key_exptmod_initialize));
        exit(1);
    } 
    
    mp_clear(&generator);
    mp_clear(&bigPrime);
}
