#include<tommath.h>
#include<iostream>

int main() {

    const char* pENV = "pVariable";

    const char* pValue = getenv(pENV);

    mp_int p;
    mp_err mp_initialize = mp_init(&p);
    if(mp_initialize != MP_OKAY){
        printf("Error initializing mp: %s\n", mp_error_to_string(mp_initialize));
    }
    mp_err error = mp_read_radix(&p, pValue, 16);
    if(error != MP_OKAY){
        printf("Error reading radix: %s\n", mp_error_to_string(error));
    }


    mp_int g;
    mp_err g_initialize = mp_init_i32(&g, 2);
    if(g_initialize != MP_OKAY){
        printf("Error initializing g: %s\n", mp_error_to_string(g_initialize));
    }


    mp_int private_key_a;
    mp_err private_key_initialize_a = mp_init(&private_key_a);
    if(private_key_initialize_a != MP_OKAY){
        printf("Error initializing private_key_a: %s\n", mp_error_to_string(private_key_initialize_a));
    }
    mp_err random_initialize_a = mp_rand(&private_key_a, 64);
    if(random_initialize_a != MP_OKAY){
        printf("Error while initializing private_key_a with random value: %s\n", mp_error_to_string(random_initialize_a));
    }


    mp_int private_key_b;
    mp_err private_key_initialize_b = mp_init(&private_key_b);
    if(private_key_initialize_b != MP_OKAY){
        printf("Error initializing private_key_b: %s\n", mp_error_to_string(private_key_initialize_b));
    }
    mp_err random_initialize_b = mp_rand(&private_key_b, 64);
    if(random_initialize_b != MP_OKAY){
        printf("Error while initializing private_key_b with random value: %s\n", mp_error_to_string(random_initialize_b));
    }


    mp_int public_key_a;
    mp_err public_key_initialize_a = mp_init(&public_key_a);
    if(public_key_initialize_a != MP_OKAY){
        printf("Error initializing public_key_a: %s\n", mp_error_to_string(public_key_initialize_a));
    }
    mp_err public_key_expt_initialize_a = mp_exptmod(&g, &private_key_a, &p, &public_key_a);
    if(public_key_expt_initialize_a != MP_OKAY){
        printf("Error while calculating public_key_a: %s\n", mp_error_to_string(public_key_expt_initialize_a));
    }


    mp_int public_key_b;
    mp_err public_key_initialize_b = mp_init(&public_key_b);
    if(public_key_initialize_b != MP_OKAY){
        printf("Error initializing public_key_b: %s\n", mp_error_to_string(public_key_initialize_b));
    }
    mp_err public_key_expt_initialize_b = mp_exptmod(&g, &private_key_b, &p, &public_key_b);
    if(public_key_expt_initialize_b != MP_OKAY){
        printf("Error while calculating public_key_b: %s\n", mp_error_to_string(public_key_expt_initialize_b));
    }

    
    mp_int shared_key_a;
    mp_err shared_key_initialize_a = mp_init(&shared_key_a);
    if(shared_key_initialize_a != MP_OKAY){
        printf("Error initializing shared_key_a: %s\n", mp_error_to_string(shared_key_initialize_a));
    }
    mp_err shared_key_expt_initialize_a = mp_exptmod(&public_key_b, &private_key_a, &p, &shared_key_a);
    if(shared_key_expt_initialize_a != MP_OKAY){
        printf("Error while calculating shared_key_a: %s\n", mp_error_to_string(shared_key_expt_initialize_a));
    }

    mp_int shared_key_b;
    mp_err shared_key_initialize_b = mp_init(&shared_key_b);
    if(shared_key_initialize_b != MP_OKAY){
        printf("Error initializing shared_key_b: %s\n", mp_error_to_string(shared_key_initialize_b));
    }
    mp_err shared_key_expt_initialize_b = mp_exptmod(&public_key_a, &private_key_b, &p, &shared_key_b);
    if(shared_key_expt_initialize_b != MP_OKAY){
        printf("Error while calculating shared_key_b: %s\n", mp_error_to_string(shared_key_expt_initialize_b));
    }

    mp_ord answer = mp_cmp(&shared_key_a, &shared_key_b);
    std::cout << answer << '\n';


    /*char output[1024];*/
    /*size_t public_key_size;*/
    /*mp_err convertPublicKey = mp_to_radix(&public_key, output, sizeof(output), &public_key_size, 10);*/
    /*if(convertPublicKey != MP_OKAY){*/
    /*    printf("Error while coverting public key to radix: %s\n", mp_error_to_string(convertPublicKey));*/
    /*}*/
    /*printf("Public Key: %s\n", output);*/
    /*printf("Size of Public Key: %zu\n", public_key_size);*/

    mp_clear(&p);
    mp_clear(&g);
    mp_clear(&private_key_a);
    mp_clear(&private_key_b);
    mp_clear(&public_key_a);
    mp_clear(&public_key_b);
    mp_clear(&shared_key_a);
    mp_clear(&shared_key_b);
    return 0;
}
