#include<tommath.h>
#include<iostream>

int main() {


    // Creating big prime p variable
    mp_int p;
    mp_err mp_initialize = mp_init(&p);
    if(mp_initialize != MP_OKAY){
        printf("Error initializing mp: %s\n", mp_error_to_string(mp_initialize));
    }
    mp_err error = mp_read_radix(&p, "FFFFFFFFFFFFFFFFADF85458A2BB4A9AAFDC5620273D3CF1D8B9C583CE2D3695A9E13641146433FBCC939DCE249B3EF97D2FE363630C75D8F681B202AEC4617AD3DF1ED5D5FD65612433F51F5F066ED0856365553DED1AF3B557135E7F57C935984F0C70E0E68B77E2A689DAF3EFE8721DF158A136ADE73530ACCA4F483A797ABC0AB182B324FB61D108A94BB2C8E3FBB96ADAB760D7F4681D4F42A3DE394DF4AE56EDE76372BB190B07A7C8EE0A6D709E02FCE1CDF7E2ECC03404CD28342F619172FE9CE98583FF8E4F1232EEF28183C3FE3B1B4C6FAD733BB5FCBC2EC22005C58EF1837D1683B2C6F34A26C1B2EFFA886B423861285C97FFFFFFFFFFFFFFFF", 16);
    if(error != MP_OKAY){
        printf("Error reading radix: %s\n", mp_error_to_string(error));
    }


    //Creating g = 2
    mp_int g;
    mp_err g_initialize = mp_init_i32(&g, 2);
    if(g_initialize != MP_OKAY){
        printf("Error initializing g: %s\n", mp_error_to_string(g_initialize));
    }


    // Creating private key A
    mp_int private_key_a;
    mp_err private_key_initialize_a = mp_init(&private_key_a);
    if(private_key_initialize_a != MP_OKAY){
        printf("Error initializing private_key_a: %s\n", mp_error_to_string(private_key_initialize_a));
    }
    mp_err random_initialize_a = mp_rand(&private_key_a, 64);
    if(random_initialize_a != MP_OKAY){
        printf("Error while initializing private_key_a with random value: %s\n", mp_error_to_string(random_initialize_a));
    }


    // Creating private key B
    mp_int private_key_b;
    mp_err private_key_initialize_b = mp_init(&private_key_b);
    if(private_key_initialize_b != MP_OKAY){
        printf("Error initializing private_key_b: %s\n", mp_error_to_string(private_key_initialize_b));
    }
    mp_err random_initialize_b = mp_rand(&private_key_b, 64);
    if(random_initialize_b != MP_OKAY){
        printf("Error while initializing private_key_b with random value: %s\n", mp_error_to_string(random_initialize_b));
    }


    //Creating public key A
    mp_int public_key_a;
    mp_err public_key_initialize_a = mp_init(&public_key_a);
    if(public_key_initialize_a != MP_OKAY){
        printf("Error initializing public_key_a: %s\n", mp_error_to_string(public_key_initialize_a));
    }
    mp_err public_key_expt_initialize_a = mp_exptmod(&g, &private_key_a, &p, &public_key_a);
    if(public_key_expt_initialize_a != MP_OKAY){
        printf("Error while calculating public_key_a: %s\n", mp_error_to_string(public_key_expt_initialize_a));
    }


    //Creating public key B
    mp_int public_key_b;
    mp_err public_key_initialize_b = mp_init(&public_key_b);
    if(public_key_initialize_b != MP_OKAY){
        printf("Error initializing public_key_b: %s\n", mp_error_to_string(public_key_initialize_b));
    }
    mp_err public_key_expt_initialize_b = mp_exptmod(&g, &private_key_b, &p, &public_key_b);
    if(public_key_expt_initialize_b != MP_OKAY){
        printf("Error while calculating public_key_b: %s\n", mp_error_to_string(public_key_expt_initialize_b));
    }

    
    //Creating shared key A
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
