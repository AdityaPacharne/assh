#include<tommath.h>
#include<iostream>
#include<sys/socket.h>
#include<sys/types.h>
#include<netdb.h>
#include<unistd.h>
#include "crypto/crypto.h"
#include "crypto/hashing/sha256.h"

#define PORT "14641"

int main() {
    
    struct addrinfo hints;
    struct addrinfo *results;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;

    int fetch_address_info = getaddrinfo("127.0.0.1", PORT, &hints, &results);
    if(fetch_address_info != 0){
        fprintf(stderr, "Error while fetching address info: %s\n", gai_strerror(fetch_address_info));
        exit(1);
    }

    for(auto addrinfo_node = results; addrinfo_node != NULL; addrinfo_node = addrinfo_node->ai_next){
        int sockfd = socket(addrinfo_node->ai_family,
                            addrinfo_node->ai_socktype,
                            addrinfo_node->ai_protocol);
        if(sockfd == -1){
            fprintf(stderr, "Error while creating a socket\n");
            continue;
        }

        int socket_connect = connect(sockfd,
                                    addrinfo_node->ai_addr,
                                    addrinfo_node->ai_addrlen);
        if(socket_connect == -1){
            fprintf(stderr, "Error while connecting to a socket\n");
            exit(1);
        }

        mp_int private_key;
        generate_private_key(private_key);

        mp_int public_key;
        generate_public_key(private_key, public_key);

        uint8_t public_key_buffer[256];
        size_t public_key_written = mp_to_buffer(public_key, public_key_buffer);

        int send_status = send(sockfd, public_key_buffer, public_key_written, 0);
        if(send_status == -1){
            fprintf(stderr, "Error while sending data through socket\n");
        }

        uint8_t server_public_key_buffer[256];

        int recv_status = recv(sockfd, server_public_key_buffer, 256, MSG_WAITALL);
        if(recv_status == 0){
            printf("Connection Closed...\n");
            exit(0);
        }
        else if(recv_status == -1){
            fprintf(stderr, "Error while receiving message\n");
            exit(1);
        }

        mp_int server_public_key = buffer_to_mp(server_public_key_buffer, recv_status);

        mp_int shared_key = calculate_shared_key(server_public_key, private_key);

        uint8_t shared_key_buffer[256];
        size_t shared_key_written = mp_to_buffer(shared_key, shared_key_buffer);
        const char* shared_key_char = reinterpret_cast<const char*>(shared_key_buffer);
        std::string hashed = sha256(std::string(shared_key_char, shared_key_written));
        std::cout << "Shared Key Char: " << hashed << '\n';

        view_mp(shared_key);

        mp_clear(&private_key);
        mp_clear(&public_key);
        mp_clear(&server_public_key);
        mp_clear(&shared_key);
        close(sockfd);
    }

    freeaddrinfo(results);
}
