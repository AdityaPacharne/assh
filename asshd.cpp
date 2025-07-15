#include<tommath.h>
#include<iostream>
#include<sys/socket.h>
#include<sys/types.h>
#include<netdb.h>
#include<unistd.h>
#include "crypto/crypto.h"
#include "crypto/hashing/sha256.h"

#define PORT "14641"
#define BACKLOG 5

int main(){

    struct addrinfo hints;
    struct addrinfo *results;
    hints.ai_flags = AI_PASSIVE;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    int fetch_address_info = getaddrinfo(NULL, PORT, &hints, &results);
    if(fetch_address_info != 0){
        fprintf(stderr, "Error while fetching address info: %s\n", gai_strerror(fetch_address_info));
        exit(1);
    }

    for(auto addrinfo_node = results; addrinfo_node != NULL; addrinfo_node = addrinfo_node->ai_next){
        
        int sockfd = socket(addrinfo_node->ai_family, addrinfo_node->ai_socktype, addrinfo_node->ai_protocol);
        int yes = 1;
        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) == -1) {
            perror("setsockopt");
            exit(1);
        }
        if(sockfd == -1){
            fprintf(stderr, "Error while creating socket\n");
            continue;
        }

        int bind_status = bind(sockfd, addrinfo_node->ai_addr, addrinfo_node->ai_addrlen);
        if(bind_status == -1){
            fprintf(stderr, "Error while binding socket to a port\n");
            continue;
        }

        int listen_status = listen(sockfd, BACKLOG);
        if(listen_status == -1){
            fprintf(stderr, "Error while listening on a port\n");
            exit(1);
        }

        struct sockaddr_storage client_addr;
        socklen_t client_addr_len = sizeof(client_addr);
        int accept_sockfd = accept(sockfd, (struct sockaddr*)&client_addr, &client_addr_len);
        if(accept_sockfd == -1){
            fprintf(stderr, "Error whle accepting a connection\n");
            break;
        }

        uint8_t peer_public_key_buffer[256];
        int recv_status = recv(accept_sockfd, peer_public_key_buffer, 256, MSG_WAITALL); 
        if(recv_status == 0){
            fprintf(stderr, "Client has closed the connection...\n");
            exit(1);
        }
        if(recv_status == -1){
            fprintf(stderr, "Error while receiving client's public key\n");
            exit(1);
        }

        mp_int private_key;
        generate_private_key(private_key);

        mp_int public_key;
        generate_public_key(private_key, public_key);

        uint8_t public_key_buffer[256];
        size_t public_key_written = mp_to_buffer(public_key, public_key_buffer);

        int send_status = send(accept_sockfd, public_key_buffer, public_key_written, 0);
        if(send_status == -1){
            fprintf(stderr, "Error while sending data through socket\n");
            exit(1);
        }

        mp_int peer_public_key = buffer_to_mp(peer_public_key_buffer, recv_status);

        std::string symmetric_key = calculate_symmetric_key(peer_public_key, private_key);

        std::cout << "Symmetric Key: " << symmetric_key << '\n';

        mp_clear(&private_key);
        mp_clear(&public_key);
        mp_clear(&peer_public_key);

        close(accept_sockfd);
        close(sockfd);
        break;
    }

    freeaddrinfo(results);

    return 0;
}
