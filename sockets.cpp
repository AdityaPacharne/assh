#include<iostream>
#include<tommath.h>
#include<sys/socket.h>
#include<sys/types.h>
#include<netdb.h>
#include<unistd.h>
#include "crypto.cpp"

int main() {
    
    struct addrinfo hints;
    struct addrinfo *results;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;

    int fetch_address_info = getaddrinfo("127.0.0.1", "8080", &hints, &results);
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
            exit(1);
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

        uint8_t receiver_public_key_buffer[256];

        int recv_status = recv(sockfd, receiver_public_key_buffer, 256, MSG_WAITALL);
        if(recv_status == 0){
            printf("Connection Closed...\n");
            exit(0);
        }
        else if(recv_status == -1){
            fprintf(stderr, "Error while receiving message\n");
            exit(1);
        }

        mp_int receiver_public_key = buffer_to_mp(receiver_public_key_buffer, recv_status);

        mp_int shared_key = calculate_shared_key(&receiver_public_key, &private_key);

        mp_clear(&private_key);
        mp_clear(&public_key);
        mp_clear(&receiver_public_key);
        mp_clear(&shared_key);
        close(sockfd);
    }

    freeaddrinfo(results);
}
