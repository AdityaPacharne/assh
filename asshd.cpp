#include<tommath.h>
#include<iostream>
#include<sys/socket.h>
#include<sys/types.h>
#include<netdb.h>
#include<unistd.h>
#include "crypto/crypto.h"
#include "crypto/hashing/sha256.h"

constexpr auto PORT = "14641";
constexpr auto BACKLOG = 5;

int create_and_bind_socket(const std::string& port){
    /*
     * Fetch network info of our own port 14641
     * Bind a socket to this port
     * Return the socket file descriptor
     */
    addrinfo hints;
    hints.ai_flags = AI_PASSIVE;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    addrinfo *results;

    int status = getaddrinfo(NULL, port.c_str(), &hints, &results);
    if(status != 0){
        std::cerr << "Error while fetching address info: " << gai_strerror(status) << '\n';
        exit(1);
    }

    int sockfd = -1;
    for(auto node = results; node != NULL; node = node->ai_next){
        sockfd = socket(node->ai_family, node->ai_socktype, node->ai_protocol);
        if(sockfd == -1) continue;

        int yes = 1;
        if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) < 0){
            std::cerr << "setsockopt(SO_REUSEADDR) failed\n";
            close(sockfd);
            continue;
        }

        if(bind(sockfd, node->ai_addr, node->ai_addrlen) != -1) break;
        close(sockfd);
        sockfd = -1;
    }

    freeaddrinfo(results);

    if(sockfd == -1){
        std::cerr << "Error while binding to a socket\n";
        exit(1);
    }

    return sockfd;
}

std::string perform_key_exchange(int sockfd){
    /*
     * Listen on the port
     * New sockfd is created after accpeting the connection
     * Generate private and public key
     * Return symmetric_key
     */
    if(listen(sockfd, BACKLOG) == -1){
        std::cerr << "Error while listening on a port\n";
        exit(1);
    }

    sockaddr_storage peer_addr;
    socklen_t peer_addr_length = sizeof(peer_addr);
    int accept_sockfd = accept(sockfd, (struct sockaddr*)&peer_addr, &peer_addr_length);
    if(accept_sockfd == -1){
        std::cerr << "Error while accepting a connection\n";
        exit(1);
    }

    uint8_t peer_key_buffer[256];
    int recv_status = recv(accept_sockfd, peer_key_buffer, 256, MSG_WAITALL);
    if(recv_status <= 0){
        std::cerr << "Error while receiving peer's public_key or Connection closed...\n";
        exit(1);
    }

    mp_int private_key, public_key;
    generate_private_key(private_key);
    generate_public_key(private_key, public_key);

    uint8_t public_key_buffer[256];
    size_t public_key_written = mp_to_buffer(public_key, public_key_buffer);

    if(send(accept_sockfd, public_key_buffer, public_key_written, 0) == -1){
        std::cerr << "Error while sending public_key\n";
        exit(1);
    }

    mp_int peer_public_key = buffer_to_mp(peer_key_buffer, recv_status);

    std::string symmetric_key = calculate_symmetric_key(peer_public_key, private_key);
    std::cout << "Symmetric Key: " << symmetric_key << '\n';

    mp_clear(&private_key);
    mp_clear(&public_key);
    mp_clear(&peer_public_key);

    close(accept_sockfd);
    close(sockfd);

    return symmetric_key;
}

int main(){
    int sockfd = create_and_bind_socket(PORT);
    std::string symmetric_key = perform_key_exchange(sockfd);
    return 0;
}
