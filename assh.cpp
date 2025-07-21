#include<tommath.h>
#include<iostream>
#include<sys/socket.h>
#include<sys/types.h>
#include<netdb.h>
#include<unistd.h>
#include<cstring>
#include "crypto/crypto.h"
#include "crypto/hashing/sha256.h"
#include "crypto/aes/aes.h"

constexpr auto PORT = "14641";

int connect_to_peer(const std::string& ip, const std::string& port){
    /*
     * Fetching network info of ip and port taken as parameters
     * Create and connect to a socket
     * Return socket file descriptor
     */
    addrinfo hints;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;

    addrinfo* results;

    int status = getaddrinfo(ip.c_str(), port.c_str(), &hints, &results);
    std::cout << "Connecting to IP: " << ip << std::endl;
    if(status != 0){
        std::cerr << "Error while fetching address info: " << gai_strerror(status) << '\n';
        exit(1);
    }
    std::cout << "I guess no erro while connecting to IP\n";

    int sockfd = -1;
    for(auto node = results; node != NULL; node = node->ai_next){
        sockfd = socket(node->ai_family, node->ai_socktype, node->ai_protocol);
        std::cout << "sockfd: " << sockfd << std::endl;
        if(sockfd == -1) continue;
        if(connect(sockfd, node->ai_addr, node->ai_addrlen) == 0) break;
        close(sockfd);
        sockfd = -1;
    }
    freeaddrinfo(results);

    if(sockfd == -1){
        std::cerr << "Failed to connect to the server\n";
        exit(1);
    }

    return sockfd;
}

std::string perform_key_exchange(int sockfd){
    /*
     * Generate public and private key
     * Send our public key over to the peer and wait for their public_key to arrive
     * Generate a symmetric using that
     */
    mp_int private_key, public_key;
    generate_private_key(private_key);
    generate_public_key(private_key, public_key);

    uint8_t public_key_buffer[256];
    size_t public_key_written = mp_to_buffer(public_key, public_key_buffer);

    int send_status = send(sockfd, public_key_buffer, public_key_written, 0);
    if(send_status == -1){
        std::cerr << "Error while public_key exchange\n";
        exit(1);
    }

    uint8_t peer_key_buffer[256];

    int recv_status = recv(sockfd, peer_key_buffer, 256, MSG_WAITALL);
    if(recv_status <= 0){
        std::cerr << "Error while receiving peer's public_key or Connection closed...\n";
        exit(1);
    }

    mp_int peer_public_key = buffer_to_mp(peer_key_buffer, recv_status);

    std::string symmetric_key = calculate_symmetric_key(peer_public_key, private_key);
    std::cout << "Symmetric Key: " << symmetric_key << "\n";

    mp_clear(&private_key);
    mp_clear(&public_key);
    mp_clear(&peer_public_key);

    return symmetric_key;
}

void command_loop(int sockfd, const std::string& symmetric_key){
    /*
     * Command loop takes input from user
     * Encrypts the command and sends it over
     */
    std::string command;

    while(getline(std::cin >> std::ws, command)){
        if(command == "exit") break;

        unsigned char iv[16];
        for(int i = 0; i < 16; i++) iv[i] = rand() % 256;

        unsigned char iv_copy[16];
        memcpy(iv_copy, iv, 16);

        std::string ctr_enc = aes_ctr(command, symmetric_key, iv);

        uint32_t ctr_enc_size = htonl(ctr_enc.size());

        send(sockfd, &ctr_enc_size, 4, 0);
        send(sockfd, ctr_enc.data(), ctr_enc.size(), 0);
        send(sockfd, iv, 16, 0);

        std::string ctr_dec = aes_ctr(ctr_enc, symmetric_key, iv_copy);
    }
}

int main(int argc, char* argv[]) {
    std::cout << argv[1] << std::endl;
    int sockfd = connect_to_peer(argv[1], PORT);
    std::string symmetric_key = perform_key_exchange(sockfd);
    command_loop(sockfd, symmetric_key);
    close(sockfd);
    return 0;
}
