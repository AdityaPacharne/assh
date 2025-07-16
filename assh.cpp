#include<tommath.h>
#include<iostream>
#include<sys/socket.h>
#include<sys/types.h>
#include<netdb.h>
#include<unistd.h>
#include "crypto/crypto.h"
#include "crypto/hashing/sha256.h"
#include "crypto/aes/aes.h"

constexpr auto PEER_IP = "127.0.0.1";
constexpr auto PORT = "14641";

int connect_to_peer(const std::string& ip, const std::string& port){
    addrinfo hints;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;

    addrinfo* results;

    int status = getaddrinfo(ip.c_str(), port.c_str(), &hints, &results);
    if(status != 0){
        fprintf(stderr, "Error while fetching address info: %s\n", gai_strerror(status));
        exit(1);
    }

    int sockfd = 1;
    for(auto node = results; node != NULL; node = node->ai_next){
        sockfd = socket(node->ai_family, node->ai_socktype, node->ai_protocol);
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
    mp_int private_key, public_key;
    generate_private_key(private_key);
    generate_public_key(private_key, public_key);

    uint8_t public_key_buffer[256];
    size_t public_key_written = mp_to_buffer(public_key, public_key_buffer);

    int send_status = send(sockfd, public_key_buffer, public_key_written, 0);
    if(send_status == -1) std::cerr << "Error while public_key exchange\n";

    uint8_t peer_key_buffer[256];

    int recv_status = recv(sockfd, peer_key_buffer, 256, MSG_WAITALL);
    if(recv_status <= 0){
        std::cerr << "Error while receiving peer's public_key or Connection closed...\n";
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
    std::string command;

    while(true){
        std::cout << '>';
        std::cin >> command;

        if(command == "exit") break;

        int padding = 0;
        int command_length = command.size();
        unsigned char* command_cipher = command_encrypt(command, symmetric_key, padding);

        std::cout << "Encrypted command: " << command_cipher << '\n';

        std::string decrypted_command = command_decrypt(command_cipher, symmetric_key, command_length, padding);

        delete[] command_cipher;
    }
}

int main() {
    int sockfd = connect_to_peer(PEER_IP, PORT);
    std::string symmetric_key = perform_key_exchange(sockfd);
    command_loop(sockfd, symmetric_key);
    close(sockfd);
    return 0;
}
