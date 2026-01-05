#include <cstdint>
#include <iostream>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
// #include <sys/socket.h>
// #include <unistd.h>

bool sendAll(int sock, const uint8_t* data, size_t size) {
    size_t sent = 0;
    while (sent < size) {
        ssize_t n = send(sock, data + sent, size - sent, 0);
        if (n <= 0) return false;
        sent += n;
    }
    return true;
}

bool recvAll(int sock, uint8_t* data, size_t size) {
    size_t received = 0;
    while (received < size) {
        ssize_t n = recv(sock, data + received, size - received, 0);
        if (n <= 0) return false;
        received += n;
    }
    return true;
}