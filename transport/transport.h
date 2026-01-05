#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

bool sendAll(int sock, const uint8_t* data, size_t size);
bool recvAll(int sock, uint8_t* data, size_t size);
