#pragma once

#include <vector>
#include "../crypto/crypto.h"
#include <mutex>
#include "../transport/transport.h"

struct ClientInfo {
    int socket;
    CryptoSession session;
    std::array<unsigned char, 32> publicKey;
};

extern std::vector<ClientInfo> clients;
extern std::mutex clientsMutex;

void handleClient(int clientSocket);