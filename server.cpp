#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include "crypto/crypto.h"
#include "transport/transport.h"
#include "protocol/packet.h"


int main() {
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);

    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(8080);
    serverAddress.sin_addr.s_addr = INADDR_ANY;

    bind(serverSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress));

    listen(serverSocket, 5);

    std::cout << "Server listening on port 8080...\n";
    int clientSocket = accept(serverSocket, nullptr, nullptr);
    std::cout << "Client connected\n";

    CryptoSession crypto;
    KeyPair serverKeys = crypto.generateKeyPair();

    sendAll(clientSocket, serverKeys.publicKey.data(), 32);

    std::array<uint8_t, 32> clientPub;
    recvAll(clientSocket, clientPub.data(), 32);

    crypto.deriveSessionKey(serverKeys, clientPub, false);    
    while (true) {
        uint32_t netsize;
        if(!recvAll(clientSocket, (uint8_t*)&netsize, sizeof(netsize))) break;
        
        uint32_t packetsize = ntohl(netsize);
        std::vector<uint8_t> raw(packetsize);
        if(!recvAll(clientSocket, raw.data(), packetsize)) break;

        EncryptedPacket epkt = deserializeEncryptedPacket(raw);
        auto plaintext = crypto.decryptPacket(epkt);
        TextPacket pkt = deserializePacket(plaintext);
        std::string message(pkt.payload.begin(), pkt.payload.end());
        std::cout << "Received: " << message << "\n";
    }

    close(clientSocket);
    close(serverSocket);
}
