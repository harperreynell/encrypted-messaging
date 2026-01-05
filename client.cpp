#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <array>
#include "protocol/packet.h"
#include "crypto/crypto.h"
#include "transport/transport.h"

int main() {
    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);

    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(8080);
    serverAddress.sin_addr.s_addr = INADDR_ANY;

    connect(clientSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress));
    std::cout << "Connected to the server\n";

    CryptoSession crypto;
    KeyPair clientKeys = crypto.generateKeyPair();

    std::array<uint8_t, 32> serverpub;
    recvAll(clientSocket, serverpub.data(), 32);
    sendAll(clientSocket, clientKeys.publicKey.data(), 32);
    crypto.deriveSessionKey(clientKeys, serverpub, true);

    while (true) {
        std::string text;
        std::getline(std::cin, text);
        if (text == "exit") break;

        TextPacket pkt;
        pkt.header.type = PacketType::text;
        pkt.payload.assign(text.begin(), text.end());
        pkt.header.payloadsize = pkt.payload.size();

        auto bytes = serializePacket(pkt);
        EncryptedPacket enc = crypto.encryptPacket(bytes);
        auto raw = serializeEncryptedPacket(enc);

        uint32_t size = htonl(raw.size());
        sendAll(clientSocket, (uint8_t*)&size, 4);
        sendAll(clientSocket, raw.data(), raw.size());
    }

    close(clientSocket);
}