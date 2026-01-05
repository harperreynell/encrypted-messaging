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
    CryptoSession crypto;

    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(8080);
    serverAddress.sin_addr.s_addr = INADDR_ANY;

    connect(clientSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress));
    std::cout << "Connected to the server\n";
    KeyPair clientKeys = crypto.generateKeyPair();


    std::array<uint8_t, 32> serverPub;
    recvAll(clientSocket, serverPub.data(), 32);

    sendAll(clientSocket, clientKeys.publicKey.data(), 32);

    crypto.deriveSessionKey(clientKeys, serverPub, true);

    while(true) {
        std::string messagetext;
        std::getline(std::cin, messagetext);
        if(messagetext == "stop") {
            break;
        }
        std::cout << "Sending message: " << messagetext << '\n';

        TextPacket tpkt;
        tpkt.header.type = PacketType::text;
        tpkt.payload.assign(messagetext.begin(), messagetext.end());
        tpkt.header.payloadsize = tpkt.payload.size();

        auto bytes = serializePacket(tpkt);
        EncryptedPacket pkt = crypto.encryptPacket(bytes);

        auto raw = serializeEncryptedPacket(pkt);
        uint32_t totalsize = raw.size();
        uint32_t netsize = htonl(totalsize);

        sendAll(clientSocket, (uint8_t*)&netsize, sizeof(netsize));
        sendAll(clientSocket, raw.data(), raw.size());
    }

    close(clientSocket);
}