#include "session.h"

#include <mutex>
#include <algorithm>

std::vector<ClientInfo> clients;
std::mutex clientsMutex;

void handleClient(int clientSocket) {
    ClientInfo client;
    client.socket = clientSocket;

    KeyPair serverKeys = client.session.generateKeyPair();
    sendAll(clientSocket, serverKeys.publicKey.data(), 32);

    recvAll(clientSocket, client.publicKey.data(), 32);
    client.session.deriveSessionKey(serverKeys, client.publicKey, false);   

    {
        std::lock_guard<std::mutex> lock(clientsMutex);
        clients.push_back(client);
    }

    while (true) {
        uint32_t netsize;
        if(!recvAll(clientSocket, (uint8_t*)&netsize, sizeof(netsize))) break;
        
        uint32_t packetsize = ntohl(netsize);
        std::vector<uint8_t> raw(packetsize);
        if(!recvAll(clientSocket, raw.data(), packetsize)) break;

        EncryptedPacket epkt = deserializeEncryptedPacket(raw);
        auto plaintext = client.session.decryptPacket(epkt);
        TextPacket pkt = deserializePacket(plaintext);

        std::string message(pkt.payload.begin(), pkt.payload.end());
        std::cout << "Received: " << message << "\n";

        std::vector<ClientInfo> snapshot;
        {
            std::lock_guard<std::mutex> lock(clientsMutex);
            snapshot = clients;
        }
        for (auto& other : snapshot) {
            if (other.socket == client.socket) continue;

            EncryptedPacket out = other.session.encryptPacket(plaintext);
            auto rawOut = serializeEncryptedPacket(out);

            uint32_t size = htonl(rawOut.size());
            if (!sendAll(other.socket, (uint8_t*)&size, 4) ||
                !sendAll(other.socket, rawOut.data(), rawOut.size())) {
            }
        }
    }

    close(clientSocket);

    {
        std::lock_guard<std::mutex> lock(clientsMutex);
        clients.erase(
            std::remove_if(clients.begin(), clients.end(), [&](const ClientInfo& c) {return c.socket == clientSocket; }),
            clients.end()
        );
    }

    std::cout << "Client disconnected\n";
}