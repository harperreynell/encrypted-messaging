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

    while (true) {
        uint32_t netsize;
        if(!recvAll(clientSocket, (uint8_t*)&netsize, sizeof(netsize))) break;
        
        uint32_t packetsize = ntohl(netsize);
        std::vector<uint8_t> raw(packetsize);
        if(!recvAll(clientSocket, raw.data(), packetsize)) break;

        EncryptedPacket epkt = deserializeEncryptedPacket(raw);
        auto plaintext = client.session.decryptPacket(epkt);
        TextPacket pkt = deserializePacket(plaintext);

        if(pkt.header.type == PacketType::handshake) {
            std::string requested(pkt.payload.begin(), pkt.payload.end());

            {
                std::lock_guard<std::mutex> lock(clientsMutex);
                for(const auto& c : clients) {
                    if (c.username == requested) {
                        TextPacket out;
                        out.header.type = PacketType::control;
                        std::string msg = "USERNAME_TAKEN";
                        out.payload.assign(msg.begin(), msg.end());
                        out.header.payloadsize = out.payload.size();

                        auto bytes = serializePacket(out);
                        EncryptedPacket epkt = client.session.encryptPacket(bytes);
                        auto rawpkt = serializeEncryptedPacket(epkt);
                        
                        uint32_t size = htonl(rawpkt.size());
                        sendAll(clientSocket, (uint8_t*)&size, 4);
                        sendAll(clientSocket, rawpkt.data(), rawpkt.size());

                        close(clientSocket);
                        return;
                    }
                }

                client.username = requested;
                clients.push_back(client);
            }

            std::time_t now = std::time(nullptr);
            std::tm tm = *std::localtime(&now);

            char buf[32];
            std::strftime(buf, sizeof(buf), "%d/%m/%Y:%H:%M", &tm);

            std::cout << "\r" << "[" << buf << " | " << "* " << "] " << "User " + client.username + " connected\n";

            TextPacket ok;
            ok.header.type = PacketType::control;
            std::string msg = "OK";
            ok.payload.assign(msg.begin(), msg.end());
            ok.header.payloadsize = ok.payload.size();

            auto bytes = serializePacket(ok);
            EncryptedPacket eok = client.session.encryptPacket(bytes);
            auto raw = serializeEncryptedPacket(eok);

            uint32_t size = htonl(raw.size());
            sendAll(clientSocket, (uint8_t*)&size, 4);
            sendAll(clientSocket, raw.data(), raw.size());

            continue;
        }

        if (pkt.header.type == PacketType::text) {
            std::string message(pkt.payload.begin(), pkt.payload.end());
            std::cout << "Received: " << message << "\n" << std::flush;
        }

        std::vector<ClientInfo> snapshot;
        {
            std::lock_guard<std::mutex> lock(clientsMutex);
            snapshot = clients;
        }
        for (auto& other : snapshot) {
            if (other.socket == client.socket) continue;

            std::vector<uint8_t> payload;
            payload.push_back(client.username.size());
            payload.insert(payload.end(), client.username.begin(), client.username.end());
            payload.insert(payload.end(), pkt.payload.begin(), pkt.payload.end());

            TextPacket out;
            out.header.type = PacketType::text;
            out.header.payloadsize = payload.size();
            out.payload = payload;

            auto bytes = serializePacket(out);
            EncryptedPacket out_r = other.session.encryptPacket(bytes);
            auto rawOut = serializeEncryptedPacket(out_r);

            uint32_t size = htonl(rawOut.size());
            if (!sendAll(other.socket, (uint8_t*)&size, 4) ||
                !sendAll(other.socket, rawOut.data(), rawOut.size())) {
            }
        }
    }

    close(clientSocket);
    broadcastSystem("User " + client.username + " disconnected", clientSocket);

    {
        std::lock_guard<std::mutex> lock(clientsMutex);
        clients.erase(
            std::remove_if(clients.begin(), clients.end(), [&](const ClientInfo& c) {return c.socket == clientSocket; }),
            clients.end()
        );
    }

    std::time_t now = std::time(nullptr);
    std::tm tm = *std::localtime(&now);

    char buf[32];
    std::strftime(buf, sizeof(buf), "%d/%m/%Y:%H:%M", &tm);
    std::cout << "\r" << "[" << buf << " | " << "* " << "] " << "User " + client.username + " disconected\n";
}

void broadcastSystem(const std::string& msg, int except = -1) {
    std::vector<ClientInfo> snapshot;
    {
        std::lock_guard<std::mutex> lock(clientsMutex);
        snapshot = clients;
    }

    for (auto& c : snapshot) {
        if (c.socket == except) continue;

        std::vector<uint8_t> payload;
        payload.push_back(1);
        payload.push_back('*');
        payload.insert(payload.end(), msg.begin(), msg.end());

        TextPacket out;
        out.header.type = PacketType::text;
        out.payload = payload;
        out.header.payloadsize = out.payload.size();

        auto bytes = serializePacket(out);
        EncryptedPacket pkt = c.session.encryptPacket(bytes);
        auto raw = serializeEncryptedPacket(pkt);

        uint32_t size = ntohl(raw.size());
        sendAll(c.socket, (uint8_t*)&size, 4);
        sendAll(c.socket, raw.data(), raw.size());
    }
}