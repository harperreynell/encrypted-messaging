#include "session.h"

#include <mutex>
#include <algorithm>
#include <sodium.h>
#include <fstream>

std::vector<ClientInfo> clients;
std::mutex clientsMutex;
RoomState room;
std::vector<HistoryEntry> history;
std::mutex historyMutex;

void initRoomKey() {
    randombytes_buf(room.key.data(), room.key.size());
}

void saveHistory(const HistoryEntry& e) {
    std::ofstream f("history.dat", std::ios::binary | std::ios::app);
    if(!f) return;

    uint32_t sz = e.encrypted_payload.size();
    f.write(reinterpret_cast<const char*>(&sz), sizeof(sz));
    f.write(reinterpret_cast<const char*>(e.encrypted_payload.data()), sz);
}

void loadHistory() {
    std::ifstream f("history.dat", std::ios::binary);
    if(!f) return;

    while(f) {
        uint32_t sz = 0;
        f.read(reinterpret_cast<char*>(&sz), sizeof(sz));
        if(!f || sz == 0) break;

        std::vector<uint8_t> payload(sz);
        f.read(reinterpret_cast<char*>(payload.data()), sz);
        if(!f) break;

        HistoryEntry e;
        e.encrypted_payload = std::move(payload);
        history.push_back(std::move(e));
    }
}

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

            TextPacket rk;
            rk.header.type = PacketType::room_key;
            rk.payload.assign(room.key.begin(), room.key.end());
            rk.header.payloadsize = rk.payload.size();

            auto bytes_rk = serializePacket(rk);
            auto enc_rk = client.session.encryptPacket(bytes_rk);
            auto raw_rk = serializeEncryptedPacket(enc_rk);

            uint32_t size_rk = htonl(raw_rk.size());
            sendAll(clientSocket, (uint8_t*)&size_rk, 4);
            sendAll(clientSocket, raw_rk.data(), raw_rk.size());

            {
                std::lock_guard<std::mutex> lock(historyMutex);
                for(auto& e : history) {
                    TextPacket out;
                    out.header.type = PacketType::history_chunk;
                    out.payload = e.encrypted_payload;
                    out.header.payloadsize = out.payload.size();

                    auto bytes = serializePacket(out);
                    auto enc = client.session.encryptPacket(bytes);
                    auto raw = serializeEncryptedPacket(enc);

                    uint32_t sz = htonl(raw.size());
                    sendAll(clientSocket, (uint8_t*)&sz, 4);
                    sendAll(clientSocket, raw.data(), raw.size());
                }
            }

            broadcastSystem("User " + client.username + " connected", client.socket);
            continue;
        }

        if(pkt.header.type == PacketType::text) {
            std::vector<uint8_t> payload;
            payload.push_back(client.username.size());
            payload.insert(payload.end(), client.username.begin(), client.username.end());

            std::vector<uint8_t> encryptedMsg(pkt.payload.size());
            for(size_t i = 0; i < pkt.payload.size(); i++)
                encryptedMsg[i] = pkt.payload[i] ^ room.key[i % room.key.size()];

            payload.insert(payload.end(), encryptedMsg.begin(), encryptedMsg.end());

            HistoryEntry e;
            e.encrypted_payload = payload;

            {
                std::lock_guard<std::mutex> lock(historyMutex);
                history.push_back(std::move(e));
            }

            saveHistory(history.back());
        }

        std::vector<ClientInfo> snapshot;
        {
            std::lock_guard<std::mutex> lock(clientsMutex);
            snapshot = clients;
        }
        for (auto& other : snapshot) {
            if (other.socket == client.socket) continue;

            std::vector<uint8_t> encryptedMsg(pkt.payload.size());
            for (size_t i = 0; i < pkt.payload.size(); i++)
                encryptedMsg[i] = pkt.payload[i] ^ room.key[i % room.key.size()];

            std::vector<uint8_t> payload;
            payload.push_back(client.username.size());
            payload.insert(payload.end(), client.username.begin(), client.username.end());
            payload.insert(payload.end(), encryptedMsg.begin(), encryptedMsg.end());

            TextPacket out;
            out.header.type = PacketType::text;
            out.header.payloadsize = payload.size();
            out.payload = payload;

            auto bytes = serializePacket(out);
            EncryptedPacket out_r = other.session.encryptPacket(bytes);
            auto rawOut = serializeEncryptedPacket(out_r);

            uint32_t size = htonl(rawOut.size());
            sendAll(other.socket, (uint8_t*)&size, 4);
            sendAll(other.socket, rawOut.data(), rawOut.size());
        }
    }

    broadcastSystem("User " + client.username + " disconnected", clientSocket);
    close(clientSocket);

    {
        std::lock_guard<std::mutex> lock(clientsMutex);
        clients.erase(
            std::remove_if(clients.begin(), clients.end(), [&](const ClientInfo& c) { return c.socket == clientSocket; }),
            clients.end()
        );
    }

    std::time_t now = std::time(nullptr);
    std::tm tm = *std::localtime(&now);

    char buf[32];
    std::strftime(buf, sizeof(buf), "%d/%m/%Y:%H:%M", &tm);
    std::cout << "\r" << "[" << buf << " | * ] User " + client.username + " disconnected\n";
}

void broadcastSystem(const std::string& msg, int except) {
    std::vector<ClientInfo> snapshot;
    {
        std::lock_guard<std::mutex> lock(clientsMutex);
        snapshot = clients;
    }

    for(auto& c : snapshot) {
        if(c.socket == except) continue;

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

        uint32_t size = htonl(raw.size());
        sendAll(c.socket, (uint8_t*)&size, 4);
        sendAll(c.socket, raw.data(), raw.size());
    }
}
