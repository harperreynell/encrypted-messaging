#pragma once
#include <vector>
#include <string>
#include <array>
#include <mutex>
#include <algorithm>

#include "../protocol/packet.h"
#include "../crypto/crypto.h"
#include "../transport/transport.h"

struct HistoryEntry {
    std::string username;
    std::string message;
    std::vector<uint8_t> encrypted_payload;
};

struct ClientInfo {
    int socket;
    CryptoSession session;
    std::array<unsigned char, 32> publicKey;
    std::string username;
};

struct RoomState {
    std::array<uint8_t, 32> key;
};

extern std::vector<ClientInfo> clients;
extern std::mutex clientsMutex;
extern RoomState room;
extern std::vector<HistoryEntry> history;
extern std::mutex historyMutex;

void initRoomKey();
void loadHistory();
void handleClient(int clientSocket);
void broadcastSystem(const std::string& msg, int except);