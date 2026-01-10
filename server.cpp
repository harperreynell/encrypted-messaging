#include <iostream>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <thread>
#include <signal.h>
#include <atomic>
#include <sodium.h>

#include "session/session.h"

#define PORT 8080
std::atomic<bool> running(true);
int serverSocketGlobal = -1;

void signalHandler(int) {
    running = false;
    if(serverSocketGlobal != -1) {
        shutdown(serverSocketGlobal, SHUT_RDWR);
        close(serverSocketGlobal);
    }
}

int main() {
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);

    if(sodium_init() < 0) {
        std::cerr << "libsodium init failed\n";
        return 1;
    }

    history.clear();
    loadHistory();
    initRoomKey();

    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    serverSocketGlobal = serverSocket;

    sockaddr_in serverAddress{};
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(PORT);
    serverAddress.sin_addr.s_addr = INADDR_ANY;

    bind(serverSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress));
    listen(serverSocket, 10);

    std::cout << "Server listening on port " << PORT << "...\n";

    while(running) {
        sockaddr_in clientAddr;
        socklen_t len = sizeof(clientAddr);
        int clientSocket = accept(serverSocket, (sockaddr*)&clientAddr, &len);
        if(clientSocket < 0) {
            if(!running) break;
            continue;
        }

        std::thread(handleClient, clientSocket).detach();
    }

    std::vector<ClientInfo> snapshot;
    {
        std::lock_guard<std::mutex> lock(clientsMutex);
        snapshot = clients;
        clients.clear();
    }

    TextPacket out;
    out.header.type = PacketType::control;
    std::string msg = "SERVER_SHUTDOWN";
    out.payload.assign(msg.begin(), msg.end());
    out.header.payloadsize = out.payload.size();

    for(auto& c : snapshot) {
        auto bytes = serializePacket(out);
        auto enc = c.session.encryptPacket(bytes);
        auto raw = serializeEncryptedPacket(enc);

        uint32_t size = htonl(raw.size());
        sendAll(c.socket, (uint8_t*)&size, 4);
        sendAll(c.socket, raw.data(), raw.size());

        shutdown(c.socket, SHUT_RDWR);
        close(c.socket);
    }

    close(serverSocket);
    std::cout << "Server shutdown succeeded\n";
}
