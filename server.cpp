#include <iostream>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <thread>

#include "session/session.h"

int main() {
    int serverSocket = socket(AF_INET, SOCK_STREAM, 0);

    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(8080);
    serverAddress.sin_addr.s_addr = INADDR_ANY;

    bind(serverSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress));
    listen(serverSocket, 10);

    std::cout << "Server listening on port 8080...\n";

    while(true) {
        int clientSocket = accept(serverSocket, nullptr, nullptr);
        std::cout << "Client connected\n";
        std::thread(handleClient, clientSocket).detach();
    }
}
