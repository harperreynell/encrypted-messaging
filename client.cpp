#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <array>
#include <thread>

#include "protocol/packet.h"
#include "crypto/crypto.h"
#include "transport/transport.h"
#include "iparser/iparser.h"

#define CLR_RESET   "\033[0m"
#define CLR_USER    "\033[1;36m"
#define CLR_MSG     "\033[0;37m"
#define CLR_SYS     "\033[1;33m"


void recvLoop(int sock, CryptoSession* crypto) {
    while (true) {
        uint32_t netsize;
        if (!recvAll(sock, (uint8_t*)&netsize, 4)) break;

        uint32_t size = ntohl(netsize);
        std::vector<uint8_t> raw(size);
        if(!recvAll(sock, raw.data(), size)) break;
        
        EncryptedPacket epkt = deserializeEncryptedPacket(raw);
        auto plaintext = crypto->decryptPacket(epkt);
        TextPacket tpkt = deserializePacket(plaintext);

        if (tpkt.header.type == PacketType::control) {
            std::string msg(tpkt.payload.begin(), tpkt.payload.end());
            if (msg == "SERVER_SHUTDOWN") {
                std::cout << "\nServer disconnected\n";
                exit(0);
            }
            continue;
        }

        if (tpkt.header.type != PacketType::text)
            continue;

        if (tpkt.payload.size() < 1)
            continue;

        uint8_t namelen = tpkt.payload[0];
        if (tpkt.payload.size() < 1 + namelen) continue;

        std::string username(tpkt.payload.begin() + 1, tpkt.payload.begin() + 1 + namelen);

        std::string msg(tpkt.payload.begin() + 1 + namelen, tpkt.payload.end());
    


        std::time_t now = std::time(nullptr);
        std::tm tm = *std::localtime(&now);

        char buf[32];
        std::strftime(buf, sizeof(buf), "%d/%m/%Y:%H:%M", &tm);

        bool system = (username == "*");

        std::cout << "\r[" << buf << " | ";

        if (system)
            std::cout << CLR_SYS << username << CLR_RESET;
        else
            std::cout << CLR_USER << username << CLR_RESET;

        std::cout << "] ";

        if (system)
            std::cout << CLR_SYS << msg << CLR_RESET;
        else
            std::cout << CLR_MSG << msg << CLR_RESET;

        std::cout << "\n> " << std::flush;
    }
}

int main(int argc, char** argv) { 
    int clientSocket = socket(AF_INET, SOCK_STREAM, 0);

    InputParser input(argc, argv);

    sockaddr_in serverAddress;
    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = htons(8082);
    serverAddress.sin_addr.s_addr = INADDR_ANY;

    connect(clientSocket, (struct sockaddr*)&serverAddress, sizeof(serverAddress));
    std::cout << "Connected to the server\n> ";

    CryptoSession crypto;
    KeyPair clientKeys = crypto.generateKeyPair();

    std::array<uint8_t, 32> serverpub;
    recvAll(clientSocket, serverpub.data(), 32);
    sendAll(clientSocket, clientKeys.publicKey.data(), 32);
    crypto.deriveSessionKey(clientKeys, serverpub, true);

    if (!input.cmdOptionExists("-u")) {
        throw std::runtime_error("No username provided");
    }

    std::string username = input.getCmdOption("-u");
    TextPacket pkt_u;
    pkt_u.header.type = PacketType::handshake;
    pkt_u.payload.assign(username.begin(), username.end());
    pkt_u.header.payloadsize = pkt_u.payload.size();

    auto bytes_u = serializePacket(pkt_u);
    EncryptedPacket epkt_u = crypto.encryptPacket(bytes_u);
    auto raw_u = serializeEncryptedPacket(epkt_u);

    uint32_t size = htonl(raw_u.size());
    sendAll(clientSocket, (uint8_t*)&size, 4);
    sendAll(clientSocket, raw_u.data(), raw_u.size());

    uint32_t netsize;
    recvAll(clientSocket, (uint8_t*)&netsize, 4);
    uint32_t c_size = ntohl(netsize);

    std::vector<uint8_t> raw(c_size);
    recvAll(clientSocket, raw.data(), c_size);

    EncryptedPacket epkt= deserializeEncryptedPacket(raw);
    auto plain = crypto.decryptPacket(epkt);
    TextPacket tpkt = deserializePacket(plain);

    if (tpkt.header.type != PacketType::control) {
        std::cerr << "Protocol error\n";
        return -1;
    }

    std::string ans(tpkt.payload.begin(), tpkt.payload.end());
    if (ans != "OK") {
        std::cerr << "Username exists: " << ans << "\n";
        return -1;
    }

    std::thread(recvLoop, clientSocket, &crypto).detach();

    while (true) {
        std::string text;
        std::getline(std::cin, text);
        if (text == "exit") break;
        std::cout << "> ";
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

    shutdown(clientSocket, SHUT_RDWR); 
    close(clientSocket);
}