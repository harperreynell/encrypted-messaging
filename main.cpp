#include "crypto/crypto.h"
#include "protocol/packet.h"
#include <iostream>

int main() {
    CryptoSession user1, user2;

    auto user1keys = user1.generateKeyPair();
    auto user2keys = user2.generateKeyPair();

    user1.deriveSessionKey(user1keys, user2keys.publicKey, true);
    user2.deriveSessionKey(user2keys, user1keys.publicKey, false);

    std::vector<std::string> messages = {"Hello world!", "Hello, what is your name?", "My name is Heinz Doofenschmirtz:)"};

    for(int i = 0; i < messages.size(); i++) {
        std::string messagetext = messages[i];
        std::cout << "Message before encryption: " << messagetext << "\n";

        TextPacket tpkt;
        tpkt.header.type = PacketType::text;
        tpkt.payload.assign(messagetext.begin(), messagetext.end());
        tpkt.header.payloadsize = tpkt.payload.size();
        auto bytes = serializePacket(tpkt);

        EncryptedPacket pkt = user1.encryptPacket(bytes);
        std::cout << "Message efter encryption: " << pkt.ciphertext.data() << "; Nonce: " << pkt.nonce.data() << '\n';

        auto decbytes = user2.decryptPacket(pkt);
        TextPacket dpkt = deserializePacket(decbytes);
        std::string message(dpkt.payload.begin(), dpkt.payload.end());
        std::cout << "Message after decryption: " << message << "\n\n\n";
    }
}