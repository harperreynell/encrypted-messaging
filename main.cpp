#include "crypto/crypto.h"
#include <iostream>

std::vector<uint8_t> str_to_uint8t(std::string messagetext) {
    std::vector<uint8_t> msg(messagetext.begin(), messagetext.end());
    return msg;
}

int main() {
    CryptoSession user1, user2;

    auto user1keys = user1.generateKeyPair();
    auto user2keys = user2.generateKeyPair();

    user1.deriveSessionKey(user1keys, user2keys.publicKey, true);
    user2.deriveSessionKey(user2keys, user1keys.publicKey, false);

    std::vector<std::string> messages = {"Hello world!", "Hello, what is your name", "My name is Heinz Doofenschmirtz:)"};

    for(int i = 0; i < messages.size(); i++) {
        std::string messagetext = messages[i];
        std::cout << "Message before encryption: " << messagetext << "\n";

        std::vector<uint8_t> msg(messagetext.begin(), messagetext.end());

        EncryptedPacket pkt = user1.encryptPacket(msg);
        std::cout << "Message efter encryption: " << pkt.ciphertext.data() << "; Nonce: " << pkt.counter << '\n';

        auto dec = user2.decryptPacket(pkt);
        std::cout << "Message after decryption: " << dec.data() << "\n\n\n";
    }
}