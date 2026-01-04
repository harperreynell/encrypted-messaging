#include "crypto/crypto.h"
#include <iostream>

void printvector(std::vector<uint8_t> msg) {
    for(int i = 0; i < msg.size(); i++) {
        std::cout << msg[i];
    }

    std::cout << std::endl;
}

int main() {
    CryptoSession user1, user2;

    auto user1keys = user1.generateKeyPair();
    auto user2keys = user2.generateKeyPair();

    user1.deriveSessionKey(user1keys, user2keys.publicKey, true);
    user2.deriveSessionKey(user2keys, user1keys.publicKey, false);

    std::string messagetext = "Hello WoRLd!";
    std::vector<uint8_t> msg(messagetext.begin(), messagetext.end());

    auto enc = user1.encrypt(msg);
    std::cout << enc.data() << '\n';

    auto dec = user2.decrypt(enc);
    std::cout << dec.data() << '\n';
}