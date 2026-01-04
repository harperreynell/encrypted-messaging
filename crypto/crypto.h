#pragma once

#include <array>
#include <vector>
#include <cstdint>

struct KeyPair {
    std::array<unsigned char, 32> publicKey;
    std::array<unsigned char, 32> privateKey;
};

class CryptoSession {
public:
    CryptoSession();

    static KeyPair generateKeyPair();
    
    void deriveSessionKey(
        const KeyPair& local,
        const std::array<unsigned char, 32>& remotePublicKey,
        bool isClient
    );

    std::vector<unsigned char> encrypt(const std::vector<unsigned char>& data);
    std::vector<unsigned char> decrypt(const std::vector<unsigned char>& data);

private:
    std::array<unsigned char, 32> txKey;
    std::array<unsigned char, 32> rxKey; 

    uint64_t txNonceCounter;
    uint64_t rxNonceCounter;

    void makeNonce(uint64_t counter, uint8_t nonce[12]);
};