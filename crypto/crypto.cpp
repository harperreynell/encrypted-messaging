#include "crypto.h"
#include <sodium.h>
#include <cstring>
#include <stdexcept>

CryptoSession::CryptoSession() 
    : txNonceCounter(0), 
    rxNonceCounter(0) {
    if(sodium_init() < 0) {
        throw std::runtime_error("Libsodium init failed");
    }
}

KeyPair CryptoSession::generateKeyPair() {
    KeyPair kp;
    crypto_kx_keypair(
        kp.publicKey.data(),
        kp.privateKey.data()
    );

    return kp;
}

void CryptoSession::deriveSessionKey(const KeyPair& local, const std::array<uint8_t, 32> &remotePublicKey, bool isClient) {
    if(isClient) {
        if(crypto_kx_client_session_keys(
            rxKey.data(),
            txKey.data(),
            local.publicKey.data(),
            local.privateKey.data(),
            remotePublicKey.data()
        ) != 0) {
            throw std::runtime_error("Key exchange failed (client)");
        }
    } else {
        if(crypto_kx_server_session_keys(
            rxKey.data(),
            txKey.data(),
            local.publicKey.data(),
            local.privateKey.data(),
            remotePublicKey.data()
        ) != 0) {
            throw std::runtime_error("Key exchange failed (server)");
        }
    }
}

void CryptoSession::makeNonce(uint64_t counter, uint8_t nonce[12]) {
    std::memset(nonce, 0, 12);
    std::memcpy(nonce + 4, &counter, sizeof(counter));
}

EncryptedPacket CryptoSession::encryptPacket(const std::vector<uint8_t>& plaintext) {
    EncryptedPacket pkt;
    pkt.counter = txNonceCounter++;
    uint8_t nonce[12];
    makeNonce(pkt.counter, nonce);

    pkt.ciphertext.resize(plaintext.size() + crypto_aead_chacha20poly1305_ietf_ABYTES);

    unsigned long long ciphertextlen;
    crypto_aead_chacha20poly1305_ietf_encrypt(
        pkt.ciphertext.data(),
        &ciphertextlen,
        plaintext.data(),
        plaintext.size(),
        nullptr,
        0,
        nullptr,
        nonce,
        txKey.data()
    );

    pkt.ciphertext.resize(ciphertextlen);
    return pkt;
}

std::vector<uint8_t> CryptoSession::decryptPacket(const EncryptedPacket& pkt) {
    if(pkt.counter < rxNonceCounter) {
        throw std::runtime_error("Replay detected");
    }

    rxNonceCounter = pkt.counter + 1;

    uint8_t nonce[12];
    makeNonce(pkt.counter, nonce);
    
    std::vector<uint8_t> plaintext(pkt.ciphertext.size());
    unsigned long long plaintextlen;

    if(crypto_aead_chacha20poly1305_ietf_decrypt(
        plaintext.data(),
        &plaintextlen,
        nullptr,
        pkt.ciphertext.data(),
        pkt.ciphertext.size(),
        nullptr,
        0,
        nonce,
        rxKey.data()
    ) != 0) {
        throw std::runtime_error("Decryption failed");
    }

    plaintext.resize(plaintextlen);
    return plaintext;
}