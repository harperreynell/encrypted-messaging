#pragma once

#include <vector>
#include <cstdint>

struct EncryptedPacket {
    uint64_t counter;
    std::vector<uint8_t> ciphertext;
};