#pragma once

#include <vector>
#include <cstdint>

struct EncryptedPacket {
    std::array<uint8_t, 12> nonce;
    std::vector<uint8_t> ciphertext;
};

enum class PacketType : uint8_t {
    handshake = 1,
    text     = 2,
    control   = 3
};

struct PacketHeader {
    PacketType type;
    uint32_t payloadsize;
};

struct TextPacket {
    PacketHeader header;
    std::vector<uint8_t> payload;
};

std::vector<uint8_t> serializePacket(const TextPacket& pkt);
TextPacket deserializePacket(const std::vector<uint8_t>& data);
std::vector<uint8_t> serializeEncryptedPacket(const EncryptedPacket& pkt);
EncryptedPacket deserializeEncryptedPacket(const std::vector<uint8_t>& data);