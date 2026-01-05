#include "packet.h"
#include <stdexcept>
#include <cstring>
#include <vector>

static void writeUint32(std::vector<uint8_t>& buf, uint32_t value) {
    buf.push_back((value >> 24) & 0xFF);
    buf.push_back((value >> 16) & 0xFF);
    buf.push_back((value >> 8) & 0xFF);
    buf.push_back(value & 0xFF);
}

static uint32_t readUint32(const uint8_t* data) {
    return (uint32_t(data[0]) << 24) | 
           (uint32_t(data[1]) << 16) |
           (uint32_t(data[2]) << 8)  |
           (uint32_t(data[3]));
}

std::vector<uint8_t> serializePacket(const TextPacket& pkt) {
    std::vector<uint8_t> out;
    out.push_back(static_cast<uint8_t>(pkt.header.type));
    writeUint32(out, pkt.header.payloadsize);

    out.insert(out.end(), pkt.payload.begin(), pkt.payload.end());

    return out;
}

TextPacket deserializePacket(const std::vector<uint8_t>& data) {
    if (data.size() < 5) throw std::runtime_error("Packet too small");
    TextPacket pkt;

    pkt.header.type = static_cast<PacketType>(data[0]);
    pkt.header.payloadsize = readUint32(&data[1]);

    if (data.size() != 5 + pkt.header.payloadsize) {
        throw std::runtime_error("Packet size mismatch");
    }

    pkt.payload.assign(
        data.begin() + 5,
        data.end()
    );

    return pkt;
}

std::vector<uint8_t> serializeEncryptedPacket(const EncryptedPacket& pkt) {
    std::vector<uint8_t> out;

    out.insert(out.end(), pkt.nonce.begin(), pkt.nonce.end());

    uint32_t len = pkt.ciphertext.size();
    out.push_back((len >> 24) & 0xFF);
    out.push_back((len >> 16) & 0xFF);
    out.push_back((len >> 8) & 0xFF);
    out.push_back(len & 0xFF);

    out.insert(out.end(), pkt.ciphertext.begin(), pkt.ciphertext.end());
    return out;
}

EncryptedPacket deserializeEncryptedPacket(const std::vector<uint8_t>& data) {
    if (data.size() < 16)
        throw std::runtime_error("Encrypted packet too small");

    EncryptedPacket pkt;
    std::memcpy(pkt.nonce.data(), data.data(), pkt.nonce.size());

    uint32_t len =
        (uint32_t(data[12]) << 24) |
        (uint32_t(data[13]) << 16) |
        (uint32_t(data[14]) << 8)  |
        (uint32_t(data[15]));

    if (data.size() != 16 + len)
        throw std::runtime_error("Encrypted packet size mismatch");

    pkt.ciphertext.assign(
        data.begin() + 16,
        data.end()
    );

    return pkt;
}
