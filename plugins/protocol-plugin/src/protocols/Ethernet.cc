#include "Ethernet.h"

using namespace plugin::Demo_Foo;

Ethernet::Ethernet() : llanalyzer::Analyzer("Ethernet"), protocol(0), currentPacket(nullptr) {
}

Ethernet::~Ethernet() = default;

uint32_t Ethernet::getIdentifier(Packet* packet) {
    currentPacket = packet;

    // Extract protocol identifier
    protocol = (packet->data[12] << 8u) + packet->data[13];
    return protocol;
}

void Ethernet::analyze(Packet* packet) {
    if (currentPacket != packet) {
        getIdentifier(packet);
    }

    packet->eth_type = protocol;
    packet->l2_dst = packet->data;
    packet->l2_src = packet->data + 6;

    packet->cur_pos = packet->data + 14;

    protocol = 0;
    currentPacket = nullptr;
}
