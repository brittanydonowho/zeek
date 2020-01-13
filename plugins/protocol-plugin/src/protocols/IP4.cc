#include "IP4.h"

using namespace plugin::Demo_Foo;

IP4::IP4() : llanalyzer::Analyzer("IP4"), ip_hdr(nullptr), currentPacket(nullptr) {
}

IP4::~IP4() = default;

uint32_t IP4::getIdentifier(Packet* packet) {
    currentPacket = packet;

    ip_hdr = reinterpret_cast<const struct ip*>(packet->cur_pos);
    return ip_hdr->ip_p;
}

void IP4::analyze(Packet* packet) {
    if (currentPacket != packet) {
        getIdentifier(packet);
    }

    packet->cur_pos += ip_hdr->ip_hl;

    ip_hdr = nullptr;
    currentPacket = nullptr;
}
