#include "PPPOE.h"

using namespace plugin::Demo_Foo;

PPPOE::PPPOE() : llanalyzer::Analyzer("PPPOE"), protocol(0) {
}

PPPOE::~PPPOE() = default;

uint32_t PPPOE::getIdentifier(Packet* packet) {
    // Extract protocol identifier
    protocol = (packet->data[6] << 8u) + packet->data[7];
    return protocol;
}

void PPPOE::analyze(Packet* packet) {
    // Just skip over the header (PPPOE Session + PPP)
    packet->cur_pos = packet->data + 8;
}
