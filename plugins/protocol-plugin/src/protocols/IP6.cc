#include "IP6.h"

using namespace plugin::Demo_Foo;

IP6::IP6() : llanalyzer::Analyzer("IP6"), ip6_header(nullptr), savedCurPos(nullptr), currentPacket(nullptr) {
}

IP6::~IP6() = default;

uint32_t IP6::getIdentifier(Packet* packet) {
    currentPacket = packet;
    const uint8_t* cur_pos = packet->cur_pos;
    ip6_header = reinterpret_cast<const struct ip6_hdr*>(cur_pos);
    cur_pos += 40; // IPv6 header is 40 bytes long

    // Find the first identifier that is not an extension header
    // Check if the first following protocol is an extension header
    if (isExtensionHeader(ip6_header->ip6_nxt)) {
        // Goto next extension header until either NoNxt (59) or a non-extension-header
        const struct ip6_ext* ext_header = nullptr;
        do {
            ext_header = reinterpret_cast<const struct ip6_ext*>(cur_pos);

            if (ext_header->ip6e_nxt == IPPROTO_NONE) {
                // No next header --> notify that there are no more identifiers to extract
                return -1;
            }

            // Set pointer to next extension header start
            cur_pos += ((ext_header->ip6e_len + 1) * 8); // len field is a multiple of 8 byte starting at 0, 0 = 8 bytes, 1 = 16 bytes ...
        } while(isExtensionHeader(ext_header->ip6e_nxt));

        // Save cur_pos (currently pointing to the start of the encaspulated PDU for analyze
        savedCurPos = cur_pos;

        // Found a "real" next header identifier
        return ext_header->ip6e_nxt;
    } else {
        return ip6_header->ip6_nxt;
    }
}

void IP6::analyze(Packet* packet) {
    if (currentPacket != packet) {
        getIdentifier(packet);
    }

    // "Analyzing" already done in getIdentifier(), aka skipping right to the following protocol
    packet->cur_pos = savedCurPos;

    ip6_header = nullptr;
    savedCurPos = nullptr;
    currentPacket = nullptr;
}
