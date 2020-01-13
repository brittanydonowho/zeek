#pragma once

#include <llanalyzer/Analyzer.h>
#include <llanalyzer/Component.h>

namespace plugin::Demo_Foo {

class IP6 : public llanalyzer::Analyzer {
public:
    IP6();
    ~IP6() override;

    uint32_t getIdentifier(Packet* packet) override;
    void analyze(Packet* packet) override;

    static llanalyzer::Analyzer* Instantiate() {
        return new IP6();
    }

private:
    static constexpr std::array<uint8_t, 9> extensionHeaders = {0, 43, 44, 50, 51, 60, 135, 139, 140};

    const struct ip6_hdr* ip6_header;
    const uint8_t* savedCurPos;
    Packet* currentPacket;
};

} // end of namespace plugin::Demo_Foo
