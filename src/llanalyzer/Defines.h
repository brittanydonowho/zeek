#pragma once

#include <cstdint>
#include <map>

namespace llanalyzer {
    typedef uint32_t identifier_t;
    // Name of protocol analyzer that can extract these identifiers = map of (identifiers, analyzer to analyze the PDU)
    typedef std::map<std::string, std::map<identifier_t, std::string>> configset;
}