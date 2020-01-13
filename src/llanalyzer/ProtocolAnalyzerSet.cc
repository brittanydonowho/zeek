#include "ProtocolAnalyzerSet.h"

namespace llanalyzer {

ProtocolAnalyzerSet::ProtocolAnalyzerSet(configset& configuration) {
    for (const auto& currentConfig : configuration) {
        for (const auto& currentMapping : currentConfig.second) {
            // Check if already instantiated
            if (analyzerlist.count(currentMapping.second) != 0) {
                continue;
            }

            analyzerlist.emplace(currentMapping.second, llanalyzer_mgr->InstantiateAnalyzer(currentMapping.second));
        }
    }

    int x = 0;
}

ProtocolAnalyzerSet::~ProtocolAnalyzerSet() {
    for (const auto& current : analyzerlist) {
        delete current.second;
    }
}

Analyzer* ProtocolAnalyzerSet::dispatch(identifier_t identifier) {
    return nullptr;
}

void ProtocolAnalyzerSet::reset() {
}

} // end of llanalyzer namespace
