#pragma once

#include "AnalyzerSet.h"

namespace llanalyzer {

class ProtocolAnalyzerSet : public AnalyzerSet {
public:
    explicit ProtocolAnalyzerSet(configset& configuration);
    ~ProtocolAnalyzerSet() override;

    Analyzer *dispatch(identifier_t identifier) override;
    void reset() override;

private:
    std::map<std::string, Analyzer*> analyzerlist;
};

}

