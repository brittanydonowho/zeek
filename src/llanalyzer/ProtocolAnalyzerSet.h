#pragma once

#include "Config.h"
#include "AnalyzerSet.h"
#include "dispatchers/Dispatcher.h"
#include "dispatchers/VectorDispatcher.h"

namespace llanalyzer {

class ProtocolAnalyzerSet : public AnalyzerSet {
public:
    explicit ProtocolAnalyzerSet(Config& configuration);
    ~ProtocolAnalyzerSet() override;

    const Analyzer* dispatch(identifier_t identifier) const override;
    void reset() override;

private:
    using dispatcher_impl = VectorDispatcher;

    std::map<std::string, Analyzer*> analyzers;
    std::map<std::string, Dispatcher*> dispatchers;
    const Dispatcher* head;

    const Dispatcher* getDispatcher(Config& configuration, const std::string& dispatcherName);
};

}

