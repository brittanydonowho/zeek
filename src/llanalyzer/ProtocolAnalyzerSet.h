#pragma once

#include "Config.h"
#include "AnalyzerSet.h"
#include "dispatchers/Dispatcher.h"
#include "dispatchers/VectorDispatcher.h"
#include "dispatchers/UnorderedMapDispatcher.h"

namespace llanalyzer {

class ProtocolAnalyzerSet : public AnalyzerSet {
public:
    explicit ProtocolAnalyzerSet(Config& configuration);
    ~ProtocolAnalyzerSet() override;

    Analyzer* dispatch(identifier_t identifier) override;
    void reset() override;

protected:
    void DumpDebug() const override;

private:
//    using dispatcher_impl = UnorderedMapDispatcher;
    using dispatcher_impl = VectorDispatcher;

    std::map<std::string, Analyzer*> analyzers;
    std::map<std::string, Dispatcher*> dispatchers;
    Dispatcher* head;
    Dispatcher* currentState;

    Dispatcher* getDispatcher(Config& configuration, const std::string& dispatcherName);
};

}

