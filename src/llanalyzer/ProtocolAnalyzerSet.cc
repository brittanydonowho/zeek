#include "ProtocolAnalyzerSet.h"

namespace llanalyzer {

const Dispatcher* ProtocolAnalyzerSet::getDispatcher(Config& configuration, const std::string& dispatcherName) {
    // Is it already created?
    if (dispatchers.count(dispatcherName) != 0) {
        return dispatchers[dispatcherName];
    }

    // Create new dispatcher from config
    if (configuration.contains(dispatcherName)) {
        // No such dispatcher found, this is therefore implicitely a leaf
        return nullptr;
    }
    auto mappings = configuration.getDispatcherConfig(dispatcherName).getMappings();

    Dispatcher* dispatcher = new dispatcher_impl();
    for (const auto& currentMapping : mappings) {
        dispatcher->Register(currentMapping.first, analyzers.at(currentMapping.second), getDispatcher(configuration, currentMapping.second));
    }
    dispatchers.emplace(dispatcherName, dispatcher);

    return dispatcher;
}

ProtocolAnalyzerSet::ProtocolAnalyzerSet(Config& configuration) {
    // Instantiate objects for all analyzers
    for (const auto& currentDispatcherConfig : configuration.getDispatchers()) {
        for (const auto& currentMapping : currentDispatcherConfig.getMappings()) {
            // Check if already instantiated
            if (analyzers.count(currentMapping.second) != 0) {
                continue;
            }

            analyzers.emplace(currentMapping.second, llanalyzer_mgr->InstantiateAnalyzer(currentMapping.second));
        }
    }

    // Generate Dispatchers, starting at root
    head = getDispatcher(configuration, "ROOT");

    // If head is nullptr now, "ROOT" was not found in the config --> wrong config, abort
    if (head == nullptr) {
        reporter->InternalError("No dispatching configuration for ROOT of llanalyzer set.");
    }
}

ProtocolAnalyzerSet::~ProtocolAnalyzerSet() {
    for (const auto& current : analyzers) {
        delete current.second;
    }
}

const Analyzer* ProtocolAnalyzerSet::dispatch(identifier_t identifier) const {
    return nullptr;
}

void ProtocolAnalyzerSet::reset() {
}

} // end of llanalyzer namespace
