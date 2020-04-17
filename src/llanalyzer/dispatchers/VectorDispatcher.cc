#include "VectorDispatcher.h"

namespace llanalyzer {

VectorDispatcher::~VectorDispatcher() {
    _clear();
};

bool VectorDispatcher::Register(identifier_t identifier, Analyzer* analyzer, Dispatcher* dispatcher) {
    if (table.size() <= identifier) {
        table.resize(identifier + 1);
    }

    if (table[identifier] == nullptr) {
        table[identifier] = new Value(analyzer, dispatcher);
        return true;
    }
    return false;
}

void VectorDispatcher::Register(const register_map& data) {
    // Search largest identifier and resize VectorDispatcher
    identifier_t highestIdentifier = std::max_element(
            data.begin(),
            data.end(),
            [](const register_pair& a, const register_pair& b) {
                    return a.first < b.first;
            }
    )->first;

    table.resize(highestIdentifier + 1);

    for (const auto &current : data) {
        if (!Register(current.first, current.second.first, current.second.second)) {
            throw std::invalid_argument("Analyzer already registered!");
        }
    }
}

const Value* VectorDispatcher::Lookup(identifier_t identifier) const {
    if (table.size() > identifier && table[identifier] != nullptr) {
        return table[identifier];
    } else {
        return nullptr;
    }
}

size_t VectorDispatcher::size() const {
    size_t result = 0;
    for (const auto &current : table) {
        if (current != nullptr) {
            result++;
        }
    }
    return result;
}

void VectorDispatcher::clear() {
    _clear();
}

void VectorDispatcher::_clear() {
    for (const auto& current : table) {
        delete current;
    }
    table.clear();
}

void VectorDispatcher::DumpDebug() const {
#ifdef DEBUG
    for (size_t i = 0; i < table.size(); i++) {
        if (table[i] != nullptr) {
            DBG_LOG(DBG_LLPOC, "    %#8lx => %s, %p", i, table[i]->analyzer->GetAnalyzerName(), table[i]->dispatcher);
        }
    }
#endif
}

}

