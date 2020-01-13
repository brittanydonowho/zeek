#pragma once

#include <map>

#include "Defines.h"
#include "Analyzer.h"

namespace llanalyzer {

class Dispatcher; // Forward decl for Value
using register_pair = std::pair<identifier_t, std::pair<const Analyzer*, const Dispatcher*>>;
using register_map = std::map<identifier_t, std::pair<const Analyzer*, const Dispatcher*>>;

class Value {
public:
    const Analyzer* analyzer;
    const Dispatcher* dispatcher;

    Value(const Analyzer* analyzer, const Dispatcher* dispatcher) : analyzer(analyzer), dispatcher(dispatcher) {
    }
};

class Dispatcher {
public:
    virtual ~Dispatcher() = default;

    virtual bool Register(identifier_t identifier, const Analyzer* analyzer, const Dispatcher* dispatcher) = 0;
    virtual void Register(const register_map& data) {
        for (auto& current : data) {
            Register(current.first, current.second.first, current.second.second);
        }
    }

    virtual const Value* Lookup(identifier_t identifier) const = 0;

    virtual size_t size() const = 0;
    virtual void clear() = 0;

private:
};

}