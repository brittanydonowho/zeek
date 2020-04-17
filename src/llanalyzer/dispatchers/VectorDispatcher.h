#pragma once

#include "../Defines.h"
#include "Dispatcher.h"

#include <utility>

namespace llanalyzer {

class VectorDispatcher : public Dispatcher {
public:
    ~VectorDispatcher() override;

    bool Register(identifier_t identifier, Analyzer* analyzer, Dispatcher* dispatcher) override;
    void Register(const register_map& data) override;

    const Value* Lookup(identifier_t identifier) const override;

    size_t size() const override;
    void clear() override;

protected:
    void DumpDebug() const override;

private:
    std::vector<Value*> table;

    void _clear();
};

}