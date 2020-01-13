#include "Config.h"
#include "Reporter.h"

#include <algorithm>

namespace llanalyzer {
    const std::string& DispatcherConfig::getName() const {
        return name;
    }

    const std::map<identifier_t, std::string>& DispatcherConfig::getMappings() const {
        return mappings;
    }

    void DispatcherConfig::addMapping(identifier_t identifier, const std::string& analyzerName) {
        if (mappings.count(identifier)) {
            reporter->InternalError("Invalid config, identifier %x does already exist for dispatcher set %s.", identifier, name.c_str());
        }

        mappings.emplace(identifier, analyzerName);
    }

    bool DispatcherConfig::operator==(const DispatcherConfig &rhs) const {
        return name == rhs.name;
    }

    bool DispatcherConfig::operator!=(const DispatcherConfig &rhs) const {
        return !(rhs == *this);
    }

    const DispatcherConfig& Config::getDispatcherConfig(const std::string& name) const {
        auto it = std::find_if(dispatchers.begin(), dispatchers.end(), [&](const DispatcherConfig& conf) {
            return conf.getName() == name;
        });

        if (it == dispatchers.end()) {
            throw std::out_of_range("No dispatcher config found for " + name);
        } else {
            return *it;
        }
    }

    bool Config::contains(const std::string& name) const {
        auto it = std::find_if(dispatchers.begin(), dispatchers.end(), [&](const DispatcherConfig& conf) {
            return conf.getName() == name;
        });
        return it != dispatchers.end();
    }

    const std::vector<DispatcherConfig>& Config::getDispatchers() const{
        return dispatchers;
    }

    void Config::addDispatcherConfig(const std::string& name) {
        dispatchers.emplace_back(name);
    }

    void Config::addMapping(const std::string& name, identifier_t identifier, const std::string& analyzerName) {
        auto it = std::find_if(dispatchers.begin(), dispatchers.end(), [&](const DispatcherConfig& conf) {
            return conf.getName() == name;
        });

        // Create dispatcher config if it does not exist yet
        if (it == dispatchers.end()) {
            addDispatcherConfig(name);
        } else {
            it->addMapping(identifier, analyzerName);
        }
    }
}
