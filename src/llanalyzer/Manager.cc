// See the file "COPYING" in the main distribution directory for copyright.

#include <list>

#include "Config.h"
#include "Manager.h"
#include "ProtocolAnalyzerSet.h"

#include "plugin/Manager.h"

using namespace llanalyzer;

Manager::Manager()
        : plugin::ComponentManager<llanalyzer::Tag, llanalyzer::Component>("LLAnalyzer", "Tag") {
}

Manager::~Manager() {
    delete analyzerSet;
}

void Manager::InitPreScript() {
}

void Manager::InitPostScript() {
    // Read in configuration
    // TODO: just a mockup now, do for real

    // Configuration Mockup
    Config configuration;
    configuration.addMapping("ROOT", 0x1, "ETHERNET");
    configuration.addMapping("ETHERNET", 0x800, "IP4");
    configuration.addMapping("ETHERNET", 0x86DD, "IP6");
    configuration.addMapping("ETHERNET", 0x806, "ARP");
    configuration.addMapping("ETHERNET", 0x8864, "PPPOE");
    configuration.addMapping("PPPOE", 0x21, "IP4");
    configuration.addMapping("PPPOE", 0x57, "IP6");
    configuration.addMapping("IP4", 0x1, "ICMP");
    configuration.addMapping("IP6", 0x3A, "ICMP6");

    analyzerSet = new ProtocolAnalyzerSet(configuration);
}

void Manager::Done() {
}

void Manager::DumpDebug() {
#ifdef DEBUG
    DBG_LOG(DBG_LLPOC, "Available llanalyzers after zeek_init():");
    for (auto& current : GetComponents()) {
        DBG_LOG(DBG_LLPOC, "    %s (%s)", current->Name().c_str(), IsEnabled(current->Tag()) ? "enabled" : "disabled");
    }
#endif
}

bool Manager::EnableAnalyzer(const Tag& tag) {
    Component *p = Lookup(tag);

    if (!p)
        return false;

    DBG_LOG(DBG_LLPOC, "Enabling analyzer %s", p->Name().c_str());
    p->SetEnabled(true);

    return true;
}

bool Manager::EnableAnalyzer(EnumVal *val) {
    Component *p = Lookup(val);

    if (!p)
        return false;

    DBG_LOG(DBG_LLPOC, "Enabling analyzer %s", p->Name().c_str());
    p->SetEnabled(true);

    return true;
}

bool Manager::DisableAnalyzer(const Tag& tag) {
    Component *p = Lookup(tag);

    if (!p)
        return false;

    DBG_LOG(DBG_LLPOC, "Disabling analyzer %s", p->Name().c_str());
    p->SetEnabled(false);

    return true;
}

bool Manager::DisableAnalyzer(EnumVal *val) {
    Component *p = Lookup(val);

    if (!p)
        return false;

    DBG_LOG(DBG_LLPOC, "Disabling analyzer %s", p->Name().c_str());
    p->SetEnabled(false);

    return true;
}

void Manager::DisableAllAnalyzers() {
    DBG_LOG(DBG_LLPOC, "Disabling all analyzers");

    auto all_analyzers = GetComponents();
    for ( const auto& analyzer : all_analyzers )
        analyzer->SetEnabled(false);
}

llanalyzer::Tag Manager::GetAnalyzerTag(const char *name) {
    return GetComponentTag(name);
}

bool Manager::IsEnabled(Tag tag) {
    if (!tag)
        return false;

    Component *p = Lookup(tag);

    if (!p)
        return false;

    return p->Enabled();
}

bool Manager::IsEnabled(EnumVal *val) {
    Component *p = Lookup(val);

    if (!p)
        return false;

    return p->Enabled();
}

Analyzer* Manager::InstantiateAnalyzer(const Tag& tag) {
    Component* c = Lookup(tag);

    if (!c) {
        reporter->InternalWarning("request to instantiate unknown llanalyzer");
        return nullptr;
    }

    if (!c->Enabled()) return nullptr;

    if (!c->Factory()) {
        reporter->InternalWarning("analyzer %s cannot be instantiated dynamically", GetComponentName(tag).c_str());
        return nullptr;
    }

    Analyzer* a = c->Factory()();

    if (!a) {
        reporter->InternalWarning("analyzer instantiation failed");
        return nullptr;
    }

    if (tag != a->GetAnalyzerTag()) {
        reporter->InternalError("Mismatch of requested analyzer %s and instantiated analyzer %s. This usually means that the plugin author made a mistake.",
                GetComponentName(tag).c_str(), GetComponentName(a->GetAnalyzerTag()).c_str());
        return nullptr;
    }

    return a;
}

Analyzer* Manager::InstantiateAnalyzer(const std::string& name) {
    Tag tag = GetComponentTag(name);
    return tag ? InstantiateAnalyzer(tag) : nullptr;
}

void Manager::processPacket(uint8_t *packetStartPointer) {
}
