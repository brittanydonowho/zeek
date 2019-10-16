// See the file "COPYING" in the main distribution directory for copyright.

#include <list>
#include "Manager.h"

#include "Hash.h"
#include "Val.h"

#include "plugin/Manager.h"

using namespace llanalyzer;

Manager::Manager()
        : plugin::ComponentManager<analyzer::Tag, analyzer::Component>("LLAnalyzer", "Tag") {
}

Manager::~Manager() {
    // TODO implement
}

void Manager::InitPreScript() {
    // TODO Implement
}

void Manager::InitPostScript() {
    // TODO Implement
}

void Manager::DumpDebug() {
#ifdef DEBUG
    DBG_LOG(DBG_LLPOC, "Available analyzers after zeek_init():");
    list<Component *> all_analyzers = GetComponents();
    for (list<Component *>::const_iterator i = all_analyzers.begin(); i != all_analyzers.end(); ++i) {
        DBG_LOG(DBG_LLPOC, "    %s (%s)", (*i)->Name().c_str(), IsEnabled((*i)->Tag()) ? "enabled" : "disabled");
    }

#endif
}

void Manager::Done() {
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

LLAnalyzer* Manager::InstantiateAnalyzer(const Tag& tag) {
    // TODO Implement
    return nullptr;
}

LLAnalyzer* Manager::InstantiateAnalyzer(const char *name) {
    Tag tag = GetComponentTag(name);
    return tag ? InstantiateAnalyzer(tag) : nullptr;
}

bool Manager::BuildAnalyzerTree() {
    // TODO Implement: Create the tree like it was read from the config file.
    return false;
}
