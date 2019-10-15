// See the file "COPYING" in the main distribution directory for copyright.

#include "Manager.h"

#include "Hash.h"
#include "Val.h"

#include "plugin/Manager.h"

using namespace analyzer;

Manager::ConnIndex::ConnIndex(const IPAddr &_orig, const IPAddr &_resp,
                              uint16_t _resp_p, uint16_t _proto) {
    if (_orig == IPAddr(string("0.0.0.0")))
        // don't use the IPv4 mapping, use the literal unspecified address
        // to indicate a wildcard
        orig = IPAddr(string("::"));
    else
        orig = _orig;

    resp = _resp;
    resp_p = _resp_p;
    proto = _proto;
}

Manager::ConnIndex::ConnIndex() {
    orig = resp = IPAddr("0.0.0.0");
    resp_p = 0;
    proto = 0;
}

bool Manager::ConnIndex::operator<(const ConnIndex &other) const {
    if (orig != other.orig)
        return orig < other.orig;

    if (resp != other.resp)
        return resp < other.resp;

    if (proto != other.proto)
        return proto < other.proto;

    if (resp_p != other.resp_p)
        return resp_p < other.resp_p;

    return false;
}

Manager::Manager()
        : plugin::ComponentManager<analyzer::Tag, analyzer::Component>("Analyzer", "Tag") {
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
    DBG_LOG(DBG_ANALYZER, "Available analyzers after zeek_init():");
    list<Component *> all_analyzers = GetComponents();
    for (list<Component *>::const_iterator i = all_analyzers.begin(); i != all_analyzers.end(); ++i)
        DBG_LOG(DBG_ANALYZER, "    %s (%s)", (*i)->Name().c_str(),
                IsEnabled((*i)->Tag()) ? "enabled" : "disabled");

    DBG_LOG(DBG_ANALYZER, " ");
    DBG_LOG(DBG_ANALYZER, "Analyzers by port:");

    for (analyzer_map_by_port::const_iterator i = analyzers_by_port_tcp.begin();
         i != analyzers_by_port_tcp.end(); i++) {
        string s;

        for (tag_set::const_iterator j = i->second->begin(); j != i->second->end(); j++)
            s += string(GetComponentName(*j)) + " ";

        DBG_LOG(DBG_ANALYZER, "    %d/tcp: %s", i->first, s.c_str());
    }

    for (analyzer_map_by_port::const_iterator i = analyzers_by_port_udp.begin();
         i != analyzers_by_port_udp.end(); i++) {
        string s;

        for (tag_set::const_iterator j = i->second->begin(); j != i->second->end(); j++)
            s += string(GetComponentName(*j)) + " ";

        DBG_LOG(DBG_ANALYZER, "    %d/udp: %s", i->first, s.c_str());
    }

#endif
}

void Manager::Done() {
}

bool Manager::EnableAnalyzer(Tag tag) {
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

bool Manager::DisableAnalyzer(Tag tag) {
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

analyzer::Tag Manager::GetAnalyzerTag(const char *name) {
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

Analyzer *Manager::InstantiateAnalyzer(Tag tag, Connection *conn) {
    Component *c = Lookup(tag);

    if (!c) {
        reporter->InternalWarning("request to instantiate unknown analyzer");
        return 0;
    }

    if (!c->Enabled())
        return 0;

    if (!c->Factory()) {
        reporter->InternalWarning("analyzer %s cannot be instantiated dynamically",
                                  GetComponentName(tag).c_str());
        return 0;
    }

    Analyzer *a = c->Factory()(conn);

    if (!a) {
        reporter->InternalWarning("analyzer instantiation failed");
        return 0;
    }

    a->SetAnalyzerTag(tag);

    return a;
}

Analyzer *Manager::InstantiateAnalyzer(const char *name, Connection *conn) {
    Tag tag = GetComponentTag(name);
    return tag ? InstantiateAnalyzer(tag, conn) : 0;
}

bool Manager::BuildAnalyzerTree(Connection *conn) {
    // TODO Implement: Create the tree like it was read from the config file.
    return false;
}
