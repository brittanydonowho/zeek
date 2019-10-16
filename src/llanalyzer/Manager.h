// See the file "COPYING" in the main distribution directory for copyright.

/**
 * The central management unit for registering and instantiating low layer analyzers.
 *
 * For each low layer protocol that Bro supports, there's one class derived from
 * llanalyzer::LLAnalyzer. Once we have decided that a connection's payload is to
 * be parsed as a given protocol, we instantiate the corresponding
 * analyzer-derived class and add the new instance as a child node into the
 * connection's analyzer tree.
 *
 * In addition to the analyzer-derived class itself, for each protocol
 * there's also "meta-class" derived from analyzer::Component that describes
 * the analyzer, including status information on if that particular protocol
 * analysis is currently enabled.
 *
 * To identify an analyzer (or to be precise: a component), the manager
 * maintains mappings of (1) analyzer::Tag to component, and (2)
 * human-readable analyzer name to component.
 */
#ifndef ANALYZER_MANAGER_H
#define ANALYZER_MANAGER_H

#include <queue>
#include <vector>

#include "LLAnalyzer.h"
#include "Component.h"
#include "Tag.h"
#include "plugin/ComponentManager.h"

#include "../Dict.h"
#include "../net_util.h"
#include "../IP.h"

#include "analyzer/analyzer.bif.h"

namespace llanalyzer {

/**
 * Class maintaining and scheduling available protocol analyzers.
 *
 * The manager maintains a registry of all available protocol analyzers,
 * including a mapping between their textual names and analyzer::Tag. It
 * instantantiates new analyzers on demand. For new connections, the manager
 * sets up their initial analyzer tree, including adding the right \c PIA,
 * respecting well-known ports, and tracking any analyzers specifically
 * scheduled for individidual connections.
 */
class Manager : public plugin::ComponentManager<Tag, Component> {
public:
	/**
	 * Constructor.
	 */
	Manager();

	/**
	 * Destructor.
	 */
	~Manager();

	/**
	 * First-stage initializion of the manager. This is called early on
	 * during Bro's initialization, before any scripts are processed.
	 */
	void InitPreScript();

	/**
	 * Second-stage initialization of the manager. This is called late
	 * during Bro's initialization after any scripts are processed.
	 */
	void InitPostScript();

	/**
	 * Finished the manager's operations.
	 */
	void Done();

	/**
	 * Dumps out the state of all registered analyzers to the \c analyzer
	 * debug stream. Should be called only after any \c zeek_init events
	 * have executed to ensure that any of their changes are applied.
	 */
	void DumpDebug(); // Called after zeek_init() events.

	/**
	 * Enables an analyzer type. Only enabled analyzers will be
	 * instantiated for new connections.
	 *
	 * @param tag The analyzer's tag.
	 *
	 * @return True if successful.
	 */
	bool EnableAnalyzer(const Tag& tag);

	/**
	 * Enables an analyzer type. Only enabled analyzers will be
	 * instantiated for new connections.
	 *
	 * @param tag The analyzer's tag as an enum of script type \c
	 * Analyzer::Tag.
	 *
	 * @return True if successful.
	 */
	bool EnableAnalyzer(EnumVal* tag);

	/**
	 * Enables an analyzer type. Disabled analyzers will not be
	 * instantiated for new connections.
	 *
	 * @param tag The analyzer's tag.
	 *
	 * @return True if successful.
	 */
	bool DisableAnalyzer(const Tag& tag);

	/**
	 * Disables an analyzer type. Disabled analyzers will not be
	 * instantiated for new connections.
	 *
	 * @param tag The analyzer's tag as an enum of script type \c
	 * Analyzer::Tag.
	 *
	 * @return True if successful.
	 */
	bool DisableAnalyzer(EnumVal* tag);

	/**
	 * Disables all currently registered analyzers.
	 */
	void DisableAllAnalyzers();

	/**
	 * Returns the tag associated with an analyer name, or the tag
	 * associated with an error if no such analyzer exists.
	 *
	 * @param name The canonical analyzer name to check.
	 */
	Tag GetAnalyzerTag(const char* name);

	/**
	 * Returns true if an analyzer is enabled.
	 *
	 * @param tag The analyzer's tag.
	 */
	bool IsEnabled(Tag tag);

	/**
	 * Returns true if an analyzer is enabled.
	 *
	 * @param tag The analyzer's tag as an enum of script type \c
	 * Analyzer::Tag.
	 */
	bool IsEnabled(EnumVal* tag);

	/**
	 * Instantiates a new analyzer instance.
	 *
	 * @param tag The analyzer's tag.
	 *
	 * @return The new analyzer instance. Returns
	 * null if tag is invalid, the requested analyzer is disabled, or the
	 * analyzer can't be instantiated.
	 */
	LLAnalyzer* InstantiateAnalyzer(const Tag& tag);

	/**
	 * Instantiates a new analyzer.
	 *
	 * @param name The name of the analyzer.
	 *
	 * @return The new analyzer instance. Returns
	 * null if the name is not known or if the requested analyzer that is
	 * disabled.
	 */
	LLAnalyzer* InstantiateAnalyzer(const char* name);

	/**
	 *
	 */
	bool BuildAnalyzerTree(Connection* conn);

private:
	typedef set<Tag> tag_set;
	typedef map<uint32_t, tag_set*> lla_map;

	lla_map llanalyzer_map;
};

}

extern llanalyzer::Manager* llanalyzer_mgr;

#endif
