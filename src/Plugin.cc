#include "Plugin.h"
#include "TCP.h"

namespace plugin { namespace Writer_TCP { Plugin plugin; } }

using namespace plugin::Writer_TCP;

plugin::Configuration Plugin::Configure() {
	AddComponent(new ::logging::Component("TCP", ::logging::writer::TCP::Instantiate));

	plugin::Configuration config;
	config.name = "Writer::TCP";
	config.description = "TCP log writer";
	config.version.major = 0;
	config.version.minor = 2;
	config.version.patch = 2;
	return config;
}
