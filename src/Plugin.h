#ifndef BRO_PLUGIN_WRITER_TCP
#define BRO_PLUGIN_WRITER_TCP

#include <plugin/Plugin.h>

namespace plugin {
namespace Writer_TCP {

class Plugin : public ::plugin::Plugin {
	protected:
		// Overridden from plugin::Plugin.
		plugin::Configuration Configure() override;
};

extern Plugin plugin;

}
}

#endif
