
#ifndef BRO_PLUGIN_HACKILLINOIS_SAFE_BROWSING
#define BRO_PLUGIN_HACKILLINOIS_SAFE_BROWSING

#include <iostream>
#include <curl/curl.h>
#include <curl/easy.h>
#include <cstring>
#include <sstream>
#include <iomanip>

#include <plugin/Plugin.h>

namespace plugin {
namespace HackIllinois_Safe_Browsing {

class Plugin : public ::plugin::Plugin
{
public:
	int download_list_types();
	int download_dataset_for_list(char* list_name);
	int download_redirect_data_for_list(char* redirect_url);
	int download_full_hash_data(char* hash_prefix);
protected:
	// Overridden from plugin::Plugin.
	virtual plugin::Configuration Configure();
};

extern Plugin plugin;

}
}

#endif
