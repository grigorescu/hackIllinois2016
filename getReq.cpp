#include <iostream>
#include <curl/curl.h>
#include <cstring>
#include <sstream>
//#include <iomanip>
using namespace std;

string url_encode(const string &value) 
{
    ostringstream escaped;
    escaped.fill('0');
    escaped << hex;

    for (string::const_iterator i = value.begin(), n = value.end(); i != n; ++i) {
        string::value_type c = (*i);

        // Keep alphanumeric and other accepted characters intact
        // make sure c is positive for msvc assertion
        if (c >= 0 && (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~')) {
            escaped << c;
            continue;
        }

        // Any other characters are percent-encoded
        escaped << uppercase;
        escaped << '%' << setw(2) << int((unsigned char) c);
        escaped << nouppercase;
	
    }

    return escaped.str();
}

int main(int argc, char *argv[])
{
	CURL *curl = curl_easy_init();
	string client = "firefox";
	string apikey = "AIzaSyCdA-CmA7dusGVUIw3d9LubMumv-JgqxMg";
	string appver = "1.01";
	string pver = "3.1";
	string URL = "http://www.google.com";
	//string URL = "https://sb-ssl.google.com/safebrowsing/api/lookup?client=fedora&key=AIzaSyCdA-CmA7dusGVUIw3d9LubMumv-JgqxMg&appver=1.01&pver=3.1&url="+URLReq;
	//string URL1 = "https://sb-ssl.google.com/safebrowsing/api/lookup?client=fedora&key=AIzaSyCdA-CmA7dusGVUIw3d9LubMumv-JgqxMg&appver=1.5.2&pver=3.1";
	
	string baseURL = "https://sb-ssl.google.com/safebrowsing/api/lookup";
	string arguments = "";
	arguments += "client=" + url_encode(client)+"&";
	arguments += "key=" + url_encode(apikey) + "&";
	arguments += "appver=" + url_encode(appver) + "&";
	arguments += "pver=" + url_encode(pver) + "&";
	arguments += "url=" + url_encode(URL);

	string url_to_req = baseURL + "?" + arguments;
	
	cout << "URL: " << url_to_req << endl;
  	curl_easy_setopt(curl, CURLOPT_URL, URL);
  	cout << "Now send the request\n";
	curl_easy_perform(curl);

	return 0;
}
