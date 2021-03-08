#pragma once

#include <atlconv.h>
#include <sstream>
#include <iostream> 
#include <cpprest/http_client.h>
#include <cpprest/json.h>


class Client_class {
public:
	bool VersionCheck();
	Client_class();

protected:
	const utility::char_t* _scheme;
	const std::wstring _host;
	const int _port;

};
