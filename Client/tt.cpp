#include <tchar.h>
#include <windows.h>
#include <cpprest/http_listener.h>
#include <cpprest/http_client.h>
#include <cpprest/json.h>
#include <openssl/sha.h>
#include <stringapiset.h>
#include <winbase.h>
#include <oleauto.h>
#include <atlconv.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
/*NID_X9_62_prime256v1*/
#include <openssl/evp.h>
#include "base64.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#pragma once


using namespace web;
using namespace web::http;
using namespace web::http::client;
using namespace web::http::experimental::listener;

#include <iostream>
#include <map>
#include <set>
#include <string>

using namespace std;
using namespace web::http;
using namespace web::http::client;
using namespace concurrency::streams;
using namespace std::chrono;
using namespace utility;




// Upload a file to an HTTP server.
int _tmain(int argc, _TCHAR* argv[])
{
	uri_builder uri(L"http://jsonplaceholder.typicode.com/posts");
	auto addr = uri.to_string();
	http_client client1(addr);

	client1.request(methods::GET, addr).then([=](http_response response)
		{
			printf("Response status code %u returned.\n", response.status_code());
			//return pplx::task_from_result(true);
			if (response.status_code() == status_codes::OK)
			{
				std::wstring output = response.extract_utf16string().get();
				std::wcout << output << std::endl;
			}
		}).wait();
	return 0;
}

