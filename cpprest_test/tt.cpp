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



//
//// Upload a file to an HTTP server.
//int _tmain(int argc, _TCHAR* argv[])
//{
//	uri_builder uri(L"http://jsonplaceholder.typicode.com/posts");
//	auto addr = uri.to_string();
//	http_client client1(addr);
//
//	client1.request(methods::GET, addr).then([=](http_response response)
//		{
//			printf("Response status code %u returned.\n", response.status_code());
//			//return pplx::task_from_result(true);
//			if (response.status_code() == status_codes::OK)
//			{
//				std::wstring output = response.extract_utf16string().get();
//				std::wcout << output << std::endl;
//			}
//		}).wait();
//	return 0;
//}
//
//
//
//#include <iostream>
//#include <cpprest/http_client.h>
//#include <cpprest/filestream.h>
//#include <cpprest/uri.h>
//#include <cpprest/json.h>
//using namespace std;
//using namespace utility;
//using namespace web;
//using namespace web::http;
//using namespace web::http::client;
//using namespace concurrency::streams;
////
////int main() {
////	// Create a file stream to write the received file into it.
////	auto fileStream = std::make_shared<ostream>();
////
////	// Open stream to output file.
////	pplx::task<void> requestTask = fstream::open_ostream(U("users.json"))
////
////		// Make a GET request.
////		.then([=](ostream outFile) {
////		*fileStream = outFile;
////
////		// Create http_client to send the request.
////		http_client client(U("https://reqres.in"));
////
////		// Build request URI and start the request.
////		return client.request(methods::GET, uri_builder(U("api")).append_path(U("users")).to_string());
////			})
////
////		// Get the response.
////				.then([=](http_response response) {
////				// Check the status code.
////				if (response.status_code() != 200) {
////					throw std::runtime_error("Returned " + std::to_string(response.status_code()));
////				}
////
////				// Write the response body to file stream.
////				response.body().read_to_end(fileStream->streambuf()).wait();
////
////				// Close the file.
////				return fileStream->close();
////					});
////
////			// Wait for the concurrent tasks to finish.
////			try {
////				while (!requestTask.is_done()) { std::cout << "."; }
////			}
////			catch (const std::exception& e) {
////				printf("Error exception:%s\n", e.what());
////			}
////
////			return 0;
////}
//
//#include "cpprest/http_client.h"
//#include <mutex>
//
//#if defined(_WIN32) && !defined(__cplusplus_winrt)
//// Extra includes for Windows desktop.
//#include <windows.h>
//
//#include <Shellapi.h>
//#endif
//
//#include "cpprest/http_client.h"
//#include "cpprest/http_listener.h"
//
//using namespace utility;
//using namespace web;
//using namespace web::http;
//using namespace web::http::client;
//using namespace web::http::oauth1::experimental;
//using namespace web::http::experimental::listener;
//
////
//// Set key & secret pair to enable session for that service.
////
//static const utility::string_t s_linkedin_key;
//static const utility::string_t s_linkedin_secret;
//
//static const utility::string_t s_twitter_key;
//static const utility::string_t s_twitter_secret;
//
////
//// Utility method to open browser on Windows, OS X and Linux systems.
////
//static void open_browser(utility::string_t auth_uri)
//{
//#if defined(_WIN32) && !defined(__cplusplus_winrt)
//    // NOTE: Windows desktop only.
//    auto r = ShellExecuteA(NULL, "open", conversions::utf16_to_utf8(auth_uri).c_str(), NULL, NULL, SW_SHOWNORMAL);
//#elif defined(__APPLE__)
//    // NOTE: OS X only.
//    string_t browser_cmd(U("open \"") + auth_uri + U("\""));
//    (void)system(browser_cmd.c_str());
//#else
//    // NOTE: Linux/X11 only.
//    string_t browser_cmd(U("xdg-open \"") + auth_uri + U("\""));
//    (void)system(browser_cmd.c_str());
//#endif
//}
//
////
//// A simple listener class to capture OAuth 1.0 HTTP redirect to localhost.
//// The listener captures redirected URI and obtains the token.
//// This type of listener can be implemented in the back-end to capture and store tokens.
////
//class oauth1_code_listener
//{
//public:
//    oauth1_code_listener(uri listen_uri, oauth1_config& config)
//        : m_listener(new http_listener(listen_uri)), m_config(config)
//    {
//        m_listener->support([this](http::http_request request) -> void {
//            if (request.request_uri().path() == U("/") && request.request_uri().query() != U(""))
//            {
//                m_resplock.lock();
//
//                m_config.token_from_redirected_uri(request.request_uri())
//                    .then([this, request](pplx::task<void> token_task) -> void {
//                    try
//                    {
//                        token_task.wait();
//                        m_tce.set(true);
//                    }
//                    catch (const oauth1_exception& e)
//                    {
//                        ucout << "Error: " << e.what() << std::endl;
//                        m_tce.set(false);
//                    }
//                        });
//
//                request.reply(status_codes::OK, U("Ok."));
//
//                m_resplock.unlock();
//            }
//            else
//            {
//                request.reply(status_codes::NotFound, U("Not found."));
//            }
//            });
//
//        m_listener->open().wait();
//    }
//
//    ~oauth1_code_listener() { m_listener->close().wait(); }
//
//    pplx::task<bool> listen_for_code() { return pplx::create_task(m_tce); }
//
//private:
//    std::unique_ptr<http_listener> m_listener;
//    pplx::task_completion_event<bool> m_tce;
//    oauth1_config& m_config;
//    std::mutex m_resplock;
//};
//
////
//// Base class for OAuth 1.0 sessions of this sample.
////
//class oauth1_session_sample
//{
//public:
//    oauth1_session_sample(utility::string_t name,
//        utility::string_t consumer_key,
//        utility::string_t consumer_secret,
//        utility::string_t temp_endpoint,
//        utility::string_t auth_endpoint,
//        utility::string_t token_endpoint,
//        utility::string_t callback_uri)
//        : m_oauth1_config(consumer_key,
//            consumer_secret,
//            temp_endpoint,
//            auth_endpoint,
//            token_endpoint,
//            callback_uri,
//            oauth1_methods::hmac_sha1)
//        , m_name(name)
//        , m_listener(new oauth1_code_listener(callback_uri, m_oauth1_config))
//    {
//    }
//
//    void run()
//    {
//        if (is_enabled())
//        {
//            ucout << "Running " << m_name.c_str() << " session..." << std::endl;
//
//            if (!m_oauth1_config.token().is_valid_access_token())
//            {
//                if (do_authorization().get())
//                {
//                    m_http_config.set_oauth1(m_oauth1_config);
//                }
//                else
//                {
//                    ucout << "Authorization failed for " << m_name.c_str() << "." << std::endl;
//                }
//            }
//
//            run_internal();
//        }
//        else
//        {
//            ucout << "Skipped " << m_name.c_str()
//                << " session sample because app key or secret is empty. Please see instructions." << std::endl;
//        }
//    }
//
//protected:
//    virtual void run_internal() = 0;
//
//    pplx::task<bool> do_authorization()
//    {
//        if (open_browser_auth())
//        {
//            return m_listener->listen_for_code();
//        }
//        else
//        {
//            return pplx::create_task([]() { return false; });
//        }
//    }
//
//    http_client_config m_http_config;
//    oauth1_config m_oauth1_config;
//
//private:
//    bool is_enabled() const
//    {
//        return !m_oauth1_config.consumer_key().empty() && !m_oauth1_config.consumer_secret().empty();
//    }
//
//    bool open_browser_auth()
//    {
//        auto auth_uri_task(m_oauth1_config.build_authorization_uri());
//        try
//        {
//            auto auth_uri(auth_uri_task.get());
//            ucout << "Opening browser in URI:" << std::endl;
//            ucout << auth_uri << std::endl;
//            open_browser(auth_uri);
//            return true;
//        }
//        catch (const oauth1_exception& e)
//        {
//            ucout << "Error: " << e.what() << std::endl;
//            return false;
//        }
//    }
//
//    utility::string_t m_name;
//    std::unique_ptr<oauth1_code_listener> m_listener;
//};
//
////
//// Specialized class for LinkedIn OAuth 1.0 session.
////
//class linkedin_session_sample : public oauth1_session_sample
//{
//public:
//    linkedin_session_sample()
//        : oauth1_session_sample(U("LinkedIn"),
//            s_linkedin_key,
//            s_linkedin_secret,
//            U("https://api.linkedin.com/uas/oauth/requestToken"),
//            U("https://www.linkedin.com/uas/oauth/authenticate"),
//            U("https://api.linkedin.com/uas/oauth/accessToken"),
//            U("http://localhost:8888/"))
//    {
//    }
//
//protected:
//    void run_internal() override
//    {
//        http_client api(U("https://api.linkedin.com/v1/people/"), m_http_config);
//        ucout << "Requesting user information:" << std::endl;
//        ucout << "Information: " << api.request(methods::GET, U("~?format=json")).get().extract_json().get()
//            << std::endl;
//    }
//};
//
////
//// Specialized class for Twitter OAuth 1.0 session.
////
//class twitter_session_sample : public oauth1_session_sample
//{
//public:
//    twitter_session_sample()
//        : oauth1_session_sample(U("Twitter"),
//            s_twitter_key,
//            s_twitter_secret,
//            U("https://api.twitter.com/oauth/request_token"),
//            U("https://api.twitter.com/oauth/authorize"),
//            U("https://api.twitter.com/oauth/access_token"),
//            U("http://testhost.local:8890/"))
//    {
//    }
//
//protected:
//    void run_internal() override
//    {
//        http_client api(U("https://api.twitter.com/1.1/"), m_http_config);
//        ucout << "Requesting account information:" << std::endl;
//        ucout << api.request(methods::GET, U("account/settings.json")).get().extract_json().get() << std::endl;
//    }
//};
////
////#ifdef _WIN32
////int wmain(int argc, wchar_t* argv[])
////#else
////int main(int argc, char* argv[])
////#endif
////{
////    ucout << "Running OAuth 1.0 client sample..." << std::endl;
////
////    linkedin_session_sample linkedin;
////    twitter_session_sample twitter;
////
////    linkedin.run();
////    twitter.run();
////
////    ucout << "Done." << std::endl;
////    return 0;
////}
//
//void display_json(
//    json::value const& jvalue,
//    utility::string_t const& prefix)
//{
//    std::wcout << prefix << jvalue.serialize() << std::endl;
//}
//
//void main()
//{
//    /*json::value* answer;
//    http_client client(U("https://api.github.com/"));
//    client.request(methods::GET, L"/repos/jankais3r/Forensic-Version-Checker/releases/latest").then([](http_response response)
//        {
//            if (response.status_code() == status_codes::OK)
//            {
//                std::cout << "response.extract_json()" << std::endl;
//                return response.extract_json();
//            }
//            std::cout << "task_from_result(json::value())" << response.status_code() << std::endl;
//            return pplx::task_from_result(json::value());
//        })
//        .then([&](pplx::task<json::value> previousTask)
//            {
//                try
//                {
//                    *answer = previousTask.get();
//                    display_json(previousTask.get(), L"RES: ");
//                }
//                catch (http_exception const& e)
//                {
//                    wcout << e.what() << endl;
//                }
//            })
//            .wait();*/
//
//
//    //uri_builder uri(L"https://api.github.com/repos/jankais3r/Forensic-Version-Checker/releases/latest");
//    //auto addr = uri.to_string();
//    //http_client client1(U("https://api.github.com/"));
//
//    //client1.request(methods::GET, addr).then([&](http_response response)
//    //    {
//    //        printf("Response status code %u returned.\n", response.status_code());
//    //        //return pplx::task_from_result(true);
//    //        if (response.status_code() == status_codes::OK)
//    //        {
//    //            json::value output = response.extract_json().get();
//    //            display_json(output, L"Request : ");
//    //        }
//    //    }).wait();
//
//    http_listener listener(L"http://127.0.0.1:36249");
//
//    listener.open();
//    listener.support(methods::POST, handle_post);
//
//    json::value answer;
//    uri_builder uri(L"https://api.github.com/repos/jankais3r/Forensic-Version-Checker/releases/latest");
//    auto addr = uri.to_string();
//    http_client github(U("https://api.github.com/"));
//
//    github.request(methods::GET, addr).then([&](http_response response)
//        {
//            printf("Response status code %u returned.\n", response.status_code());
//            //return pplx::task_from_result(true);
//            if (response.status_code() == status_codes::OK)
//            {
//                json::value latest_data = response.extract_json().get();
//                std::wstring version = latest_data.at(L"tag_name").as_string();
//                if (!wcscmp(version.c_str(), L"30.0.3"))
//                {
//                    std::cout << " 성 공 " << std::endl;
//                    return true;
//                }
//            }
//            else
//            {
//                std::cout << "상태 오류 " << std::endl;
//            }
//        }).wait();
//}
//
//int main()
//{
//json::value version_data = json::value::null();
//web::json::value Client_fileVer = json::value::object();
//uri_builder uri(L"https://api.github.com/repos/BeomBeom2/Zabbix/releases");
//auto addr = uri.to_string();
//http_client github(U("https://api.github.com"));
//json::value latest_data;
//std::wstring hash;
//std::wstring hash_val;
//size_t index = 0;
//github.request(methods::GET, addr).then([&](http_response response)
//    {
//        if (response.status_code() == status_codes::OK)
//        {
//            version_data = response.extract_json().get();
//            std::wcout << L"\n :::::::::::::VERSION INFO::::::::::::: \n" << std::endl;
//            for (int index = 0; index < version_data.size(); ++index)
//            {
//                std::wcout << L"version : " << version_data[index][L"tag_name"] << std::endl;
//                std::wstring version_func = version_data[index][L"body"].as_string();
//                index = version_func.find(L"hash");
//                if (index != std::wstring::npos)
//                {
//                    hash = version_func.substr(index);
//                    hash_val = hash.substr(hash.find(L"\""));
//                    std::wcout << L"hash_val : " << hash_val << std::endl;
//                }
//                else
//                    std::cout << "error" << std::endl;
//            }
//        }
//        else
//            printf("ERROR, status code %u. \n", response.status_code());
//    }).wait();
//}
//
//bool version_info(http_client& github, const std::wstring& Client_version) {
//    json::value version_data = json::value::null();
//    size_t fun_index = 0, pos = 0;
//    uri_builder uri(L"https://api.github.com/repos/BeomBeom2/Zabbix/releases");
//    auto addr = uri.to_string();
//    github.request(methods::GET, addr).then([&](http_response response)
//        {
//            if (response.status_code() == status_codes::OK)
//            {
//                version_data = response.extract_json().get();
//                std::wcout << L"\n::::::::::::VERSION INFO:::::::::::: \n" << std::endl;
//                for (int index = 0; index < version_data.size(); ++index)
//                {
//                    fun_index = 0, pos = 0;
//                    std::wcout << L"version : " << version_data[index][L"tag_name"] << std::endl;
//                    std::wstring version_func = version_data[index][L"body"].as_string();
//                    std::cout << version_func.length() << std::endl;
//                    for (fun_index = 0; fun_index < version_func.length();)
//                    {
//                        pos = version_func.find(L"\\r\\n");
//                        if (pos == std::wstring::npos)
//                            break;
//                        std::wcout << version_func.substr(fun_index, pos) << std::endl;
//                        fun_index += pos;
//                    }
//                }
//            }
//            else
//                printf("ERROR, status code %u. \n", response.status_code());
//        }).wait();
//        return true;
//}
//
// header include
//

#include <windows.h>
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
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <string.h>
#include "base64.h"
#include <TCHAR.h>
#include  "zlib/UnZipCTL.h"
#include "zlib/FolderList.h"
#include <shellapi.h>
#include<tchar.h>
#include<urlmon.h>

#pragma comment(lib, "cpprest141_2_10d.lib")
#pragma comment(lib,"version.lib")
#pragma comment (lib,"urlmon.lib")
using namespace web;
using namespace web::http;
using namespace web::http::client;

//int main()
//{
//	HRESULT hr = URLDownloadToFile(NULL, L"https://github.com/BeomBeom2/Zabbix/releases/download/v1.3.0/zlib-1.2.3.exe",
//		L"C:\\Unzip\\zlib-1.2.3.exe", 0, NULL);
//
//	std::cout << (int)hr << std::endl;
//
//	HINSTANCE result = ::ShellExecute(NULL, _T("open"), _T("C:\\test1\\zlib-1.2.3.exe"), NULL, NULL, SW_SHOW);
//
//
//	DWORD dwExitCode;
//	DWORD dwPID = GetCurrentProcessId();    // 현재 자신의 프로세스 ID 가져오기.
//
//	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, dwPID);    // 프로세스 핸들 가져오기
//
//	if (NULL != hProcess)
//	{
//		GetExitCodeProcess(hProcess, &dwExitCode);   // 프로세스 나가기 코드 얻어오기
//		TerminateProcess(hProcess, dwExitCode);    // 프로세스 연결 끊기
//		WaitForSingleObject(hProcess, INFINITE); // 종료 될때까지 대기
//		CloseHandle(hProcess);                                 // 프로세스 핸들 닫기
//	}
//
//	return 0;
//}