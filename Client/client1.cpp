//#include <iostream>
//using namespace std;
//
//#include <cpprest/http_client.h>
//#include <cpprest/filestream.h>
//
//#pragma comment(lib, "cpprest141_2_10")	 // windows only
//using namespace utility;                    // common utilities like string conversions
//using namespace web;                        // common features like uris.
//using namespace web::http;                  // common http functionality
//using namespace web::http::client;          // http client features
//using namespace concurrency::streams;       // asynchronous streams
//
//
//void gethttp()
//{
//	http_client client(u("http://127.0.0.1:39249"));
//	auto resp = client.request(u("get")).get();
//
//	wcout << u("status : ") << resp.status_code() << endl;
//	wcout << "content-type : " << resp.headers().content_type() << endl;
//	//wcout << resp.extract_json(true).get() << endl;
//	web::json::value  json_data = resp.extract_json(true).get(); //_asyncrtimp json :: array = json 값이 배열 값인 경우에만 json 배열로 변환
//	
//	auto array = json_data.as_array();
//	for (int i = 0; i < 5 /*array.size()*/; ++i)
//	{
//		auto id = array[i].at(1).as_string();
//		auto title = array[i].at(2).as_string();
//		std::wcout << "id : " << id << std::endl;
//		std::wcout << "type : " << title << std::endl;
//		
//	}
//
//		/*if (json_data.is_string())
//		{
//			auto key = e.as_string();
//			auto pos = dictionary.find(key);
//
//			if (pos == dictionary.end())
//			{
//				answer[key] = json::value::string(l"<nil>");
//			}
//			else
//			{
//				answer[pos->first] = json::value::string(pos->second);
//			}
//		}*/
//
//}
//
//void gethttpasync()
//{
//	http_client client(u("https://jsonplaceholder.typicode.com/todos/"));
//
//	client.request(u("get")).then([](http_response resp) {
//		wcout << u("status : ") << resp.status_code() << endl;
//		wcout << "content-type : " << resp.headers().content_type() << endl;
//
//		resp.extract_string(true).then([](string_t sboby) {
//			wcout << sboby << endl;
//			}).wait();
//
//		}).wait();
//
//}
//
//
//void getjson()
//{
//	http_client client(u("http://date.jsontest.com/"));
//
//	http_request req(methods::get);
//
//	client.request(req).then([=](http_response r) {
//		wcout << u("status : ") << r.status_code() << endl;
//		wcout << "content-type : " << r.headers().content_type() << endl;
//
//		//{
//		//		"time": "11:25:23 am",
//		//		"milliseconds_since_epoch" : 1423999523092,
//		//		"date" : "02-15-2015"
//		//}
//
//		r.extract_json(true).then([](json::value v) {
//			wcout << v.at(u("date")).as_string() << endl;
//			wcout << v.at(u("time")).as_string() << endl;
//			}).wait();
//
//		}).wait();
//
//}
//
//int main(int argc, char* argv[])
//{
//	wcout.imbue(locale("kor"));  // windows only
//
//	gethttp();
//	/*gethttpasync();
//	getjson();*/
//
//	return 0;
//}
//
