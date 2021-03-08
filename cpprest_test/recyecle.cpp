////
////BSTR get_server_hash()
////{
////    std::wstring path = L"C:\\server\\test.zip";
////    std::ifstream file(path, std::ios::binary | std::ios::in);
////
////    file.seekg(0, std::ios::end);
////    size_t file_size = file.tellg();
////
////    file.clear();
////    file.seekg(0, std::ios::beg);
////
////    static char file_hash[65] = { 0, };
////    unsigned char hash[SHA256_DIGEST_LENGTH];
////    SHA256_CTX sha256;
////    SHA256_Init(&sha256);
////    const int bufSize = 32768;
////
////    char* buffer = (char*)malloc(bufSize);
////    int bytesRead = 0;
////
////    while (!file.eof())
////    {
////        file.read(buffer, bufSize);
////        SHA256_Update(&sha256, buffer, file.gcount());
////    }
////    SHA256_Final(hash, &sha256);
////    sha256_hash_string(hash, file_hash);
////
////    file.close();
////    free(buffer);
////    /*ANSI to UNICODE*/
////    int lenA = lstrlenA(file_hash); // #include <winbase.h>
////    int lenW;
////    BSTR unicode_hash = NULL; // #include <oleauto.h>
////
////    lenW = ::MultiByteToWideChar(CP_ACP, 0, file_hash, lenA, 0, 0); // #include <stringapiset.h>
////    if (lenW > 0)
////    {
////        // 변환 성공 여부 확인
////        unicode_hash = ::SysAllocStringLen(0, lenW); // #include <oleauto.h>
////        ::MultiByteToWideChar(CP_ACP, 0, file_hash, lenA, unicode_hash, lenW);
////    }
////
////    ::SysFreeString(unicode_hash);
////    return unicode_hash;
////}
////
//#include "base64.h"
//#include <iostream>
//
//int main() {
//
//    bool all_tests_passed = true;
//
//    const std::string orig =
//        "René Nyffenegger\n"
//        "http://www.renenyffenegger.ch\n"
//        "passion for data\n";
//
//    std::string encoded = base64_encode(reinterpret_cast<const unsigned char*>(orig.c_str()), orig.length());
//    std::string decoded = base64_decode(encoded);
//
//    if (encoded != "UmVuw6kgTnlmZmVuZWdnZXIKaHR0cDovL3d3dy5yZW5lbnlmZmVuZWdnZXIuY2gKcGFzc2lvbiBmb3IgZGF0YQo=") {
//        std::cout << "Encoding is wrong" << std::endl;
//        all_tests_passed = false;
//    }
//
//    if (decoded != orig) {
//        std::cout << "decoded != orig" << std::endl;
//        all_tests_passed = false;
//    }
//
//    // Test all possibilites of fill bytes (none, one =, two ==)
//    // References calculated with: https://www.base64encode.org/
//
//    std::string rest0_original = "abc";
//    std::string rest0_reference = "YWJj";
//
//    std::string rest0_encoded = base64_encode(reinterpret_cast<const unsigned char*>(rest0_original.c_str()),
//        rest0_original.length());
//    std::string rest0_decoded = base64_decode(rest0_encoded);
//
//    if (rest0_decoded != rest0_original) {
//        std::cout << "rest0_decoded != rest0_original" << std::endl;
//        all_tests_passed = false;
//    }
//    if (rest0_reference != rest0_encoded) {
//        std::cout << "rest0_reference != rest0_encoded" << std::endl;
//        all_tests_passed = false;
//    }
//
//    // std::cout << "encoded:   " << rest0_encoded << std::endl;
//    // std::cout << "reference: " << rest0_reference << std::endl;
//    // std::cout << "decoded:   " << rest0_decoded << std::endl << std::endl;
//
//    std::string rest1_original = "abcd";
//    std::string rest1_reference = "YWJjZA==";
//
//    std::string rest1_encoded = base64_encode(reinterpret_cast<const unsigned char*>(rest1_original.c_str()),
//        rest1_original.length());
//    std::string rest1_decoded = base64_decode(rest1_encoded);
//
//    if (rest1_decoded != rest1_original) {
//        std::cout << "rest1_decoded != rest1_original" << std::endl;
//        all_tests_passed = false;
//    }
//    if (rest1_reference != rest1_encoded) {
//        std::cout << "rest1_reference != rest1_encoded" << std::endl;
//        all_tests_passed = false;
//    }
//
//    // std::cout << "encoded:   " << rest1_encoded << std::endl;
//    // std::cout << "reference: " << rest1_reference << std::endl;
//    // std::cout << "decoded:   " << rest1_decoded << std::endl << std::endl;
//
//    std::string rest2_original = "abcde";
//    std::string rest2_reference = "YWJjZGU=";
//
//    std::string rest2_encoded = base64_encode(reinterpret_cast<const unsigned char*>(rest2_original.c_str()),
//        rest2_original.length());
//    std::string rest2_decoded = base64_decode(rest2_encoded);
//
//    if (rest2_decoded != rest2_original) {
//        std::cout << "rest2_decoded != rest2_original" << std::endl;
//        all_tests_passed = false;
//    }
//    if (rest2_reference != rest2_encoded) {
//        std::cout << "rest2_reference != rest2_encoded" << std::endl;
//        all_tests_passed = false;
//    }
//
//    // std::cout << "encoded:   " << rest2_encoded << std::endl;
//    // std::cout << "reference: " << rest2_reference << std::endl;
//    // std::cout << "decoded:   " << rest2_decoded << std::endl << std::endl;
//    //
//
//    // --------------------------------------------------------------
//    //
//    // Data that is 17 bytes long requires one padding byte when
//    // base-64 encoded. Such an encoded string could not correctly
//    // be decoded when encoded with «url semantics». This bug
//    // was discovered by https://github.com/kosniaz. The following
//    // test checks if this bug was fixed:
//    //
//    std::string a17_orig = "aaaaaaaaaaaaaaaaa";
//    std::string a17_encoded = base64_encode(a17_orig, false);
//    std::string a17_encoded_url = base64_encode(a17_orig, true);
//
//    if (a17_encoded != "YWFhYWFhYWFhYWFhYWFhYWE=") {
//        std::cout << "Failed to encode a17" << std::endl;
//        all_tests_passed = false;
//    }
//
//    if (a17_encoded_url != "YWFhYWFhYWFhYWFhYWFhYWE.") {
//        std::cout << "Failed to encode a17 (url)" << std::endl;
//        all_tests_passed = false;
//    }
//
//    if (base64_decode(a17_encoded_url) != a17_orig) {
//        std::cout << "Failed to decode a17 (url)" << std::endl;
//        all_tests_passed = false;
//    }
//
//    if (base64_decode(a17_encoded) != a17_orig) {
//        std::cout << "Failed to decode a17 (no url)" << std::endl;
//        all_tests_passed = false;
//    }
//
//    // --------------------------------------------------------------
//
//    // characters 63 and 64 / URL encoding
//
//    std::string s_6364 = "\x03" "\xef" "\xff" "\xf9";
//
//    std::string s_6364_encoded = base64_encode(s_6364, false);
//    std::string s_6364_encoded_url = base64_encode(s_6364, true);
//
//    if (s_6364_encoded != "A+//+Q==") {
//        std::cout << "Failed to encode_6364 (no url)" << std::endl;
//        all_tests_passed = false;
//    }
//
//    if (s_6364_encoded_url != "A-__-Q..") {
//        std::cout << "Failed to encode_6364 (url)" << std::endl;
//        all_tests_passed = false;
//    }
//
//    if (base64_decode(s_6364_encoded) != s_6364) {
//        std::cout << "Failed to decode s_6364_encoded" << std::endl;
//        all_tests_passed = false;
//    }
//
//    if (base64_decode(s_6364_encoded_url) != s_6364) {
//        std::cout << "Failed to decode s_6364_encoded_url" << std::endl;
//        all_tests_passed = false;
//    }
//
//    std::string numbers =
//        "one two three four five six seven eight nine ten eleven twelve "
//        "thirteen fourteen fivteen sixteen seventeen eighteen nineteen "
//        "twenty twenty-one";
//    std::string encoded_mime = base64_encode_mime(numbers);
//
//    std::string encoded_mime_expeced =
//        "b25lIHR3byB0aHJlZSBmb3VyIGZpdmUgc2l4IHNldmVuIGVpZ2h0IG5pbmUgdGVuIGVsZXZlbiB0\n"
//        "d2VsdmUgdGhpcnRlZW4gZm91cnRlZW4gZml2dGVlbiBzaXh0ZWVuIHNldmVudGVlbiBlaWdodGVl\n"
//        "biBuaW5ldGVlbiB0d2VudHkgdHdlbnR5LW9uZQ==";
//
//    if (encoded_mime != encoded_mime_expeced) {
//        std::cout << "Failed: base64_encode_mime s_6364_encoded" << std::endl;
//        all_tests_passed = false;
//    }
//
//    //
//    // Set 2nd parameter remove_linebreaks to true in order decode a
//    // mime encoded string:
//    //
//    std::string decoded_mime = base64_decode(encoded_mime, true);
//
//    if (decoded_mime != numbers) {
//        std::cout << "Failed: base64_decode(..., true)" << std::endl;
//        all_tests_passed = false;
//    }
//
//    // ----------------------------------------------
//
//    std::string unpadded_input = "YWJjZGVmZw"; // Note the 'missing' "=="
//    std::string unpadded_decoded = base64_decode(unpadded_input);
//    if (unpadded_decoded != "abcdefg") {
//        std::cout << "Failed to decode unpadded input " << unpadded_input << std::endl;
//        all_tests_passed = false;
//    }
//
//    unpadded_input = "YWJjZGU"; // Note the 'missing' "="
//    unpadded_decoded = base64_decode(unpadded_input);
//    if (unpadded_decoded != "abcde") {
//        std::cout << "Failed to decode unpadded input " << unpadded_input << std::endl;
//        std::cout << unpadded_decoded << std::endl;
//        all_tests_passed = false;
//    }
//
//    unpadded_input = "";
//    unpadded_decoded = base64_decode(unpadded_input);
//    if (unpadded_decoded != "") {
//        std::cout << "Failed to decode unpadded input " << unpadded_input << std::endl;
//        std::cout << unpadded_decoded << std::endl;
//        all_tests_passed = false;
//    }
//
//    unpadded_input = "YQ";
//    unpadded_decoded = base64_decode(unpadded_input);
//    if (unpadded_decoded != "a") {
//        std::cout << "Failed to decode unpadded input " << unpadded_input << std::endl;
//        std::cout << unpadded_decoded << std::endl;
//        all_tests_passed = false;
//    }
//
//    unpadded_input = "YWI";
//    unpadded_decoded = base64_decode(unpadded_input);
//    if (unpadded_decoded != "ab") {
//        std::cout << "Failed to decode unpadded input " << unpadded_input << std::endl;
//        std::cout << unpadded_decoded << std::endl;
//        all_tests_passed = false;
//    }
//
//    // --------------------------------------------------------------
//
//#if __cplusplus >= 201703L
// //
// // Test the string_view interface (which required C++17)
// //
//    std::string_view sv_orig = "foobarbaz";
//    std::string_view sv_encoded = base64_encode(sv_orig);
//
//    if (sv_encoded != "Zm9vYmFyYmF6") {
//        std::cout << "Failed to encode with string_view" << std::endl;
//        all_tests_passed = false;
//    }
//
//    std::string_view sv_decoded = base64_decode(sv_encoded);
//
//    if (sv_decoded != sv_orig) {
//        std::cout << "Failed to decode with string_view" << std::endl;
//        all_tests_passed = false;
//    }
//
//#endif
//
//    if (all_tests_passed) return 0;
//    return 1;
//}


//make_task_request(client, methods::POST, key_exchange)
    //    .then([](http_response response)
    //        {
    //            if (response.status_code() == status_codes::OK)
    //            {
    //                std::cout << "response.extract_json()" << std::endl;
    //                return response.extract_json();
    //            }
    //            std::cout << "task_from_result(json::value())" << response.status_code() << std::endl;
    //            return pplx::task_from_result(json::value());
    //        })
    //    .then([&](pplx::task<json::value> previoustask)
    //        {
    //            try
    //            {
    //                const json::value& answer = previoustask.get();
    //                //display_json(previoustask.get(), l"res: ");

    //                /*서버 키 디코딩*/
    //                std::wstring wencoded = answer.at(L"key_data").as_string();
    //                std::string encoded;
    //                encoded.assign(wencoded.begin(), wencoded.end());
    //                std::string decoded = base64_decode(encoded, false);
    //                unsigned char* client_keybuf = (unsigned char*)decoded.c_str();

    //                /*서버 키 사이즈 값 변환*/
    //                std::wstring wstr_size = answer.at(L"key_size").as_string();
    //                size_t clientkey_size = _wtoi(wstr_size.c_str());

    //                /*클라이언트로 부터 가져온 키, 키 길이로 버퍼를 key로 변환*/
    //                int size1 = ec_key_oct2key(tmpkey, client_keybuf, clientkey_size, nullptr);

    //                /*받은 클라이언트 키로 최종 비밀 키 생성*/
    //                SecretKey_Len = EC_DH(&Client_secret, Client_key, ec_key_get0_public_key(tmpkey));

    //                printf("\n");
    //                printf("client-secret key is : ");
    //                for (int i = 0; i < secretkey_len; i++)
    //                    printf(" %c", client_secret[i]);
    //                printf("\n");

    //                /*파일 데이터 디코딩*/
    //                wencoded = answer.at(L"zip_data").as_string();
    //                encoded.assign(wencoded.begin(), wencoded.end());
    //                decoded = base64_decode(encoded, false);
    //                const char* zip_data = decoded.c_str();
    //                
    //                /*파일 크기 디코딩*/
    //                wstr_size = answer.at(L"zip_size").as_string();
    //                size_t zip_size = _wtoi(wstr_size.c_str());
    //                downloadfile(zip_data, zip_size);

    //                /*해시 생성*/
    //                size_t hash_packet_size = 0;
    //                std::wstring filepath = L"c:\\test.zip";
    //                const char* hash_data = sha256_file(filepath, hash_packet_size);
    //                std::wstring whash_data(&hash_data[0], &hash_data[hash_packet_size - 1]);

    //                std::wstring whash_size = answer.at(L"hash_size").as_string();
    //                size_t hash_size = _wtoi(whash_size.c_str());

    //                if (hash_packet_size != hash_size)
    //                {
    //                    std::cout << "파일 해시 값 길이 다름" << std::endl;
    //                }
    //                std::wstring server_hash_data = answer.at(L"hash_data").as_string();

    //                /*파일 해시가 일치 할 경우*/
    //                if (!wcscmp(server_hash_data.c_str(), whash_data.c_str()))
    //                {
    //                    std::cout << "파일 해시 일치!!" << std::endl;
    //                    Unzipctl ctl("pwtest.zip");
    //                    ctl.extractall("pwtest", reinterpret_cast<const char*>(client_secret));
    //                }
    //            }
    //            catch (http_exception const& e)
    //            {
    //                wcout << e.what() << endl;
    //            }
    //        }).wait();

            //json::value& answer = make_request(client, methods::POST, key_exchange);

            //json::array& array = answer.as_array();
            //std::wcout << array.at(1) << std::endl;

            //int size1 = EC_KEY_oct2key(tmpkey, Client_keyBuf, size, nullptr); 
            //SecretKey_Len = EC_DH(&Client_Secret, Client_Key, EC_KEY_get0_public_key(tmpkey));

           /* printf("Client key is : ");
            for (int i = 0; i < SecretKey_Len; i++)
                printf(" %c", Client_Secret[i]);*/


//void handle_post11(http_request message) {
//    std::wcout << message.to_string() << std::endl;
//    json::value request_json;
//    json::value response_value;
//    response_value[L"response"] = json::value::string(L"input을 확인하세요.");
//
//    try {
//        request_json = message.extract_json().get();
//    }
//    catch (json::json_exception& e) {
//        std::cout << "message.extrace_json().get() Exception : " << e.what() << std::endl;
//        //response_value[L"response"] = json::value::string(e.what());
//        message.reply(status_codes::BadRequest, response_value);
//        return;
//    }
//
//    if (request_json.is_null() || request_json.size() > 4) {
//        std::wcout << L"Received_Json_Value : " << request_json << L" => Bad Request" << std::endl;
//        message.reply(status_codes::BadRequest, response_value);
//        return;
//    }
//
//    if (request_json.is_object() && request_json.size() == 4) {
//        bool hasApplicationId = request_json.has_field(L"app_type");
//        bool hasResourceId = request_json.has_field(L"resource_id");
//        bool hasCallerHandleId = request_json.has_field(L"caller_handle_id");
//        bool hasNewHandleId = request_json.has_field(L"new_handle_id");
//
//        if (!hasApplicationId || !hasResourceId || !hasCallerHandleId || !hasNewHandleId) {
//            std::wcout << L"Received_Json_Value From : " << request_json << L" => Bad Request" << std::endl;
//            message.reply(status_codes::BadRequest, response_value);
//            return;
//        }
//        else {
//            json::value response_success_value;
//            json::value json_value;
//            json_value[L"app_type"] = request_json.at(L"app_type");
//            json_value[L"resource_id"] = request_json.at(L"resource_id");
//            json_value[L"caller_handle_id"] = request_json.at(L"caller_handle_id");
//            json_value[L"new_handle_id"] = request_json.at(L"new_handle_id");
//
//            std::wcout << L"Received_Json_Value From : " << json_value << L" => successfully received" << std::endl;
//            std::cout << std::endl;
//
//            std::wstring app_type = request_json.at(L"app_type").as_string();
//            std::wstring resource_id = request_json.at(L"resource_id").as_string();
//            std::wstring caller_handle_id = request_json.at(L"caller_handle_id").as_string();
//            std::wstring new_handle_id = request_json.at(L"new_handle_id").as_string();
//
//            std::wstring shellCmd = L"./test_bash.sh " + app_type + L" " + resource_id + L" " + caller_handle_id + L" " + new_handle_id;
//            std::wcout << L"shellCmd : " << shellCmd << std::endl;
//            //			system(shellCmd.c_str());
//                        /*
//                         * 여기에 추가
//                         */
//            response_success_value[L"result"] = json::value::string(L"successfully received");
//            response_success_value[L"requestd_value"] = json_value;
//            message.reply(status_codes::OK, response_success_value);
//            return;
//        }
//    }
//    else
//        message.reply(status_codes::BadRequest, response_value);
//};