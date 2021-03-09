#include <windows.h>
#include <cpprest/http_listener.h>
#include <cpprest/http_client.h>
#include <cpprest/json.h>
#include <openssl/sha.h>
#include <atlconv.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
/*NID_X9_62_prime256v1*/
#include <openssl/evp.h>
#include "base64.h"
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <TCHAR.h>
#include  "zlib/ZipCTL.h"
#include "zlib/FolderList.h"

#pragma comment(lib, "cpprest141_2_10d")
 
#include <iostream> 
#include <set> 

#define TRACE(msg)            wcout << msg
#define TRACE_ACTION(a, k, v) wcout << a << L" (" << k << L", " << v << L")\n"

bool Server_keyExchange(const web::json::array& req_array, web::json::value& answer);
static char* sha256_file(const std::wstring path, size_t& packet_size);
void sha256_hash_string(unsigned char hash[SHA256_DIGEST_LENGTH], char outputBuffer[65]);

std::map<utility::string_t, utility::string_t> dictionary;
enum class DATA_TYPE { _REQ_CHECK = 0, _KEY_EXCHANGE };
void display_json(
    web::json::value const& jvalue,
    utility::string_t const& prefix)
{
    std::wcout << prefix << jvalue.serialize() << std::endl;
}

void convert_str2wstr(const std::string& src, std::wstring& dest)
{
    USES_CONVERSION;
    dest = A2W(src.c_str());
}

void convert_wstr2str(const std::wstring& src, std::string& dest)
{
    USES_CONVERSION;
    dest = W2A(src.c_str());
}

void sha256_hash_string(unsigned char hash[SHA256_DIGEST_LENGTH], char outputBuffer[65])
{
    int i = 0;
    for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf_s(outputBuffer + (i * 2), sizeof(outputBuffer), "%02x", hash[i]);
    }
    outputBuffer[64] = 0;
}

void handle_request(
    web::http::http_request request,
    std::function<void(web::json::value const&, web::json::value&)> action)
{
    auto answer = web::json::value::object();
    request
        .extract_json()
        .then([&answer, &action](pplx::task<web::json::value> task) {
        try
        {
            auto const& jvalue = task.get();
            display_json(jvalue, L"R: ");

            if (!jvalue.is_null())
            {
                action(jvalue, answer);
            }
        }
        catch (web::http::http_exception const& e)
        {
            std::wcout << e.what() << std::endl;
        }
            })
        .wait();
            display_json(answer, L"S: ");
            request.reply(web::http::status_codes::OK, answer);
}


void handle_put(web::http::http_request request)
{
    std::TRACE("\nhandle PUT\n");

    handle_request(
        request,
        [](web::json::value const& jvalue, web::json::value& answer)
        {
            for (auto const& e : jvalue.as_object()) //as_object : JSON 값이 객체 값인 경우에만 json 객체로 변환
            {
                if (e.second.is_string())
                {
                    auto key = e.first;
                    auto value = e.second.as_string();

                    if (dictionary.find(key) == dictionary.end())
                    {
                        std::TRACE_ACTION(L"added", key, value);
                        answer[key] = web::json::value::string(L"<put>");
                    }
                    else
                    {
                        std::TRACE_ACTION(L"updated", key, value);
                        answer[key] = web::json::value::string(L"<updated>");
                    }

                    dictionary[key] = value;
                }
            }
        });
}

void handle_del(web::http::http_request request)
{
    std::TRACE("\nhandle DEL\n");

    handle_request(
        request,
        [](web::json::value const& jvalue, web::json::value& answer)
        {
            std::set<utility::string_t> keys;
            for (auto const& e : jvalue.as_array())
            {
                if (e.is_string())
                {
                    auto key = e.as_string();

                    auto pos = dictionary.find(key);
                    if (pos == dictionary.end())
                    {
                        answer[key] = web::json::value::string(L"<failed>");
                    }
                    else
                    {
                        std::TRACE_ACTION(L"deleted", pos->first, pos->second);
                        answer[key] = web::json::value::string(L"<deleted>");
                        keys.insert(key);
                    }
                }
            }

            for (auto const& key : keys)
                dictionary.erase(key);
        });
}

/*Nice little macro to save a few lines.*/
void die(const char* reason)
{
    fprintf(stderr, reason);
    fflush(stderr);
    exit(1);
}

/*Key generation function for throwaway keys.*/
EC_KEY* gen_key(void)
{
    EC_KEY* key;

    key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    if (key == NULL)
        die("Failed to create lKey object.\n");

    if (!EC_KEY_generate_key(key))
        die("Failed to generate EC key.\n");

    return key;
}

/*Elliptic Curve Diffie-Hellman function*/
int EC_DH(unsigned char** secret, EC_KEY* key, const EC_POINT* pPub)
{
    int secretLen;

    secretLen = EC_GROUP_get_degree(EC_KEY_get0_group(key));
    secretLen = (secretLen + 7) / 8;

    //printf("key len : %d\n", secretLen);

    *secret = (unsigned char*)malloc(secretLen);
    if (!(*secret))
        die("Failed to allocate memory for secret.\n");
    secretLen = ECDH_compute_key(*secret, secretLen, pPub, key, NULL);

    //printf("secret key len : %d\n", secretLen);

    return secretLen;
}

char* ZipToBytes(const std::wstring& full_filePath, size_t& size)
{
    std::ifstream file(full_filePath, std::ios::binary | std::ios::in); // 입력 스트림 file객체 생성

    if (file.is_open())
    {
        // get file size		
        file.seekg(0, std::ios::end);
        size = file.tellg();

        file.clear();
        file.seekg(0, std::ios::beg);

        char* pBuf = new char[size];
        memset(pBuf, 0, size);

        file.read(pBuf, size); // 스트림에서 size 개의 문자를 추출 하여 puf가 가리키는 배열에 저장합니다 .
        file.close();
        return pBuf;
    }
    else
        return nullptr;

    return nullptr;
}
bool PW_zip(const std::string& folder_Path, const char* password)
{
    FolderList::ZIP_FLIST flist;

    FolderList fn;
    fn(folder_Path, flist);

    ZipCTL ctl("pwtest.zip"); //만들 파일 이름
    ctl.make(folder_Path.c_str(), flist, password); //압축할 폴더 경로
    return true;
}

static char* sha256_file(const std::wstring path, size_t& packet_size)
{
    std::ifstream file(path, std::ios::binary | std::ios::in);
    file.seekg(0, std::ios::end);
    size_t file_size = file.tellg();
    file.clear();
    file.seekg(0, std::ios::beg);

    static char file_hash[65] = { 0, };
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    const int bufSize = 32768;

    char* buffer = (char*)malloc(bufSize);
    int bytesRead = 0;

    while (!file.eof())
    {
        file.read(buffer, bufSize);
        SHA256_Update(&sha256, buffer, file.gcount());
    }
    SHA256_Final(hash, &sha256);
    sha256_hash_string(hash, file_hash); 

    packet_size = sizeof(file_hash);
    file.close();
    free(buffer);
    return file_hash;
}

unsigned char* Server_KeyExchange(const web::json::value& req_array, web::json::value& answer) {
    EC_KEY* Server_Key, * tmpkey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    int SecretKey_Len;
    unsigned char* Secret_key = NULL;
    unsigned char* Server_keyBuf = NULL;

    /*클라이언트 키 디코딩*/
    std::wstring wstr_encoded = req_array.at(L"key_data").as_string();
    std::string str_encoded;
    convert_wstr2str(wstr_encoded, str_encoded);
    std::string decoded = base64_decode(str_encoded, false);
    unsigned char* Client_keyBuf = (unsigned char*)decoded.c_str();
    wstr_encoded.clear();

    /*클라이언트 키 사이즈 값 변환*/
    std::wstring wstr_size = req_array.at(L"key_size").as_string();
    size_t ClientKey_size = _wtoi(wstr_size.c_str());

    /*클라이언트로 부터 가져온 키, 키 길이로 버퍼를 key로 변환*/
    int size1 = EC_KEY_oct2key(tmpkey, Client_keyBuf, ClientKey_size, nullptr);
    str_encoded.clear();
    decoded.clear();
    wstr_size.clear();

    /*서버 키 생성 및 버퍼 대입*/
    Server_Key = gen_key();
    int size = EC_KEY_key2buf(Server_Key, EC_KEY_get_conv_form(Server_Key), &Server_keyBuf, nullptr);
    std::cout << "\n Server_keyBuf : " << Server_keyBuf << std::endl;

    /*서버 키를 보내기 위한 인코딩*/
    str_encoded = base64_encode(reinterpret_cast<const unsigned char*>(Server_keyBuf), (size_t)size, false);
    convert_str2wstr(str_encoded, wstr_encoded);

    /*서버의 키 길이를 보내기 위한 wstring 변환*/
    std::string str_size = std::to_string(size);
    convert_str2wstr(str_size, wstr_size);

    answer[L"key_data"] = web::json::value::string(wstr_encoded);
    answer[L"key_size"] = web::json::value::string(wstr_size);

    /*받은 클라이언트 키로 최종 비밀 키 생성*/
    SecretKey_Len = EC_DH(&Secret_key, Server_Key, EC_KEY_get0_public_key(tmpkey));

    std::cout << std::endl;
    printf("Server-secret key : ");
    for (int i = 0; i < SecretKey_Len; i++)
        printf(" %c", Secret_key[i]);
    std::cout << std::endl;

    EC_KEY_free(Server_Key);
    OPENSSL_free(Server_keyBuf);
    return Secret_key;
}

bool Server_FileCheck(const web::json::value& req_array, web::json::value& answer)
{
    /*서버 비밀 키 생성*/
    unsigned char* Secret_key = Server_KeyExchange(req_array, answer);

    /*최종 비밀 키로 암호 압축*/
    std::string folder_Path = "C:\\server_file";
    PW_zip(folder_Path, reinterpret_cast<const char*>(Secret_key));

    /*암호 압축된 파일 buf에 담기, 사이즈 가져오기*/
    size_t zip_packet_size = 0;
    std::wstring wfolder_Path = L"C:\\Users\\TESTPC\\Desktop\\backup\\cpprest_test_02_24\\Project1\\pwtest.zip";
    const char* zip_data = ZipToBytes(wfolder_Path, zip_packet_size);
    std::string zip_encoded = base64_encode(reinterpret_cast<const unsigned char*>(zip_data), zip_packet_size, false);
    std::wstring wzip_encoded(zip_encoded.begin(), zip_encoded.end());

    /*압축 된 집 크기 wstring으로 변환*/
    std::string spacket_size = std::to_string(zip_packet_size);
    std::wstring wpacket_size;
    convert_str2wstr(spacket_size, wpacket_size);

    answer[L"zip_data"] = web::json::value::string(wzip_encoded);
    answer[L"zip_size"] = web::json::value::string(wpacket_size);
    spacket_size.clear();
    wpacket_size.clear();

    /*해시 생성*/
    size_t hash_packet_size = 0;
    const char* hash_data = sha256_file(wfolder_Path, hash_packet_size);
    std::wstring wHash_data(&hash_data[0], &hash_data[hash_packet_size - 1]);

    /*해시 사이즈 wstring으로 변환*/
    spacket_size = std::to_string(hash_packet_size);
    convert_str2wstr(spacket_size, wpacket_size);

    answer[L"hash_size"] = web::json::value::string(wpacket_size);
    answer[L"hash_data"] = web::json::value::string(wHash_data);
    display_json(answer, L"Server-Response : ");

    free(Secret_key);
    CRYPTO_cleanup_all_ex_data();
    delete[] zip_data;
    return true;
}

bool Server_VersionCheck(const web::json::value& req_array, web::json::value& answer)
{
    std::wstring wstr_encoded = req_array.at(L"version").as_string();

    web::http::uri_builder uri(L"https://api.github.com/repos/BeomBeom2/Zabbix/releases/latest");
    auto addr = uri.to_string();
    web::http::client::http_client github(U("https://api.github.com/"));

    github.request(web::http::methods::GET, addr).then([&](web::http::http_response response)
        {
            if (response.status_code() == web::http::status_codes::OK)
            {
                web::json::value latest_data = response.extract_json().get();
                std::wstring version = latest_data.at(L"tag_name").as_string();

                answer[L"version"] = web::json::value::string(version);
                if(!wcscmp(wstr_encoded.c_str(), version.c_str()))
                {
                    answer[L"result"] = web::json::value::string(L"true");
                }
                else 
                    answer[L"result"] = web::json::value::string(L"false");
            }
            else
                printf("ERROR, status code %u returned.\n", response.status_code());
        }).wait();

    return true;
}

bool handle_post(web::http::http_request request)
{
    std::TRACE("\nhandle POST\n");
    web::json::value answer = web::json::value::object();
    bool result = false;
    web::json::value request_json;
    try {
        request_json = request.extract_json().get();
        display_json(request_json, L"Client Request : ");
    }
    catch (web::json::json_exception& e) {
        std::cout << "Error Msg : " << e.what() << std::endl;
        request.reply(web::http::status_codes::BadRequest, answer);
        return false;
    }
    std::wstring data_type = request_json.at(L"DATA_TYPE").as_string();

    if (!wcscmp(data_type.c_str(), L"_UPDATE_CHECK"))
    {
        result = Server_VersionCheck(request_json, answer);
    }
    else if (!wcscmp(data_type.c_str(), L"_KEY_EXCHANGE"))
    {
        result = Server_FileCheck(request_json, answer);
    }
    if (result)
    {
        std::cout << " \n Response 성 공 \n" << std::endl;
        display_json(answer, L"Server-Response : ");
        request.reply(web::http::status_codes::OK, answer);
        return true;
    }
    else
    {
        request.reply(web::http::status_codes::BadRequest, answer);
        return false;
    }
} 



int main()
{
    web::http::experimental::listener::http_listener listener(L"http://127.0.0.1:36259");

    listener.open();
    listener.support(web::http::methods::POST, handle_post);
    listener.support(web::http::methods::PUT, handle_put);
    listener.support(web::http::methods::DEL, handle_del);

    try
    {
        listener
            .open()
            .then([&listener]() {std::TRACE(L"\nStarting to listen\n"); })
            .wait();

        while (true);
    }
    catch (std::exception const& e)
    {
        std::wcout << e.what() << std::endl;
    }
    return 0;
}