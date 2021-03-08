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
#include <tchar.h>
#include <urlmon.h> 
#pragma comment(lib, "cpprest141_2_10d.lib")
#pragma comment(lib,"version.lib")
#pragma comment (lib,"urlmon.lib") 

enum DATA_TYPE { _KEY_CHECK };

static const char* base64_chars[2] = {
             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789"
             "+/",

             "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
             "abcdefghijklmnopqrstuvwxyz"
             "0123456789"
             "-_" };

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

pplx::task<web::http::http_response> make_task_request(
    web::http::client::http_client& client,
    web::http::method mtd,
    web::json::value const& jvalue)
{
    return (mtd == web::http::methods::GET || mtd == web::http::methods::HEAD) ?
        client.request(mtd, L"/restdemo") :
        client.request(mtd, L"/restdemo", jvalue);
}

void make_request(
    web::http::client::http_client& client,
    web::http::method mtd,
    web::json::value const& jvalue, web::json::value* answer)
{
    make_task_request(client, mtd, jvalue)
        .then([](web::http::http_response response)
            {
                if (response.status_code() == web::http::status_codes::OK)
                {
                    //std::cout << "response.extract_json()" << std::endl;
                    return response.extract_json();
                }
                //std::cout << "task_from_result(json::value())" << response.status_code() << std::endl;
                return pplx::task_from_result(web::json::value());
            })
        .then([&](pplx::task<web::json::value> previousTask)
            {
                try
                {
                    *answer = previousTask.get();
                    display_json(*answer, L"Server-Response : ");
                }
                catch (web::http::http_exception const& e)
                {
                    std::wcout << e.what() << std::endl;
                }
            })
                .wait();

    return;
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

bool requestIngerity(web::http::client::http_client& client)
{
    auto getHashCheck = web::json::value::array();
    getHashCheck[0] = web::json::value::string(L"_REQ_CHECK");

    std::wstring path = L"C:\\test.zip";
    std::ifstream file(path, std::ios::binary | std::ios::in);

    file.seekg(0, std::ios::end);
    size_t file_size = file.tellg();
    file.clear();
    file.seekg(0, std::ios::beg);

    size_t hash_size = 65;
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
    file.close();

    /*ANSI to UNICODE*/
    int lenA = lstrlenA(file_hash); // #include <winbase.h>
    int lenW;
    BSTR unicode_hash = NULL; // #include <oleauto.h>

    lenW = ::MultiByteToWideChar(CP_ACP, 0, file_hash, lenA, 0, 0); // #include <stringapiset.h>
    if (lenW > 0)
    {
        // 변환 성공 여부 확인
        unicode_hash = ::SysAllocStringLen(0, lenW); // #include <oleauto.h>
        ::MultiByteToWideChar(CP_ACP, 0, file_hash, lenA, unicode_hash, lenW);
    }

    getHashCheck[1] = web::json::value::string(unicode_hash);
    display_json(getHashCheck, L"S: ");
    //make_request(client, methods::POST, getHashCheck, );

    ::SysFreeString(unicode_hash);  // free BSTR #include <oleauto.h>
    free(buffer);
    return true;
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

    std::cout << "Client hash is : " << file_hash << std::endl;

    packet_size = sizeof(file_hash);
    file.close();
    free(buffer);
    return file_hash;
}

bool downloadFile(const char* buf, const size_t& size, const std::wstring path) //buf = 실제 파일 데이터 값, size = 파일 데이터 크기
{ // 1GB = 2 ^ 30, 10 ^ 9 = 1,073,741,824         unsigned int_MAX = 4,294,967,295
    size_t recv_filesize = 0;

    std::ofstream file(path, std::ios::binary | std::ios::out);
    file.write(buf, size);
    file.close();

    return true;
}
unsigned char* Client_keyExchange(web::http::client::http_client& client, web::json::value& answer)
{
    auto key_exchange = web::json::value::object();
    EC_KEY* Client_Key, * tmpkey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    int SecretKey_Len;
    unsigned char* Secret_key = NULL;
    unsigned char* Client_keyBuf = NULL;
    unsigned char* Server_keyBuf = NULL;

    /*키 생성*/
    Client_Key = gen_key();
    int size = EC_KEY_key2buf(Client_Key, EC_KEY_get_conv_form(Client_Key), &Client_keyBuf, nullptr);
    
    /*키를 보내기 위해 인코딩*/
    std::string Client_keyStr(reinterpret_cast<const char*>(Client_keyBuf));
    std::string encoded = base64_encode(reinterpret_cast<const unsigned char*>(Client_keyBuf), (size_t)size, false);
    std::wstring wEncoded;
    convert_str2wstr(encoded, wEncoded);
    Client_keyStr.clear();
    encoded.clear();  

    /*키 길이를 보내기 위한 wstring 변환*/
    std::string str_size = std::to_string(size);
    std::wstring wstr_size;
    wstr_size.assign(str_size.begin(), str_size.end());
    str_size.clear();

    key_exchange[L"key_data"] = web::json::value::string(wEncoded);
    key_exchange[L"key_size"] = web::json::value::string(wstr_size);
    key_exchange[L"DATA_TYPE"] = web::json::value::string(L"_KEY_EXCHANGE");
    display_json(key_exchange, L"Client-Request : ");
    wEncoded.clear();
    wstr_size.clear();

    make_request(client, web::http::methods::POST, key_exchange, &answer);

    /*서버 키 디코딩*/
    wEncoded = answer.at(L"key_data").as_string();
    convert_wstr2str(wEncoded, encoded);
    std::string decoded = base64_decode(encoded, false);
    Server_keyBuf = (unsigned char*)decoded.c_str();
    std::cout << "\n Server_keyBuf from Server : " << Server_keyBuf << std::endl;
    /*서버 키 사이즈 값 변환*/
    wstr_size = answer.at(L"key_size").as_string();
    size_t ServerKey_size = _wtoi(wstr_size.c_str());

    /*서버로 부터 가져온 키, 키 길이로 버퍼를 key로 변환*/
    int size1 = EC_KEY_oct2key(tmpkey, Server_keyBuf, ServerKey_size, nullptr);
    decoded.clear();

    /*서버 키로 비밀 키 생성*/
    SecretKey_Len = EC_DH(&Secret_key, Client_Key, EC_KEY_get0_public_key(tmpkey));

    std::cout << std::endl;
    printf("Client-secret key is : ");
    for (int i = 0; i < SecretKey_Len; i++)
        printf(" %c", Secret_key[i]);
    std::cout << std::endl;

    OPENSSL_free(Client_keyBuf);
    EC_KEY_free(Client_Key);
    return Secret_key;
}

bool Client_FileCheck(web::http::client::http_client& client)
{
    /*비밀 키 생성*/
    web::json::value answer;
    unsigned char* Secret_key = Client_keyExchange(client, answer);

    /*파일 데이터 디코딩*/
    std::wstring wEncoded = answer.at(L"zip_data").as_string();
    std::string encoded;
    encoded.assign(wEncoded.begin(), wEncoded.end());
    std::string decoded = base64_decode(encoded, false);
    const char* zip_data = decoded.c_str();
    wEncoded.clear();
    encoded.clear();

    /*파일 크기 디코딩, 파일 다운*/
    std::wstring wstr_size = answer.at(L"zip_size").as_string();
    size_t zip_size = _wtoi(wstr_size.c_str());
    std::wstring filePath = L"C:\\Client_downFIle\\pwtest.zip";
    downloadFile(zip_data, zip_size, filePath);
    decoded.clear();
    wstr_size.clear();

    /*해시 생성*/
    size_t hash_packet_size = 0; 
    const char* hash_data = sha256_file(filePath, hash_packet_size);
    std::wstring wHash_data(&hash_data[0], &hash_data[hash_packet_size - 1]);

    /*서버 해시 값 가져오기*/
    std::wstring whash_size = answer.at(L"hash_size").as_string();
    size_t hash_size = _wtoi(whash_size.c_str());

    if (hash_packet_size != hash_size)
    {
        std::cout << "파일 해시 값 길이 다름" << std::endl;
        return false;
    }
    std::wstring server_hash_data = answer.at(L"hash_data").as_string();

    /*파일 해시가 일치 할 경우*/
    if (!wcscmp(server_hash_data.c_str(), wHash_data.c_str()))
    {
        std::cout << "파일 해시 일치" << std::endl;
        UnzipCTL ctl("C:\\Client_downFIle\\pwtest.zip"); //파일 위치
        ctl.extractall("C:\\Client_downFIle", reinterpret_cast<const char*>(Secret_key)); //압축을 풀 폴더 경로
    }
    else
        std::cout << "파일 변조" << std::endl;
    
    free(Secret_key);
    CRYPTO_cleanup_all_ex_data();
    return 0;
}
std::wstring file_version()
{
    web::json::value answer;
    auto updata_check_json = web::json::value::object();
    // 버전정보를 담을 버퍼
    char* buffer = NULL;
    // 버전을 확인할 파일
    std::wstring name(L"C:\\test1\\chrome.exe");
    DWORD infoSize = 0;
    std::wstring wVersion = L"";

    // 파일로부터 버전정보데이터의 크기가 얼마인지를 구합니다.
    infoSize = GetFileVersionInfoSize(name.c_str(), 0);
    if (infoSize != 0)
    {
    // 버퍼할당
    buffer = new char[infoSize];
        if (buffer)
        {
            // 버전정보데이터를 가져옵니다.
            if (GetFileVersionInfo(name.c_str(), 0, infoSize, buffer) != 0)
            {
                VS_FIXEDFILEINFO* pFineInfo = NULL;
                UINT bufLen = 0;
                // buffer로 부터 VS_FIXEDFILEINFO 정보를 가져옵니다.
                if (VerQueryValue(buffer, L"\\", (LPVOID*)&pFineInfo, &bufLen) != 0)
                {
                    WORD majorVer, minorVer, buildNum, revisionNum;
                    majorVer = HIWORD(pFineInfo->dwFileVersionMS);
                    minorVer = LOWORD(pFineInfo->dwFileVersionMS);
                    buildNum = HIWORD(pFineInfo->dwFileVersionLS);
                    revisionNum = LOWORD(pFineInfo->dwFileVersionLS);

                    wVersion = std::to_wstring(majorVer) + L"." + std::to_wstring(minorVer) + L"." + std::to_wstring(buildNum) + L"." + std::to_wstring(revisionNum);
                }
            }
            delete[] buffer;
        } 
    }
    return wVersion;
}

bool VersionCheck()
{
    std::wstring&& Client_version = file_version();
    web::json::value info;
    web::json::value Client_fileVer = web::json::value::object();
    web::http::uri_builder uri(L"https://api.github.com/repos/BeomBeom2/Zabbix/releases/latest");
    auto addr = uri.to_string();
    web::http::client::http_client* github = new web::http::client::http_client(U("https://api.github.com/"));
    web::json::value latest_info;
    std::wstring latest_body;
    std::wstring wfolder_Path = L"C:\\Unzip\\"; 

    github->request(web::http::methods::GET, addr).then([&](web::http::http_response response)
    {
        if (response.status_code() == web::http::status_codes::OK)
        {
            /*response에서 버전정보, 설치파일 url, release body, 설치파일 이름 parse*/
            latest_info = response.extract_json().get();
            info[L"server_ver"] = latest_info.at(L"tag_name");
            latest_body = latest_info[L"body"].as_string();
            auto array = latest_info[L"assets"].as_array();
            info[L"file_url"] = array[0][L"browser_download_url"];
            info[L"file_name"] = array[0][L"name"];
            wfolder_Path += info[L"file_name"].as_string(); 

            /*release body에서 hash값 parse */
            size_t index = latest_body.find(L"hash"); 
            if (index != std::wstring::npos)
            {
                std::wstring hash_str = latest_body.substr(index);
                info[L"file_hash"] = web::json::value(hash_str.substr(hash_str.find(L"\"") + 1, 64));
                display_json(info[L"file_hash"], L"Server hash : ");
            }
            else
            {
                std::cout << "hash search error" << std::endl;
                info[L"file_hash"] = web::json::value(L"hash load error");
            }

            std::wcout << L"Client version is : " << Client_version << std::endl;
            std::wcout << L"Server version is : " << info[L"server_ver"] << std::endl;

            /*현재 파일 버전이 서버 버전과 일치 할 경우(최신 버전일 경우)*/
            if (!wcscmp(Client_version.c_str(), info[L"server_ver"].as_string().c_str()))
            {
                std::cout << "current version is latest version!" << std::endl;
            }
            else
            {
                std::cout << "current version is not latest version\n download file!" << std::endl;
                /*URL 바이너리 다운로드*/
                HRESULT hr = URLDownloadToFile(NULL, info[L"file_url"].as_string().c_str(),
                    wfolder_Path.c_str(), 0, NULL);

                /*설치파일 해시 생성*/
                size_t hash_packet_size = 0;
                const char* hash_data = sha256_file(wfolder_Path, hash_packet_size);
                std::wstring wHash_data(&hash_data[0], &hash_data[hash_packet_size - 1]);

                if (!wcscmp(wHash_data.c_str(), info[L"file_hash"].as_string().c_str()))
                {
                    std::cout << "파일 해시 일치" << std::endl;
                    HINSTANCE result = ::ShellExecute(NULL, _T("runas"), wfolder_Path.c_str(), NULL, NULL, SW_SHOW);
                }
                else
                {
                    /*파일 해시가 불 일치할 경우 파일 재 다운로드 및 해시 검사*/
                    std::cout << "파일 해시 불 일치 \n다운로드 재시작" << std::endl;
                    HRESULT hr = URLDownloadToFile(NULL, info[L"file_hash"].as_string().c_str(),
                        wfolder_Path.c_str(), 0, NULL);

                    size_t hash_packet_size = 0;
                    const char* hash_data = sha256_file(wfolder_Path, hash_packet_size);
                    std::wstring wHash_data(&hash_data[0], &hash_data[hash_packet_size - 1]);
                    
                    if (!wcscmp(wHash_data.c_str(), info[L"file_hash"].as_string().c_str()))
                    {
                        std::cout << "파일 해시 일치" << std::endl;
                        HINSTANCE result = ::ShellExecute(NULL, _T("runas"), wfolder_Path.c_str(), NULL, NULL, SW_SHOW);
                    }
                    else
                        /*두번 째도 해시가 불일치할 경우*/
                        std::cout << "관리자에게 문의" << std::endl;
                }
            }
        }
        else
        {
            printf("REQ ERROR, status code %u. \n", response.status_code());
        }
    }).wait();

    return true;
}

void Client_class()
{ 
}

int main()
{
    web::http::client::http_client client(U("http://127.0.0.1:36259"));
    VersionCheck();
    //update_check(client);
    //Client_FileCheck(client);
}