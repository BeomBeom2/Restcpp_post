#include <windows.h>
#include <cpprest/http_client.h>
#include <cpprest/json.h>
#include <openssl/sha.h> 
#include <atlconv.h>
#include <openssl/ec.h> 
#include <openssl/ecdh.h>
/*NID_X9_62_prime256v1*/
#include <openssl/evp.h>
#include <stdlib.h>
#include <iostream>
#include <string>
#include "base64.h"
#include <TCHAR.h>
#include  "zlib/UnZipCTL.h"
#include "zlib/FolderList.h"
#include <urlmon.h> 
#pragma comment(lib, "cpprest141_2_10d.lib")
#pragma comment(lib,"version.lib")
#pragma comment (lib,"urlmon.lib")  

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

//bool requestIngerity(web::http::client::http_client& client)
//{
//    auto getHashCheck = web::json::value::array();
//    getHashCheck[0] = web::json::value::string(L"_REQ_CHECK");
//
//    std::wstring path = L"C:\\test.zip";
//    std::ifstream file(path, std::ios::binary | std::ios::in);
//
//    file.seekg(0, std::ios::end);
//    size_t file_size = file.tellg();
//    file.clear();
//    file.seekg(0, std::ios::beg);
//
//    size_t hash_size = 65;
//    static char file_hash[65] = { 0, };
//    unsigned char hash[SHA256_DIGEST_LENGTH];
//    SHA256_CTX sha256;
//    SHA256_Init(&sha256);
//    const int bufSize = 32768;
//
//    char* buffer = (char*)malloc(bufSize);
//    int bytesRead = 0;
//
//    while (!file.eof())
//    {
//        file.read(buffer, bufSize);
//        SHA256_Update(&sha256, buffer, file.gcount());
//    }
//    SHA256_Final(hash, &sha256);
//    sha256_hash_string(hash, file_hash);
//    file.close();
//
//    /*ANSI to UNICODE*/
//    int lenA = lstrlenA(file_hash); // #include <winbase.h>
//    int lenW;
//    BSTR unicode_hash = NULL; // #include <oleauto.h>
//
//    lenW = ::MultiByteToWideChar(CP_ACP, 0, file_hash, lenA, 0, 0); // #include <stringapiset.h>
//    if (lenW > 0)
//    {
//        // 변환 성공 여부 확인
//        unicode_hash = ::SysAllocStringLen(0, lenW); // #include <oleauto.h>
//        ::MultiByteToWideChar(CP_ACP, 0, file_hash, lenA, unicode_hash, lenW);
//    }
//
//    getHashCheck[1] = web::json::value::string(unicode_hash);
//    display_json(getHashCheck, L"S: ");
//    //make_request(client, methods::POST, getHashCheck, );
//
//    ::SysFreeString(unicode_hash);  // free BSTR #include <oleauto.h>
//    free(buffer);
//    return true;
//}

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

static char* sha256_file(const std::wstring path, size_t& packet_size, char* file_hash)
{
    std::ifstream file(path, std::ios::binary | std::ios::in);
    file.seekg(0, std::ios::end);
    size_t file_size = file.tellg();
    file.clear();
    file.seekg(0, std::ios::beg);

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

//unsigned char* Client_keyExchange(web::http::client::http_client& client, web::json::value& answer)
//{
//    auto key_exchange = web::json::value::object();
//    EC_KEY* Client_Key, * tmpkey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
//    int SecretKey_Len;
//    unsigned char* Secret_key = NULL;
//    unsigned char* Client_keyBuf = NULL;
//    unsigned char* Server_keyBuf = NULL;
//
//    /*키 생성*/
//    Client_Key = gen_key();
//    size_t size = EC_KEY_key2buf(Client_Key, EC_KEY_get_conv_form(Client_Key), &Client_keyBuf, nullptr);
//    
//    /*키를 보내기 위해 인코딩*/
//    std::string Client_keyStr(reinterpret_cast<const char*>(Client_keyBuf));
//    std::string encoded = base64_encode(reinterpret_cast<const unsigned char*>(Client_keyBuf), size, false);
//    std::wstring wEncoded;
//    convert_str2wstr(encoded, wEncoded);
//    Client_keyStr.clear();
//    encoded.clear();  
//
//    /*키 길이를 보내기 위한 wstring 변환*/
//    std::string str_size = std::to_string(size);
//    std::wstring wstr_size;
//    wstr_size.assign(str_size.begin(), str_size.end());
//    str_size.clear();
//
//    key_exchange[L"key_data"] = web::json::value::string(wEncoded);
//    key_exchange[L"key_size"] = web::json::value::string(wstr_size);
//    key_exchange[L"DATA_TYPE"] = web::json::value::string(L"_KEY_EXCHANGE");
//    display_json(key_exchange, L"Client-Request : ");
//    wEncoded.clear();
//    wstr_size.clear();
//
//    make_request(client, web::http::methods::POST, key_exchange, &answer);
//
//    /*서버 키 디코딩*/
//    wEncoded = answer.at(L"key_data").as_string();
//    convert_wstr2str(wEncoded, encoded);
//    std::string decoded = base64_decode(encoded, false);
//    Server_keyBuf = (unsigned char*)decoded.c_str();
//    std::cout << "\n Server_keyBuf from Server : " << Server_keyBuf << std::endl;
//    /*서버 키 사이즈 값 변환*/
//    wstr_size = answer.at(L"key_size").as_string();
//    size_t ServerKey_size = _wtoi(wstr_size.c_str());
//
//    /*서버로 부터 가져온 키, 키 길이로 버퍼를 key로 변환*/
//    int size1 = EC_KEY_oct2key(tmpkey, Server_keyBuf, ServerKey_size, nullptr);
//    decoded.clear();
//
//    /*서버 키로 비밀 키 생성*/
//    SecretKey_Len = EC_DH(&Secret_key, Client_Key, EC_KEY_get0_public_key(tmpkey));
//
//    std::cout << std::endl;
//    printf("Client-secret key is : ");
//    for (int i = 0; i < SecretKey_Len; i++)
//        printf(" %c", Secret_key[i]);
//    std::cout << std::endl;
//
//    OPENSSL_free(Client_keyBuf);
//    EC_KEY_free(Client_Key);
//    return Secret_key;
//}

/*서버와 키 교환*/
//bool Client_FileCheck(web::http::client::http_client& client)
//{
//    /*비밀 키 생성*/
//    web::json::value answer;
//    unsigned char* Secret_key = Client_keyExchange(client, answer);
//
//    /*파일 데이터 디코딩*/
//    std::wstring wEncoded = answer.at(L"zip_data").as_string();
//    std::string encoded;
//    encoded.assign(wEncoded.begin(), wEncoded.end());
//    std::string decoded = base64_decode(encoded, false);
//    const char* zip_data = decoded.c_str();
//    wEncoded.clear();
//    encoded.clear();
//
//    /*파일 크기 디코딩, 파일 다운*/
//    std::wstring wstr_size = answer.at(L"zip_size").as_string();
//    size_t zip_size = _wtoi(wstr_size.c_str());
//    std::wstring filePath = L"C:\\Client_downFIle\\pwtest.zip";
//    downloadFile(zip_data, zip_size, filePath);
//    decoded.clear();
//    wstr_size.clear();
//
//    /*해시 생성*/
//    size_t hash_packet_size = 0; 
//    const char* hash_data = sha256_file(filePath, hash_packet_size);
//    std::wstring wHash_data(&hash_data[0], &hash_data[hash_packet_size - 1]);
//
//    /*서버 해시 값 가져오기*/
//    std::wstring whash_size = answer.at(L"hash_size").as_string();
//    size_t hash_size = _wtoi(whash_size.c_str());
//
//    if (hash_packet_size != hash_size)
//    {
//        std::cout << "파일 해시 값 길이 다름" << std::endl;
//        return false;
//    }
//    std::wstring server_hash_data = answer.at(L"hash_data").as_string();
//
//    /*파일 해시가 일치 할 경우*/
//    if (!wcscmp(server_hash_data.c_str(), wHash_data.c_str()))
//    {
//        std::cout << "파일 해시 일치" << std::endl;
//        UnzipCTL ctl("C:\\Client_downFIle\\pwtest.zip"); //파일 위치
//        ctl.extractall("C:\\Client_downFIle", reinterpret_cast<const char*>(Secret_key)); //압축을 풀 폴더 경로
//    }
//    else
//        std::cout << "파일 변조" << std::endl;
//    
//    free(Secret_key);
//    CRYPTO_cleanup_all_ex_data();
//    return 0;
//}

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

                    wVersion = std::to_wstring(majorVer) + L"." + std::to_wstring(minorVer) +
                        L"." + std::to_wstring(buildNum) + L"." + std::to_wstring(revisionNum);
                }
            }
            delete[] buffer;
        }
    }
    return wVersion;
}

/*경로 내에 없는 폴더 생성*/
//void MakeSubFolder(LPCTSTR path)
//{
//    if (!SetCurrentDirectory(path)) {
//        TCHAR tmpPath[MAX_PATH];
//        memset(tmpPath, 0, MAX_PATH);
//        _tcscpy(tmpPath, path);
//
//        LPTSTR rPt = _tcsrchr(tmpPath, '\\');
//
//        if (rPt) {
//            *rPt = 0;
//            MakeSubFolder(tmpPath);
//        }
//        CreateDirectory(path, NULL);
//    }
//} 

int  Unzip(const char* path)
{
    do {
        unzFile uf = unzOpen(path);
        if (NULL == uf) break;

        int ret = unzGoToFirstFile(uf);
        if (UNZ_OK != ret) {
            unzClose(uf);
            break;
        }

        /// 현재  방문중인  파일  목록  정보  추출   
        const  int MAX_COMMENT = 256;

        char filename[MAX_PATH];
        char comment[MAX_COMMENT];

        unz_file_info info;
        unzGetCurrentFileInfo(uf, &info, filename, MAX_PATH, NULL, 0, comment, MAX_COMMENT);

        std::cout << "filename:" << filename << " Comment:" << comment << std::endl;
        std::cout << " compressed_size:" << info.compressed_size << " uncompressed_size:" << info.uncompressed_size << std::endl;


        //현재  파일을  열기.
        ret = unzOpenCurrentFile(uf);

        const  int BUF = 1024;
        Bytef in[BUF];
        int readsize(0);

        std::ofstream op;
        op.open(filename, std::ios_base::binary);

        do {
            readsize = unzReadCurrentFile(uf, (void*)in, BUF);
            op.write((const  char*)in, readsize);

        } while (0 != readsize);

        op.close();

        unzCloseCurrentFile(uf);

        /////
        unzClose(uf);

    } while (false);

    system("pause");

    return 0;
}

bool VersionCheck()
{
    std::wstring&& Client_version = L"v1.3.0" /*file_version()*/;
    web::json::value info;
    std::wstring access_token = L"?ref=master&access_token=912b6197c5734eb476c87b0ad86d602b55f07ba4";
    web::http::uri_builder uri(L"https://api.github.com/repos/BeomBeom2/Private_test/releases/latest?ref=master&access_token=912b6197c5734eb476c87b0ad86d602b55f07ba4");
    auto addr = uri.to_string();
    web::http::client::http_client* github = new web::http::client::http_client(U("https://api.github.com/"));
    web::json::value latest_info;
    std::wstring latest_body;
    bool Needed_download = false;

    github->request(web::http::methods::GET, addr).then([&](web::http::http_response response)
        {
            if (response.status_code() == web::http::status_codes::OK)
            {
                /*response에서 버전정보, 설치파일 url, release body, 설치파일 이름 parse*/
                latest_info = response.extract_json().get();
                info[L"server_ver"] = latest_info.at(L"tag_name");
                info[L"zipball_url"] = latest_info.at(L"zipball_url");
                info[L"zip_name"] = latest_info[L"name"];
                latest_body = latest_info[L"body"].as_string();
                auto array = latest_info[L"assets"].as_array();
                //info[L"file_url"] = array[0][L"browser_download_url"];

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

                std::wcout << L"Client version is : " << L"\"" << Client_version << L"\"" << std::endl;
                std::wcout << L"Server version is : " << info[L"server_ver"] << std::endl;

                /*현재 파일 버전이 서버 버전과 일치 할 경우(최신 버전일 경우)*/
                if (!wcscmp(Client_version.c_str(), info[L"server_ver"].as_string().c_str()))
                {
                    std::cout << "current version is latest version!" << std::endl;
                }
                else
                    Needed_download = true;
            }
            else
            {
                std::cerr << "REQ ERROR, status code " << response.status_code() << std::endl;
            }
        }).wait();


        /*최신 설치파일이 필요한 경우*/
        if (Needed_download)
        {
            std::wstring zip_url = info[L"zipball_url"].as_string();
            zip_url += access_token;
            github->request(web::http::methods::GET, zip_url).then([&](web::http::http_response response)
                {
                    if (response.status_code() == web::http::status_codes::OK)
                    {
                        /*zipball 데이터 가져오기*/
                        std::string zip_data = response.extract_utf8string(true).get();
                        size_t size = zip_data.size();

                        const char* temp_path = getenv("TEMP");
                        size_t length = strlen(temp_path);

                        std::cout << temp_path << std::endl;

                        std::wstring wTemp_path(length, L'#');

                        //#pragma warning (disable : 4996)
                        // Or add to the preprocessor: _CRT_SECURE_NO_WARNINGS
                        mbstowcs(&wTemp_path[0], temp_path, length);

                        //std::wstring wfolder_Path = L"C:\\Users\\mslm01\\Downloads\\"; 

                        //if ((_waccess(wfolder_Path.c_str(), 0)) == -1)
                        //	CreateDirectory(wfolder_Path.c_str(), NULL);
                        wTemp_path += L"\\MSLM_Ver_";
                        wTemp_path += info[L"server_ver"].as_string();

                        std::cout << "current version is not latest version\n download file!" << std::endl;

                        /*zip파일 다운로드*/
                        downloadFile(zip_data.c_str(), size, wTemp_path + L".zip");




                        /*설치파일 해시 생성*/
                        size_t hash_packet_size = 0;
                        char Client_hash[65];
                        const char* hash_data = sha256_file(wTemp_path, hash_packet_size, Client_hash);

                        std::string Server_hash;
                        convert_wstr2str(info[L"file_hash"].as_string(), Server_hash);

                        if (!_strcmpi(Client_hash, Server_hash.c_str()))
                        {
                            std::cout << "파일 해시 일치" << std::endl;
                            //HINSTANCE result = ShellExecute(NULL, _T("runas"), wfolder_Path.c_str(), NULL, NULL, SW_SHOW);
                        }
                        else
                        {
                            /*파일 해시가 불 일치할 경우 파일 재 다운로드 및 해시 검사*/
                            std::cout << "파일 해시 불 일치 \n다운로드 재시작" << std::endl;

                        }
                    }
                }).wait();
        }
        return true;
}

int main()
{
    //web::http::client::http_client client(U("http://127.0.0.1:36259"));
    VersionCheck();
    //Client_FileCheck(client);    
    return 0;
}