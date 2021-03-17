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
# include <direct.h>
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
//        // ��ȯ ���� ���� Ȯ��
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

int mymkdir(const char* dirname)
{
    int ret = 0;
#ifdef _WIN32
    ret = _mkdir(dirname);
#elif unix
    ret = mkdir(dirname, 0775);
#elif __APPLE__
    ret = mkdir(dirname, 0775);
#endif
    return ret;
}

/* change_file_date : change the date/time of a file
    filename : the filename of the file where date/time must be modified
    dosdate : the new date at the MSDos format (4 bytes)
    tmu_date : the SAME new date at the tm_unz format */
void change_file_date(const char* filename, uLong dosdate, tm_unz tmu_date)
{
#ifdef _WIN32
    HANDLE hFile;
    FILETIME ftm, ftLocal, ftCreate, ftLastAcc, ftLastWrite;

    hFile = CreateFileA(filename, GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, 0, NULL);
    GetFileTime(hFile, &ftCreate, &ftLastAcc, &ftLastWrite);
    DosDateTimeToFileTime((WORD)(dosdate >> 16), (WORD)dosdate, &ftLocal);
    LocalFileTimeToFileTime(&ftLocal, &ftm);
    SetFileTime(hFile, &ftm, &ftLastAcc, &ftm);
    CloseHandle(hFile);
#else
#ifdef unix || __APPLE__
    struct utimbuf ut;
    struct tm newdate;
    newdate.tm_sec = tmu_date.tm_sec;
    newdate.tm_min = tmu_date.tm_min;
    newdate.tm_hour = tmu_date.tm_hour;
    newdate.tm_mday = tmu_date.tm_mday;
    newdate.tm_mon = tmu_date.tm_mon;
    if (tmu_date.tm_year > 1900)
        newdate.tm_year = tmu_date.tm_year - 1900;
    else
        newdate.tm_year = tmu_date.tm_year;
    newdate.tm_isdst = -1;

    ut.actime = ut.modtime = mktime(&newdate);
    utime(filename, &ut);
#endif
#endif
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

bool downloadFile(const char* buf, const size_t& size, const std::wstring path) //buf = ���� ���� ������ ��, size = ���� ������ ũ��
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
//    /*Ű ����*/
//    Client_Key = gen_key();
//    size_t size = EC_KEY_key2buf(Client_Key, EC_KEY_get_conv_form(Client_Key), &Client_keyBuf, nullptr);
//    
//    /*Ű�� ������ ���� ���ڵ�*/
//    std::string Client_keyStr(reinterpret_cast<const char*>(Client_keyBuf));
//    std::string encoded = base64_encode(reinterpret_cast<const unsigned char*>(Client_keyBuf), size, false);
//    std::wstring wEncoded;
//    convert_str2wstr(encoded, wEncoded);
//    Client_keyStr.clear();
//    encoded.clear();  
//
//    /*Ű ���̸� ������ ���� wstring ��ȯ*/
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
//    /*���� Ű ���ڵ�*/
//    wEncoded = answer.at(L"key_data").as_string();
//    convert_wstr2str(wEncoded, encoded);
//    std::string decoded = base64_decode(encoded, false);
//    Server_keyBuf = (unsigned char*)decoded.c_str();
//    std::cout << "\n Server_keyBuf from Server : " << Server_keyBuf << std::endl;
//    /*���� Ű ������ �� ��ȯ*/
//    wstr_size = answer.at(L"key_size").as_string();
//    size_t ServerKey_size = _wtoi(wstr_size.c_str());
//
//    /*������ ���� ������ Ű, Ű ���̷� ���۸� key�� ��ȯ*/
//    int size1 = EC_KEY_oct2key(tmpkey, Server_keyBuf, ServerKey_size, nullptr);
//    decoded.clear();
//
//    /*���� Ű�� ��� Ű ����*/
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

/*������ Ű ��ȯ*/
//bool Client_FileCheck(web::http::client::http_client& client)
//{
//    /*��� Ű ����*/
//    web::json::value answer;
//    unsigned char* Secret_key = Client_keyExchange(client, answer);
//
//    /*���� ������ ���ڵ�*/
//    std::wstring wEncoded = answer.at(L"zip_data").as_string();
//    std::string encoded;
//    encoded.assign(wEncoded.begin(), wEncoded.end());
//    std::string decoded = base64_decode(encoded, false);
//    const char* zip_data = decoded.c_str();
//    wEncoded.clear();
//    encoded.clear();
//
//    /*���� ũ�� ���ڵ�, ���� �ٿ�*/
//    std::wstring wstr_size = answer.at(L"zip_size").as_string();
//    size_t zip_size = _wtoi(wstr_size.c_str());
//    std::wstring filePath = L"C:\\Client_downFIle\\pwtest.zip";
//    downloadFile(zip_data, zip_size, filePath);
//    decoded.clear();
//    wstr_size.clear();
//
//    /*�ؽ� ����*/
//    size_t hash_packet_size = 0; 
//    const char* hash_data = sha256_file(filePath, hash_packet_size);
//    std::wstring wHash_data(&hash_data[0], &hash_data[hash_packet_size - 1]);
//
//    /*���� �ؽ� �� ��������*/
//    std::wstring whash_size = answer.at(L"hash_size").as_string();
//    size_t hash_size = _wtoi(whash_size.c_str());
//
//    if (hash_packet_size != hash_size)
//    {
//        std::cout << "���� �ؽ� �� ���� �ٸ�" << std::endl;
//        return false;
//    }
//    std::wstring server_hash_data = answer.at(L"hash_data").as_string();
//
//    /*���� �ؽð� ��ġ �� ���*/
//    if (!wcscmp(server_hash_data.c_str(), wHash_data.c_str()))
//    {
//        std::cout << "���� �ؽ� ��ġ" << std::endl;
//        UnzipCTL ctl("C:\\Client_downFIle\\pwtest.zip"); //���� ��ġ
//        ctl.extractall("C:\\Client_downFIle", reinterpret_cast<const char*>(Secret_key)); //������ Ǯ ���� ���
//    }
//    else
//        std::cout << "���� ����" << std::endl;
//    
//    free(Secret_key);
//    CRYPTO_cleanup_all_ex_data();
//    return 0;
//}

std::wstring file_version()
{
    web::json::value answer;
    auto updata_check_json = web::json::value::object();
    // ���������� ���� ����
    char* buffer = NULL;
    // ������ Ȯ���� ����
    std::wstring name(L"C:\\test1\\chrome.exe");
    DWORD infoSize = 0;
    std::wstring wVersion = L"";

    // ���Ϸκ��� ���������������� ũ�Ⱑ �������� ���մϴ�.
    infoSize = GetFileVersionInfoSize(name.c_str(), 0);
    if (infoSize != 0)
    {
        // �����Ҵ�
        buffer = new char[infoSize];
        if (buffer)
        {
            // �������������͸� �����ɴϴ�.
            if (GetFileVersionInfo(name.c_str(), 0, infoSize, buffer) != 0)
            {
                VS_FIXEDFILEINFO* pFineInfo = NULL;
                UINT bufLen = 0;
                // buffer�� ���� VS_FIXEDFILEINFO ������ �����ɴϴ�.
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

/*��� ���� ���� ���� ����*/
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

/*������ �������� ����*/
int mkdirs(const char* path)
{
    char tmp_path[1024];
    const char* tmp = path;
    int len = 0; int ret;
    if (path == NULL || strlen(path) >= 1024)
    {
        return -1;
    }
    /* ���� ���丮�� �����ϴ� �� �˻��Ͽ�, ������ �ÿ� ���� ���丮�� ������ */
    while ((tmp = strchr(tmp, '/')) != NULL)
    {
        len = tmp - path;
        tmp++;
        if (len == 0)
        {
            continue;
        }
        strncpy(tmp_path, path, len);
        tmp_path[len] = 0x00;
        if ((ret = mymkdir(tmp_path)) == -1)
        {
            if (errno != EEXIST)
                return -1;
        }
    }
    if (mymkdir(path) == -1)
    {
        if (errno != EEXIST)
            return -1;
    }
    return 0;
}

int do_extract_currentfile(unzFile uf, std::wstring& execute_filepath)
{
    char filename_inzip[256];
    char* filename_withoutpath;
    char* p;
    int err = UNZ_OK;
    FILE* fout = NULL;
    void* buf;
    uInt size_buf = 8192;
    unz_file_info64 file_info;

    /*uf(unzFile)�� ���õ� ���� ���� ��������*/
    err = unzGetCurrentFileInfo64(uf, &file_info, filename_inzip, sizeof(filename_inzip), NULL, 0, NULL, 0);

    if (err != UNZ_OK)
    {
        printf("Current file cannot open, error code : %d\n", err);
        return err;
    }

    /*���� ��ü ���*/
    char* file_fullpath = getenv("TEMP");
    int env_size = strlen(getenv("TEMP"));
    strcat(file_fullpath, "\\");
    strcat(file_fullpath, filename_inzip);

    /*write�� ����*/
    buf = (void*)malloc(size_buf);
    if (buf == NULL)
    {
        printf("Allocating memory error\n");
        return UNZ_INTERNALERROR;
    }

    /*�ش� ��� ���� �������� �������� Ž�� �� ������ ��� ���� �ڸ���*/
    p = filename_withoutpath = filename_inzip;
    while ((*p) != '\0')
    {
        if (((*p) == '/') || ((*p) == '\\'))
            filename_withoutpath = p + 1;
        p++;
    }

    /*��� ���� ������ ���*/
    if ((*filename_withoutpath) == '\0')
    {
        printf("Create Path: %s\n", file_fullpath);
        mkdirs(file_fullpath);
    }
    /*��� ���� ������ ��� */
    else
    {
        /*�ش� ������ setup�������� �˻�*/
        std::wstring filename(&filename_withoutpath[0], &filename_withoutpath[strlen(filename_withoutpath)]);
        size_t index = filename.find(L"Setup");

        /*setup������ ���*/
        if (index != std::wstring::npos)
        {
            std::wstring excute_path(&file_fullpath[0], &file_fullpath[strlen(file_fullpath)]);
            execute_filepath = excute_path;
        }

        err = unzOpenCurrentFilePassword(uf, NULL);
        if (err != UNZ_OK)
        {
            printf("CurrentFilePassword cannot open, error code %d\n", err);
        }

        if (err == UNZ_OK)
        {
            //�ش� ��� ���� ������ ���, ������ ���� �������� ���� �� ���� write
            char c = *(file_fullpath + strlen(file_fullpath) - 1 - strlen(filename_withoutpath));
            *(file_fullpath + strlen(file_fullpath) - 1 - strlen(filename_withoutpath)) = '\0';
            mkdirs(file_fullpath);
            *(file_fullpath + strlen(file_fullpath)) = c;
            fout = fopen64(file_fullpath, "wb");

            if (fout == NULL)
                printf("open error, path is %s\n", file_fullpath);
        }

        if (fout != NULL)
        {
            printf(" extracting file: %s\n", filename_withoutpath);

            /*�ش� ���� write*/
            do
            {
                err = unzReadCurrentFile(uf, buf, size_buf);
                if (err < 0)
                {
                    printf("error %d with zipfile in unzReadCurrentFile\n", err);
                    break;
                }
                if (err > 0)
                    if (fwrite(buf, err, 1, fout) != 1)
                    {
                        printf("writing extracted file error\n");
                        err = UNZ_ERRNO;
                        break;
                    }
            } while (err > 0);
            if (fout)
                fclose(fout);

            if (err == 0)
                /*���� ��¥, �ð� ����*/
                change_file_date(&file_fullpath[0], file_info.dosDate,
                    file_info.tmu_date);
        }
        if (err == UNZ_OK)
        {
            err = unzCloseCurrentFile(uf);
            if (err != UNZ_OK)
            {
                printf("error %d with zipfile in unzCloseCurrentFile\n", err);
            }
        }
        else
            unzCloseCurrentFile(uf);
    }
    memset(&file_fullpath[env_size], 0, strlen(filename_inzip + 1));
    free(buf);
    return err;
}

int do_extract(unzFile uf, std::wstring& execute_filepath)
{
    uLong i;
    unz_global_info64 unz_info;
    int err;
    FILE* fout = NULL;
    err = unzGetGlobalInfo64(uf, &unz_info);
    if (err != UNZ_OK)
        printf("zipfile in unzGetGlobalInfo request error, code : %d\n", err);

    for (i = 0; i < unz_info.number_entry; i++)
    {
        if (do_extract_currentfile(uf, execute_filepath) != UNZ_OK)
            break;

        if ((i + 1) < unz_info.number_entry)
        {
            err = unzGoToNextFile(uf);
            if (err != UNZ_OK)
            {
                printf("Next file cannot open, error code %d\n", err);
                break;
            }
        }
    }
    return 0;
}


int Unzip(const char* zipfilename, std::wstring& execute_filepath)
{
    int ret_value = 0;
    unzFile uf = NULL;

#        ifdef USEWIN32IOAPI
    zlib_filefunc64_def ffunc;
#        endif

#        ifdef USEWIN32IOAPI
    fill_win32_filefunc64A(&ffunc);
    uf = unzOpen2_64(zipfilename, &ffunc);
#        else
    uf = unzOpen64(zipfilename);
#        endif 

    if (uf == NULL)
    {
        printf("Cannot open %s\n", zipfilename);
        return 1;
    }
    printf("%s opened\n", zipfilename);

    ret_value = do_extract(uf, execute_filepath);
    unzClose(uf);

    return ret_value;
}

bool VersionCheck()
{
    std::wstring&& Client_version = L"v1.3.0" /*file_version()*/;
    web::json::value info;
    std::wstring access_token = L"?ref=master&access_token=d7602348c431078347b314d78d795a9384d3366b";
    web::http::uri_builder uri(L"https://api.github.com/repos/BeomBeom2/Private_test/releases/latest?ref=master&access_token=d7602348c431078347b314d78d795a9384d3366b");
    auto addr = uri.to_string();
    web::http::client::http_client* github = new web::http::client::http_client(U("https://api.github.com/"));
    web::json::value latest_info;
    std::wstring latest_body;
    std::wstring execute_filepath;
    bool Needed_download = false;

    github->request(web::http::methods::GET, addr).then([&](web::http::http_response response)
        {
            if (response.status_code() == web::http::status_codes::OK)
            {
                /*response���� ��������, ��ġ���� url, release body, ��ġ���� �̸� parse*/
                latest_info = response.extract_json().get();
                info[L"server_ver"] = latest_info.at(L"tag_name");
                info[L"zipball_url"] = latest_info.at(L"zipball_url");
                info[L"zip_name"] = latest_info[L"name"];
                latest_body = latest_info[L"body"].as_string();
                auto array = latest_info[L"assets"].as_array();
                //info[L"file_url"] = array[0][L"browser_download_url"];

                /*release body���� hash�� parse */
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

                /*���� ���� ������ ���� ������ ��ġ �� ���(�ֽ� ������ ���)*/
                if (!wcscmp(Client_version.c_str(), info[L"server_ver"].as_string().c_str()))
                {
                    std::cout << "current version is latest version!" << std::endl;
                }
                else
                    Needed_download = true;
            }
            else
            {
                std::cerr << "REQ ERROR, status code : " << response.status_code() << std::endl;
            }
        }).wait();


        /*�ֽ� ��ġ������ �ʿ��� ���*/
        if (Needed_download)
        {
            std::wstring zip_url = info[L"zipball_url"].as_string();
            zip_url += access_token;
            github->request(web::http::methods::GET, zip_url).then([&](web::http::http_response response)
                {
                    if (response.status_code() == web::http::status_codes::OK)
                    {
                        /*zipball ������ ��������*/
                        std::string zip_data = response.extract_utf8string(true).get();
                        size_t size = zip_data.size();

                        const char* temp_path = getenv("TEMP");
                        size_t length = strlen(temp_path);

                        std::cout << "My temp path : " << temp_path << std::endl;

                        std::wstring wTemp_path_zip(length, L'#');

                        //#pragma warning (disable : 4996)
                        // Or add to the preprocessor: _CRT_SECURE_NO_WARNINGS
                        mbstowcs(&wTemp_path_zip[0], temp_path, length);

                        /*zip���� �̸� ���̱�*/
                        //if ((_waccess(wfolder_Path.c_str(), 0)) == -1)
                        //	CreateDirectory(wfolder_Path.c_str(), NULL);
                        wTemp_path_zip += L"\\MSLM_Ver_";
                        wTemp_path_zip += info[L"server_ver"].as_string();
                        wTemp_path_zip += L".zip";
                        std::cout << "current version is not latest version\n download file!" << std::endl;

                        /*zip���� �ٿ�ε�*/
                        downloadFile(zip_data.c_str(), size, wTemp_path_zip);

                        /*zip���� ���� ����*/
                        std::string Temp_path_zip;
                        convert_wstr2str(wTemp_path_zip, Temp_path_zip);
                        Unzip(&Temp_path_zip[0], execute_filepath);


                        /*��ġ���� �ؽ� ����*/
                        size_t hash_packet_size = 0;
                        char Client_hash[65];
                        const char* hash_data = sha256_file(execute_filepath, hash_packet_size, Client_hash);

                        std::string Server_hash;
                        convert_wstr2str(info[L"file_hash"].as_string(), Server_hash);

                        if (!_strcmpi(Client_hash, Server_hash.c_str()))
                        {
                            std::cout << "���� �ؽ� ��ġ" << std::endl;
                            HINSTANCE result = ShellExecute(NULL, _T("runas"), execute_filepath.c_str(), NULL, NULL, SW_SHOW);
                        }
                        else
                        {
                            /*���� �ؽð� �� ��ġ�� ��� ���� �� �ٿ�ε� �� �ؽ� �˻�*/
                            std::cout << "���� �ؽ� �� ��ġ \n" << std::endl;
                        }
                    }
                    else
                    {
                        std::cerr << "download url request error, status code : " << response.status_code() << std::endl;
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