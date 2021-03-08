///*BSTR 자료형을 이용한 해쉬(SHA-256)생성*/
//BSTR get_server_hash()
//{
//    std::wstring path = L"C:\\server\\test.zip";
//    std::ifstream file(path, std::ios::binary | std::ios::in);
//
//    file.seekg(0, std::ios::end);
//    size_t file_size = file.tellg();
//
//    file.clear();
//    file.seekg(0, std::ios::beg);
//
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
//
//    file.close();
//    free(buffer);
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
//    ::SysFreeString(unicode_hash);
//    return unicode_hash;
//}