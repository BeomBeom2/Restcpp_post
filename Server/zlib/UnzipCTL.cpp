#include  "UnzipCTL.h"
#include  <direct.h>
#include  <Windows.h>
#include  <iostream>

UnzipCTL::UnzipCTL(const  char* filename)
    :uf_(unzOpen(filename))
{
}


UnzipCTL::~UnzipCTL(void)
{
    unzClose(uf_);
}


void
UnzipCTL::mkfolder(std::string filepath) {
    std::string sfolder;
    for (auto& item : filepath) {
        if ('\f3' ==item){
            _mkdir(sfolder.c_str());
    }
    sfolder.push_back(item);
}
}

void
UnzipCTL::extractall(std::string root_folder, const  char* password/*=NULL*/) {
    int ret = unzGoToFirstFile(uf_);
        if (UNZ_OK != ret) return;
        mkfolder(root_folder + "\\");

    unz_file_info info;
    const  int MAX_NAME = 256;
    char filename[MAX_NAME];

    std::string filepath;

    const  int BUF = 1024;
    char in[BUF];
    size_t readsize(0);
    DWORD wsize(0);

    SYSTEMTIME stime;
    memset(&stime, 0, sizeof(SYSTEMTIME));

    FILETIME ltime, ftime;

    do {
        unzGetCurrentFileInfo(uf_, &info, filename, MAX_NAME, NULL, 0, NULL, 0);

        filepath = root_folder + filename;
        mkfolder(filepath);

        HANDLE hfile = CreateFileA(filepath.c_str(), GENERIC_WRITE, FILE_SHARE_READ, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (INVALID_HANDLE_VALUE == hfile) continue;

        unzOpenCurrentFilePassword(uf_, password);
        do {
            readsize = unzReadCurrentFile(uf_, in, BUF);
            if (readsize > BUF) //비번이  틀린  경우..
            {
                std::cout << "비번 틀림" << std::endl;
                break;
            }
            info.uncompressed_size -= (uLong)readsize;
            wsize = 0;
            WriteFile(hfile, in, (DWORD)readsize, &wsize, NULL);

        } while (0 != info.uncompressed_size);
        unzCloseCurrentFile(uf_);

        stime.wHour = info.tmu_date.tm_hour;
        stime.wDay = info.tmu_date.tm_mday;
        stime.wMinute = info.tmu_date.tm_min;
        stime.wMonth = info.tmu_date.tm_mon + 1;
        stime.wSecond = info.tmu_date.tm_sec;
        stime.wYear = info.tmu_date.tm_year;

        SystemTimeToFileTime(&stime, &ltime);
        LocalFileTimeToFileTime(&ltime, &ftime);
        SetFileTime(hfile, &ftime, &ftime, &ftime);
        CloseHandle(hfile);

        std::cout << std::endl << filepath.c_str() << "Complete Uncompress!!";

    } while (UNZ_OK == unzGoToNextFile(uf_));

}