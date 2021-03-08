#include  "ZipCTL.h"
#include  <iostream>

ZipCTL::ZipCTL(const  char* zipfilename, int append)
    :zf_(zipOpen(zipfilename, append))
{
}


ZipCTL::~ZipCTL(void)
{
    zipClose(zf_, "");
}


uLong
ZipCTL::get_crc(std::ifstream& fp) {
    std::fstream::pos_type cpos = fp.tellg();
    uLong crc(0);

    const  int BUF = 1024;
    char in[BUF];
    uInt readSize(0);

    do {
        fp.read(in, BUF);
        readSize = (uInt)fp.gcount();
        crc = crc32(crc, (const Bytef*)in, readSize);

    } while (!fp.eof());
    fp.clear();

    fp.seekg(cpos, std::ios_base::beg);

    return crc;
}

void
ZipCTL::make(const  char* root_folder, FolderList::ZIP_FLIST& mlist, const  char* password/*=NULL*/) {
    zip_fileinfo info;
    memset(&info, 0, sizeof(zip_fileinfo));
    size_t len = strlen(root_folder);

    const  int BUF = 1024;
    char in[BUF];
    size_t readsize(0);

    for (auto& item : mlist) {
        SYSTEMTIME& mtime = item.time_;
        info.tmz_date.tm_hour = mtime.wHour;
        info.tmz_date.tm_mday = mtime.wDay;
        info.tmz_date.tm_min = mtime.wMinute;
        info.tmz_date.tm_mon = mtime.wMonth - 1;
        info.tmz_date.tm_sec = mtime.wSecond;
        info.tmz_date.tm_year = mtime.wYear;

        const  char* m = item.filepath_.c_str();
        std::ifstream fp(m, std::ios_base::binary);

        if (!password) {
            zipOpenNewFileInZip(zf_, m + len, &info, NULL, 0, NULL, 0, NULL, Z_DEFLATED, Z_BEST_SPEED);
        }
        else {
            uLong crc = get_crc(fp);
            zipOpenNewFileInZip3(zf_, m + len, &info, NULL, 0, NULL, 0, NULL, Z_DEFLATED, Z_BEST_SPEED,
                0,
                -MAX_WBITS,
                DEF_MEM_LEVEL,
                Z_DEFAULT_STRATEGY,
                password,
                crc
            );
        }

        do {
            fp.read(in, BUF);
            readsize = (size_t)fp.gcount();
            zipWriteInFileInZip(zf_, in, readsize);
        } while (!fp.eof());
        fp.close();

        zipCloseFileInZip(zf_);

        std::cout << std::endl << m << " Complete Compress!!";
    }

}