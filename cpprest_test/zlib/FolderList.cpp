#include  "FolderList.h"

FolderList::FolderList(void)
{
}

FolderList::~FolderList(void)
{
}

void
FolderList::operator() (std::string foldername, ZIP_FLIST& mlist)
{
    std::string sfolder = foldername + "\\*.*";

    WIN32_FIND_DATAA ffd;
    HANDLE hFind = FindFirstFileA(sfolder.c_str(), &ffd);
    if (INVALID_HANDLE_VALUE == hFind) return;

    FLIST flist;
    FILETIME ltime;

    do {
        if (!_strcmpi(ffd.cFileName, ".") || !_strcmpi(ffd.cFileName, "..")) continue;

        flist.filepath_ = foldername + "\\" + ffd.cFileName;
        if (ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            operator() (flist.filepath_, mlist);
            continue;
        }
        FileTimeToLocalFileTime(&ffd.ftCreationTime, &ltime);
        FileTimeToSystemTime(&ltime, &flist.time_);
        mlist.push_back(flist);

    } while (FindNextFileA(hFind, &ffd));

}