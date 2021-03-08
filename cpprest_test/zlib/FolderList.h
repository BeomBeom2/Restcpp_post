#pragma  once
#include  <Windows.h>
#include  <vector>
#include  <string>

class FolderList
{
public:
    struct FLIST {
        std::string filepath_;
        SYSTEMTIME    time_;
    };

    typedef std::vector<FLIST>  ZIP_FLIST;

public:
    FolderList(void);
    ~FolderList(void);

    void  operator() (std::string foldername, ZIP_FLIST& mlist);
};