#include  <fstream>
#include  "FolderList.h"
#include  "zip.h"

class ZipCTL
{
private:
    zipFile zf_;

public:
    explicit ZipCTL(const  char* zipfilename, int append = APPEND_STATUS_CREATE);
    ~ZipCTL(void);

    void make(const  char* root_folder, FolderList::ZIP_FLIST& mlist, const  char* password = NULL);
private:
    uLong get_crc(std::ifstream& fp);
};
