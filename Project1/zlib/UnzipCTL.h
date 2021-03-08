#include  "unzip.h"
#include  <string>

class UnzipCTL
{
private:
    unzFile uf_;


public:
    explicit UnzipCTL(const  char* filename);
    ~UnzipCTL(void);
    void extractall(std::string root_folder, const  char* password = NULL);

private:
    void mkfolder(std::string filepath);
};
