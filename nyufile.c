#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdbool.h>
#include <openssl/sha.h>

#define SHA_DIGEST_LENGTH 20

// I copied and paste the definition of data structures from the lab description
#pragma pack(push,1)
typedef struct BootEntry {
  unsigned char  BS_jmpBoot[3];     // Assembly instruction to jump to boot code
  unsigned char  BS_OEMName[8];     // OEM Name in ASCII
  unsigned short BPB_BytsPerSec;    // Bytes per sector. Allowed values include 512, 1024, 2048, and 4096
  unsigned char  BPB_SecPerClus;    // Sectors per cluster (data unit). Allowed values are powers of 2, but the cluster size must be 32KB or smaller
  unsigned short BPB_RsvdSecCnt;    // Size in sectors of the reserved area
  unsigned char  BPB_NumFATs;       // Number of FATs
  unsigned short BPB_RootEntCnt;    // Maximum number of files in the root directory for FAT12 and FAT16. This is 0 for FAT32
  unsigned short BPB_TotSec16;      // 16-bit value of number of sectors in file system
  unsigned char  BPB_Media;         // Media type
  unsigned short BPB_FATSz16;       // 16-bit size in sectors of each FAT for FAT12 and FAT16. For FAT32, this field is 0
  unsigned short BPB_SecPerTrk;     // Sectors per track of storage device
  unsigned short BPB_NumHeads;      // Number of heads in storage device
  unsigned int   BPB_HiddSec;       // Number of sectors before the start of partition
  unsigned int   BPB_TotSec32;      // 32-bit value of number of sectors in file system. Either this value or the 16-bit value above must be 0
  unsigned int   BPB_FATSz32;       // 32-bit size in sectors of one FAT
  unsigned short BPB_ExtFlags;      // A flag for FAT
  unsigned short BPB_FSVer;         // The major and minor version number
  unsigned int   BPB_RootClus;      // Cluster where the root directory can be found
  unsigned short BPB_FSInfo;        // Sector where FSINFO structure can be found
  unsigned short BPB_BkBootSec;     // Sector where backup copy of boot sector is located
  unsigned char  BPB_Reserved[12];  // Reserved
  unsigned char  BS_DrvNum;         // BIOS INT13h drive number
  unsigned char  BS_Reserved1;      // Not used
  unsigned char  BS_BootSig;        // Extended boot signature to identify if the next three values are valid
  unsigned int   BS_VolID;          // Volume serial number
  unsigned char  BS_VolLab[11];     // Volume label in ASCII. User defines when creating the file system
  unsigned char  BS_FilSysType[8];  // File system type label in ASCII
} BootEntry;
#pragma pack(pop)

#pragma pack(push,1)
typedef struct DirEntry {
  unsigned char  DIR_Name[11];      // File name
  unsigned char  DIR_Attr;          // File attributes
  unsigned char  DIR_NTRes;         // Reserved
  unsigned char  DIR_CrtTimeTenth;  // Created time (tenths of second)
  unsigned short DIR_CrtTime;       // Created time (hours, minutes, seconds)
  unsigned short DIR_CrtDate;       // Created day
  unsigned short DIR_LstAccDate;    // Accessed day
  unsigned short DIR_FstClusHI;     // High 2 bytes of the first cluster address
  unsigned short DIR_WrtTime;       // Written time (hours, minutes, seconds
  unsigned short DIR_WrtDate;       // Written day
  unsigned short DIR_FstClusLO;     // Low 2 bytes of the first cluster address
  unsigned int   DIR_FileSize;      // File size in bytes. (0 for directories)
} DirEntry;
#pragma pack(pop)

//比较SHA-1 hash
//如果是hex array，转换
bool hashes(unsigned char *hash, unsigned char *sha, bool convert) {
    unsigned char *shaConverted;
    //I learned the sscanf technique to convert hex array from https://stackoverflow.com/questions/17945718/converting-a-hex-string-array-to-hex-array
    if(convert){
        shaConverted = malloc(SHA_DIGEST_LENGTH);
        for (int i = 0; i < SHA_DIGEST_LENGTH * 2; i += 2) {
            char hexArr[3] = {sha[i], sha[i + 1], '\0'};
            sscanf(hexArr, "%2hhx", &shaConverted[i / 2]);
        }
    }else{
        shaConverted = sha;
    }

    //I learned that we use memcmp() to compare hashes from https://stackoverflow.com/questions/37193767/compare-hashes-in-c
    //I learned how to use memcmp() from https://cplusplus.com/reference/cstring/memcmp/
    if(memcmp(hash, shaConverted, SHA_DIGEST_LENGTH) == 0){
        return true; 
    }
    else{
        /*
        for (int i = 0; i < 20; i++) {
            printf("%02x", hash[i]);
        }
        printf("\n");
        for (int i = 0; i < 20; i++) {
            printf("%02x", shaConverted[i]);
        }
        printf("\n");*/
        return false;
    }
}

void printErrorMessage(){
    //I read about multipe line c string from https://dalelane.co.uk/blog/?p=88
    printf("Usage: ./nyufile disk <options>\n"
    "  -i                     Print the file system information.\n"
    "  -l                     List the root directory.\n"
    "  -r filename [-s sha1]  Recover a contiguous file.\n"
    "  -R filename -s sha1    Recover a possibly non-contiguous file.\n");
    exit(1);
}

//阅读disk entry中first cluster，用little endian
unsigned int readFirstCluster(DirEntry *dirEntry){
    //I learned how to read little endian numbers by attending Katheryn Zhou's tutoring session
    //I learned how to convert hex number into regular number digit by digit from https://stackoverflow.com/questions/33868998/what-does-a0-addr-0xff
    //first read from the end of the high 2 bytes
    unsigned char byte1 = (dirEntry ->  DIR_FstClusHI & 0xFF); 
    unsigned char byte2 = ((dirEntry ->  DIR_FstClusHI  >> 8) & 0xFF);
    //then read from the end of the low 2 bytes
    unsigned char byte3 = (dirEntry ->  DIR_FstClusLO & 0xFF); 
    unsigned char byte4 = ((dirEntry ->  DIR_FstClusLO >> 8) & 0xFF);
    unsigned int result = byte1 + byte2 + byte3 + byte4;
    return result;
}

//recover一个file
//先修改名字
//再loop through所有FAT，修改每个cluster的下一个
void recover(DirEntry *rootDirEntry, char *addr, BootEntry *fat32disk, char *filename, bool sha){
    //set back the first character of the original filename
    rootDirEntry -> DIR_Name[0] = (unsigned char)filename[0];
    //updating all the fats if file is not empty
    //I learned that empty file has no FAT from ed stem discussion
    if((int)rootDirEntry -> DIR_FileSize > 0){
        unsigned int numberOfCluster = rootDirEntry -> DIR_FileSize / (fat32disk -> BPB_SecPerClus * fat32disk -> BPB_BytsPerSec);
        if(rootDirEntry -> DIR_FileSize % (fat32disk -> BPB_SecPerClus * fat32disk -> BPB_BytsPerSec) > 0){
            numberOfCluster++;
        }
        //printf("%d\n", (int)numberOfCluster);
        unsigned int firstCluster = readFirstCluster(rootDirEntry);
        for(int i = 0; i < fat32disk -> BPB_NumFATs; i++){
            //printf("First Cluster: %d\n", (int)firstCluster);
            unsigned int fatIOffset = fat32disk -> BPB_RsvdSecCnt * fat32disk -> BPB_BytsPerSec + i * fat32disk -> BPB_FATSz32 * fat32disk -> BPB_BytsPerSec;
            unsigned int *fatIRootDir = (unsigned int *)(addr + fatIOffset + firstCluster * sizeof(unsigned int));
            for(unsigned int m = 1; m < numberOfCluster; m++){
                *fatIRootDir = firstCluster + m;
                fatIRootDir = (unsigned int *)(addr + fatIOffset + (firstCluster + m) * sizeof(unsigned int));
            }
            *fatIRootDir = 0x0ffffff8;
            //44 45 46 EOF
        }
    }else{
        //空file
        /*
        unsigned int firstCluster = readFirstCluster(rootDirEntry);
        for(int i = 0; i < fat32disk -> BPB_NumFATs; i++){
            //printf("First Cluster: %d\n", (int)firstCluster);
            unsigned int fatIOffset = fat32disk -> BPB_RsvdSecCnt * fat32disk -> BPB_BytsPerSec + i * fat32disk -> BPB_FATSz32 * fat32disk -> BPB_BytsPerSec;
            unsigned int *fatIRootDir = (unsigned int *)(addr + fatIOffset + firstCluster * sizeof(unsigned int));
            *fatIRootDir = 0x0ffffff8;
        }
        */
    }

    int l = 0;
    while(filename[l] != '\0'){
        printf("%c", filename[l]);
        l++;
    }
    if(!sha) printf(": successfully recovered\n");
    else printf(": successfully recovered with SHA-1\n");
    //printf("finished\n");
}

//-l: 阅读当前cluster中所有directory entries，打印信息
int readRootDirectory(char *addr, BootEntry *fat32disk, int offset){
    int numOfEntries = (fat32disk -> BPB_SecPerClus * fat32disk -> BPB_BytsPerSec) / sizeof(DirEntry);
    int i;
    int fileCount = 0;
    for(i = 0; i < numOfEntries; i++){
        DirEntry *rootDirEntry = (DirEntry *)(addr + offset + sizeof(DirEntry) * i);
        //I learned that we don't need to continue reading if the file is unallocated from attending Katheryn Zhou's tutoring session
        if(rootDirEntry -> DIR_Name[0] == 0x00){
            break;
        }
        if(rootDirEntry -> DIR_Name[0] != 0x00 
        && rootDirEntry -> DIR_Name[0] != 0xe5 
        && rootDirEntry -> DIR_Attr != 0x0f){
            fileCount++;
            int j = 0;
            //filename
            while(j <= 7 && rootDirEntry -> DIR_Name[j] != ' '){
                printf("%c", rootDirEntry -> DIR_Name[j]);
                j++;
            }
            j = 8;
            if(rootDirEntry -> DIR_Name[j] != ' ') printf(".");
            //extension
            while(j <= 10 && rootDirEntry -> DIR_Name[j] != ' '){
                printf("%c", rootDirEntry -> DIR_Name[j]);
                j++;
            }
            if(rootDirEntry -> DIR_Attr == 0x10){
                printf("/");
            }
            printf(" (");
            if(rootDirEntry -> DIR_Attr != 0x10){
                printf("size = ");
                // I learned how to convert unsigned int to int from https://stackoverflow.com/questions/5129498/how-to-cast-or-convert-an-unsigned-int-to-int-in-c
                printf("%d", (int)rootDirEntry -> DIR_FileSize);
                if((int)rootDirEntry -> DIR_FileSize != 0) printf(", ");
            }
            // I learned how to convert unsigned short to int from https://www.convertdatatypes.com/Convert-ushort-to-int-in-C.html
            if(rootDirEntry -> DIR_Attr == 0x10 || (int)rootDirEntry -> DIR_FileSize != 0){
                printf("starting cluster = ");
                printf("%d", (int)readFirstCluster(rootDirEntry));
            }
            printf(")\n");
        }
    }
    return fileCount;
}

//recover small or contiguously allocated file
DirEntry *recoverySmallFile(char *addr, BootEntry *fat32disk, int offset, char *filename){
    int numOfEntries = (fat32disk -> BPB_SecPerClus * fat32disk -> BPB_BytsPerSec) / sizeof(DirEntry);
    int i;
    DirEntry *toRecover = NULL;
    for(i = 0; i < numOfEntries; i++){
        DirEntry *rootDirEntry = (DirEntry *)(addr + offset + sizeof(DirEntry) * i);
        if(rootDirEntry -> DIR_Name[0] == 0x00){
            break;
        }
        //printf("%d\n", rootDirEntry -> DIR_Name[0]);
        if(rootDirEntry -> DIR_Name[0] == 0xe5 && rootDirEntry -> DIR_Attr != 0x10){
            //printf("There is a file named correctly\n");
            int k = 1;
            int j = 1;
            bool correct = true;
            //filename
            //I learned how to compare char with unsigned char from https://stackoverflow.com/questions/42738938/comparing-unsigned-char-with-signed-char
            while(j <= 7 && rootDirEntry -> DIR_Name[j] != ' '){
                //printf("%c\n", rootDirEntry -> DIR_Name[j]);
                if(filename[k] == '\0' || rootDirEntry -> DIR_Name[j] != filename[k]){
                    correct = false;
                }
                //printf("%c\n", filename[k]);
                k++;
                j++;
            }
            //printf("Passed filename\n");
            j = 8;
            if(filename[k] != '\0' && rootDirEntry -> DIR_Name[j] != ' ' && filename[k] == '.'){
                k++;
            };
            //extension
            while(j <= 10 && rootDirEntry -> DIR_Name[j] != ' '){
                if(filename[k] == '\0' || rootDirEntry -> DIR_Name[j] != filename[k]){
                    correct = false;
                }
                //printf("%c\n", filename[k]);
                k++;
                j++;
            }
            if(correct && toRecover == NULL){
                toRecover = rootDirEntry;
                /*recover(rootDirEntry, addr, fat32disk, filename, false);
                exit(1);*/
            }else if(correct && toRecover != NULL){
                int l = 0;
                while(filename[l] != '\0'){
                    printf("%c", filename[l]);
                    l++;
                }
                printf(": multiple candidates found\n");
                exit(1);
            }
        }
    }
    return toRecover;
}

//用于比较file的sha和argument中的sha的程序
//复制file的内容，生成file的sha
void checkSHA1(char *addr, DirEntry *rootDirEntry, BootEntry *fat32disk, unsigned char *sha, char *filename){
    //printf("started checking\n");
    unsigned char *shaEmpty = (unsigned char *)"da39a3ee5e6b4b0d3255bfef95601890afd80709";
    if((int)rootDirEntry -> DIR_FileSize == 0 && hashes(sha, shaEmpty, false)){
        recover(rootDirEntry, addr, fat32disk, filename, true);
        exit(0);

    }else if((int)rootDirEntry -> DIR_FileSize > 0){
        unsigned int numberOfCluster = rootDirEntry -> DIR_FileSize / (fat32disk -> BPB_SecPerClus * fat32disk -> BPB_BytsPerSec);
        unsigned int remainder = rootDirEntry -> DIR_FileSize - numberOfCluster * fat32disk -> BPB_SecPerClus * fat32disk -> BPB_BytsPerSec;

        //I learned that I need to copy the whole file's content by attending Saturaday's Tutoring Session (I forgot tutor's name)
        unsigned char *file = (unsigned char *)malloc((int)rootDirEntry -> DIR_FileSize * sizeof(unsigned char));
        unsigned int fileLength = 0;
        unsigned int firstCluster = readFirstCluster(rootDirEntry);
        for(unsigned int i = 0; i < numberOfCluster; i++){
            unsigned int clusterOffset = fat32disk -> BPB_RsvdSecCnt * fat32disk -> BPB_BytsPerSec +  
            fat32disk -> BPB_NumFATs * fat32disk -> BPB_FATSz32 * fat32disk -> BPB_BytsPerSec + 
            (firstCluster + i - 2) * fat32disk -> BPB_SecPerClus * fat32disk -> BPB_BytsPerSec;
            unsigned char *cluster = (unsigned char *)(addr + clusterOffset);
            for(unsigned int j = 0; j < fat32disk -> BPB_SecPerClus * fat32disk -> BPB_BytsPerSec; j++){
                file[fileLength] = cluster[j];
                fileLength++;
            }
        }
        if(remainder > 0){
            unsigned int clusterOffset = fat32disk -> BPB_RsvdSecCnt * fat32disk -> BPB_BytsPerSec +  
            fat32disk -> BPB_NumFATs * fat32disk -> BPB_FATSz32 * fat32disk -> BPB_BytsPerSec + 
            (firstCluster + numberOfCluster - 2) * fat32disk -> BPB_SecPerClus * fat32disk -> BPB_BytsPerSec;
            unsigned char *cluster = (unsigned char *)(addr + clusterOffset);
            for(unsigned int j = 0; j < remainder; j++){
                file[fileLength] = cluster[j];
                fileLength++;
            }
        }
        /*for (int i = 0; i < (int)fileLength; i++) {
            printf("%c", file[i]);
        }*/
        //printf("%d and %d\n", (int)rootDirEntry -> DIR_FileSize, (int)fileLength);
        unsigned char *fileSha1 = (unsigned char *)malloc(SHA_DIGEST_LENGTH);
        SHA1(file, (size_t)rootDirEntry -> DIR_FileSize, fileSha1);
        if(hashes(fileSha1, sha, true)){
            recover(rootDirEntry, addr, fat32disk, filename, true);
            exit(0);
        }
    }
}

//recover有SHA的small或者contiguous file
void recoverySmallFileSHA1(char *addr, BootEntry *fat32disk, int offset, char *filename, unsigned char* sha){
    //printf("Checking a new disk!\n");
    int numOfEntries = (fat32disk -> BPB_SecPerClus * fat32disk -> BPB_BytsPerSec) / sizeof(DirEntry);
    int i;
    //bool recovered = false;
    for(i = 0; i < numOfEntries; i++){
        DirEntry *rootDirEntry = (DirEntry *)(addr + offset + sizeof(DirEntry) * i);
        if(rootDirEntry -> DIR_Name[0] == 0x00){
            break;
        }
        //printf("%d\n", rootDirEntry -> DIR_Name[0]);
        if(rootDirEntry -> DIR_Name[0] == 0xe5){
            //printf("There is a file named correctly\n");
            int k = 1;
            int j = 1;
            bool correct = true;
            //filename
            //I learned how to compare char with unsigned char from https://stackoverflow.com/questions/42738938/comparing-unsigned-char-with-signed-char
            while(j <= 7 && rootDirEntry -> DIR_Name[j] != ' '){
                //printf("%c\n", rootDirEntry -> DIR_Name[j]);
                if(filename[k] == '\0' || rootDirEntry -> DIR_Name[j] != filename[k]){
                    correct = false;
                }
                //printf("%c\n", filename[k]);
                k++;
                j++;
            }
            //printf("Passed filename\n");
            j = 8;
            if(filename[k] != '\0' && rootDirEntry -> DIR_Name[j] != ' ' && filename[k] == '.'){
                k++;
            };
            //extension
            while(j <= 10 && rootDirEntry -> DIR_Name[j] != ' '){
                if(filename[k] == '\0' || rootDirEntry -> DIR_Name[j] != filename[k]){
                    correct = false;
                }
                //printf("%c\n", filename[k]);
                k++;
                j++;
            }
            if(correct){
                checkSHA1(addr, rootDirEntry, fat32disk, sha, filename);
            }
        }
    }
}

int main(int argc, char *argv[]){
    int c;

    //i read about how to detect if there is no option from https://stackoverflow.com/questions/53355970/detecting-no-option-with-getopt-in-c-in-linux
    //there can only be one argument, the disk name
    if(argc == 1){
        printErrorMessage();
    }
    // I learned how to use mmap() from lab3 code
    // Read file from argument 2
    int fd = open(argv[1], O_RDWR);
    if (fd == -1){
        printErrorMessage();
    }

    BootEntry *fat32disk = mmap(NULL, sizeof(BootEntry), PROT_READ, MAP_PRIVATE, fd, 0);
    if (fat32disk == MAP_FAILED) fprintf (stderr, "Failed in mapping disk into memory");
    if((int)fat32disk -> BPB_FATSz16 != 0) fprintf (stderr, "System is not in FAT32");

    // I learned from lab3 to get file size and get the whole disk
    // I learned that I need to use mmap() again instead of working on the fat32disk by going to the tutoring session
    struct stat sb;
    if (fstat(fd, &sb) == -1) fprintf (stderr, "Failed in getting the file size");
    // I learned the options for mmap from professor's extra lecture on lab4
    char *addr = mmap(NULL, sb.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (addr == MAP_FAILED) fprintf (stderr, "Failed in mapping file into memory");

    // I learned how to calculate root directory offset from attending the lectures.
    unsigned int rootDirOffset = fat32disk -> BPB_RsvdSecCnt * fat32disk -> BPB_BytsPerSec +  
    fat32disk -> BPB_NumFATs * fat32disk -> BPB_FATSz32 * fat32disk -> BPB_BytsPerSec + 
    (fat32disk -> BPB_RootClus - 2) * fat32disk -> BPB_SecPerClus * fat32disk -> BPB_BytsPerSec;
    //reserved area + FAT + (clusters - 2)
    unsigned int fat1Offset = fat32disk -> BPB_RsvdSecCnt * fat32disk -> BPB_BytsPerSec;

    bool r = false;
    bool R = false;
    bool s = false;
    int fileCount = 0; // for option -l
    unsigned int *fatRootDir;
    char *filename;
    unsigned char *sha;
    // I reused the parser program i have designed before in lab3 to better understand getopt()
    while ((c = getopt (argc, argv, "ilr:R:s:")) != -1){
        switch (c)
        {
            case 'i':
                //I read about multipe line c string from https://dalelane.co.uk/blog/?p=88
                printf("Number of FATs = %d\n"
                "Number of bytes per sector = %d\n"
                "Number of sectors per cluster = %d\n"
                "Number of reserved sectors = %d\n", 
                fat32disk -> BPB_NumFATs, fat32disk -> BPB_BytsPerSec, fat32disk -> BPB_SecPerClus, fat32disk -> BPB_RsvdSecCnt);
                break;
            case 'l':
                fileCount += readRootDirectory(addr, fat32disk, rootDirOffset);
                fatRootDir = (unsigned int *)(addr + fat1Offset + fat32disk -> BPB_RootClus * sizeof(unsigned int));
                while(*fatRootDir < 0x0ffffff8){
                    rootDirOffset = fat32disk -> BPB_RsvdSecCnt * fat32disk -> BPB_BytsPerSec +  
                    fat32disk -> BPB_NumFATs * fat32disk -> BPB_FATSz32 * fat32disk -> BPB_BytsPerSec + 
                    (*fatRootDir - 2) * fat32disk -> BPB_SecPerClus * fat32disk -> BPB_BytsPerSec;
                    fileCount += readRootDirectory(addr, fat32disk, rootDirOffset);
                    fatRootDir = (unsigned int *)(addr + fat1Offset + *fatRootDir * sizeof(unsigned int));
                }
                printf("Total number of entries = ");
                printf("%d\n", fileCount);
                break;
            case 'r':
                //printf("Got r\n");
                r = true;
                filename = optarg;
                break;
            case 'R':
                R = true;
                filename = optarg;
                break;
            case 's':
                if(!r && !R){
                    printErrorMessage();
                }
                //printf("Got s\n");
                s = true;
                sha = (unsigned char *)optarg;
                /*printf("The sha in argument: ");
                for (int i = 0; sha[i] != '\0'; i++) {
                    printf("%c %d ", sha[i], i);
                }
                printf("\n");*/
                break;
            default:
                //I read about multipe line c string from https://dalelane.co.uk/blog/?p=88
                printErrorMessage();
                break;
        }
    } 


    DirEntry *toRecover = NULL; // for option -r
    DirEntry *output = NULL; // for option -r
    if((R && !s) || (R && r)){
        printErrorMessage();
    }else if(r && !s){
        //recovering small or continuous files without SHA-1
        toRecover = recoverySmallFile(addr, fat32disk, rootDirOffset, filename);
        // check if fat size is too small. I learned this form attending the tutoring session.
        if(fat32disk -> BPB_RootClus * sizeof(unsigned int) < fat32disk -> BPB_FATSz32 * fat32disk -> BPB_BytsPerSec){
            fatRootDir = (unsigned int *)(addr + fat1Offset + fat32disk -> BPB_RootClus * sizeof(unsigned int));
            while(*fatRootDir < 0x0ffffff8){
                rootDirOffset = fat32disk -> BPB_RsvdSecCnt * fat32disk -> BPB_BytsPerSec +  
                fat32disk -> BPB_NumFATs * fat32disk -> BPB_FATSz32 * fat32disk -> BPB_BytsPerSec + 
                (*fatRootDir - 2) * fat32disk -> BPB_SecPerClus * fat32disk -> BPB_BytsPerSec;
                output = recoverySmallFile(addr, fat32disk, rootDirOffset, filename);
                if(toRecover != NULL && output != NULL){
                    toRecover = output;
                    /*
                    int l = 0;
                    while(filename[l] != '\0'){
                        printf("%c", filename[l]);
                        l++;
                    }
                    printf(": multiple candidates found\n");
                    exit(1);*/
                }else if(toRecover == NULL && output != NULL){
                    toRecover = output;
                }
                if(*fatRootDir * sizeof(unsigned int) >= fat32disk -> BPB_FATSz32 * fat32disk -> BPB_BytsPerSec) break;
                fatRootDir = (unsigned int *)(addr + fat1Offset + *fatRootDir * sizeof(unsigned int));
            }
        }
        if(toRecover == NULL){
            int l = 0;
            while(filename[l] != '\0'){
                printf("%c", filename[l]);
                l++;
            }
            printf(": file not found\n");
            exit(1);
        }else{
            recover(toRecover, addr, fat32disk, filename, false);
        }
    }else if(r && s){
        //recovering small or continuous files with SHA-1
        recoverySmallFileSHA1(addr, fat32disk, rootDirOffset, filename, sha);
        fatRootDir = (unsigned int *)(addr + fat1Offset + fat32disk -> BPB_RootClus * sizeof(unsigned int));
        while(*fatRootDir < 0x0ffffff8){
            rootDirOffset = fat32disk -> BPB_RsvdSecCnt * fat32disk -> BPB_BytsPerSec +  
            fat32disk -> BPB_NumFATs * fat32disk -> BPB_FATSz32 * fat32disk -> BPB_BytsPerSec + 
            (*fatRootDir - 2) * fat32disk -> BPB_SecPerClus * fat32disk -> BPB_BytsPerSec;
            recoverySmallFileSHA1(addr, fat32disk, rootDirOffset, filename, sha);
            fatRootDir = (unsigned int *)(addr + fat1Offset + *fatRootDir * sizeof(unsigned int));
        }
        int l = 0;
        while(filename[l] != '\0'){
            printf("%c", filename[l]);
            l++;
        }
        printf(": file not found\n");
        exit(1);
    }else if(R && s){
        //recovering small or continuous files with SHA-1
        recoverySmallFileSHA1(addr, fat32disk, rootDirOffset, filename, sha);
        fatRootDir = (unsigned int *)(addr + fat1Offset + fat32disk -> BPB_RootClus * sizeof(unsigned int));
        while(*fatRootDir < 0x0ffffff8){
            rootDirOffset = fat32disk -> BPB_RsvdSecCnt * fat32disk -> BPB_BytsPerSec +  
            fat32disk -> BPB_NumFATs * fat32disk -> BPB_FATSz32 * fat32disk -> BPB_BytsPerSec + 
            (*fatRootDir - 2) * fat32disk -> BPB_SecPerClus * fat32disk -> BPB_BytsPerSec;
            recoverySmallFileSHA1(addr, fat32disk, rootDirOffset, filename, sha);
            fatRootDir = (unsigned int *)(addr + fat1Offset + *fatRootDir * sizeof(unsigned int));
        }
        int l = 0;
        while(filename[l] != '\0'){
            printf("%c", filename[l]);
            l++;
        }
        printf(": file not found\n");
        exit(1);
    }

    return 0;
}