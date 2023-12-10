#ifndef STRUCTURES_H
#define STRUCTURES_H

#include <stdint.h>

typedef         uint8_t                 BYTE;
typedef         uint16_t                WORD;
typedef         uint32_t                DWORD;
typedef         uint64_t                QWORD;

#define IMAGE_DOS_SIGNATURE                     0x5A4D      // MZ
#define IMAGE_NT_SIGNATURE                      0x00004550  // PE00

#define IMAGE_DIRECTORY_ENTRY_EXPORT            0
#define IMAGE_DIRECTORY_ENTRY_IMPORT            1

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES        15
#define IMAGE_SIZEOF_SHORT_NAME                 8

#define IMAGE_ORDINAL_FLAG64                    (((QWORD)0x80000000 << 32) | 0x00000000)
#define IMAGE_ORDINAL_FLAG32                    0x80000000

#define IMAGE_NT_OPTIONAL_HDR32_MAGIC           0x10B
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC           0x20B

// Size: 64 Bytes
typedef struct _IMAGE_DOS_HEADER
{
    WORD                   e_magic;
    WORD                   e_cblp;
    WORD                   e_cp;
    WORD                   e_crlc;
    WORD                   e_cparhdr;
    WORD                   e_minalloc;
    WORD                   e_maxalloc;
    WORD                   e_ss;
    WORD                   e_sp;
    WORD                   e_csum;
    WORD                   e_ip;
    WORD                   e_cs;
    WORD                   e_lfarlc;
    WORD                   e_ovno;
    WORD                   e_res[4];
    WORD                   e_oemid;
    WORD                   e_oeminfo;
    WORD                   e_res2[10];
    DWORD                  e_lfanew;
}   IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

typedef struct _IMAGE_FILE_HEADER {
    WORD                    Machine;
    WORD                    NumberOfSections;
    DWORD                   TimeDateStamp;
    DWORD                   PointerToSymbolTable;
    DWORD                   NumberOfSymbols;
    WORD                    SizeOfOptionalHeader;
    WORD                    Characteristics;
}    IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD                   VirtualAddress;
    DWORD                   Size;
}    IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_OPTIONAL_HEADER {
    WORD                    Magic;
    BYTE                    MajorLinkerVersion;
    BYTE                    MinorLinkerVersion;
    DWORD                   SizeOfCode;
    DWORD                   SizeOfInitializedData;
    DWORD                   SizeOfUninitializedData;
    DWORD                   AddressOfEntryPoint;
    DWORD                   BaseOfCode;
    DWORD                   BaseOfData;
    DWORD                   ImageBase;
    DWORD                   SectionAlignment;
    DWORD                   FileAlignment;
    WORD                    MajorOperatingSystemVersion;
    WORD                    MinorOperatingSystemVersion;
    WORD                    MajorImageVersion;
    WORD                    MinorImageVersion;
    WORD                    MajorSubsystemVersion;
    WORD                    MinorSubsystemVersion;
    DWORD                   Win32VersionValue;
    DWORD                   SizeOfImage;
    DWORD                   SizeOfHeaders;
    DWORD                   CheckSum;
    WORD                    Subsystem;
    WORD                    DllCharacteristics;
    DWORD                   SizeOfStackReserve;
    DWORD                   SizeOfStackCommit;
    DWORD                   SizeOfHeapReserve;
    DWORD                   SizeOfHeapCommit;
    DWORD                   LoaderFlags;
    DWORD                   NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY    DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
}   IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    WORD                    Magic;
    BYTE                    MajorLinkerVersion;
    BYTE                    MinorLinkerVersion;
    DWORD                   SizeOfCode;
    DWORD                   SizeOfInitializedData;
    DWORD                   SizeOfUninitializedData;
    DWORD                   AddressOfEntryPoint;
    DWORD                   BaseOfCode;
    QWORD                   ImageBase;
    DWORD                   SectionAlignment;
    DWORD                   FileAlignment;
    WORD                    MajorOperatingSystemVersion;
    WORD                    MinorOperatingSystemVersion;
    WORD                    MajorImageVersion;
    WORD                    MinorImageVersion;
    WORD                    MajorSubsystemVersion;
    WORD                    MinorSubsystemVersion;
    DWORD                   Win32VersionValue;
    DWORD                   SizeOfImage;
    DWORD                   SizeOfHeaders;
    DWORD                   CheckSum;
    WORD                    Subsystem;
    WORD                    DllCharacteristics;
    QWORD                   SizeOfStackReserve;
    QWORD                   SizeOfStackCommit;
    QWORD                   SizeOfHeapReserve;
    QWORD                   SizeOfHeapCommit;
    DWORD                   LoaderFlags;
    DWORD                   NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY    DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
}   IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;

typedef struct _IMAGE_NT_HEADERS64 {
    DWORD                   Signature;
    IMAGE_FILE_HEADER       FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
}   IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_NT_HEADERS32 {
    DWORD                   Signature;
    IMAGE_FILE_HEADER       FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
}   IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;

typedef struct _IMAGE_SECTION_HEADER {
    BYTE                   Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
        DWORD               PhysicalAddress;
        DWORD               VirtualSize;
    } Misc;
    DWORD                   VirtualAddress;
    DWORD                   SizeOfRawData;
    DWORD                   PointerToRawData;
    DWORD                   PointerToRelocations;
    DWORD                   PointerToLinenumbers;
    WORD                    NumberOfRelocations;
    WORD                    NumberOfLinenumbers;
    DWORD                   Characteristics;
}   IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        DWORD               Characteristics;
        DWORD               OriginalFirstThunk;
    }    DUMMYUNIONNAME;
    DWORD                   TimeDateStamp;
    DWORD                   ForwarderChain;
    DWORD                   Name;
    DWORD                   FirstThunk;
}   IMAGE_IMPORT_DESCRIPTOR, *PIMAGE_IMPORT_DESCRIPTOR;

typedef struct _IMAGE_THUNK_DATA64 {
    union {
        QWORD               ForwarderString;
        QWORD               Function;
        QWORD               Ordinal;
        QWORD               AddressOfData;
    } u1;
}    IMAGE_THUNK_DATA64,    *PIMAGE_THUNK_DATA64;

typedef struct _IMAGE_THUNK_DATA32 {
    union {
        DWORD ForwarderString;
        DWORD Function;
        DWORD Ordinal;
        DWORD AddressOfData;
    } u1;
} IMAGE_THUNK_DATA32,   *PIMAGE_THUNK_DATA32;

typedef struct _IMAGE_IMPORT_BY_NAME {
    WORD                    Hint;
    BYTE                    Name[1];
} IMAGE_IMPORT_BY_NAME,*PIMAGE_IMPORT_BY_NAME;

typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD                   Characteristics;
    DWORD                   TimeDateStamp;
    WORD                    MajorVersion;
    WORD                    MinorVersion;
    DWORD                   Name;
    DWORD                   Base;
    DWORD                   NumberOfFunctions;
    DWORD                   NumberOfNames;
    DWORD                   AddressOfFunctions;
    DWORD                   AddressOfNames;
    DWORD                   AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;

#endif
