#include "../Headers/Parser.h"

void Error(const char * Message)
{
    fprintf(stderr,"[-] %s\n", Message);
    exit(1);
}

void Parse(BYTE * RawData)
{
    PIMAGE_DOS_HEADER DOSHeader = (PIMAGE_DOS_HEADER) RawData;

    if (DOSHeader -> e_magic != IMAGE_DOS_SIGNATURE)
        Error("Invalid PE File");

    DWORD Signature = (((PIMAGE_NT_HEADERS32) (RawData + DOSHeader -> e_lfanew))->Signature);

    if (Signature != IMAGE_NT_SIGNATURE)
        Error("Invalid PE File");

    WORD Magic = (((PIMAGE_NT_HEADERS32) (RawData + DOSHeader -> e_lfanew))->OptionalHeader).Magic;

    switch (Magic) {
        case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
            Parse64(RawData);
            break;
        case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
            Parse32(RawData);
            break;
        default:
            Error("Unknown Architecture.\n");
    }

}

void Parse32(BYTE * RawData)
{
    PIMAGE_DOS_HEADER           DOSHeader           ;
    PIMAGE_NT_HEADERS32         NTHeader            ;

    // Read the DOS Header into our DOSHeader Pointer

    DOSHeader = (PIMAGE_DOS_HEADER) RawData;
    PrintDOS(DOSHeader);

    // Map the NTHeader into our NTHeader Pointer

    NTHeader = (PIMAGE_NT_HEADERS32) (RawData + DOSHeader -> e_lfanew);

    PrintNT32(NTHeader);

    void * SectionLocation = (void *) (&NTHeader->OptionalHeader) + NTHeader -> FileHeader.SizeOfOptionalHeader;

    PIMAGE_SECTION_HEADER Sections [NTHeader -> FileHeader.NumberOfSections];

    for (int i = 0; i < NTHeader->FileHeader.NumberOfSections; i++) {
        Sections[i] = (PIMAGE_SECTION_HEADER) (SectionLocation + (sizeof(IMAGE_SECTION_HEADER) * i));
    }

    PrintSections(Sections, NTHeader -> FileHeader.NumberOfSections);

    // Parse Imports

    if (NTHeader -> OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size > 0)
        ParseImports(NTHeader, Sections, RawData);

    // Export Directory

    if (NTHeader -> OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size > 0)
        ParseExports(NTHeader, Sections, RawData);
}

void Parse64(BYTE * RawData)
{
    PIMAGE_DOS_HEADER           DOSHeader           ;
    PIMAGE_NT_HEADERS64         NTHeader            ;

    // Read the DOS Header into our DOSHeader Pointer

    DOSHeader = (PIMAGE_DOS_HEADER) RawData;
    PrintDOS(DOSHeader);

    // Map the NTHeader into our NTHeader Pointer

    NTHeader = (PIMAGE_NT_HEADERS64) (RawData + DOSHeader -> e_lfanew);

    PrintNT64(NTHeader);

    void * SectionLocation = (void *) (&NTHeader->OptionalHeader) + NTHeader -> FileHeader.SizeOfOptionalHeader;

    PIMAGE_SECTION_HEADER Sections [NTHeader -> FileHeader.NumberOfSections];

    for (int i = 0; i < NTHeader->FileHeader.NumberOfSections; i++) {
        Sections[i] = (PIMAGE_SECTION_HEADER) (SectionLocation + (sizeof(IMAGE_SECTION_HEADER) * i));
    }

    PrintSections(Sections, NTHeader -> FileHeader.NumberOfSections);

    // Parse Imports

    if (NTHeader -> OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size > 0)
        ParseImports(NTHeader, Sections, RawData);

    // Export Directory

    if (NTHeader -> OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size > 0)
        ParseExports(NTHeader, Sections, RawData);
}

QWORD RVA2Physical(IMAGE_SECTION_HEADER ** pSections, BYTE pNumberOfSections, QWORD pRVA)
{
    for (int i = 0; i < pNumberOfSections; i++)
    {
        PIMAGE_SECTION_HEADER currentSection = pSections[i];

        QWORD sectionStart = currentSection -> VirtualAddress;
        QWORD sectionStop  = sectionStart + currentSection -> SizeOfRawData;

        if (pRVA >= sectionStart && pRVA < sectionStop)
            return pRVA - (sectionStart - currentSection -> PointerToRawData);
    }

    return -1;
}

void ParseImports(void * NTHeader, PIMAGE_SECTION_HEADER * Sections, BYTE * RawData)
{
    WORD Magic = ((IMAGE_NT_HEADERS32 *)NTHeader)->OptionalHeader.Magic;

    IMAGE_FILE_HEADER FileHeader = ((PIMAGE_NT_HEADERS32)NTHeader)->FileHeader;

    QWORD ImportAddress;

    if (Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        IMAGE_OPTIONAL_HEADER32 OptionalHeader = ((PIMAGE_NT_HEADERS32)NTHeader) -> OptionalHeader;
        ImportAddress = RVA2Physical(Sections, FileHeader.NumberOfSections, OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    }
    else {
        IMAGE_OPTIONAL_HEADER64 OptionalHeader = ((PIMAGE_NT_HEADERS64)NTHeader) -> OptionalHeader;
        ImportAddress = RVA2Physical(Sections, FileHeader.NumberOfSections,OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    }

    PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR) (RawData + ImportAddress);

    for (; ImportDescriptor->FirstThunk; ImportDescriptor++) {
        char *ImportName = (char *) (RawData + RVA2Physical(Sections, FileHeader.NumberOfSections,ImportDescriptor->Name));
        PrintImportDescriptor(ImportDescriptor, ImportName);

        QWORD Offset = RVA2Physical(Sections, FileHeader.NumberOfSections,ImportDescriptor->FirstThunk);

        if (Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        {
            PIMAGE_THUNK_DATA32 ImportThunk = (PIMAGE_THUNK_DATA32) (RawData + Offset);

            for (; ImportThunk->u1.AddressOfData; ImportThunk++)
            {
                if (ImportThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG32)
                {
                    PRINT_ATTRIBUTE("Ordinal Import", (ImportThunk->u1.Function & 0xFFFF));
                }
                else {
                    DWORD NameAddress = RVA2Physical(Sections, FileHeader.NumberOfSections,(ImportThunk->u1.AddressOfData & 0x2FFFFFFF));

                    PIMAGE_IMPORT_BY_NAME NamedImport = (PIMAGE_IMPORT_BY_NAME) (RawData + NameAddress);
                    PRINT_NAMED_IMPORT(NamedImport -> Name, NamedImport -> Hint);
                }
            }
        }
        else {
            PIMAGE_THUNK_DATA64 ImportThunk = (PIMAGE_THUNK_DATA64) (RawData + Offset);

            for (; ImportThunk->u1.AddressOfData; ImportThunk++)
            {
                if (ImportThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG64)
                {
                    PRINT_ATTRIBUTE_LONG("Importing by Ordinal", (ImportThunk->u1.Function & 0xFFFF));
                }
                else {
                    DWORD NameAddress = RVA2Physical(Sections, FileHeader.NumberOfSections,(ImportThunk->u1.AddressOfData & 0x2FFFFFFF));

                    PIMAGE_IMPORT_BY_NAME NamedImport = (PIMAGE_IMPORT_BY_NAME) (RawData + NameAddress);
                    PRINT_NAMED_IMPORT(NamedImport -> Name, NamedImport -> Hint);

                }
            }
        }
    }
}

void ParseExports(void * NTHeader, PIMAGE_SECTION_HEADER * Sections, BYTE * RawData)
{
    WORD Magic = ((PIMAGE_NT_HEADERS32)NTHeader)-> OptionalHeader.Magic;

    IMAGE_FILE_HEADER FileHeader = ((PIMAGE_NT_HEADERS32)NTHeader)->FileHeader;

    QWORD ExportAddress;

    if (Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        IMAGE_OPTIONAL_HEADER32 OptionalHeader = ((PIMAGE_NT_HEADERS32)NTHeader) -> OptionalHeader;
        ExportAddress = RVA2Physical(Sections, FileHeader.NumberOfSections, OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    }
    else {
        IMAGE_OPTIONAL_HEADER64 OptionalHeader = ((PIMAGE_NT_HEADERS64)NTHeader) -> OptionalHeader;
        ExportAddress = RVA2Physical(Sections, FileHeader.NumberOfSections, OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    }

    PIMAGE_EXPORT_DIRECTORY ExportDirectory = (PIMAGE_EXPORT_DIRECTORY) (RawData + ExportAddress);

    char * ExportName = (char *) RawData + RVA2Physical(Sections, FileHeader.NumberOfSections, ExportDirectory -> Name);

    PrintExportDirectory(ExportDirectory, ExportName);

    DWORD *AddressOfFunctions =     (DWORD *)   (RawData + RVA2Physical(Sections, FileHeader.NumberOfSections,ExportDirectory->AddressOfFunctions));
    DWORD *AddressOfNames =         (DWORD *)   (RawData + RVA2Physical(Sections, FileHeader.NumberOfSections,ExportDirectory->AddressOfNames));
    WORD *AddressOfNameOrdinals =   (WORD *)    (RawData + RVA2Physical(Sections, FileHeader.NumberOfSections, ExportDirectory->AddressOfNameOrdinals));

    for (int i = 0; i < ExportDirectory->NumberOfFunctions; i++) {
        printf("\t\tExported Function: %-10X Ordinal: %-10X", AddressOfFunctions[i], ExportDirectory->Base + i);

        for (int j = 0; j < ExportDirectory->NumberOfNames; j++)

            if (AddressOfNameOrdinals[j] == i)
                printf("Name RVA: %-10X Name: %-40s", AddressOfNames[j], (char *) (RawData + RVA2Physical(Sections,FileHeader.NumberOfSections,AddressOfNames[j])));

        printf("\n");
    }

}
