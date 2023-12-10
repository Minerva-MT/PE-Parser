#include "../Headers/Print.h"

char * Directories [] = {
        "Export",
        "Import",
        "Resource",
        "Exception",
        "Security",
        "Base Relocation Table",
        "Debug",
        "Copywrite",
        "Global Pointer",
        "Thread Local Storage",
        "Load Configuration",
        "Bound Import",
        "Import Address Table",
        "Delay Load Imports",
        ".NET"
};

void PrintDOS(PIMAGE_DOS_HEADER pDosHeader) {
    printf("[*] DOS Header\n");
    PRINT_ATTRIBUTE("Magic",                                pDosHeader -> e_magic);
    PRINT_ATTRIBUTE("Bytes on Last Page",                   pDosHeader -> e_cblp);
    PRINT_ATTRIBUTE("Pages in File",                        pDosHeader -> e_cp);
    PRINT_ATTRIBUTE("Relocations",                          pDosHeader -> e_crlc);
    PRINT_ATTRIBUTE("Size of Header (in Paragraphs)",       pDosHeader -> e_cparhdr);
    PRINT_ATTRIBUTE("Minimum Extra Paragraphs Needed",      pDosHeader -> e_minalloc);
    PRINT_ATTRIBUTE("Maximum Extra Paragraphs Needed",      pDosHeader -> e_maxalloc);
    PRINT_ATTRIBUTE("Initial SS Value (Relative)",          pDosHeader -> e_ss);
    PRINT_ATTRIBUTE("Initial SP Value",                     pDosHeader -> e_sp);
    PRINT_ATTRIBUTE("Checksum",                             pDosHeader -> e_csum);
    PRINT_ATTRIBUTE("Initial IP Value",                     pDosHeader -> e_ip);
    PRINT_ATTRIBUTE("Initial CS Value (Relative)",          pDosHeader -> e_cs);
    PRINT_ATTRIBUTE("File Address of Relocation Table",     pDosHeader -> e_lfarlc);
    PRINT_ATTRIBUTE("Overlay Number",                       pDosHeader -> e_ovno);
    PRINT_ATTRIBUTE("OEM Identifier",                       pDosHeader -> e_oemid);
    PRINT_ATTRIBUTE("OEM Information",                      pDosHeader -> e_oeminfo);
    PRINT_ATTRIBUTE("Address of new Header",                pDosHeader -> e_lfanew);
}

void PrintNT64  (PIMAGE_NT_HEADERS64 pNTHeader)
{
    printf("[*] NT Header\n");

    PRINT_ATTRIBUTE("NT Signature",                         pNTHeader -> Signature);

    printf("\t[*] File Header\n");

    PRINT_ATTRIBUTE("\t\tMachine",                          pNTHeader -> FileHeader.Machine);
    PRINT_ATTRIBUTE("\t\tNumber of Sections",               pNTHeader -> FileHeader.NumberOfSections);
    PRINT_ATTRIBUTE("\t\tTimeDate Stamp",                   pNTHeader -> FileHeader.TimeDateStamp);
    PRINT_ATTRIBUTE("\t\tPointer to Symbol Table",          pNTHeader -> FileHeader.PointerToSymbolTable);
    PRINT_ATTRIBUTE("\t\tNumber of Symbols",                pNTHeader -> FileHeader.NumberOfSymbols);
    PRINT_ATTRIBUTE("\t\tSize of Optional Header",          pNTHeader -> FileHeader.SizeOfOptionalHeader);
    PRINT_ATTRIBUTE("\t\tCharacteristics",                  pNTHeader -> FileHeader.Characteristics);

    printf("\t[*] Optional Header\n");

    PRINT_ATTRIBUTE("\t\tMagic",                            pNTHeader ->OptionalHeader.Magic);
    PRINT_ATTRIBUTE("\t\tMajor Linker Version",             pNTHeader ->OptionalHeader.MajorLinkerVersion);
    PRINT_ATTRIBUTE("\t\tMinor Linker Version",             pNTHeader ->OptionalHeader.MinorLinkerVersion);
    PRINT_ATTRIBUTE("\t\tSize of Code",                     pNTHeader ->OptionalHeader.SizeOfCode);
    PRINT_ATTRIBUTE("\t\tSize of Initialized Data",         pNTHeader ->OptionalHeader.SizeOfInitializedData);
    PRINT_ATTRIBUTE("\t\tSize of Uninitialized Data",       pNTHeader ->OptionalHeader.SizeOfUninitializedData);
    PRINT_ATTRIBUTE("\t\tAddress of Entry Point",           pNTHeader ->OptionalHeader.AddressOfEntryPoint);
    PRINT_ATTRIBUTE("\t\tBase of Code",                     pNTHeader ->OptionalHeader.BaseOfCode);
    PRINT_ATTRIBUTE_LONG("\t\tImage Base",                  pNTHeader ->OptionalHeader.ImageBase);
    PRINT_ATTRIBUTE("\t\tSection Alignment",                pNTHeader ->OptionalHeader.SectionAlignment);
    PRINT_ATTRIBUTE("\t\tFile Alignment",                   pNTHeader ->OptionalHeader.FileAlignment);
    PRINT_ATTRIBUTE("\t\tMajor Operating System Version",   pNTHeader ->OptionalHeader.MajorOperatingSystemVersion);
    PRINT_ATTRIBUTE("\t\tMinor Operating System Version",   pNTHeader ->OptionalHeader.MinorOperatingSystemVersion);
    PRINT_ATTRIBUTE("\t\tMajor Image Version",              pNTHeader ->OptionalHeader.MajorImageVersion);
    PRINT_ATTRIBUTE("\t\tMinor Image Version",              pNTHeader ->OptionalHeader.MinorImageVersion);
    PRINT_ATTRIBUTE("\t\tMajor Subsystem Version",          pNTHeader ->OptionalHeader.MajorSubsystemVersion);
    PRINT_ATTRIBUTE("\t\tMinor Subsystem Version",          pNTHeader ->OptionalHeader.MinorSubsystemVersion);
    PRINT_ATTRIBUTE("\t\tWin32 Version Value",              pNTHeader ->OptionalHeader.Win32VersionValue);
    PRINT_ATTRIBUTE("\t\tSize of Image",                    pNTHeader ->OptionalHeader.SizeOfImage);
    PRINT_ATTRIBUTE("\t\tSize of Headers",                  pNTHeader ->OptionalHeader.SizeOfHeaders);
    PRINT_ATTRIBUTE("\t\tChecksum",                         pNTHeader ->OptionalHeader.CheckSum);
    PRINT_ATTRIBUTE("\t\tSubsystem",                        pNTHeader ->OptionalHeader.Subsystem);
    PRINT_ATTRIBUTE("\t\tDLL Characteristics",              pNTHeader ->OptionalHeader.DllCharacteristics);
    PRINT_ATTRIBUTE_LONG("\t\tSize of Stack Reserve",       pNTHeader ->OptionalHeader.SizeOfStackReserve);
    PRINT_ATTRIBUTE_LONG("\t\tSize of Stack Commit",        pNTHeader ->OptionalHeader.SizeOfStackCommit);
    PRINT_ATTRIBUTE_LONG("\t\tSize of Heap Reserve",        pNTHeader ->OptionalHeader.SizeOfHeapReserve);
    PRINT_ATTRIBUTE_LONG("\t\tSize of Heap Commit",         pNTHeader ->OptionalHeader.SizeOfHeapCommit);
    PRINT_ATTRIBUTE("\t\tLoader Flags",                     pNTHeader ->OptionalHeader.LoaderFlags);
    PRINT_ATTRIBUTE("\t\tNumber of RVA and Sizes",          pNTHeader ->OptionalHeader.NumberOfRvaAndSizes);

    printf("\t\t[*] Data Directories\n");

    for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i ++)
    {
        printf("\t\t\tDirectory: %-25s Virtual Address: 0x%-10X Size: 0x%-10X \n", Directories[i], pNTHeader ->OptionalHeader.DataDirectory[i].VirtualAddress, pNTHeader ->OptionalHeader.DataDirectory[i].Size);
    }
}

void PrintNT32  (PIMAGE_NT_HEADERS32 pNTHeader)
{
    printf("\t[*] NT Header\n");

    PRINT_ATTRIBUTE("\t\tNT Signature",                         pNTHeader -> Signature);

    printf("\t[*] File Header\n");

    PRINT_ATTRIBUTE("\t\tMachine",                          pNTHeader -> FileHeader.Machine);
    PRINT_ATTRIBUTE("\t\tNumber of Sections",               pNTHeader -> FileHeader.NumberOfSections);
    PRINT_ATTRIBUTE("\t\tTimeDate Stamp",                   pNTHeader -> FileHeader.TimeDateStamp);
    PRINT_ATTRIBUTE("\t\tPointer to Symbol Table",          pNTHeader -> FileHeader.PointerToSymbolTable);
    PRINT_ATTRIBUTE("\t\tNumber of Symbols",                pNTHeader -> FileHeader.NumberOfSymbols);
    PRINT_ATTRIBUTE("\t\tSize of Optional Header",          pNTHeader -> FileHeader.SizeOfOptionalHeader);
    PRINT_ATTRIBUTE("\t\tCharacteristics",                  pNTHeader -> FileHeader.Characteristics);

    printf("\t[*] Optional Header\n");

    PRINT_ATTRIBUTE("\t\tMagic",                            pNTHeader ->OptionalHeader.Magic);
    PRINT_ATTRIBUTE("\t\tMajor Linker Version",             pNTHeader ->OptionalHeader.MajorLinkerVersion);
    PRINT_ATTRIBUTE("\t\tMinor Linker Version",             pNTHeader ->OptionalHeader.MinorLinkerVersion);
    PRINT_ATTRIBUTE("\t\tSize of Code",                     pNTHeader ->OptionalHeader.SizeOfCode);
    PRINT_ATTRIBUTE("\t\tSize of Initialized Data",         pNTHeader ->OptionalHeader.SizeOfInitializedData);
    PRINT_ATTRIBUTE("\t\tSize of Uninitialized Data",       pNTHeader ->OptionalHeader.SizeOfUninitializedData);
    PRINT_ATTRIBUTE("\t\tAddress of Entry Point",           pNTHeader ->OptionalHeader.AddressOfEntryPoint);
    PRINT_ATTRIBUTE("\t\tBase of Code",                     pNTHeader ->OptionalHeader.BaseOfCode);
    PRINT_ATTRIBUTE("\t\tBase of Data",                     pNTHeader ->OptionalHeader.BaseOfData);
    PRINT_ATTRIBUTE("\t\tImage Base",                       pNTHeader ->OptionalHeader.ImageBase);
    PRINT_ATTRIBUTE("\t\tSection Alignment",                pNTHeader ->OptionalHeader.SectionAlignment);
    PRINT_ATTRIBUTE("\t\tFile Alignment",                   pNTHeader ->OptionalHeader.FileAlignment);
    PRINT_ATTRIBUTE("\t\tMajor Operating System Version",   pNTHeader ->OptionalHeader.MajorOperatingSystemVersion);
    PRINT_ATTRIBUTE("\t\tMinor Operating System Version",   pNTHeader ->OptionalHeader.MinorOperatingSystemVersion);
    PRINT_ATTRIBUTE("\t\tMajor Image Version",              pNTHeader ->OptionalHeader.MajorImageVersion);
    PRINT_ATTRIBUTE("\t\tMinor Image Version",              pNTHeader ->OptionalHeader.MinorImageVersion);
    PRINT_ATTRIBUTE("\t\tMajor Subsystem Version",          pNTHeader ->OptionalHeader.MajorSubsystemVersion);
    PRINT_ATTRIBUTE("\t\tMinor Subsystem Version",          pNTHeader ->OptionalHeader.MinorSubsystemVersion);
    PRINT_ATTRIBUTE("\t\tWin32 Version Value",              pNTHeader ->OptionalHeader.Win32VersionValue);
    PRINT_ATTRIBUTE("\t\tSize of Image",                    pNTHeader ->OptionalHeader.SizeOfImage);
    PRINT_ATTRIBUTE("\t\tSize of Headers",                  pNTHeader ->OptionalHeader.SizeOfHeaders);
    PRINT_ATTRIBUTE("\t\tChecksum",                         pNTHeader ->OptionalHeader.CheckSum);
    PRINT_ATTRIBUTE("\t\tSubsystem",                        pNTHeader ->OptionalHeader.Subsystem);
    PRINT_ATTRIBUTE("\t\tDLL Characteristics",              pNTHeader ->OptionalHeader.DllCharacteristics);
    PRINT_ATTRIBUTE("\t\tSize of Stack Reserve",            pNTHeader ->OptionalHeader.SizeOfStackReserve);
    PRINT_ATTRIBUTE("\t\tSize of Stack Commit",             pNTHeader ->OptionalHeader.SizeOfStackCommit);
    PRINT_ATTRIBUTE("\t\tSize of Heap Reserve",             pNTHeader ->OptionalHeader.SizeOfHeapReserve);
    PRINT_ATTRIBUTE("\t\tSize of Heap Commit",              pNTHeader ->OptionalHeader.SizeOfHeapCommit);
    PRINT_ATTRIBUTE("\t\tLoader Flags",                     pNTHeader ->OptionalHeader.LoaderFlags);
    PRINT_ATTRIBUTE("\t\tNumber of RVA and Sizes",          pNTHeader ->OptionalHeader.NumberOfRvaAndSizes);

    printf("\t\t[*] Data Directories\n");

    for (int i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i ++)
    {
        printf("\t\t\tDirectory: %-25s Virtual Address: 0x%-10X Size: 0x%-10X \n", Directories[i], pNTHeader ->OptionalHeader.DataDirectory[i].VirtualAddress, pNTHeader ->OptionalHeader.DataDirectory[i].Size);
    }
}


void PrintSections(PIMAGE_SECTION_HEADER pSectionHeader[], BYTE pSectionCount)
{
    for (int i = 0; i < pSectionCount; i++) {
        printf("[*] %s Section\n", pSectionHeader[i] -> Name);

        PRINT_ATTRIBUTE("Virtual Size",            pSectionHeader[i] -> Misc.VirtualSize);
        PRINT_ATTRIBUTE("Virtual Address",         pSectionHeader[i] -> VirtualAddress);
        PRINT_ATTRIBUTE("Size of Raw Data",        pSectionHeader[i] -> SizeOfRawData);
        PRINT_ATTRIBUTE("Pointer to Raw Data",     pSectionHeader[i] -> PointerToRawData);
        PRINT_ATTRIBUTE("Pointer to Relocations",  pSectionHeader[i] -> PointerToRelocations);
        PRINT_ATTRIBUTE("Pointer to Line Numbers", pSectionHeader[i] -> PointerToLinenumbers);
        PRINT_ATTRIBUTE("Number of Relocations",   pSectionHeader[i] -> NumberOfRelocations);
        PRINT_ATTRIBUTE("Number of Line Numbers",  pSectionHeader[i] -> NumberOfLinenumbers);
        PRINT_ATTRIBUTE("Characteristics",         pSectionHeader[i] -> Characteristics);
    }
}

void PrintImportDescriptor (PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor, const char * pName)
{
    printf("[*] Imports from %s\n", pName);

    PRINT_ATTRIBUTE("Original First Thunk",                 pImportDescriptor -> DUMMYUNIONNAME.OriginalFirstThunk);
    PRINT_ATTRIBUTE("TimeDate Stamp",                       pImportDescriptor -> TimeDateStamp);
    PRINT_ATTRIBUTE("Forward Chain",                        pImportDescriptor -> ForwarderChain);
    PRINT_ATTRIBUTE("First Thunk",                          pImportDescriptor -> FirstThunk);
}

void PrintExportDirectory (PIMAGE_EXPORT_DIRECTORY pExportDirectory, const char * pName)
{
    printf("[*] Exports from %s\n", pName);

    PRINT_ATTRIBUTE("Characteristics",          pExportDirectory -> Characteristics);
    PRINT_ATTRIBUTE("TimeDate Stamp",           pExportDirectory -> TimeDateStamp);
    PRINT_ATTRIBUTE("Major Version",            pExportDirectory -> MajorVersion);
    PRINT_ATTRIBUTE("Minor Version",            pExportDirectory -> MinorVersion);
    PRINT_ATTRIBUTE("Name RVA",                 pExportDirectory -> Name);
    PRINT_ATTRIBUTE("Base",                     pExportDirectory -> Base);
    PRINT_ATTRIBUTE("Number of Functions",      pExportDirectory -> NumberOfFunctions);
    PRINT_ATTRIBUTE("Number of Names",          pExportDirectory -> NumberOfNames);
    PRINT_ATTRIBUTE("Address of Functions",     pExportDirectory -> AddressOfFunctions);
    PRINT_ATTRIBUTE("Address of Names",         pExportDirectory -> AddressOfNames);
    PRINT_ATTRIBUTE("Address of Name Ordinals", pExportDirectory -> AddressOfNameOrdinals);
}