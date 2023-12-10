#ifndef PRINT_H
#define PRINT_H

#include <stdio.h>
#include "Windows.h"

#define PRINT_STRING(Key, Value) printf("\t%-60s: %s\n", Key, Value)

#define PRINT_NAMED_IMPORT(Name, Hint) printf("\tNamed Import: %-45s  Hint: 0x%X\n", Name, Hint)

#define PRINT_ATTRIBUTE(Key, Value) printf("\t%-60s 0x%X\n", Key, Value)
#define PRINT_ATTRIBUTE_LONG(Key, Value) printf("\t%-60s 0x%lX\n", Key, Value)

void PrintDOS               (PIMAGE_DOS_HEADER pDosHeader);
void PrintNT64              (PIMAGE_NT_HEADERS64 pNTHeader);
void PrintNT32              (PIMAGE_NT_HEADERS32 pNTHeader);
void PrintSections          (PIMAGE_SECTION_HEADER pSectionHeader[], BYTE pSectionCount);
void PrintImportDescriptor  (PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor, const char * pName);
void PrintExportDirectory   (PIMAGE_EXPORT_DIRECTORY pExportDirectory, const char * pName);



#endif
