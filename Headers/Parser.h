#ifndef PARSER_H
#define PARSER_H

#include <stdio.h>
#include <stdlib.h>

#include "Windows.h"
#include "Print.h"

void    Parse                   (BYTE * RawData);

void    Parse32                 (BYTE * RawData);
void    Parse64                 (BYTE * RawData);

void    ParseImports            (void * NTHeader, PIMAGE_SECTION_HEADER * Sections, BYTE * RawData);
void    ParseExports            (void * NTHeader, PIMAGE_SECTION_HEADER * Sections, BYTE * RawData);

QWORD   RVA2Physical            (IMAGE_SECTION_HEADER ** pSections, BYTE pNumberOfSections, QWORD pRVA);



#endif