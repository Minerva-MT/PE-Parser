#include <stdio.h>

#include "Headers/Parser.h"

BYTE * ReadFile(const char * FilePath)
{
    // Open File

    FILE * File = fopen(FilePath, "r");

    // Seek to the end, get the file size and rewind the file

    fseek(File, 0, SEEK_END);
    long size = ftell(File);
    rewind(File);

    // Read the Contents of the file into memory

    BYTE * data = malloc(size);
    fread(data, size, 1, File);

    // Close the file

    fclose(File);

    return data;
}

int main (int argc, char * argv[])
{
    if (argc < 2)
        printf("Usage: %s <Path to Executable>\n", argv[0]);
    else
        Parse(ReadFile(argv[1]));

    return 0;
}
