#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <stdio.h>
#include <malloc.h>

#include "MemoryModule.h"

typedef int (*MemoryDllFunc)();

char buffer[] = "D:\\Projects\\InjectDll\\x64\\Debug\\MemoryDll.dll";

int main(int argc, char *argv[])
{
    FILE *fp;
    unsigned char *data = NULL;
    size_t size;
    HMEMORYMODULE module;
    MemoryDllFunc func;

    fp = fopen(buffer, "rb");
    if (fp == NULL) {
        printf("Can't open DLL file \"%s\".", buffer);
        goto exit;
    }

    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    data = (unsigned char *)malloc(size);
    fseek(fp, 0, SEEK_SET);
    fread(data, 1, size, fp);
    fclose(fp);

    module = MemoryLoadLibrary(data);
    if (module == NULL) {
        printf("Can't load library from memory.\n");
        goto exit;
    }

exit:
    if (data) {
        free(data);
    }

    return 0;
}