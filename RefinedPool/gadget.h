#pragma once
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>
#include <string.h>

#define GADGET_MAX_GAP 20
#define CAVE_SIZE 10

static const char* GADGET_CANDIDATE_DLLS[] = {
    "C:\\WINDOWS\\System32\\DriverStore\\FileRepository\\nv_dispi.inf_amd64_20ae8f14a487d5db\\nvwgf2umx.dll",
    "nvwgf2umx.dll",
    NULL
};

static const BYTE Gadget[CAVE_SIZE] = {
    0x41, 0xFF, 0xD2,        // call r10
    0x33, 0xC0,              // xor eax, eax 
    0x48, 0x83, 0xC4, 0x28,  // add rsp, 0x28
    0xC3                     // ret
};

static const char* EXCLUDED_MODULES[] = {
    "ntdll.dll",
    "kernel32.dll",
    "kernelbase.dll",
    "user32.dll",
    "windhawk.dll",
    "win32u.dll",
    NULL
};

static BOOL IsExcluded(const char* modName) {
    char lower[MAX_PATH];
    int i = 0;
    while (modName[i] && i < MAX_PATH - 1) {
        lower[i] = (char)tolower((unsigned char)modName[i]);
        i++;
    }
    lower[i] = '\0';

    for (int j = 0; EXCLUDED_MODULES[j] != NULL; j++) {
        if (strcmp(lower, EXCLUDED_MODULES[j]) == 0)
            return TRUE;
    }
    return FALSE;
}

static PVOID FindCodeCaveInModule(HMODULE hModule) {
    if (!hModule) return NULL;

    PBYTE base = (PBYTE)hModule;

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    WORD numSections = nt->FileHeader.NumberOfSections;
    IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(nt);

    for (WORD s = 0; s < numSections; s++, section++) {

        if (!(section->Characteristics & IMAGE_SCN_MEM_EXECUTE))
            continue;

        DWORD rva = section->VirtualAddress;
        DWORD size = section->Misc.VirtualSize;

        if (size < CAVE_SIZE) continue;

        PBYTE start = base + rva;
        PBYTE end = start + size - CAVE_SIZE;

        for (PBYTE p = start; p < end; p++) {

            if (*p != 0x00 && *p != 0xCC)
                continue;

            BYTE fill = *p;
            BOOL ok = TRUE;

            for (int i = 1; i < CAVE_SIZE; i++) {
                if (p[i] != fill) { ok = FALSE; break; }
            }

            if (ok) return (PVOID)p;
        }
    }

    return NULL;
}

static PVOID FindCodeCaveInFunction(HMODULE hModule) {
    if (!hModule) return NULL;

    PBYTE base = (PBYTE)hModule;

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    // localiza a tabela .pdata (exception directory)
    DWORD excRva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
    DWORD excSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;

    if (!excRva || !excSize) return NULL;

    RUNTIME_FUNCTION* rtTable = (RUNTIME_FUNCTION*)(base + excRva);
    DWORD count = excSize / sizeof(RUNTIME_FUNCTION);

    for (DWORD f = 0; f < count; f++) {
        DWORD funcBegin = rtTable[f].BeginAddress;
        DWORD funcEnd = rtTable[f].EndAddress;
        DWORD funcSize = funcEnd - funcBegin;

        if (funcSize < CAVE_SIZE + 16) continue;

        PBYTE start = base + funcEnd - CAVE_SIZE;
        PBYTE end = base + funcBegin + 16; // nao sobrescrever o inicio

        for (PBYTE p = start; p > end; p--) {
            if (*p != 0x00 && *p != 0xCC) continue;

            BYTE fill = *p;
            BOOL ok = TRUE;

            for (int i = 1; i < CAVE_SIZE; i++) {
                if (p[i] != fill) { ok = FALSE; break; }
            }

            if (ok) {
                printf("[+] Code cave em funcao existente: RVA 0x%lX-0x%lX, cave: %p\n",
                    funcBegin, funcEnd, (void*)p);
                return (PVOID)p;
            }
        }
    }

    return NULL;
}

PVOID FindGadgetInModule(HMODULE hModule);
PVOID FindCallGadget(HMODULE* phGadgetModule);
PVOID FindCodeCave(void);
PVOID WriteGadget(HMODULE* phModule);