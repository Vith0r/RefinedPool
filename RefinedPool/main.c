#include <stdio.h>
#include "loadlib.h"

#pragma comment(lib, "psapi.lib")

int main(void) {

    const char* libName = "wininet";

    printf("\n[*] Carregando '%s' ...", libName);
    getchar();

    HMODULE hMod = LoadLib(libName);

    if (hMod) {
        printf("[+] '%s' carregada com sucesso: 0x%p\n", libName, (void*)hMod);
    }
    else {
        printf("[-] Falha ao carregar '%s'\n", libName);
    }

    printf("\nPressione Enter para sair...\n");
    getchar();
    return 0;
}