#include "loadlib.h"
#include "gadget.h"

#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "ntdll.lib")

NTSYSAPI NTSTATUS NTAPI TpAllocWork(PTP_WORK*, PTP_WORK_CALLBACK, PVOID, PTP_CALLBACK_ENVIRON);
NTSYSAPI VOID     NTAPI TpPostWork(PTP_WORK);
NTSYSAPI VOID     NTAPI TpWaitForWork(PTP_WORK, BOOL);
NTSYSAPI VOID     NTAPI TpReleaseWork(PTP_WORK);

typedef struct _TP_LOADLIB_PARAMS {
    LPSTR  LibraryName;         // rcx
    PVOID  pLoadLibraryAddress; // r10
    PVOID  pGadgetAddress;      // r11
} TP_LOADLIB_PARAMS;

extern void WorkCallback_Gadget(PTP_CALLBACK_INSTANCE, PVOID, PTP_WORK);
extern void WorkCallback_Direct(PTP_CALLBACK_INSTANCE, PVOID, PTP_WORK);

HMODULE LoadLib(LPCSTR libName) {

    PTP_WORK          workItem = NULL;
    TP_LOADLIB_PARAMS params = { 0 };
    PTP_WORK_CALLBACK callback = NULL;

    params.LibraryName = (LPSTR)libName;
    params.pLoadLibraryAddress = (PVOID)LoadLibraryA;

#if DO_GADGET == 1

    // ================================================================== //
    // Entao, quando o Thread Pool executar o WorkCallback e ele fizer    //
    // "jmp r11" -> gadget -> "call r10" -> LoadLibraryA,                 //
    // o call stack mostrara:                                             //
    // kernelbase.LoadLibraryA+8D                                         //
    // nvwgf2umx.dll+<offset do gadget>                                   //
    // ntdll.TppWorkpExecuteCallback                                      //
    // ...                                                                //
    // ================================================================== //

    HMODULE hGadgetMod = NULL;
    //params.pGadgetAddress = FindCallGadget(&hGadgetMod);
    params.pGadgetAddress = WriteGadget(&hGadgetMod);

    printf("[*] Gadget address: %p (module: %p)\n", params.pGadgetAddress, hGadgetMod);

    if (!params.pGadgetAddress) {
        OutputDebugStringA("[LoadLib] ERRO: nenhum gadget encontrado.\n");
        return NULL;
    }

    callback = (PTP_WORK_CALLBACK)WorkCallback_Gadget;

#else
    /* sem gadget */
    callback = (PTP_WORK_CALLBACK)WorkCallback_Direct;
#endif

    TpAllocWork(&workItem, callback, &params, NULL);
    TpPostWork(workItem);
    TpWaitForWork(workItem, FALSE);
    TpReleaseWork(workItem);

    return GetModuleHandleA(libName);
}