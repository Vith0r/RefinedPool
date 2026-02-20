.code

; arg1 = RCX arg2 = RDX arg3 = R8 arg4 = R9

WorkCallback_Gadget PROC
    sub  rsp, 28h                           ; Compensa o "add rsp,28h" do epilogue do gadget
    mov  r10, QWORD PTR [rdx + 08h]         ; r10 = pLoadLibraryAddress (chamado pelo gadget via "call r10")
    mov  r11, QWORD PTR [rdx + 10h]         ; r11 = pGadgetAddress
    mov  rcx, QWORD PTR [rdx]               ; rcx = LibraryName (1o argumento de LoadLibraryA)
    xor  rdx, rdx                           ; rdx = NULL (2o arg - hFile para LoadLibraryExA)
    xor  r8,  r8                            ; r8  = NULL (3o arg - dwFlags para LoadLibraryExA)
    jmp  r11
WorkCallback_Gadget ENDP

WorkCallback_Direct PROC
    mov  rcx, QWORD PTR [rdx]               ; LibraryName
    mov  rax, QWORD PTR [rdx + 08h]         ; pLoadLibraryAddress
    xor  rdx, rdx                           ; NULL
    xor  r8,  r8                            ; NULL
    jmp  rax
WorkCallback_Direct ENDP

END