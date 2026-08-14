include ksamd64.inc
include CallConv.inc

extern InstrumentationCallback:proc
EXTERNDEF __imp_RtlCaptureContext:QWORD

.code

InstrumentationCallbackProxy proc
    push rsp                     ; back-up RSP, R10, and RAX
    push r10
    push rax
    mov rax, 1
    cmp gs:[2ech], rax           ; check recursion flag
    je resume
    pop rax
    pop r10
    pop rsp
    mov gs:[2e0h], rsp           ; InstrumentationCallbackPreviousSp
    mov gs:[2d8h], r10           ; InstrumentationCallbackPreviousPc
    mov r10, rcx
    sub rsp, 4d0h
    and rsp, -10h
    mov rcx, rsp
    mov rdx, 0h
    sub rsp, 20h
    call __imp_RtlCaptureContext
    mov r8, [rcx+78h]            ; RAX from CONTEXT
    mov rdx, gs:[2d8h]           ; saved RIP
    sub rsp, 20h
    call InstrumentationCallback

resume:
    pop rax
    pop r10
    pop rsp
    jmp r10
InstrumentationCallbackProxy endp

end