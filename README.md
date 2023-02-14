```
;a macro with two parameters
;implements the write system call
%macro write_string 2
    mov     ecx,%1      ;msg
    mov     edx,%2      ;length msg
    mov     eax,4       ;sys_write
    mov     ebx,1       ;stdout
    int     0x80        ;call kernel
%endmacro
;a macro with two parameters
;implements the read system call
%macro read_string 2
    mov     ecx,%1      ;msg
    mov     edx,%2      ;length msg
    mov     eax,3       ;sys_read
    mov     ebx,0       ;stdin
    int     0x80        ;call kernel
%endmacro

segment .data
    msg1    db "**************RC4 Encryption*****************"
    lenmsg1  equ $ -msg1
    msg2    db "Plain text: "    ;string/number/pass... want to encrypt
    newline db 0xA
    msg3    db "Cipher text: "   ;hex

segment .bss
    input resb 1024
    result  resb 1024
    key resb 1024
    s resb 256  ;box

section .text
    global _start




    

RC4_KSA:    ;Key-scheduling Algorithm: giai doan hoan vi

RC4_PRGA:   ;Pseudo-Random Generation Algorithm


_start:
    push    ebp                                     ;save ebp
	mov     ebp,esp                                 ;set ebp to esp
	sub     esp,68                                  ;set 68 bytes for local variables
    
    write_string    msg1,lenmsg1
    write_string    msg2,12
    mov     byte [ebp-1],0  ;x
    mov     byte [ebp-2],0  ;y
    mov     byte [ebp-3],0  ;j
    lea             ebx,[ebp - 1027]              
	read_string     ebx,1024
    lea             ebx,[ebp - 1283] 
    RC4_Initialization:     ;giai doan khoi tao
        xor ecx,ecx
        Loop_Init:
            mov     byte [ebp+ecx-1283],ecx
            inc     ecx
            cmp     ecx,256
            jne     Loop_Init
    RC4_KSA:    ;Key-scheduling Algorithm: giai doan hoan vi
        xor ecx,ecx





```
    
