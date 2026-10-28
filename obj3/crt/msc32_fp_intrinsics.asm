; msc32_fp_intrinsics.asm - MSVC FP conversion intrinsics for dcc32
; These are MSVC compiler-generated helpers for double<->int conversions
; Assemble: ml /c /coff msc32_fp_intrinsics.asm
;
; Symbols needed (2 underscores each): __dtol3 __dtoui3 __dtoul3 __ltod3 __ultod3
; .model flat adds 1 underscore to PROC names, so we name them with 1 underscore
; and MASM generates 2-underscore COFF symbols.

.386
.model flat, C

.code

; double -> signed long (truncate toward zero)
; Input: ST(0), Output: EAX
PUBLIC _dtol3
_dtol3 PROC
    sub   esp, 8
    fistp QWORD PTR [esp]
    mov   eax, [esp]
    add   esp, 8
    ret
_dtol3 ENDP

; double -> unsigned int (truncate toward zero)
PUBLIC _dtoui3
_dtoui3 PROC
    sub   esp, 8
    fistp QWORD PTR [esp]
    mov   eax, [esp]
    add   esp, 8
    ret
_dtoui3 ENDP

; double -> unsigned long (truncate toward zero)
PUBLIC _dtoul3
_dtoul3 PROC
    sub   esp, 8
    fistp QWORD PTR [esp]
    mov   eax, [esp]
    add   esp, 8
    ret
_dtoul3 ENDP

; signed long -> double
; Input: [esp+4], Output: ST(0)
PUBLIC _ltod3
_ltod3 PROC
    fild  DWORD PTR [esp+4]
    ret
_ltod3 ENDP

; unsigned long -> double
PUBLIC _ultod3
_ultod3 PROC
    fild  DWORD PTR [esp+4]
    test  DWORD PTR [esp+4], 80000000h
    jz    @done
    push  0
    push  41F00000h
    fadd  QWORD PTR [esp]
    add   esp, 8
@done:
    ret
_ultod3 ENDP

END
