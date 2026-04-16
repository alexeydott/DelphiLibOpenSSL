; cdecl CRT thunks
.386
.model flat

EXTERN __imp__strcpy:DWORD
EXTERN __imp__calloc:DWORD
EXTERN __imp__sprintf_s:DWORD
EXTERN __imp__strcat_s:DWORD
EXTERN __imp__strcpy_s:DWORD
EXTERN __imp__strncpy_s:DWORD
EXTERN __imp__strerror_s:DWORD
EXTERN __imp__tolower:DWORD
EXTERN __imp__atoi:DWORD
EXTERN __imp___lrotl:DWORD
EXTERN __imp___lrotr:DWORD
EXTERN __imp___time64:DWORD
EXTERN __imp___lseek:DWORD
EXTERN __imp___setmode:DWORD
EXTERN __imp___stat64i32:DWORD
EXTERN __imp___strdup:DWORD
EXTERN __imp___vsnprintf_s:DWORD
EXTERN __imp___vsnwprintf:DWORD
EXTERN __imp____acrt_iob_func:DWORD
EXTERN __imp___errno:DWORD
EXTERN __imp___fstat64i32:DWORD

.code

PUBLIC _strcpy
_strcpy PROC
    jmp DWORD PTR [__imp__strcpy]
_strcpy ENDP

PUBLIC _calloc
_calloc PROC
    jmp DWORD PTR [__imp__calloc]
_calloc ENDP

PUBLIC _sprintf_s
_sprintf_s PROC
    jmp DWORD PTR [__imp__sprintf_s]
_sprintf_s ENDP

PUBLIC _strcat_s
_strcat_s PROC
    jmp DWORD PTR [__imp__strcat_s]
_strcat_s ENDP

PUBLIC _strcpy_s
_strcpy_s PROC
    jmp DWORD PTR [__imp__strcpy_s]
_strcpy_s ENDP

PUBLIC _strncpy_s
_strncpy_s PROC
    jmp DWORD PTR [__imp__strncpy_s]
_strncpy_s ENDP

PUBLIC _strerror_s
_strerror_s PROC
    jmp DWORD PTR [__imp__strerror_s]
_strerror_s ENDP

PUBLIC _tolower
_tolower PROC
    jmp DWORD PTR [__imp__tolower]
_tolower ENDP

PUBLIC _atoi
_atoi PROC
    jmp DWORD PTR [__imp__atoi]
_atoi ENDP

PUBLIC __lrotl
__lrotl PROC
    jmp DWORD PTR [__imp___lrotl]
__lrotl ENDP

PUBLIC __lrotr
__lrotr PROC
    jmp DWORD PTR [__imp___lrotr]
__lrotr ENDP

PUBLIC __time64
__time64 PROC
    jmp DWORD PTR [__imp___time64]
__time64 ENDP

PUBLIC __lseek
__lseek PROC
    jmp DWORD PTR [__imp___lseek]
__lseek ENDP

PUBLIC __setmode
__setmode PROC
    jmp DWORD PTR [__imp___setmode]
__setmode ENDP

PUBLIC __stat64i32
__stat64i32 PROC
    jmp DWORD PTR [__imp___stat64i32]
__stat64i32 ENDP

PUBLIC __strdup
__strdup PROC
    jmp DWORD PTR [__imp___strdup]
__strdup ENDP

PUBLIC __vsnprintf_s
__vsnprintf_s PROC
    jmp DWORD PTR [__imp___vsnprintf_s]
__vsnprintf_s ENDP

PUBLIC __vsnwprintf
__vsnwprintf PROC
    jmp DWORD PTR [__imp___vsnwprintf]
__vsnwprintf ENDP

PUBLIC ___acrt_iob_func
___acrt_iob_func PROC
    jmp DWORD PTR [__imp____acrt_iob_func]
___acrt_iob_func ENDP

PUBLIC __errno
__errno PROC
    jmp DWORD PTR [__imp___errno]
__errno ENDP

PUBLIC __fstat64i32
__fstat64i32 PROC
    jmp DWORD PTR [__imp___fstat64i32]
__fstat64i32 ENDP

END