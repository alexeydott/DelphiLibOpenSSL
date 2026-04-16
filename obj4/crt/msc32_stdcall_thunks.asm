; stdcall DLL thunks
.386
.model flat

EXTERN __imp__accept@12:DWORD
EXTERN __imp__bind@12:DWORD
EXTERN __imp__closesocket@4:DWORD
EXTERN __imp__connect@12:DWORD
EXTERN __imp__gethostbyaddr@12:DWORD
EXTERN __imp__gethostbyname@4:DWORD
EXTERN __imp__getpeername@12:DWORD
EXTERN __imp__getservbyname@8:DWORD
EXTERN __imp__getservbyport@8:DWORD
EXTERN __imp__getsockname@12:DWORD
EXTERN __imp__getsockopt@20:DWORD
EXTERN __imp__htonl@4:DWORD
EXTERN __imp__htons@4:DWORD
EXTERN __imp__inet_addr@4:DWORD
EXTERN __imp__inet_ntoa@4:DWORD
EXTERN __imp__ioctlsocket@12:DWORD
EXTERN __imp__listen@8:DWORD
EXTERN __imp__ntohs@4:DWORD
EXTERN __imp__recv@16:DWORD
EXTERN __imp__recvfrom@24:DWORD
EXTERN __imp__select@20:DWORD
EXTERN __imp__send@16:DWORD
EXTERN __imp__sendto@24:DWORD
EXTERN __imp__setsockopt@20:DWORD
EXTERN __imp__shutdown@8:DWORD
EXTERN __imp__socket@12:DWORD
EXTERN __imp__WSACleanup@0:DWORD
EXTERN __imp__WSAGetLastError@0:DWORD
EXTERN __imp__WSASetLastError@4:DWORD
EXTERN __imp__WSAStartup@8:DWORD
EXTERN __imp__CloseHandle@4:DWORD
EXTERN __imp__ConvertFiberToThread@0:DWORD
EXTERN __imp__ConvertThreadToFiberEx@8:DWORD
EXTERN __imp__CreateFiberEx@20:DWORD
EXTERN __imp__DeleteFiber@4:DWORD
EXTERN __imp__FindClose@4:DWORD
EXTERN __imp__FindFirstFileW@8:DWORD
EXTERN __imp__FindNextFileW@8:DWORD
EXTERN __imp__FormatMessageA@28:DWORD
EXTERN __imp__FreeLibrary@4:DWORD
EXTERN __imp__GetACP@0:DWORD
EXTERN __imp__GetEnvironmentVariableW@12:DWORD
EXTERN __imp__GetFileType@4:DWORD
EXTERN __imp__GetLastError@0:DWORD
EXTERN __imp__GetModuleHandleW@4:DWORD
EXTERN __imp__GetProcAddress@8:DWORD
EXTERN __imp__GetProcessWindowStation@0:DWORD
EXTERN __imp__GetStdHandle@4:DWORD
EXTERN __imp__GetSystemDirectoryA@8:DWORD
EXTERN __imp__GetSystemInfo@4:DWORD
EXTERN __imp__LoadLibraryA@4:DWORD
EXTERN __imp__LoadLibraryW@4:DWORD
EXTERN __imp__MultiByteToWideChar@24:DWORD
EXTERN __imp__SetLastError@4:DWORD
EXTERN __imp__SwitchToFiber@4:DWORD
EXTERN __imp__VirtualAlloc@16:DWORD
EXTERN __imp__VirtualFree@12:DWORD
EXTERN __imp__VirtualLock@8:DWORD
EXTERN __imp__VirtualProtect@16:DWORD
EXTERN __imp__WideCharToMultiByte@32:DWORD
EXTERN __imp__WriteFile@20:DWORD
EXTERN __imp__InitializeCriticalSection@4:DWORD
EXTERN __imp__Sleep@4:DWORD
EXTERN __imp__DeregisterEventSource@4:DWORD
EXTERN __imp__RegisterEventSourceW@8:DWORD
EXTERN __imp__ReportEventW@36:DWORD
EXTERN __imp__GetUserObjectInformationW@20:DWORD
EXTERN __imp__MessageBoxW@16:DWORD

.code

PUBLIC _accept@12
_accept@12 PROC
    jmp DWORD PTR [__imp__accept@12]
_accept@12 ENDP

PUBLIC _bind@12
_bind@12 PROC
    jmp DWORD PTR [__imp__bind@12]
_bind@12 ENDP

PUBLIC _closesocket@4
_closesocket@4 PROC
    jmp DWORD PTR [__imp__closesocket@4]
_closesocket@4 ENDP

PUBLIC _connect@12
_connect@12 PROC
    jmp DWORD PTR [__imp__connect@12]
_connect@12 ENDP

PUBLIC _gethostbyaddr@12
_gethostbyaddr@12 PROC
    jmp DWORD PTR [__imp__gethostbyaddr@12]
_gethostbyaddr@12 ENDP

PUBLIC _gethostbyname@4
_gethostbyname@4 PROC
    jmp DWORD PTR [__imp__gethostbyname@4]
_gethostbyname@4 ENDP

PUBLIC _getpeername@12
_getpeername@12 PROC
    jmp DWORD PTR [__imp__getpeername@12]
_getpeername@12 ENDP

PUBLIC _getservbyname@8
_getservbyname@8 PROC
    jmp DWORD PTR [__imp__getservbyname@8]
_getservbyname@8 ENDP

PUBLIC _getservbyport@8
_getservbyport@8 PROC
    jmp DWORD PTR [__imp__getservbyport@8]
_getservbyport@8 ENDP

PUBLIC _getsockname@12
_getsockname@12 PROC
    jmp DWORD PTR [__imp__getsockname@12]
_getsockname@12 ENDP

PUBLIC _getsockopt@20
_getsockopt@20 PROC
    jmp DWORD PTR [__imp__getsockopt@20]
_getsockopt@20 ENDP

PUBLIC _htonl@4
_htonl@4 PROC
    jmp DWORD PTR [__imp__htonl@4]
_htonl@4 ENDP

PUBLIC _htons@4
_htons@4 PROC
    jmp DWORD PTR [__imp__htons@4]
_htons@4 ENDP

PUBLIC _inet_addr@4
_inet_addr@4 PROC
    jmp DWORD PTR [__imp__inet_addr@4]
_inet_addr@4 ENDP

PUBLIC _inet_ntoa@4
_inet_ntoa@4 PROC
    jmp DWORD PTR [__imp__inet_ntoa@4]
_inet_ntoa@4 ENDP

PUBLIC _ioctlsocket@12
_ioctlsocket@12 PROC
    jmp DWORD PTR [__imp__ioctlsocket@12]
_ioctlsocket@12 ENDP

PUBLIC _listen@8
_listen@8 PROC
    jmp DWORD PTR [__imp__listen@8]
_listen@8 ENDP

PUBLIC _ntohs@4
_ntohs@4 PROC
    jmp DWORD PTR [__imp__ntohs@4]
_ntohs@4 ENDP

PUBLIC _recv@16
_recv@16 PROC
    jmp DWORD PTR [__imp__recv@16]
_recv@16 ENDP

PUBLIC _recvfrom@24
_recvfrom@24 PROC
    jmp DWORD PTR [__imp__recvfrom@24]
_recvfrom@24 ENDP

PUBLIC _select@20
_select@20 PROC
    jmp DWORD PTR [__imp__select@20]
_select@20 ENDP

PUBLIC _send@16
_send@16 PROC
    jmp DWORD PTR [__imp__send@16]
_send@16 ENDP

PUBLIC _sendto@24
_sendto@24 PROC
    jmp DWORD PTR [__imp__sendto@24]
_sendto@24 ENDP

PUBLIC _setsockopt@20
_setsockopt@20 PROC
    jmp DWORD PTR [__imp__setsockopt@20]
_setsockopt@20 ENDP

PUBLIC _shutdown@8
_shutdown@8 PROC
    jmp DWORD PTR [__imp__shutdown@8]
_shutdown@8 ENDP

PUBLIC _socket@12
_socket@12 PROC
    jmp DWORD PTR [__imp__socket@12]
_socket@12 ENDP

PUBLIC _WSACleanup@0
_WSACleanup@0 PROC
    jmp DWORD PTR [__imp__WSACleanup@0]
_WSACleanup@0 ENDP

PUBLIC _WSAGetLastError@0
_WSAGetLastError@0 PROC
    jmp DWORD PTR [__imp__WSAGetLastError@0]
_WSAGetLastError@0 ENDP

PUBLIC _WSASetLastError@4
_WSASetLastError@4 PROC
    jmp DWORD PTR [__imp__WSASetLastError@4]
_WSASetLastError@4 ENDP

PUBLIC _WSAStartup@8
_WSAStartup@8 PROC
    jmp DWORD PTR [__imp__WSAStartup@8]
_WSAStartup@8 ENDP

PUBLIC _CloseHandle@4
_CloseHandle@4 PROC
    jmp DWORD PTR [__imp__CloseHandle@4]
_CloseHandle@4 ENDP

PUBLIC _ConvertFiberToThread@0
_ConvertFiberToThread@0 PROC
    jmp DWORD PTR [__imp__ConvertFiberToThread@0]
_ConvertFiberToThread@0 ENDP

PUBLIC _ConvertThreadToFiberEx@8
_ConvertThreadToFiberEx@8 PROC
    jmp DWORD PTR [__imp__ConvertThreadToFiberEx@8]
_ConvertThreadToFiberEx@8 ENDP

PUBLIC _CreateFiberEx@20
_CreateFiberEx@20 PROC
    jmp DWORD PTR [__imp__CreateFiberEx@20]
_CreateFiberEx@20 ENDP

PUBLIC _DeleteFiber@4
_DeleteFiber@4 PROC
    jmp DWORD PTR [__imp__DeleteFiber@4]
_DeleteFiber@4 ENDP

PUBLIC _FindClose@4
_FindClose@4 PROC
    jmp DWORD PTR [__imp__FindClose@4]
_FindClose@4 ENDP

PUBLIC _FindFirstFileW@8
_FindFirstFileW@8 PROC
    jmp DWORD PTR [__imp__FindFirstFileW@8]
_FindFirstFileW@8 ENDP

PUBLIC _FindNextFileW@8
_FindNextFileW@8 PROC
    jmp DWORD PTR [__imp__FindNextFileW@8]
_FindNextFileW@8 ENDP

PUBLIC _FormatMessageA@28
_FormatMessageA@28 PROC
    jmp DWORD PTR [__imp__FormatMessageA@28]
_FormatMessageA@28 ENDP

PUBLIC _FreeLibrary@4
_FreeLibrary@4 PROC
    jmp DWORD PTR [__imp__FreeLibrary@4]
_FreeLibrary@4 ENDP

PUBLIC _GetACP@0
_GetACP@0 PROC
    jmp DWORD PTR [__imp__GetACP@0]
_GetACP@0 ENDP

PUBLIC _GetEnvironmentVariableW@12
_GetEnvironmentVariableW@12 PROC
    jmp DWORD PTR [__imp__GetEnvironmentVariableW@12]
_GetEnvironmentVariableW@12 ENDP

PUBLIC _GetFileType@4
_GetFileType@4 PROC
    jmp DWORD PTR [__imp__GetFileType@4]
_GetFileType@4 ENDP

PUBLIC _GetLastError@0
_GetLastError@0 PROC
    jmp DWORD PTR [__imp__GetLastError@0]
_GetLastError@0 ENDP

PUBLIC _GetModuleHandleW@4
_GetModuleHandleW@4 PROC
    jmp DWORD PTR [__imp__GetModuleHandleW@4]
_GetModuleHandleW@4 ENDP

PUBLIC _GetProcAddress@8
_GetProcAddress@8 PROC
    jmp DWORD PTR [__imp__GetProcAddress@8]
_GetProcAddress@8 ENDP

PUBLIC _GetProcessWindowStation@0
_GetProcessWindowStation@0 PROC
    jmp DWORD PTR [__imp__GetProcessWindowStation@0]
_GetProcessWindowStation@0 ENDP

PUBLIC _GetStdHandle@4
_GetStdHandle@4 PROC
    jmp DWORD PTR [__imp__GetStdHandle@4]
_GetStdHandle@4 ENDP

PUBLIC _GetSystemDirectoryA@8
_GetSystemDirectoryA@8 PROC
    jmp DWORD PTR [__imp__GetSystemDirectoryA@8]
_GetSystemDirectoryA@8 ENDP

PUBLIC _GetSystemInfo@4
_GetSystemInfo@4 PROC
    jmp DWORD PTR [__imp__GetSystemInfo@4]
_GetSystemInfo@4 ENDP

PUBLIC _LoadLibraryA@4
_LoadLibraryA@4 PROC
    jmp DWORD PTR [__imp__LoadLibraryA@4]
_LoadLibraryA@4 ENDP

PUBLIC _LoadLibraryW@4
_LoadLibraryW@4 PROC
    jmp DWORD PTR [__imp__LoadLibraryW@4]
_LoadLibraryW@4 ENDP

PUBLIC _MultiByteToWideChar@24
_MultiByteToWideChar@24 PROC
    jmp DWORD PTR [__imp__MultiByteToWideChar@24]
_MultiByteToWideChar@24 ENDP

PUBLIC _SetLastError@4
_SetLastError@4 PROC
    jmp DWORD PTR [__imp__SetLastError@4]
_SetLastError@4 ENDP

PUBLIC _SwitchToFiber@4
_SwitchToFiber@4 PROC
    jmp DWORD PTR [__imp__SwitchToFiber@4]
_SwitchToFiber@4 ENDP

PUBLIC _VirtualAlloc@16
_VirtualAlloc@16 PROC
    jmp DWORD PTR [__imp__VirtualAlloc@16]
_VirtualAlloc@16 ENDP

PUBLIC _VirtualFree@12
_VirtualFree@12 PROC
    jmp DWORD PTR [__imp__VirtualFree@12]
_VirtualFree@12 ENDP

PUBLIC _VirtualLock@8
_VirtualLock@8 PROC
    jmp DWORD PTR [__imp__VirtualLock@8]
_VirtualLock@8 ENDP

PUBLIC _VirtualProtect@16
_VirtualProtect@16 PROC
    jmp DWORD PTR [__imp__VirtualProtect@16]
_VirtualProtect@16 ENDP

PUBLIC _WideCharToMultiByte@32
_WideCharToMultiByte@32 PROC
    jmp DWORD PTR [__imp__WideCharToMultiByte@32]
_WideCharToMultiByte@32 ENDP

PUBLIC _WriteFile@20
_WriteFile@20 PROC
    jmp DWORD PTR [__imp__WriteFile@20]
_WriteFile@20 ENDP

PUBLIC _InitializeCriticalSection@4
_InitializeCriticalSection@4 PROC
    jmp DWORD PTR [__imp__InitializeCriticalSection@4]
_InitializeCriticalSection@4 ENDP

PUBLIC _Sleep@4
_Sleep@4 PROC
    jmp DWORD PTR [__imp__Sleep@4]
_Sleep@4 ENDP

PUBLIC _DeregisterEventSource@4
_DeregisterEventSource@4 PROC
    jmp DWORD PTR [__imp__DeregisterEventSource@4]
_DeregisterEventSource@4 ENDP

PUBLIC _RegisterEventSourceW@8
_RegisterEventSourceW@8 PROC
    jmp DWORD PTR [__imp__RegisterEventSourceW@8]
_RegisterEventSourceW@8 ENDP

PUBLIC _ReportEventW@36
_ReportEventW@36 PROC
    jmp DWORD PTR [__imp__ReportEventW@36]
_ReportEventW@36 ENDP

PUBLIC _GetUserObjectInformationW@20
_GetUserObjectInformationW@20 PROC
    jmp DWORD PTR [__imp__GetUserObjectInformationW@20]
_GetUserObjectInformationW@20 ENDP

PUBLIC _MessageBoxW@16
_MessageBoxW@16 PROC
    jmp DWORD PTR [__imp__MessageBoxW@16]
_MessageBoxW@16 ENDP

END