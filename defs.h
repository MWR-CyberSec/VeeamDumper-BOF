
WINBASEAPI BOOL WINAPI KERNEL32$CreateProcessA(
    LPCSTR lpApplicationName,
    LPSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCSTR lpCurrentDirectory,
    LPSTARTUPINFOA lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
);


WINBASEAPI BOOL WINAPI KERNEL32$CreatePipe(
    PHANDLE hReadPipe,
    PHANDLE hWritePipe,
    LPSECURITY_ATTRIBUTES lpPipeAttributes,
    DWORD nSize
);


WINBASEAPI BOOL WINAPI KERNEL32$SetHandleInformation(
    HANDLE hObject,
    DWORD dwMask,
    DWORD dwFlags
);


WINBASEAPI BOOL WINAPI KERNEL32$ReadFile(
    HANDLE hFile,
    LPVOID lpBuffer,
    DWORD nNumberOfBytesToRead,
    LPDWORD lpNumberOfBytesRead,
    LPOVERLAPPED lpOverlapped
);

WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle(
    HANDLE hObject
);


WINBASEAPI int __cdecl MSVCRT$strcmp(
    const char *_Str1,
    const char *_Str2
);
WINBASEAPI size_t __cdecl MSVCRT$strlen(const char *str);
WINBASEAPI char * __cdecl MSVCRT$strcat(char *dest, const char *src);
WINBASEAPI char * __cdecl MSVCRT$strcpy(char *dest, const char *src);
WINBASEAPI void * __cdecl MSVCRT$memcpy(void *dest, const void *src, size_t n);
WINBASEAPI void * __cdecl MSVCRT$realloc(void *ptr, size_t size);
WINBASEAPI void __cdecl MSVCRT$free(void *ptr);
WINBASEAPI void * __cdecl MSVCRT$malloc(size_t size);
WINBASEAPI char * __cdecl MSVCRT$strstr(const char *haystack, const char *needle);
WINBASEAPI char * __cdecl MSVCRT$strchr(const char *s, int c);




WINBASEAPI DWORD WINAPI KERNEL32$SearchPathA(
    LPCSTR lpPath,
    LPCSTR lpFileName,
    LPCSTR lpExtension,
    DWORD  nBufferLength,
    LPSTR  lpBuffer,
    LPSTR *lpFilePart
);
WINBASEAPI DWORD WINAPI KERNEL32$GetFileAttributesA(
    LPCSTR lpFileName
);
WINADVAPI LSTATUS WINAPI ADVAPI32$RegOpenKeyExA(
    HKEY hKey,
    LPCSTR lpSubKey,
    DWORD ulOptions,
    REGSAM samDesired,
    PHKEY phkResult
);
WINADVAPI LSTATUS WINAPI ADVAPI32$RegCloseKey(
    HKEY hKey
);
WINADVAPI LSTATUS WINAPI ADVAPI32$RegQueryValueExA(
    HKEY hKey,
    LPCSTR lpValueName,
    LPDWORD lpReserved,
    LPDWORD lpType,
    LPBYTE lpData,
    LPDWORD lpcbData
);
WINADVAPI BOOL WINAPI CRYPT32$CryptStringToBinaryA(
    LPCSTR pszString,
    DWORD cchString,
    DWORD dwFlags,
    BYTE *pbBinary,
    DWORD *pcbBinary,
    DWORD *pdwSkip,
    DWORD *pdwFlags
);
WINADVAPI BOOL WINAPI CRYPT32$CryptUnprotectData(
    DATA_BLOB *pDataIn,
    LPWSTR *ppszDataDescr,
    DATA_BLOB *pOptionalEntropy,
    PVOID pvReserved,
    void *pPromptStruct,
    DWORD dwFlags,
    DATA_BLOB *pDataOut
);
WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(void);

WINBASEAPI DWORD WINAPI KERNEL32$GetLastError(void);
WINBASEAPI HANDLE WINAPI KERNEL32$GetProcessHeap(void);
WINBASEAPI LPVOID WINAPI KERNEL32$HeapAlloc(HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
WINBASEAPI BOOL WINAPI KERNEL32$HeapFree(HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);
WINBASEAPI int WINAPI KERNEL32$WideCharToMultiByte(
    UINT     CodePage,
    DWORD    dwFlags,
    LPCWCH   lpWideCharStr,
    int      cchWideChar,
    LPSTR    lpMultiByteStr,
    int      cbMultiByte,
    LPCCH    lpDefaultChar,
    LPBOOL   lpUsedDefaultChar
);


#define strcmp MSVCRT$strcmp
#define strlen MSVCRT$strlen
#define strcat MSVCRT$strcat
#define strcpy MSVCRT$strcpy
#define memcpy MSVCRT$memcpy
#define realloc MSVCRT$realloc
#define free MSVCRT$free
#define malloc MSVCRT$malloc
#define strstr MSVCRT$strstr
#define strchr MSVCRT$strchr

#define SearchPathA KERNEL32$SearchPathA
#define GetFileAttributesA KERNEL32$GetFileAttributesA
#define RegOpenKeyExA ADVAPI32$RegOpenKeyExA
#define RegCloseKey ADVAPI32$RegCloseKey
#define RegQueryValueExA ADVAPI32$RegQueryValueExA

#define CreatePipe KERNEL32$CreatePipe
#define CreateProcessA KERNEL32$CreateProcessA
#define SetHandleInformation KERNEL32$SetHandleInformation
#define ReadFile KERNEL32$ReadFile
#define CloseHandle KERNEL32$CloseHandle
#define CryptStringToBinaryA CRYPT32$CryptStringToBinaryA
#define CryptUnprotectData CRYPT32$CryptUnprotectData
#define GetLastError KERNEL32$GetLastError
#define GetProcessHeap        KERNEL32$GetProcessHeap
#define HeapAlloc             KERNEL32$HeapAlloc
#define HeapFree              KERNEL32$HeapFree
#define WideCharToMultiByte   KERNEL32$WideCharToMultiByte

#define CP_UTF8 65001
#define HEAP_ZERO_MEMORY 0x00000008




