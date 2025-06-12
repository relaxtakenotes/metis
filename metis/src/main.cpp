#include <Windows.h>
#include <playsoundapi.h>
#include <processthreadsapi.h>
#include <string>
#include <format>
#include <sysinfoapi.h>
#include <vector>
#include <imagehlp.h>
#include <tlhelp32.h>
#include <winnt.h>
#include <winternl.h>
#include <codecvt>
#include <fstream>

#define STEAM_API_DEBUG_MEASURE ((DWORD)0x406D1388L)
#define STEAM_API_BULLSHIT ((DWORD)0x6A6L)
#define RPC_NT_INTERNAL_ERROR ((DWORD)0xC0020043L)

#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004

typedef enum class _KTHREAD_STATE
{
    Initialized,
    Ready,
    Running,
    Standby,
    Terminated,
    Waiting,
    Transition,
    DeferredReady,
    GateWaitObsolete,
    WaitingForProcessInSwap,
    MaximumThreadState
} KTHREAD_STATE, *PKTHREAD_STATE;

typedef enum class _KWAIT_REASON_FULL
{
    Executive,               // Waiting for an executive event.
    FreePage,                // Waiting for a free page.
    PageIn,                  // Waiting for a page to be read in.
    PoolAllocation,          // Waiting for a pool allocation.
    DelayExecution,          // Waiting due to a delay execution.           // NtDelayExecution
    Suspended,               // Waiting because the thread is suspended.    // NtSuspendThread
    UserRequest,             // Waiting due to a user request.              // NtWaitForSingleObject
    WrExecutive,             // Waiting for an executive event.
    WrFreePage,              // Waiting for a free page.
    WrPageIn,                // Waiting for a page to be read in.
    WrPoolAllocation,        // Waiting for a pool allocation.
    WrDelayExecution,        // Waiting due to a delay execution.
    WrSuspended,             // Waiting because the thread is suspended.
    WrUserRequest,           // Waiting due to a user request.
    WrEventPair,             // Waiting for an event pair.                  // NtCreateEventPair
    WrQueue,                 // Waiting for a queue.                        // NtRemoveIoCompletion
    WrLpcReceive,            // Waiting for an LPC receive.                 // NtReplyWaitReceivePort
    WrLpcReply,              // Waiting for an LPC reply.                   // NtRequestWaitReplyPort
    WrVirtualMemory,         // Waiting for virtual memory.
    WrPageOut,               // Waiting for a page to be written out.       // NtFlushVirtualMemory
    WrRendezvous,            // Waiting for a rendezvous.
    WrKeyedEvent,            // Waiting for a keyed event.                  // NtCreateKeyedEvent
    WrTerminated,            // Waiting for thread termination.
    WrProcessInSwap,         // Waiting for a process to be swapped in.
    WrCpuRateControl,        // Waiting for CPU rate control.
    WrCalloutStack,          // Waiting for a callout stack.
    WrKernel,                // Waiting for a kernel event.
    WrResource,              // Waiting for a resource.
    WrPushLock,              // Waiting for a push lock.
    WrMutex,                 // Waiting for a mutex.
    WrQuantumEnd,            // Waiting for the end of a quantum.
    WrDispatchInt,           // Waiting for a dispatch interrupt.
    WrPreempted,             // Waiting because the thread was preempted.
    WrYieldExecution,        // Waiting to yield execution.
    WrFastMutex,             // Waiting for a fast mutex.
    WrGuardedMutex,          // Waiting for a guarded mutex.
    WrRundown,               // Waiting for a rundown.
    WrAlertByThreadId,       // Waiting for an alert by thread ID.
    WrDeferredPreempt,       // Waiting for a deferred preemption.
    WrPhysicalFault,         // Waiting for a physical fault.
    WrIoRing,                // Waiting for an I/O ring.
    WrMdlCache,              // Waiting for an MDL cache.
    WrRcu,                   // Waiting for read-copy-update (RCU) synchronization.
    MaximumWaitReason
} KWAIT_REASON_FULL, *PKWAIT_REASON_FULL;

typedef struct _SYSTEM_THREAD_INFORMATION_FULL
{
    LARGE_INTEGER KernelTime;       // Number of 100-nanosecond intervals spent executing kernel code.
    LARGE_INTEGER UserTime;         // Number of 100-nanosecond intervals spent executing user code.
    LARGE_INTEGER CreateTime;       // The date and time when the thread was created.
    ULONG WaitTime;                 // The current time spent in ready queue or waiting (depending on the thread state).
    PVOID StartAddress;             // The initial start address of the thread.
    CLIENT_ID ClientId;             // The identifier of the thread and the process owning the thread.
    KPRIORITY Priority;             // The dynamic priority of the thread.
    KPRIORITY BasePriority;         // The starting priority of the thread.
    ULONG ContextSwitches;          // The total number of context switches performed.
    KTHREAD_STATE ThreadState;      // The current state of the thread.
    KWAIT_REASON_FULL WaitReason;   // The current reason the thread is waiting.
} SYSTEM_THREAD_INFORMATION_FULL, *PSYSTEM_THREAD_INFORMATION_FULL;

typedef struct _SYSTEM_PROCESS_INFORMATION_FULL
{
    ULONG NextEntryOffset;                  // The address of the previous item plus the value in the NextEntryOffset member. For the last item in the array, NextEntryOffset is 0.
    ULONG NumberOfThreads;                  // The NumberOfThreads member contains the number of threads in the process.
    ULONGLONG WorkingSetPrivateSize;        // The total private memory that a process currently has allocated and is physically resident in memory. // since VISTA
    ULONG HardFaultCount;                   // The total number of hard faults for data from disk rather than from in-memory pages. // since WIN7
    ULONG NumberOfThreadsHighWatermark;     // The peak number of threads that were running at any given point in time, indicative of potential performance bottlenecks related to thread management.
    ULONGLONG CycleTime;                    // The sum of the cycle time of all threads in the process.
    LARGE_INTEGER CreateTime;               // Number of 100-nanosecond intervals since the creation time of the process. Not updated during system timezone changes.
    LARGE_INTEGER UserTime;                 // Number of 100-nanosecond intervals the process has executed in user mode.
    LARGE_INTEGER KernelTime;               // Number of 100-nanosecond intervals the process has executed in kernel mode.
    UNICODE_STRING ImageName;               // The file name of the executable image.
    KPRIORITY BasePriority;                 // The starting priority of the process.
    HANDLE UniqueProcessId;                 // The identifier of the process.
    HANDLE InheritedFromUniqueProcessId;    // The identifier of the process that created this process. Not updated and incorrectly refers to processes with recycled identifiers. 
    ULONG HandleCount;                      // The current number of open handles used by the process.
    ULONG SessionId;                        // The identifier of the Remote Desktop Services session under which the specified process is running. 
    ULONG_PTR UniqueProcessKey;             // since VISTA (requires SystemExtendedProcessInformation)
    SIZE_T PeakVirtualSize;                 // The peak size, in bytes, of the virtual memory used by the process.
    SIZE_T VirtualSize;                     // The current size, in bytes, of virtual memory used by the process.
    ULONG PageFaultCount;                   // The total number of page faults for data that is not currently in memory. The value wraps around to zero on average 24 hours.
    SIZE_T PeakWorkingSetSize;              // The peak size, in kilobytes, of the working set of the process.
    SIZE_T WorkingSetSize;                  // The number of pages visible to the process in physical memory. These pages are resident and available for use without triggering a page fault.
    SIZE_T QuotaPeakPagedPoolUsage;         // The peak quota charged to the process for pool usage, in bytes.
    SIZE_T QuotaPagedPoolUsage;             // The quota charged to the process for paged pool usage, in bytes.
    SIZE_T QuotaPeakNonPagedPoolUsage;      // The peak quota charged to the process for nonpaged pool usage, in bytes.
    SIZE_T QuotaNonPagedPoolUsage;          // The current quota charged to the process for nonpaged pool usage.
    SIZE_T PagefileUsage;                   // The total number of bytes of page file storage in use by the process.
    SIZE_T PeakPagefileUsage;               // The maximum number of bytes of page-file storage used by the process.
    SIZE_T PrivatePageCount;                // The number of memory pages allocated for the use by the process.
    LARGE_INTEGER ReadOperationCount;       // The total number of read operations performed.
    LARGE_INTEGER WriteOperationCount;      // The total number of write operations performed.
    LARGE_INTEGER OtherOperationCount;      // The total number of I/O operations performed other than read and write operations.
    LARGE_INTEGER ReadTransferCount;        // The total number of bytes read during a read operation.
    LARGE_INTEGER WriteTransferCount;       // The total number of bytes written during a write operation.
    LARGE_INTEGER OtherTransferCount;       // The total number of bytes transferred during operations other than read and write operations.
    SYSTEM_THREAD_INFORMATION_FULL Threads[1];   // This type is not defined in the structure but was added for convenience.
} SYSTEM_PROCESS_INFORMATION_FULL, *PSYSTEM_PROCESS_INFORMATION_FULL;

struct StackFrame
{
    uintptr_t Address;
    uintptr_t ModuleBase;
    std::string Module;
    std::string File;
    std::string Name;
    uint32_t Line;
};

struct ProcessInfo {
    std::string Name;
    HANDLE PID;
    std::vector<SYSTEM_THREAD_INFORMATION_FULL> Threads;
};

struct ProcessIterator {
    void* Buffer = nullptr;

    void* GetNext( ) 
    {
        static ptrdiff_t Offset = offsetof( SYSTEM_PROCESS_INFORMATION, NextEntryOffset );

        auto Next = *reinterpret_cast<uint32_t*>( (uintptr_t)Buffer + Offset );

        if ( !Next )
            return nullptr;

        Buffer = reinterpret_cast<void*>( (uintptr_t)Buffer + Next );

        return Buffer;
    }
};

std::string GetThreadState( KTHREAD_STATE Code )
{
    switch ( Code )
    {
        case KTHREAD_STATE::Initialized: return "Initialized";
        case KTHREAD_STATE::Ready: return "Ready";
        case KTHREAD_STATE::Running: return "Running";
        case KTHREAD_STATE::Standby: return "Standby";
        case KTHREAD_STATE::Terminated: return "Terminated";
        case KTHREAD_STATE::Waiting: return "Waiting";
        case KTHREAD_STATE::Transition: return "Transition";
        case KTHREAD_STATE::DeferredReady: return "DeferredReady";
        case KTHREAD_STATE::GateWaitObsolete: return "GateWaitObsolete";
        case KTHREAD_STATE::WaitingForProcessInSwap: return "WaitingForProcessInSwap";
        case KTHREAD_STATE::MaximumThreadState: return "MaximumThreadState";
    }

    return "Unknown";
}

std::string GetThreadWaitReason( KWAIT_REASON_FULL Code )
{
    switch ( Code )
    {
        case KWAIT_REASON_FULL::Executive: return "Executive";
        case KWAIT_REASON_FULL::FreePage: return "FreePage";
        case KWAIT_REASON_FULL::PageIn: return "PageIn";
        case KWAIT_REASON_FULL::PoolAllocation: return "PoolAllocation";
        case KWAIT_REASON_FULL::DelayExecution: return "DelayExecution";
        case KWAIT_REASON_FULL::Suspended: return "Suspended";
        case KWAIT_REASON_FULL::UserRequest: return "UserRequest";
        case KWAIT_REASON_FULL::WrExecutive: return "WrExecutive";
        case KWAIT_REASON_FULL::WrFreePage: return "WrFreePage";
        case KWAIT_REASON_FULL::WrPageIn: return "WrPageIn";
        case KWAIT_REASON_FULL::WrPoolAllocation: return "WrPoolAllocation";
        case KWAIT_REASON_FULL::WrDelayExecution: return "WrDelayExecution";
        case KWAIT_REASON_FULL::WrSuspended: return "WrSuspended";
        case KWAIT_REASON_FULL::WrUserRequest: return "WrUserRequest";
        case KWAIT_REASON_FULL::WrEventPair: return "WrEventPair";
        case KWAIT_REASON_FULL::WrQueue: return "WrQueue";
        case KWAIT_REASON_FULL::WrLpcReceive: return "WrLpcReceive";
        case KWAIT_REASON_FULL::WrLpcReply: return "WrLpcReply";
        case KWAIT_REASON_FULL::WrVirtualMemory: return "WrVirtualMemory";
        case KWAIT_REASON_FULL::WrPageOut: return "WrPageOut";
        case KWAIT_REASON_FULL::WrRendezvous: return "WrRendezvous";
        case KWAIT_REASON_FULL::WrKeyedEvent: return "WrKeyedEvent";
        case KWAIT_REASON_FULL::WrTerminated: return "WrTerminated";
        case KWAIT_REASON_FULL::WrProcessInSwap: return "WrProcessInSwap";
        case KWAIT_REASON_FULL::WrCpuRateControl: return "WrCpuRateControl";
        case KWAIT_REASON_FULL::WrCalloutStack: return "WrCalloutStack";
        case KWAIT_REASON_FULL::WrKernel: return "WrKernel";
        case KWAIT_REASON_FULL::WrResource: return "WrResource";
        case KWAIT_REASON_FULL::WrPushLock: return "WrPushLock";
        case KWAIT_REASON_FULL::WrMutex: return "WrMutex";
        case KWAIT_REASON_FULL::WrQuantumEnd: return "WrQuantumEnd";
        case KWAIT_REASON_FULL::WrDispatchInt: return "WrDispatchInt";
        case KWAIT_REASON_FULL::WrPreempted: return "WrPreempted";
        case KWAIT_REASON_FULL::WrYieldExecution: return "WrYieldExecution";
        case KWAIT_REASON_FULL::WrFastMutex: return "WrFastMutex";
        case KWAIT_REASON_FULL::WrGuardedMutex: return "WrGuardedMutex";
        case KWAIT_REASON_FULL::WrRundown: return "WrRundown";
        case KWAIT_REASON_FULL::WrAlertByThreadId: return "WrAlertByThreadId";
        case KWAIT_REASON_FULL::WrDeferredPreempt: return "WrDeferredPreempt";
        case KWAIT_REASON_FULL::WrPhysicalFault: return "WrPhysicalFault";
        case KWAIT_REASON_FULL::WrIoRing: return "WrIoRing";
        case KWAIT_REASON_FULL::WrMdlCache: return "WrMdlCache";
        case KWAIT_REASON_FULL::WrRcu: return "WrRcu";
        case KWAIT_REASON_FULL::MaximumWaitReason: return "MaximumWaitReason";
    }

    return "Unknown";
}

std::string GetErrorCode( DWORD Code )
{
    switch ( Code )
    {
        case STATUS_WAIT_0: return "STATUS_WAIT_0";
        case STATUS_ABANDONED_WAIT_0: return "STATUS_ABANDONED_WAIT_0";
        case STATUS_USER_APC: return "STATUS_USER_APC";
        case STATUS_TIMEOUT: return "STATUS_TIMEOUT";
        case STATUS_PENDING: return "STATUS_PENDING";
        case DBG_EXCEPTION_HANDLED: return "DBG_EXCEPTION_HANDLED";
        case DBG_CONTINUE: return "DBG_CONTINUE";
        case STATUS_SEGMENT_NOTIFICATION: return "STATUS_SEGMENT_NOTIFICATION";
        case STATUS_FATAL_APP_EXIT: return "STATUS_FATAL_APP_EXIT";
        case DBG_REPLY_LATER: return "DBG_REPLY_LATER";
        case DBG_TERMINATE_THREAD: return "DBG_TERMINATE_THREAD";
        case DBG_TERMINATE_PROCESS: return "DBG_TERMINATE_PROCESS";
        case DBG_CONTROL_C: return "DBG_CONTROL_C";
        case DBG_PRINTEXCEPTION_C: return "DBG_PRINTEXCEPTION_C";
        case DBG_RIPEXCEPTION: return "DBG_RIPEXCEPTION";
        case DBG_CONTROL_BREAK: return "DBG_CONTROL_BREAK";
        case DBG_COMMAND_EXCEPTION: return "DBG_COMMAND_EXCEPTION";
        case DBG_PRINTEXCEPTION_WIDE_C: return "DBG_PRINTEXCEPTION_WIDE_C";
        case STATUS_GUARD_PAGE_VIOLATION: return "STATUS_GUARD_PAGE_VIOLATION";
        case STATUS_DATATYPE_MISALIGNMENT: return "STATUS_DATATYPE_MISALIGNMENT";
        case STATUS_BREAKPOINT: return "STATUS_BREAKPOINT";
        case STATUS_SINGLE_STEP: return "STATUS_SINGLE_STEP";
        case STATUS_LONGJUMP: return "STATUS_LONGJUMP";
        case STATUS_UNWIND_CONSOLIDATE: return "STATUS_UNWIND_CONSOLIDATE";
        case DBG_EXCEPTION_NOT_HANDLED: return "DBG_EXCEPTION_NOT_HANDLED";
        case STATUS_ACCESS_VIOLATION: return "STATUS_ACCESS_VIOLATION";
        case STATUS_IN_PAGE_ERROR: return "STATUS_IN_PAGE_ERROR";
        case STATUS_INVALID_HANDLE: return "STATUS_INVALID_HANDLE";
        case STATUS_INVALID_PARAMETER: return "STATUS_INVALID_PARAMETER";
        case STATUS_NO_MEMORY: return "STATUS_NO_MEMORY";
        case STATUS_ILLEGAL_INSTRUCTION: return "STATUS_ILLEGAL_INSTRUCTION";
        case STATUS_NONCONTINUABLE_EXCEPTION: return "STATUS_NONCONTINUABLE_EXCEPTION";
        case STATUS_INVALID_DISPOSITION: return "STATUS_INVALID_DISPOSITION";
        case STATUS_ARRAY_BOUNDS_EXCEEDED: return "STATUS_ARRAY_BOUNDS_EXCEEDED";
        case STATUS_FLOAT_DENORMAL_OPERAND: return "STATUS_FLOAT_DENORMAL_OPERAND";
        case STATUS_FLOAT_DIVIDE_BY_ZERO: return "STATUS_FLOAT_DIVIDE_BY_ZERO";
        case STATUS_FLOAT_INEXACT_RESULT: return "STATUS_FLOAT_INEXACT_RESULT";
        case STATUS_FLOAT_INVALID_OPERATION: return "STATUS_FLOAT_INVALID_OPERATION";
        case STATUS_FLOAT_OVERFLOW: return "STATUS_FLOAT_OVERFLOW";
        case STATUS_FLOAT_STACK_CHECK: return "STATUS_FLOAT_STACK_CHECK";
        case STATUS_FLOAT_UNDERFLOW: return "STATUS_FLOAT_UNDERFLOW";
        case STATUS_INTEGER_DIVIDE_BY_ZERO: return "STATUS_INTEGER_DIVIDE_BY_ZERO";
        case STATUS_INTEGER_OVERFLOW: return "STATUS_INTEGER_OVERFLOW";
        case STATUS_PRIVILEGED_INSTRUCTION: return "STATUS_PRIVILEGED_INSTRUCTION";
        case STATUS_STACK_OVERFLOW: return "STATUS_STACK_OVERFLOW";
        case STATUS_DLL_NOT_FOUND: return "STATUS_DLL_NOT_FOUND";
        case STATUS_ORDINAL_NOT_FOUND: return "STATUS_ORDINAL_NOT_FOUND";
        case STATUS_ENTRYPOINT_NOT_FOUND: return "STATUS_ENTRYPOINT_NOT_FOUND";
        case STATUS_CONTROL_C_EXIT: return "STATUS_CONTROL_C_EXIT";
        case STATUS_DLL_INIT_FAILED: return "STATUS_DLL_INIT_FAILED";
        case STATUS_CONTROL_STACK_VIOLATION: return "STATUS_CONTROL_STACK_VIOLATION";
        case STATUS_FLOAT_MULTIPLE_FAULTS: return "STATUS_FLOAT_MULTIPLE_FAULTS";
        case STATUS_FLOAT_MULTIPLE_TRAPS: return "STATUS_FLOAT_MULTIPLE_TRAPS";
        case STATUS_REG_NAT_CONSUMPTION: return "STATUS_REG_NAT_CONSUMPTION";
        case STATUS_HEAP_CORRUPTION: return "STATUS_HEAP_CORRUPTION";
        case STATUS_STACK_BUFFER_OVERRUN: return "STATUS_STACK_BUFFER_OVERRUN";
        case STATUS_INVALID_CRUNTIME_PARAMETER: return "STATUS_INVALID_CRUNTIME_PARAMETER";
        case STATUS_ASSERTION_FAILURE: return "STATUS_ASSERTION_FAILURE";
        case STATUS_ENCLAVE_VIOLATION: return "STATUS_ENCLAVE_VIOLATION";
        case STATUS_INTERRUPTED: return "STATUS_INTERRUPTED";
        case STATUS_THREAD_NOT_RUNNING: return "STATUS_THREAD_NOT_RUNNING";
        case STATUS_ALREADY_REGISTERED: return "STATUS_ALREADY_REGISTERED";
        default: break;
    }

    return "STATUS_UNKNOWN";
}

inline std::wstring S2WS( const std::string& str ) 
{
    using convert_typeX = std::codecvt_utf8_utf16<wchar_t>;
    std::wstring_convert<convert_typeX, wchar_t> converterX;
    return converterX.from_bytes( str );
}

inline std::string WS2S( const std::wstring& wstr ) 
{
    using convert_typeX = std::codecvt_utf8_utf16<wchar_t>;
    std::wstring_convert<convert_typeX, wchar_t> converterX;
    return converterX.to_bytes( wstr );
}

char* FileNameA( char* path )
{
    auto slash = path;
    while ( path && *path )
    {
        if ( ( *path == '\\' || *path == '/' || *path == ':' ) && path[ 1 ] && path[ 1 ] != '\\' && path[ 1 ] != '/' )
        {
            slash = path + 1;
        }
        path++;
    }

    return slash;
}

std::vector<ProcessInfo> GetAllProcesses( ) 
{
    std::vector<uint8_t> Buffer;
    std::vector<ProcessInfo> Out;

    ULONG size;
    while ( NtQuerySystemInformation( SystemProcessInformation, &Buffer[0], static_cast<ULONG>( Buffer.size( ) ), &size ) == STATUS_INFO_LENGTH_MISMATCH )
        Buffer.resize( size );

    ProcessIterator iter{ Buffer.data( ) };

    void* ptr = iter.Buffer;

    while ( ptr )
    {
        auto pi = reinterpret_cast<SYSTEM_PROCESS_INFORMATION_FULL*>( ptr );

        std::wstring s{ pi->ImageName.Buffer, pi->ImageName.Length / sizeof( wchar_t ) };
        if ( s.empty( ) ) 
        {
            ptr = iter.GetNext( );
            continue;
        }

        ProcessInfo p = { };
        p.Name = WS2S( s );
        p.PID = pi->UniqueProcessId;

        for ( DWORD i = 0; i < pi->NumberOfThreads; i++ ) 
        {
            p.Threads.push_back( pi->Threads[i] ); 
        }

        Out.emplace_back( p );

        ptr = iter.GetNext( );
    }

    return Out;
}

std::string GetRegisterDetails( std::string Register, uintptr_t Address )
{
    HANDLE Process = GetCurrentProcess( );

    auto ModuleBase = SymGetModuleBase64( Process, Address );

    if ( !ModuleBase )
        return std::format( "{}: 0x{:x} (No Associated Module [1])", Register, Address );

    char ModuleBuf[ MAX_PATH ];
    if ( !GetModuleFileNameA( ( HINSTANCE )ModuleBase, ModuleBuf, MAX_PATH ) )
        return std::format( "{}: 0x{:x} (No Associated Module [2])", Register, Address );

    auto ModuleName = FileNameA( ModuleBuf );
    auto RVA = Address - ModuleBase;

    return std::format( "{}: 0x{:x} ({}+0x{:x})", Register, Address, ModuleName, RVA );
}

std::vector<StackFrame> GetStackTrace( PCONTEXT Context )
{
    HANDLE Process = GetCurrentProcess( );
    HANDLE Thread = GetCurrentThread( );
    Context->ContextFlags = CONTEXT_FULL;

    if ( SymInitialize( Process, nullptr, TRUE ) == FALSE )
        return { };

    SymSetOptions( SYMOPT_LOAD_LINES | SYMOPT_DEFERRED_LOADS | SYMOPT_UNDNAME );

    STACKFRAME Frame64 = { };
    Frame64.AddrPC.Offset = Context->Rip;
    Frame64.AddrPC.Mode = AddrModeFlat;
    Frame64.AddrFrame.Offset = Context->Rsp;
    Frame64.AddrFrame.Mode = AddrModeFlat;
    Frame64.AddrStack.Offset = Context->Rsp;
    Frame64.AddrStack.Mode = AddrModeFlat;

    std::vector<StackFrame> Frames;
    while ( StackWalk64( IMAGE_FILE_MACHINE_AMD64, Process, Thread, &Frame64, Context, nullptr, 
                         SymFunctionTableAccess64, SymGetModuleBase64, nullptr ) )
    {
        StackFrame Frame = { };
        Frame.Address = Frame64.AddrPC.Offset;

        auto ModuleBase = SymGetModuleBase64( Process, Frame64.AddrPC.Offset );

        if ( !ModuleBase )
            continue;

        Frame.ModuleBase = ModuleBase;
        char ModuleBuf[ MAX_PATH ];
        if ( ModuleBase && GetModuleFileNameA( ( HINSTANCE )ModuleBase, ModuleBuf, MAX_PATH ) )
        {
            auto ModuleName = FileNameA( ModuleBuf );

            Frame.Module = ModuleName;
        }
        else
        {
            Frame.Module = "DLL_" + std::format( "0x{:x}", ModuleBase );
        }

        uintptr_t Offset = 0;
        char SymbolBuffer[ sizeof( IMAGEHLP_SYMBOL ) + 255 ];
        auto Symbol = ( PIMAGEHLP_SYMBOL )SymbolBuffer;
        Symbol->SizeOfStruct = sizeof( IMAGEHLP_SYMBOL ) + 255;
        Symbol->MaxNameLength = 254;

        if ( SymGetSymFromAddr64( Process, Frame64.AddrPC.Offset, &Offset, Symbol ) )
        {
            Frame.Name = Symbol->Name;
        }
        else
        {
            Frame.Name = "SUB_" + std::format( "0x{:x}", ModuleBase );
        }

        IMAGEHLP_LINE ImageLine{};
        ImageLine.SizeOfStruct = sizeof( IMAGEHLP_LINE );

        DWORD OffsetLine = 0;
        if ( SymGetLineFromAddr64( Process, Frame64.AddrPC.Offset, &OffsetLine, &ImageLine ) )
        {
            Frame.File = FileNameA( ImageLine.FileName );
            Frame.Line = ImageLine.LineNumber;
        }
        else
        {
            Frame.File = "FILE";
            Frame.Line = 0;
        }

        Frames.emplace_back( Frame );
    }

    SymCleanup( Process );

    return Frames;
}

void DumpThreadInformation( )
{
    HANDLE ProcessHandle = GetCurrentProcess( );

    std::vector<MODULEENTRY32> Modules;
    std::vector<ProcessInfo> Processes = GetAllProcesses( );

    {
        HANDLE Snapshot = CreateToolhelp32Snapshot( TH32CS_SNAPMODULE, 0 );
        if ( Snapshot == INVALID_HANDLE_VALUE )
            return;

        MODULEENTRY32 ModuleEntry;
        ModuleEntry.dwSize = sizeof( ModuleEntry );

        if ( !Module32First( Snapshot, &ModuleEntry ) )
            return;

        do 
        {
            Modules.push_back( ModuleEntry );
        } while ( Module32Next( Snapshot, &ModuleEntry ) );

        CloseHandle( Snapshot );
    }

    std::string Output = "";
    
    char _CurrentProcessPath[ MAX_PATH ];
    GetModuleFileNameA( NULL, _CurrentProcessPath, MAX_PATH );
    std::string CurrentProcessPath = _CurrentProcessPath;
    std::string CurrentProcessName = CurrentProcessPath.substr( CurrentProcessPath.find_last_of( "/\\ ") + 1 );

    for ( auto& Process : Processes )
    {
        if ( Process.Name != CurrentProcessName )
            continue;

        for ( auto& Thread : Process.Threads )
        {   
            if ( GetCurrentThreadId( ) == HandleToUlong( Thread.ClientId.UniqueThread ) )
                continue;

            HANDLE Handle = OpenThread( THREAD_ALL_ACCESS, false, HandleToUlong( Thread.ClientId.UniqueThread ) );

            SuspendThread( Handle );

            uintptr_t StartAddress = reinterpret_cast<uintptr_t>( Thread.StartAddress );

            std::string OwnerModule = "none";
            uintptr_t ModuleOffset = 0;

            for ( auto& Module : Modules )
            {
                uint64_t Base = reinterpret_cast<uint64_t>( Module.modBaseAddr );
                uint64_t Size = static_cast<uint64_t>( Module.modBaseSize );
                if ( StartAddress >= Base && StartAddress < Base + Size )
                {
                    OwnerModule = Module.szModule;
                    ModuleOffset = StartAddress - Base;
                    break;
                }
            }

            uint64_t CycleDelta = 0;
            QueryThreadCycleTime( Handle, &CycleDelta );

            std::string WaitReason = GetThreadWaitReason( Thread.WaitReason );
            std::string State = GetThreadState( Thread.ThreadState );

            CONTEXT Context = { 0 };
            Context.ContextFlags = CONTEXT_FULL;
            GetThreadContext( Handle, &Context );

            std::string Header = std::format(
                "Thread ID: {} | Start Address: {} ({}+{}) | Cycle Delta: {} | State: {} | Wait Reason: {}",
                Thread.ClientId.UniqueThread, StartAddress, OwnerModule, ModuleOffset, CycleDelta, State, WaitReason
            );

            std::string Body = "";
            auto StackTrace = GetStackTrace( &Context );
            for ( size_t i = 0; i < StackTrace.size( ); i++ )
            {
                const auto& Frame = StackTrace[ i ];

                const auto SymbolRVA = Frame.Address - Frame.ModuleBase;

                Body += std::format( "{}: \"{}\"+0x{:x}\n", i, Frame.Module, SymbolRVA );

                if ( Frame.File != "FILE" )
                    Body += std::format( "Function: {} - File: {} - Line: {}\n", Frame.Name, Frame.File, Frame.Line );
            }

            std::string Footer = "";
            if ( SymInitialize( ProcessHandle, nullptr, TRUE ) )
            {
                Footer += GetRegisterDetails( "RIP", Context.Rip ) + "\n";
                Footer += GetRegisterDetails( "RAX", Context.Rax ) + "\n";
                Footer += GetRegisterDetails( "RBX", Context.Rbx ) + "\n";
                Footer += GetRegisterDetails( "RCX", Context.Rcx ) + "\n";
                Footer += GetRegisterDetails( "RDX", Context.Rdx ) + "\n";
                Footer += GetRegisterDetails( "RBP", Context.Rbp ) + "\n";
                Footer += GetRegisterDetails( "RSP", Context.Rsp ) + "\n";
                Footer += GetRegisterDetails( "RSI", Context.Rsi ) + "\n";
                Footer += GetRegisterDetails( "RDI", Context.Rdi ) + "\n";

                SymCleanup( ProcessHandle );
            }

            Output += std::format( "{}\n\n{}\n{}\n--------\n\n", Header, Body, Footer );

            ResumeThread( Handle );
            CloseHandle( Handle );
        }
    }

    std::ofstream File( std::format( "ThreadInformation_{}.txt", GetTickCount64( ) ) );
    File << Output;
    File.close( );
}

LONG ExceptionHandler( EXCEPTION_POINTERS* Info )
{
    HANDLE Process = GetCurrentProcess( );

    switch ( Info->ExceptionRecord->ExceptionCode ) 
    {
        case DBG_PRINTEXCEPTION_C:
        case DBG_PRINTEXCEPTION_WIDE_C:
        case STATUS_BREAKPOINT:
        case STEAM_API_DEBUG_MEASURE:
        case STEAM_API_BULLSHIT:
        case RPC_NT_INTERNAL_ERROR:
        case EXCEPTION_SINGLE_STEP:
            return EXCEPTION_EXECUTE_HANDLER;
            break;
        default:
            break;
    }

    std::string Header = std::format( "An exception has occured.\nException: {} ({:x})", GetErrorCode( Info->ExceptionRecord->ExceptionCode ), Info->ExceptionRecord->ExceptionCode );

    std::string Body = "";

    auto StackTrace = GetStackTrace( Info->ContextRecord );

    for ( size_t i = 0; i < StackTrace.size( ); i++ )
    {
        const auto& Frame = StackTrace[ i ];

        const auto SymbolRVA = Frame.Address - Frame.ModuleBase;

        Body += std::format( "{}: \"{}\"+0x{:x}\n", i, Frame.Module, SymbolRVA );

        if ( Frame.File != "FILE" )
            Body += std::format( "Function: {} - File: {} - Line: {}\n", Frame.Name, Frame.File, Frame.Line );
    }

    std::string Footer = "";

    if ( SymInitialize( Process, nullptr, TRUE ) )
    {
        Footer += GetRegisterDetails( "RIP", Info->ContextRecord->Rip ) + "\n";
        Footer += GetRegisterDetails( "RAX", Info->ContextRecord->Rax ) + "\n";
        Footer += GetRegisterDetails( "RBX", Info->ContextRecord->Rbx ) + "\n";
        Footer += GetRegisterDetails( "RCX", Info->ContextRecord->Rcx ) + "\n";
        Footer += GetRegisterDetails( "RDX", Info->ContextRecord->Rdx ) + "\n";
        Footer += GetRegisterDetails( "RBP", Info->ContextRecord->Rbp ) + "\n";
        Footer += GetRegisterDetails( "RSP", Info->ContextRecord->Rsp ) + "\n";
        Footer += GetRegisterDetails( "RSI", Info->ContextRecord->Rsi ) + "\n";
        Footer += GetRegisterDetails( "RDI", Info->ContextRecord->Rdi ) + "\n";

        SymCleanup( Process );
    }

    DumpThreadInformation( );

    std::ofstream File( std::format( "Crash_{}.txt", GetTickCount64( ) ) );
    File << std::format( "{}\n\n{}\n{}\n", Header, Body, Footer ).c_str( );
    File.close( );

    exit( 0 );

    return EXCEPTION_EXECUTE_HANDLER;
}

DWORD WINAPI StartThread( LPVOID lpParam ) 
{
    AddVectoredExceptionHandler( 0, ExceptionHandler );

    PlaySoundA( "C:\\Windows\\Media\\Speech On.wav", NULL, SND_FILENAME | SND_ASYNC );

    while ( true )
    {
        static bool Released = true;
        if ( GetAsyncKeyState( VK_SHIFT ) && GetAsyncKeyState( VK_CONTROL ) && GetAsyncKeyState( VK_CAPITAL ) )
        {
            if ( Released )
            {
                PlaySoundA( "C:\\Windows\\Media\\Windows Pop-up Blocked.wav", NULL, SND_FILENAME | SND_ASYNC );
                DumpThreadInformation( );
            }
            Released = false;
        } 
        else 
        {
            Released = true;
        }
        Sleep( 500 );
    }

    return 0;
}

extern "C" __declspec(dllexport) BOOL WINAPI DllMain( HINSTANCE Instance, DWORD Reason, LPVOID Reserved )
{
    if ( Reason == DLL_PROCESS_ATTACH )
        CreateThread( 0, 0, ( LPTHREAD_START_ROUTINE ) StartThread, 0, 0, 0 );

    return TRUE;
}