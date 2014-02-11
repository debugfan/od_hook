// od_hook.cpp : Defines the entry point for the DLL application.
//

#include <windows.h>
#include <detours.h>
#include "read_config.h"
#include "debug_log.h"
#include <map>
using namespace std;

#include <detours.h>
#pragma comment(lib, "detours.lib")

#ifdef USE_DETOURED_DLL
#pragma comment(lib, "detoured.lib")
#else
HMODULE WINAPI Detoured()
{
    return NULL;
}
#endif

#define EFLAGS_TRAP 0x00000100

#define IsNullString(x) (x == NULL ? "NULL" : x)

typedef struct {
    VOID * address;
    int length;
    DWORD condition;
    int slot;
} HARDWARE_BREAKPOINT;

#define HARDWARE_BREAKPOINT_NONE        0
#define HARDWARE_BREAKPOINT_FOUND       1    
#define HARDWARE_BREAKPOINT_SET_TRAP    2    
#define HARDWARE_BREAKPOINT_HIT_TRAP    3 
#define HARDWARE_BREAKPOINT_UNKNOWN     4   

map<DWORD, int> thread_states;

static DWORD main_thread_id = 0;

static BOOL (WINAPI * Real_CreateProcessA)(
                                          LPCTSTR lpApplicationName,
                                          LPTSTR lpCommandLine,
                                          LPSECURITY_ATTRIBUTES lpProcessAttributes,
                                          LPSECURITY_ATTRIBUTES lpThreadAttributes,
                                          BOOL bInheritHandles,
                                          DWORD dwCreationFlags,
                                          LPVOID lpEnvironment,
                                          LPCTSTR lpCurrentDirectory,
                                          LPSTARTUPINFO lpStartupInfo,
                                          LPPROCESS_INFORMATION lpProcessInformation
                                          ) = CreateProcessA;

static BOOL (WINAPI * Real_GetThreadContext)(
                      HANDLE hThread,
                      LPCONTEXT lpContext
                      ) = GetThreadContext;

static BOOL (WINAPI * Real_SetThreadContext) (
                                              HANDLE hThread,
                                              const CONTEXT* lpContext
                                              ) = SetThreadContext;

static BOOL (WINAPI * Real_WaitForDebugEvent) (
                                 LPDEBUG_EVENT lpDebugEvent,
                                 DWORD dwMilliseconds
                                 ) = WaitForDebugEvent;

static BOOL (WINAPI * Real_ContinueDebugEvent) (
                               DWORD dwProcessId,
                               DWORD dwThreadId,
                               DWORD dwContinueStatus
                               ) = ContinueDebugEvent;

static BOOL (WINAPI * Real_ReadProcessMemory) (
                              HANDLE hProcess,
                              LPCVOID lpBaseAddress,
                              LPVOID lpBuffer,
                              SIZE_T nSize,
                              SIZE_T* lpNumberOfBytesRead
                              ) = ReadProcessMemory;

static BOOL (WINAPI *Real_WriteProcessMemory) (
                               HANDLE hProcess,
                               LPVOID lpBaseAddress,
                               LPCVOID lpBuffer,
                               SIZE_T nSize,
                               SIZE_T* lpNumberOfBytesWritten
                               ) = WriteProcessMemory;


static int ep_flag = 0;

BOOL GetThreadContextById(DWORD thread_id, LPCONTEXT lpContext)
{
    BOOL ret;
    HANDLE h = OpenThread(THREAD_ALL_ACCESS, FALSE, thread_id);
    if(h == NULL)
    {
        return FALSE;
    }
    ret = GetThreadContext(h, lpContext);
    CloseHandle(h);
    return ret;
}

BOOL SetThreadContextById(DWORD thread_id, LPCONTEXT lpContext)
{
    BOOL ret;
    HANDLE h = OpenThread(THREAD_ALL_ACCESS, FALSE, thread_id);
    if(h == NULL)
    {
        return FALSE;
    }
    ret = SetThreadContext(h, lpContext);
    CloseHandle(h);
    return ret;
}

BOOL update_context_by_hwbp(CONTEXT *ctx, int slot, void *address, int length, int condition)
{
    //# Enable the appropriate flag in the DR7
    //# register to set the breakpoint
    ctx->Dr7 |= 1 << (slot * 2);
    
    //# Save the address of the breakpoint in the
    //# free register that we found
    //        if   available == 0: context.Dr0 = address
    //            elif available == 1: context.Dr1 = address
    //            elif available == 2: context.Dr2 = address
    //            elif available == 3: context.Dr3 = address
    if   (slot == 0) ctx->Dr0 = (unsigned long)address;
    else if (slot == 1) ctx->Dr1 = (unsigned long)address;
    else if (slot == 2) ctx->Dr2 = (unsigned long)address;
    else if (slot == 3) ctx->Dr3 = (unsigned long)address;
    
    //# Set the breakpoint condition
    //ctx->Dr7 |= condition << ((available * 4) + 16);
    ctx->Dr7 = ctx->Dr7 & (~(0x3 << ((slot * 4) + 16)));
    ctx->Dr7 = ctx->Dr7 | (condition << ((slot * 4) + 16));
    
    //# Set the length
    length--;
    ctx->Dr7 = ctx->Dr7  & (~(0x3 << ((slot * 4) + 18)));
    ctx->Dr7 = ctx->Dr7 | (length << ((slot * 4) + 18));
    
    log_info(("[update_context_by_hwbp]Dr0: %x, Dr1: %x, Dr2: %x, Dr3: %x, Dr6: %x, Dr7: %x",
        ctx->Dr0, ctx->Dr1, ctx->Dr2, ctx->Dr3, ctx->Dr6, ctx->Dr7));

    return TRUE;
}

BOOL set_hwbp(HANDLE thread_handle, DWORD thread_id, int available, void *address, int length, int condition)
{
#if _MSC_VER < 1300
#undef __FUNCTION__
#define __FUNCTION__ "set_hw_bp"
#endif

    CONTEXT context;
    context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
    
    if(thread_handle == NULL) 
    {
        if(!GetThreadContextById(thread_id, &context))
        {
            log_error(("[%s]GetThreadContextById failed", __FUNCTION__));
            return FALSE;
        }
    }
    else 
    {
        //context = self.get_thread_context(thread_id=thread_id)
        if(!GetThreadContext(thread_handle, &context))
        {
            log_error(("[%s]GetThreadContext failed", __FUNCTION__));
            if(!GetThreadContextById(thread_id, &context)) 
            {
                log_error(("[%s]GetThreadContextById failed", __FUNCTION__));
                return FALSE;
            }
        }
    }
    
    update_context_by_hwbp(&context, available, address, length, condition);
    
    //# Set this threads context with the debug registers
    //# set
    //            h_thread = self.open_thread(thread_id)
    //            kernel32.SetThreadContext(h_thread,byref(context))
    //if(!SetThreadContext(hThread, &context))
    if(!SetThreadContextById(thread_id, &context))
    {
        log_error(("[%s]SetThreadContext failed", __FUNCTION__));
        return FALSE;
    }
    return TRUE;
}

BOOL set_single_step(HANDLE thread_handle, BOOL enable)
{
#if _MSC_VER < 1300
#undef __FUNCTION__
#define __FUNCTION__ "set_single_step"
#endif

    CONTEXT context;
    context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;

    //context = self.get_thread_context(thread_id=thread_id)
    if(!GetThreadContext(thread_handle, &context))
    {
        log_error(("[%s]GetThreadContext failed", __FUNCTION__));
        return FALSE;
    }

    log_info(("[%s]context.EFlags: %x", __FUNCTION__, context.EFlags));

    if(enable) 
    {
        if(context.EFlags & EFLAGS_TRAP) 
        {
            return TRUE;
        }
        context.EFlags |= EFLAGS_TRAP;
    }
    else 
    {
        if(!(context.EFlags & EFLAGS_TRAP)) 
        {
            return TRUE;
        }

        context.EFlags = context.EFlags & (0xFFFFFFFF ^ EFLAGS_TRAP);
    }

    if(!SetThreadContext(thread_handle, &context))
    {
        log_error(("[%s]SetThreadContext failed", __FUNCTION__));
        return FALSE;
    }

    return TRUE;
}

BOOL is_single_step(DWORD thread_id)
{
#if _MSC_VER < 1300
#undef __FUNCTION__
#define __FUNCTION__ "is_single_step"
#endif
    
    CONTEXT context;
    context.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;

    if(!GetThreadContextById(thread_id, &context))
    {
        log_error(("[%s]GetThreadContextById failed", __FUNCTION__));
        return FALSE;
    }

    if(context.EFlags & EFLAGS_TRAP) 
    {
        return TRUE;
    }
    else
    {
        return FALSE;
    }
}

BOOL GetHardwareBreakpointInfo(HARDWARE_BREAKPOINT *hwbp, int slot, CONTEXT *ctx) 
{
    if(!(ctx->Dr7 & (1 << (slot * 2))))
    {
        return FALSE;
    }
    
    hwbp->slot = slot;
    
    if   (slot == 0) hwbp->address = (VOID *)ctx->Dr0;
    else if (slot == 1) hwbp->address = (VOID *)ctx->Dr1;
    else if (slot == 2) hwbp->address = (VOID *)ctx->Dr2;
    else if (slot == 3) hwbp->address = (VOID *)ctx->Dr3;
    
    //# Set the breakpoint condition
    //context.Dr7 |= condition << ((available * 4) + 16);
    hwbp->condition = (ctx->Dr7 >> ((slot * 4) + 16) & 0x3);
    
    //# Set the length
    //length--;
    //context.Dr7 |= length << ((available * 4) + 18);
    hwbp->length = ((ctx->Dr7 >> ((slot * 4) + 18)) & 0x3) + 1;
    
    return TRUE;
}

VOID DumpHardwareBreakpoint(DWORD tid)
{
#if _MSC_VER < 1300
#undef __FUNCTION__
#define __FUNCTION__ "DumpHardwareBreakpoint"
#endif

    HARDWARE_BREAKPOINT hwbp;
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;

    if(FALSE == GetThreadContextById(tid, &ctx))
    {
        log_error(("[%s]GetThreadContextById failed", __FUNCTION__));
        return;
    }

    log_info(("[%s]Dump hardware breakpoint, thread id 0x%x", 
        __FUNCTION__, 
        tid));

    for(int slot = 0; slot < 4; slot++)
    {
        if(GetHardwareBreakpointInfo(&hwbp, slot, &ctx))
        {
            log_info(("[%s]slot: %d, address: 0x%x, length: %d, condition: 0x%x",
                __FUNCTION__,
                slot,
                hwbp.address,
                hwbp.length,
                hwbp.condition));
        }
    }
}

BOOL CopyHardwareBreakpoint(DWORD src_tid, DWORD dest_tid)
{
#if _MSC_VER < 1300
#undef __FUNCTION__
#define __FUNCTION__ "CopyHardwareBreakpoint"
#endif

    HARDWARE_BREAKPOINT hwbp;
    CONTEXT src_ctx;
    src_ctx.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
    if(FALSE == GetThreadContextById(src_tid, &src_ctx))
    {
        log_error(("[%s]GetThreadContextById failed", __FUNCTION__));
        return FALSE;
    }
    for(int slot = 0; slot < 4; slot++)
    {
        if(GetHardwareBreakpointInfo(&hwbp, slot, &src_ctx))
        {
            log_info(("[%s]set hardware breakpoint, address: 0x%x", 
                __FUNCTION__,
                hwbp.address));
            set_hwbp(NULL, dest_tid, hwbp.slot, hwbp.address, hwbp.length, hwbp.condition);
        }
    }
    return TRUE;
}

BOOL WINAPI My_CreateProcessA(
                          LPCTSTR lpApplicationName,
                          LPTSTR lpCommandLine,
                          LPSECURITY_ATTRIBUTES lpProcessAttributes,
                          LPSECURITY_ATTRIBUTES lpThreadAttributes,
                          BOOL bInheritHandles,
                          DWORD dwCreationFlags,
                          LPVOID lpEnvironment,
                          LPCTSTR lpCurrentDirectory,
                          LPSTARTUPINFO lpStartupInfo,
                          LPPROCESS_INFORMATION lpProcessInformation
                          )
{
    log_info(("[%s]lpApplicationName: %s, "
        "lpCommandLine: %s, "
        "lpProcessAttributes: %x, "
        "lpThreadAttributes: %x, "
        "bInheritHandles: %x, "
        "dwCreationFlags: %x, "
        "lpEnvironment: %x, "
        "lpCurrentDirectory: %s, "
        "lpStartupInfo: %x, "
        "lpProcessInformation: %x",
        "My_CreateProcessA",
        IsNullString(lpApplicationName),
        IsNullString(lpCommandLine),
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        dwCreationFlags,
        lpEnvironment,
        IsNullString(lpCurrentDirectory),
        lpStartupInfo,
        lpProcessInformation));
    return Real_CreateProcessA(lpApplicationName,
        lpCommandLine,
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        lpProcessInformation);
}

BOOL WINAPI My_GetThreadContext(
                       HANDLE hThread,
                       LPCONTEXT lpContext
                       )
{
    BOOL ret = Real_GetThreadContext(hThread, lpContext);
    log_info(("My_SetThreadContext Entry"));
    if(ret)
    {
        log_info(("[My_GetThreadContext]Dr0: %x, Dr1: %x, Dr2: %x, Dr3: %x, Dr6: %x, Dr7: %x",
            lpContext->Dr0, lpContext->Dr1, lpContext->Dr2, lpContext->Dr3, lpContext->Dr6, lpContext->Dr7));
    }
    else 
    {
        log_error(("[My_GetThreadContext]failed"));
    }

    return ret;
}

BOOL hwbp_exists(CONTEXT *ctx, int slot)
{
    if((ctx->Dr7 & (1 << (slot * 2))))
    {
        return TRUE;
    }
    else 
    {
        return FALSE;
    }
}

BOOL is_stopped_by_hwbp(DWORD thread_id)
{
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
    GetThreadContextById(thread_id, &ctx);
    for(int i = 0; i < 4; i++)
    {
        if(ctx.Dr6 & (1 << i))
        {
            if(hwbp_exists(&ctx, i)) 
            {
                return TRUE;
            }
        }
    }
    return FALSE;
}

BOOL WINAPI My_SetThreadContext(
                                HANDLE hThread,
                                const CONTEXT* lpContext
                                )
{
    log_info(("My_SetThreadContext Entry"));
    log_info(("[My_SetThreadContext]Dr0: %x, Dr1: %x, Dr2: %x, Dr3: %x, Dr6: %x, Dr7: %x",
        lpContext->Dr0, lpContext->Dr1, lpContext->Dr2, lpContext->Dr3, lpContext->Dr6, lpContext->Dr7));
    return Real_SetThreadContext(hThread, lpContext);
}

BOOL WINAPI My_WaitForDebugEvent(
                                 LPDEBUG_EVENT lpDebugEvent,
                                 DWORD dwMilliseconds
                                 )
{
#if _MSC_VER < 1300
#undef __FUNCTION__
#define __FUNCTION__ "My_WaitForDebugEvent"
#endif

    BOOL ret;
    DWORD thread_id;

    //Log_info2("[%s]dwMilliseconds: %d",
    //    __FUNCTION__, 
    //    dwMilliseconds);

    ret = Real_WaitForDebugEvent(lpDebugEvent, dwMilliseconds);

    if(ret == FALSE)
    {
        return FALSE;
    }
    
    if(lpDebugEvent == NULL)
    {
        return ret;
    }

    log_info2(("[%s]dwThreadId: 0x%x, dwDebugEventCode: 0x%x",
        __FUNCTION__, 
        lpDebugEvent->dwThreadId,
        lpDebugEvent->dwDebugEventCode));

    if(lpDebugEvent->dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT) 
    {
        thread_id = lpDebugEvent->dwThreadId;
        log_info(("[%s]CREATE_PROCESS_DEBUG_EVENT, thread_id: 0x%x",
            __FUNCTION__,
            thread_id));
        main_thread_id = thread_id;
        DumpHardwareBreakpoint(thread_id);
        thread_states[thread_id] = HARDWARE_BREAKPOINT_NONE;
        return ret;
    }

    if(lpDebugEvent->dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT) 
    {
        HANDLE thread_handle;
        thread_handle = lpDebugEvent->u.CreateThread.hThread;
        thread_id = lpDebugEvent->dwThreadId;
        log_info(("[%s]CREATE_THREAD_DEBUG_EVENT, thread_handle: 0x%x, thread_id: 0x%x",
             __FUNCTION__,
             thread_handle,
             thread_id));
        CopyHardwareBreakpoint(main_thread_id, thread_id);
        DumpHardwareBreakpoint(thread_id);
        thread_states[thread_id] = HARDWARE_BREAKPOINT_NONE;
        return ret;
    }
    
    if(lpDebugEvent->dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
    {
        DWORD exception_code;
        PVOID exception_address;

        exception_code = lpDebugEvent->u.Exception.ExceptionRecord.ExceptionCode;
        exception_address = lpDebugEvent->u.Exception.ExceptionRecord.ExceptionAddress;

        log_info2(("[%s]EXCEPTION_DEBUG_EVENT, exception_code: 0x%x, exception_address: 0x%x",
            __FUNCTION__,
            exception_code,
            exception_address));

        if(exception_code == EXCEPTION_SINGLE_STEP)
        {
            thread_id = lpDebugEvent->dwThreadId;

            DumpHardwareBreakpoint(thread_id);
            DumpHardwareBreakpoint(main_thread_id);

            if(thread_states[thread_id] == HARDWARE_BREAKPOINT_SET_TRAP)
            {
                thread_states[thread_id] = HARDWARE_BREAKPOINT_HIT_TRAP;
            }
            else
            {
                if(is_stopped_by_hwbp(thread_id))
                {
                    thread_states[thread_id] = HARDWARE_BREAKPOINT_FOUND;
                }
                else
                {
                    thread_states[thread_id] = HARDWARE_BREAKPOINT_NONE;
                }
            }

            return ret;
        }

        if(g_skip_some_exceptions)
        {
            // skip some exceptions
            if(exception_code == EXCEPTION_INT_OVERFLOW
                || exception_code == EXCEPTION_ILLEGAL_INSTRUCTION)
            {
                log_warn(("[%s]Skip an exception. dwThreadId: 0x%x, dwDebugEventCode: 0x%x",
                    __FUNCTION__, 
                    lpDebugEvent->dwThreadId,
                    lpDebugEvent->dwDebugEventCode));
                
                ContinueDebugEvent(lpDebugEvent->dwProcessId,
                    lpDebugEvent->dwThreadId,
                    DBG_EXCEPTION_NOT_HANDLED);
                return WaitForDebugEvent(lpDebugEvent, dwMilliseconds);
            }
        }

        return ret;
    }
    else
    {
        thread_id = lpDebugEvent->dwThreadId;
        thread_states[thread_id] = HARDWARE_BREAKPOINT_NONE;
    }

    return ret;
}

BOOL WINAPI My_ContinueDebugEvent (
                                                DWORD dwProcessId,
                                                DWORD dwThreadId,
                                                DWORD dwContinueStatus
                               ) 
{
#if _MSC_VER < 1300
#undef __FUNCTION__
#define __FUNCTION__ "My_ContinueDebugEvent"
#endif

    log_info2(("[%s]dwProcessId: 0x%x, dwThreadId: 0x%x, dwContinueStatus: 0x%x", 
        __FUNCTION__,
        dwProcessId,
        dwThreadId,
        dwContinueStatus));

    if(thread_states[dwThreadId] == HARDWARE_BREAKPOINT_FOUND)
    {
        if(is_single_step(dwThreadId))
        {
            thread_states[dwThreadId] = HARDWARE_BREAKPOINT_SET_TRAP;
        }
        else
        {
            thread_states[dwThreadId] = HARDWARE_BREAKPOINT_UNKNOWN;
        }
    }
    else if(thread_states[dwThreadId] == HARDWARE_BREAKPOINT_HIT_TRAP)
    {
        if(dwContinueStatus != DBG_CONTINUE)
        {
            if(dwThreadId != main_thread_id)
            {
                log_info(("[%s]Restore hardware breakpoints", __FUNCTION__));
                CopyHardwareBreakpoint(main_thread_id, dwThreadId);
            }
            else
            {
                log_info(("[%s]Don't know how to restore hardware breakpoints", __FUNCTION__));
            }
            
            log_info(("[%s]Correct debug continue status", __FUNCTION__));
            dwContinueStatus = DBG_CONTINUE;
        }
        
        DumpHardwareBreakpoint(dwThreadId);

        thread_states[dwThreadId] = HARDWARE_BREAKPOINT_NONE;
    }
    else
    {
        thread_states[dwThreadId] = HARDWARE_BREAKPOINT_NONE;
    }

    return Real_ContinueDebugEvent(dwProcessId, dwThreadId, dwContinueStatus);
}

BOOL WINAPI My_ReadProcessMemory(
                              HANDLE hProcess,
                              LPCVOID lpBaseAddress,
                              LPVOID lpBuffer,
                              SIZE_T nSize,
                              SIZE_T* lpNumberOfBytesRead
                              )
{
    BOOL ret = Real_ReadProcessMemory(hProcess,
        lpBaseAddress,
        lpBuffer,
        nSize,
        lpNumberOfBytesRead);
    log_info(("[My_ReadProcessMemory]lpBaseAddress: %x, lpBuffer: %x, nSize: %x, lpNumberOfBytesRead: %x", 
        lpBaseAddress,
        lpBuffer,
        nSize,
        lpNumberOfBytesRead
        ));
    return ret;
}

BOOL WINAPI My_WriteProcessMemory(
                               HANDLE hProcess,
                               LPVOID lpBaseAddress,
                               LPCVOID lpBuffer,
                               SIZE_T nSize,
                               SIZE_T* lpNumberOfBytesWritten
                               )
{
    log_info(("[WriteProcessMemory]lpBaseAddress: %x, lpBuffer: %x, nSize: %x, lpNumberOfBytesWritten: %x", 
        lpBaseAddress,
        lpBuffer,
        nSize,
        lpNumberOfBytesWritten
        ));
    return Real_WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
}

BOOL (WINAPI *Real_SetForegroundWindow) (
                                HWND hWnd
                                ) = SetForegroundWindow;

BOOL WINAPI My_SetForegroundWindow(HWND hWnd)
{
    if(g_disable_set_fore_ground_window)
    {
        return TRUE;
    }
    else
    {
        return Real_SetForegroundWindow(hWnd);
    }
}

extern "C" __declspec(dllexport) int donothing(int x) 
{
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved)
{
    LONG result = NO_ERROR;
    if (dwReason == DLL_PROCESS_ATTACH)
    {
        Sleep(100);
        init_and_read_config(hinst);
        DetourRestoreAfterWith();
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
#ifdef _DEBUG
        result |= DetourAttach(&(PVOID&)Real_CreateProcessA, My_CreateProcessA);
        result |= DetourAttach(&(PVOID&)Real_GetThreadContext, My_GetThreadContext);
        result |= DetourAttach(&(PVOID&)Real_SetThreadContext, My_SetThreadContext);
#endif
        if(g_fix_hardware_breakpoints_bugs)
        {
            result |= DetourAttach(&(PVOID&)Real_WaitForDebugEvent, My_WaitForDebugEvent);
            result |= DetourAttach(&(PVOID&)Real_ContinueDebugEvent, My_ContinueDebugEvent);
        }
#ifdef _DEBUG
        result |= DetourAttach(&(PVOID&)Real_ReadProcessMemory, My_ReadProcessMemory);
        result |= DetourAttach(&(PVOID&)Real_WriteProcessMemory, My_WriteProcessMemory);
#endif
        result |= DetourAttach(&(PVOID&)Real_SetForegroundWindow, My_SetForegroundWindow);
        DetourTransactionCommit();
        if(result != NO_ERROR)
        {
            log_error(("Detour failed, error code: %x", result));
        }
    }
    else if (dwReason == DLL_PROCESS_DETACH) 
    {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
#ifdef _DEBUG
        DetourDetach(&(PVOID&)Real_CreateProcessA, My_CreateProcessA);
        DetourDetach(&(PVOID&)Real_GetThreadContext, My_GetThreadContext);
        DetourDetach(&(PVOID&)Real_SetThreadContext, My_SetThreadContext);
#endif
        if(g_fix_hardware_breakpoints_bugs)
        {
            DetourDetach(&(PVOID&)Real_WaitForDebugEvent, My_WaitForDebugEvent);
            DetourDetach(&(PVOID&)Real_ContinueDebugEvent, My_ContinueDebugEvent);
        }
#ifdef _DEBUG
        DetourDetach(&(PVOID&)Real_ReadProcessMemory, My_ReadProcessMemory);
        DetourDetach(&(PVOID&)Real_WriteProcessMemory, My_WriteProcessMemory);
#endif
        DetourDetach(&(PVOID&)Real_SetForegroundWindow, My_SetForegroundWindow);
        DetourTransactionCommit();
    }
    return TRUE;
}


//
///////////////////////////////////////////////////////////////// End of File.
