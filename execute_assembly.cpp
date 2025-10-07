#include "execute_assembly.hpp"

struct StdCapture {
    DWORD kind{};
    HANDLE old = INVALID_HANDLE_VALUE;
    HANDLE r = INVALID_HANDLE_VALUE, w = INVALID_HANDLE_VALUE;
    std::thread th;
    std::string* sink = nullptr;

    bool start(DWORD k, std::string& target) {
        kind = k; sink = &target;
        SECURITY_ATTRIBUTES sa{ sizeof(sa), nullptr, TRUE };
        if (!CreatePipe(&r, &w, &sa, 0)) return false;
        SetHandleInformation(r, HANDLE_FLAG_INHERIT, 0);
        old = GetStdHandle(kind);
        SetStdHandle(kind, w);
        th = std::thread([this]() {
            char buf[4096];
            for (;;) {
                DWORD n = 0;
                if (!ReadFile(r, buf, sizeof(buf), &n, nullptr) || n == 0) break;
                sink->append(buf, buf + n);
            }
            });
        return true;
    }
    void stop() {
        if (w != INVALID_HANDLE_VALUE) { FlushFileBuffers(w); CloseHandle(w); w = INVALID_HANDLE_VALUE; }
        if (th.joinable()) th.join();
        SetStdHandle(kind, old);
        if (r != INVALID_HANDLE_VALUE) { CloseHandle(r); r = INVALID_HANDLE_VALUE; }
    }
};

static void vlog(std::string& out, const char* fmt, va_list ap) {
    char buf[2048];
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    if (n <= 0) return;
    size_t to_write = (size_t)((n < (int)sizeof(buf) - 1) ? n : ((int)sizeof(buf) - 1));
    fwrite(buf, 1, to_write, stdout);
    out.append(buf, (size_t)n);
}

static void logf(std::string& out, const char* fmt, ...) {
    va_list ap; va_start(ap, fmt); vlog(out, fmt, ap); va_end(ap);
}

static SAFEARRAY* BytesToSA(const void* buf, size_t n) {
    SAFEARRAY* sa = SafeArrayCreateVector(VT_UI1, 0, (ULONG)n);
    if (!sa) return nullptr;
    void* p = nullptr;
    if (SUCCEEDED(SafeArrayAccessData(sa, &p))) {
        memcpy(p, buf, n);
        SafeArrayUnaccessData(sa);
        return sa;
    }
    SafeArrayDestroy(sa);
    return nullptr;
}

static std::wstring utf8_to_wide(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
    std::wstring w(n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), w.data(), n);
    return w;
}


BOOL ExecuteAssembly(
    std::string& out,
    const std::vector<uint8_t>& asmBytes,
    const std::vector<std::string>& args
)
{
    BOOL ok = FALSE;

    ICLRMetaHost* pMetaHost = nullptr;
    IEnumUnknown* pEnum = nullptr;
    ICLRRuntimeInfo* pRuntimeInfoV4 = nullptr;
    ICorRuntimeHost* host = nullptr;
    IUnknown* pNewDomainThunk = nullptr;
    _AppDomainPtr spTempDomain = nullptr;
    _AssemblyPtr spAsm = nullptr;
    _MethodInfoPtr entry = nullptr;

    SAFEARRAY* saAsm = nullptr;
    SAFEARRAY* saStrs = nullptr;
    SAFEARRAY* saParams = nullptr;

    VARIANT vtStrs;
    VariantInit(&vtStrs);

    VARIANT vtRet;
    VariantInit(&vtRet);

    LONG numArgs = 0;

    StdCapture capOut;
    StdCapture capErr;

    bool capOutOn = false;
    bool capErrOn = false;

    std::string capStdout;
    std::string capStderr;

    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr))
    {
        logf(out, "[!] CoInitializeEx: 0x%08X\n", hr);
        return FALSE;
    }

    hr = CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, (LPVOID*)&pMetaHost);
    if (FAILED(hr))
    {
        logf(out, "[!] CLRCreateInstance: 0x%08X\n", hr);
        goto cleanup;
    }

    hr = pMetaHost->EnumerateInstalledRuntimes(&pEnum);
    if (FAILED(hr))
    {
        logf(out, "[!] EnumerateInstalledRuntimes: 0x%08X\n", hr);
        goto cleanup;
    }

    {
        IUnknown* pUnk = nullptr;
        ULONG fetched = 0;

        while (pEnum->Next(1, &pUnk, &fetched) == S_OK && fetched == 1)
        {
            ICLRRuntimeInfo* pRuntimeInfo = nullptr;

            HRESULT hrQi = pUnk->QueryInterface(IID_PPV_ARGS(&pRuntimeInfo));
            if (SUCCEEDED(hrQi))
            {
                WCHAR ver[50];
                DWORD len = ARRAYSIZE(ver);

                HRESULT hrVer = pRuntimeInfo->GetVersionString(ver, &len);
                if (SUCCEEDED(hrVer))
                {
                    logf(out, "[+] Runtime installed: %ws\n", ver);

                    if (wcsncmp(ver, L"v4.", 3) == 0)
                    {
                        if (pRuntimeInfoV4)
                        {
                            pRuntimeInfoV4->Release();
                        }

                        pRuntimeInfoV4 = pRuntimeInfo;
                        pRuntimeInfoV4->AddRef();
                    }
                }

                pRuntimeInfo->Release();
            }

            pUnk->Release();
        }
    }

    if (!pRuntimeInfoV4)
    {
        logf(out, "[!] Runtime v4.x not found\n");
        goto cleanup;
    }

    hr = pRuntimeInfoV4->GetInterface(CLSID_CorRuntimeHost, IID_PPV_ARGS(&host));
    if (FAILED(hr))
    {
        logf(out, "[!] GetInterface(CorRuntimeHost): 0x%08X\n", hr);
        goto cleanup;
    }

    hr = host->Start();
    if (FAILED(hr))
    {
        logf(out, "[!] host->Start: 0x%08X\n", hr);
        goto cleanup;
    }

    hr = host->CreateDomainEx(L"TempDomain", nullptr, nullptr, &pNewDomainThunk);
    if (FAILED(hr) || !pNewDomainThunk)
    {
        logf(out, "[!] CreateDomainEx: 0x%08X\n", hr);
        goto cleanup;
    }

    hr = pNewDomainThunk->QueryInterface(__uuidof(_AppDomain), (void**)&spTempDomain);
    if (FAILED(hr) || !spTempDomain)
    {
        logf(out, "[!] QI _AppDomain: 0x%08X\n", hr);
        goto cleanup;
    }

    if (asmBytes.empty())
    {
        logf(out, "[!] asmBytes vacío\n");
        goto cleanup;
    }

    saAsm = BytesToSA(asmBytes.data(), asmBytes.size());
    if (!saAsm)
    {
        logf(out, "[!] BytesToSA falló\n");
        goto cleanup;
    }

    hr = spTempDomain->Load_3(saAsm, &spAsm);
    SafeArrayDestroy(saAsm);
    saAsm = nullptr;

    if (FAILED(hr) || !spAsm)
    {
        logf(out, "[!] Load_3: 0x%08X\n", hr);
        goto cleanup;
    }

    hr = spAsm->get_EntryPoint(&entry);
    if (FAILED(hr) || !entry)
    {
        logf(out, "[!] get_EntryPoint: 0x%08X\n", hr);
        goto cleanup;
    }

    numArgs = static_cast<LONG>(args.size());

    saStrs = SafeArrayCreateVector(VT_BSTR, 0, static_cast<ULONG>(numArgs));
    if (!saStrs)
    {
        logf(out, "[!] SafeArrayCreateVector(string[]) falló\n");
        goto cleanup;
    }

    for (LONG i = 0; i < numArgs; ++i)
    {
        const std::string& s = args[static_cast<size_t>(i)];
        std::wstring w = utf8_to_wide(s);

        logf(out, "  args[%ld]: %ls\n", i, w.c_str());

        BSTR b = SysAllocStringLen(w.data(), static_cast<UINT>(w.size()));
        if (!b)
        {
            logf(out, "[!] SysAllocStringLen falló en %ld\n", i);
            goto cleanup;
        }

        HRESULT hrPut = SafeArrayPutElement(saStrs, &i, b);

        SysFreeString(b);

        if (FAILED(hrPut))
        {
            logf(out, "[!] SafeArrayPutElement arg %ld: 0x%08X\n", i, hrPut);
            goto cleanup;
        }
    }

    VariantInit(&vtStrs);
    vtStrs.vt = VT_ARRAY | VT_BSTR;
    vtStrs.parray = saStrs;

    saParams = SafeArrayCreateVector(VT_VARIANT, 0, 1);
    if (!saParams)
    {
        logf(out, "[!] SafeArrayCreateVector(object[]) falló\n");
        goto cleanup;
    }

    {
        LONG idx = 0;
        HRESULT hrPutParam = SafeArrayPutElement(saParams, &idx, &vtStrs);
        if (FAILED(hrPutParam))
        {
            logf(out, "[!] SafeArrayPutElement params: 0x%08X\n", hrPutParam);
            goto cleanup;
        }
    }

    capOutOn = capOut.start(STD_OUTPUT_HANDLE, capStdout);
    capErrOn = capErr.start(STD_ERROR_HANDLE, capStderr);

    {
        VARIANT vtThis;
        VariantInit(&vtThis);

        hr = entry->Invoke_3(vtThis, saParams, &vtRet);
    }

    if (capOutOn)
    {
        capOut.stop();
        capOutOn = false;
    }

    if (capErrOn)
    {
        capErr.stop();
        capErrOn = false;
    }

    if (FAILED(hr))
    {
        logf(out, "[!] EntryPoint Invoke: 0x%08X\n", hr);
        goto cleanup;
    }

    if (vtRet.vt == VT_I4)
    {
        logf(out, "[+] Return code: %ld\n", vtRet.lVal);
    }

    out += "[stdout]\n";
    out += capStdout;

    out += "\n[stderr]\n";
    out += capStderr;

    ok = TRUE;

cleanup:
    if (capOutOn)
    {
        capOut.stop();
        capOutOn = false;
    }

    if (capErrOn)
    {
        capErr.stop();
        capErrOn = false;
    }

    VariantClear(&vtRet);
    VariantClear(&vtStrs);

    if (saParams)
    {
        SafeArrayDestroy(saParams);
    }

    if (host && pNewDomainThunk)
    {
        host->UnloadDomain(pNewDomainThunk);
    }

    if (pNewDomainThunk)
    {
        pNewDomainThunk->Release();
        pNewDomainThunk = nullptr;
    }

    if (host)
    {
        host->Stop();
        host->Release();
        host = nullptr;
    }

    if (pRuntimeInfoV4)
    {
        pRuntimeInfoV4->Release();
        pRuntimeInfoV4 = nullptr;
    }

    if (pEnum)
    {
        pEnum->Release();
        pEnum = nullptr;
    }

    if (pMetaHost)
    {
        pMetaHost->Release();
        pMetaHost = nullptr;
    }

    CoUninitialize();

    return ok;
}
