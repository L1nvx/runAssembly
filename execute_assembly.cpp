#include "execute_assembly.hpp"

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

    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr))
    {
        printf("[!] CoInitializeEx: 0x%08X\n", hr);
        return FALSE;
    }

    hr = CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, (LPVOID*)&pMetaHost);
    if (FAILED(hr))
    {
        printf("[!] CLRCreateInstance: 0x%08X\n", hr);
        goto cleanup;
    }

    hr = pMetaHost->EnumerateInstalledRuntimes(&pEnum);
    if (FAILED(hr))
    {
        printf("[!] EnumerateInstalledRuntimes: 0x%08X\n", hr);
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
                    printf("[+] Runtime installed: %ws\n", ver);

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
        printf("[!] Runtime v4.x not found\n");
        goto cleanup;
    }

    hr = pRuntimeInfoV4->GetInterface(CLSID_CorRuntimeHost, IID_PPV_ARGS(&host));
    if (FAILED(hr))
    {
        printf("[!] GetInterface(CorRuntimeHost): 0x%08X\n", hr);
        goto cleanup;
    }

    hr = host->Start();
    if (FAILED(hr))
    {
        printf("[!] host->Start: 0x%08X\n", hr);
        goto cleanup;
    }

    hr = host->CreateDomainEx(L"TempDomain", nullptr, nullptr, &pNewDomainThunk);
    if (FAILED(hr) || !pNewDomainThunk)
    {
        printf("[!] CreateDomainEx: 0x%08X\n", hr);
        goto cleanup;
    }

    hr = pNewDomainThunk->QueryInterface(__uuidof(_AppDomain), (void**)&spTempDomain);
    if (FAILED(hr) || !spTempDomain)
    {
        printf("[!] QI _AppDomain: 0x%08X\n", hr);
        goto cleanup;
    }

    if (asmBytes.empty())
    {
        printf("[!] asmBytes empty\n");
        goto cleanup;
    }

    saAsm = BytesToSA(asmBytes.data(), asmBytes.size());
    if (!saAsm)
    {
        printf("[!] BytesToSA failed\n");
        goto cleanup;
    }

    hr = spTempDomain->Load_3(saAsm, &spAsm);
    SafeArrayDestroy(saAsm);
    saAsm = nullptr;

    if (FAILED(hr) || !spAsm)
    {
        printf("[!] Load_3: 0x%08X\n", hr);
        goto cleanup;
    }

    hr = spAsm->get_EntryPoint(&entry);
    if (FAILED(hr) || !entry)
    {
        printf("[!] get_EntryPoint: 0x%08X\n", hr);
        goto cleanup;
    }

    numArgs = static_cast<LONG>(args.size());

    saStrs = SafeArrayCreateVector(VT_BSTR, 0, static_cast<ULONG>(numArgs));
    if (!saStrs)
    {
        printf("[!] SafeArrayCreateVector(string[]) failed\n");
        goto cleanup;
    }

    for (LONG i = 0; i < numArgs; ++i)
    {
        const std::string& s = args[static_cast<size_t>(i)];
        std::wstring w = utf8_to_wide(s);

        printf("  args[%ld]: %ls\n", i, w.c_str());

        BSTR b = SysAllocStringLen(w.data(), static_cast<UINT>(w.size()));
        if (!b)
        {
            printf("[!] SysAllocStringLen failed at %ld\n", i);
            goto cleanup;
        }

        HRESULT hrPut = SafeArrayPutElement(saStrs, &i, b);

        SysFreeString(b);

        if (FAILED(hrPut))
        {
            printf("[!] SafeArrayPutElement arg %ld: 0x%08X\n", i, hrPut);
            goto cleanup;
        }
    }

    VariantInit(&vtStrs);
    vtStrs.vt = VT_ARRAY | VT_BSTR;
    vtStrs.parray = saStrs;

    saParams = SafeArrayCreateVector(VT_VARIANT, 0, 1);
    if (!saParams)
    {
        printf("[!] SafeArrayCreateVector(object[]) failed\n");
        goto cleanup;
    }

    {
        LONG idx = 0;
        HRESULT hrPutParam = SafeArrayPutElement(saParams, &idx, &vtStrs);
        if (FAILED(hrPutParam))
        {
            printf("[!] SafeArrayPutElement params: 0x%08X\n", hrPutParam);
            goto cleanup;
        }
    }

    {
        VARIANT vtThis;
        VariantInit(&vtThis);

        hr = entry->Invoke_3(vtThis, saParams, &vtRet);
    }

    if (FAILED(hr))
    {
        printf("[!] EntryPoint Invoke: 0x%08X\n", hr);
        goto cleanup;
    }

    if (vtRet.vt == VT_I4)
    {
        printf("[+] Return code: %ld\n", vtRet.lVal);
    }

    ok = TRUE;

cleanup:
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
