#include "http.hpp"
#include <windows.h>
#include <winhttp.h>
#include <vector>
#include <iostream>
#include <string>

#pragma comment(lib, "winhttp.lib")

Client::Client(const std::string& server, int port, bool useTls)
    : server(server),
    port(port),
    useTls(useTls)
{
    std::cout << "(debug)--> server = " << this->server << std::endl;
    std::cout << "(debug)--> port   = " << this->port << std::endl;
    std::cout << "(debug)--> useTls = " << (this->useTls ? "true" : "false") << std::endl;
}

std::string Client::Get(const std::string& path)
{
    std::string err;

    std::cout << "(debug)--> GET " << path << std::endl;

    HINTERNET hSession = WinHttpOpen(
        L"Mozilla",
        WINHTTP_ACCESS_TYPE_NO_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0
    );

    if (!hSession)
    {
        return "Error creating session: " + std::to_string(GetLastError());
    }

    int defaultPort = this->useTls ? 443 : 80;

    int actualPort = this->port == 0 ? defaultPort : this->port;

    std::wstring hostW(this->server.begin(), this->server.end());

    HINTERNET hConnect = WinHttpConnect(
        hSession,
        hostW.c_str(),
        static_cast<INTERNET_PORT>(actualPort),
        0
    );

    if (!hConnect)
    {
        DWORD le = GetLastError();
        WinHttpCloseHandle(hSession);
        return "Error connecting: " + std::to_string(le);
    }

    LPCWSTR acceptTypes[] = { L"*/*", nullptr };

    std::wstring pathW(path.begin(), path.end());

    DWORD openFlags = this->useTls ? WINHTTP_FLAG_SECURE : 0;

    HINTERNET hRequest = WinHttpOpenRequest(
        hConnect,
        L"GET",
        pathW.c_str(),
        nullptr,
        WINHTTP_NO_REFERER,
        acceptTypes,
        openFlags
    );

    if (!hRequest)
    {
        DWORD le = GetLastError();
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "Error creating request: " + std::to_string(le);
    }

    if (this->useTls)
    {
        DWORD securityFlags = 0;
        DWORD size = sizeof(securityFlags);

        BOOL gotFlags = WinHttpQueryOption(
            hRequest,
            WINHTTP_OPTION_SECURITY_FLAGS,
            &securityFlags,
            &size
        );

        (void)gotFlags;

        securityFlags |= SECURITY_FLAG_IGNORE_UNKNOWN_CA;
        securityFlags |= SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
        securityFlags |= SECURITY_FLAG_IGNORE_CERT_CN_INVALID;
        securityFlags |= SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;

        BOOL setOk = WinHttpSetOption(
            hRequest,
            WINHTTP_OPTION_SECURITY_FLAGS,
            &securityFlags,
            sizeof(securityFlags)
        );

        if (!setOk)
        {
            DWORD le = GetLastError();
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return "Error setting security options: " + std::to_string(le);
        }
    }

    LPCWSTR headers = L"Accept: */*\r\n";

    BOOL sent = WinHttpSendRequest(
        hRequest,
        headers,
        static_cast<DWORD>(-1),
        WINHTTP_NO_REQUEST_DATA,
        0,
        0,
        0
    );

    if (!sent)
    {
        DWORD le = GetLastError();
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return "Error sending request: " + std::to_string(le);
    }

    BOOL recvd = WinHttpReceiveResponse(
        hRequest,
        nullptr
    );

    if (!recvd)
    {
        DWORD le = GetLastError();
        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return std::string("Error in ReceiveResponse: ") + std::to_string(le);
    }

    DWORD statusCode = 0;
    DWORD size = sizeof(statusCode);

    BOOL gotStatus = WinHttpQueryHeaders(
        hRequest,
        WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
        WINHTTP_HEADER_NAME_BY_INDEX,
        &statusCode,
        &size,
        WINHTTP_NO_HEADER_INDEX
    );

    (void)gotStatus;

    std::string response;

    for (;;)
    {
        DWORD bytesAvailable = 0;

        BOOL q = WinHttpQueryDataAvailable(
            hRequest,
            &bytesAvailable
        );

        if (!q)
        {
            break;
        }

        if (bytesAvailable == 0)
        {
            break;
        }

        std::vector<char> buffer;
        buffer.resize(bytesAvailable);

        DWORD bytesRead = 0;

        BOOL r = WinHttpReadData(
            hRequest,
            buffer.data(),
            bytesAvailable,
            &bytesRead
        );

        if (!r)
        {
            break;
        }

        if (bytesRead == 0)
        {
            break;
        }

        response.append(buffer.data(), bytesRead);
    }

    WinHttpCloseHandle(hRequest);
    WinHttpCloseHandle(hConnect);
    WinHttpCloseHandle(hSession);

    return response;
}
