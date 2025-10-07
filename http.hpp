#pragma once
#include <windows.h>
#include <winhttp.h>
#include <iostream>
#include <vector>
#include <string>
#pragma comment(lib, "winhttp.lib")


class Client {
public:
    const std::string server;
    const int port;
    const bool useTls;

    Client(const std::string& server, int port, bool useTls);

    std::string Get(const std::string& path);
};
