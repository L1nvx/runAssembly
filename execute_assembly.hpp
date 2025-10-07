#define NOMINMAX

#include <windows.h>
#include <vector>
#include <cstdint>
#include <iostream>
#include <fstream>
#include <metahost.h>
#include <mscoree.h>
#include <string>
#include <cstdarg>
#include <thread>

#pragma comment(lib, "mscoree.lib")
#pragma comment(lib, "oleaut32.lib")
#pragma comment(lib, "comsuppw.lib")

#import "C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\mscorlib.tlb" \
    raw_interfaces_only high_property_prefixes("_get","_put","_putref") \
    rename("ReportEvent", "InteropServices_ReportEvent") auto_rename

using namespace mscorlib;

BOOL ExecuteAssembly(
    const std::vector<uint8_t>& asmBytes,
    const std::vector<std::string>& args
);
