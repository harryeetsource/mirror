// Step 1: Include necessary headers
#include <Windows.h>
#include <Psapi.h>
#include <DbgHelp.h>
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <codecvt>

// Step 2: Define the signature of the thread function
void GenerateMemoryDump(DWORD processId, const std::wstring& outputDirectory, int* progress, std::mutex* mutex);

int main(int argc, char* argv[])
{
    // Step 3: Parse command line arguments
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <output_directory>" << std::endl;
        return 1;
    }

    std::wstring outputDirectory = std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>>().from_bytes(argv[1]);

    // Step 4: Get the process IDs for all running processes
    DWORD processIds[1024], cbNeeded;
    if (!EnumProcesses(processIds, sizeof(processIds), &cbNeeded)) {
        std::cerr << "Failed to enumerate processes" << std::endl;
        return 1;
    }

    // Step 5: Determine how many process IDs were returned
    int numProcesses = cbNeeded / sizeof(DWORD);

    // Step 6: Create a progress counter and display a starting message
    int progress = 0;
    std::mutex mutex;
    std::cout << "Generating memory dumps for " << numProcesses << " processes..." << std::endl;

    // Step 7: Loop through the process IDs and create a thread for each process to write
    std::vector<std::thread> threads;
    for (int i = 0; i < numProcesses; i++) {
        DWORD processId = processIds[i];
        if (processId != 0) {
            threads.push_back(std::thread(GenerateMemoryDump, processId, outputDirectory, &progress, &mutex));
        }
    }

    // Step 8: Wait for all threads to complete
    for (std::thread& thread : threads) {
        thread.join();
    }

    // Step 9: Display a completion message
    std::cout << "Memory dumps have been generated in " << std::string(outputDirectory.begin(), outputDirectory.end()) << std::endl;

    return 0;
}

// Step 10: Define the GenerateMemoryDump function
void GenerateMemoryDump(DWORD processId, const std::wstring& outputDirectory, int* progress, std::mutex* mutex)
{
    // Step 11: Open a handle to the process
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (hProcess == nullptr) {
        return;
    }

    // Step 12: Get the process name
    WCHAR processName[MAX_PATH] = { 0 };
    DWORD processNameLength = MAX_PATH;
    QueryFullProcessImageNameW(hProcess, 0, processName, &processNameLength);
    std::wstring processNameStr(processName);

    // Step 13: Create the output file name
    std::wstring outputFileName = outputDirectory + L"\\" + std::to_wstring(processId) + L"_" + processNameStr.substr(processNameStr.rfind(L"\\") + 1) + L".dmp";

    // Step 14: Create the memory dump
    HANDLE hFile = CreateFileW(outputFileName.c_str(), GENERIC_WRITE, 0, NULL, CREATE
