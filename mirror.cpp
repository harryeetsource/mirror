// Step 1: Include necessary headers
#include <Windows.h>
#include <Psapi.h>
#include <DbgHelp.h>
#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <mutex>
#include <chrono>
#include <fstream>

// Step 2: Define the signature of the thread function
void GenerateMemoryDump(DWORD processId, const std::wstring& outputFileName, int* progress, std::mutex* mutex);

int main(int argc, char* argv[])
{
    // Step 3: Parse command line arguments
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <output_file>" << std::endl;
        return 1;
    }

    std::wstring outputFileName = std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>>().from_bytes(argv[1]);

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
            threads.push_back(std::thread(GenerateMemoryDump, processId, outputFileName, &progress, &mutex));
        }
    }

    // Step 8: Wait for all threads to complete
    for (std::thread& thread : threads) {
        thread.join();
    }

    // Step 9: Display a completion message
    std::cout << "Memory dumps have been generated in " << std::string(outputFileName.begin(), outputFileName.end()) << std::endl;

    return 0;
}

void GenerateMemoryDump(DWORD processId, const std::wstring& outputFileName, int* progress, std::mutex* mutex)
{
    // Step 10: Open a handle to the process
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (hProcess == nullptr) {
        return;
    }

    // Step 11: Create the output file name
    std::ofstream outfile(outputFileName, std::ios::out | std::ios::binary | std::ios::app);

    // Step 12: Create the memory dump
    BOOL success = MiniDumpWriteDump(hProcess, processId, outfile.handle(), MiniDumpWithFullMemory, NULL, NULL, NULL);
    if (success) {
        *mutex.lock();
        ++(*progress);
        std::wcout << L"[" << std::wstring(*progress / 10, L'#') << std::wstring(10 - *progress / 10, L' ') << L"] " << *progress << L"% complete" << std::endl;
        *mutex.unlock();
    }

CloseHandle(hFile);
CloseHandle(hProcess);

// Step 13: Lock the mutex and update the progress counter
{
    std::lock_guard<std::mutex> lock(*mutex);
    (*progress)++;
    double percentComplete = static_cast<double>(*progress) / numProcesses * 100;
    std::cout << "[" << std::string(percentComplete / 10, '#') << std::string(10 - percentComplete / 10, ' ') << "] " << static_cast<int>(percentComplete) << "% complete" << std::endl;
}
