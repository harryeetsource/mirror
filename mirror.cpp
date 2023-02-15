#include <Windows.h>
#include <iostream>
#include <vector>
#include <psapi.h>
#include <DbgHelp.h>
using namespace std;

// A function that generates a memory dump file for a specified process.
void GenerateMemoryDump(DWORD* processId)
{
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, *processId);
    if (hProcess == NULL) {
        cerr << "Error: Unable to open process with ID " << *processId << endl;
        return;
    }

    // Get the process name.
    WCHAR processName[MAX_PATH];
    if (GetModuleFileNameExW(hProcess, NULL, processName, MAX_PATH) == 0) {
        cerr << "Error: Unable to get process name for process with ID " << *processId << endl;
        CloseHandle(hProcess);
        return;
    }

    // Generate the memory dump file.
    HANDLE hFile = CreateFileW(processName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        cerr << "Error: Unable to create memory dump file for process with ID " << *processId << endl;
        CloseHandle(hProcess);
        return;
    }

    if (!MiniDumpWriteDump(hProcess, *processId, hFile, MiniDumpNormal, NULL, NULL, NULL)) {
        cerr << "Error: Unable to generate memory dump for process with ID " << *processId << endl;
        CloseHandle(hFile);
        CloseHandle(hProcess);
        return;
    }

    wcout << L"Generated memory dump for process with ID " << *processId << endl;

    CloseHandle(hFile);
    CloseHandle(hProcess);
}

int main()
{
    // Get the IDs of all processes.
    DWORD processes[1024];
    DWORD bytesReturned;
    if (!EnumProcesses(processes, sizeof(processes), &bytesReturned)) {
        cerr << "Error: Unable to enumerate processes" << endl;
        return 1;
    }

    // Calculate the number of processes.
    DWORD numProcesses = bytesReturned / sizeof(DWORD);

    // Create a thread pool to generate memory dumps.
    const DWORD poolSize = 8;
    HANDLE threadPool[poolSize];
    vector<DWORD> processIds;

    for (DWORD i = 0; i < numProcesses; i++) {
        processIds.push_back(processes[i]);
    }

    for (DWORD i = 0; i < poolSize; i++) {
        threadPool[i] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)GenerateMemoryDump, (LPVOID)&processIds[i], 0, NULL);
    }

    // Wait for all threads to finish.
    WaitForMultipleObjects(poolSize, threadPool, TRUE, INFINITE);

    // Clean up the thread pool.
    for (DWORD i = 0; i < poolSize; i++) {
        CloseHandle(threadPool[i]);
    }

    return 0;
}
