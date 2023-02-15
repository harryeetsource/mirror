#include <windows.h>
#include <dbghelp.h>
#include <vector>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <fstream>
#include <psapi.h>
#include <functional>
#include <future>
#include <queue>
#include <tchar.h>

#ifdef _WIN64
#pragma comment(lib, "dbghelp.lib")
#else
#pragma comment(lib, "dbghelp32.lib")
#endif

const DWORD kPageSize = 4096;

// Thread pool class
class ThreadPool {
public:
    explicit ThreadPool(size_t num_threads)
        : stop(false)
    {
        for (size_t i = 0; i < num_threads; ++i)
            workers.emplace_back(
                [this]
                {
                    for (;;)
                    {
                        std::function<void()> task;
                        {
                            std::unique_lock<std::mutex> lock(this->queue_mutex);
                            this->condition.wait(lock,
                                [this] { return this->stop || !this->tasks.empty(); });
                            if (this->stop && this->tasks.empty())
                                return;
                            task = std::move(this->tasks.front());
                            this->tasks.pop();
                        }
                        task();
                    }
                }
            );
    }

    ~ThreadPool()
    {
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            stop = true;
        }
        condition.notify_all();
        for (std::thread &worker : workers)
            worker.join();
    }

    template<class F, class... Args>
    auto enqueue(F&& f, Args&&... args)
        -> std::future<typename std::result_of<F(Args...)>::type>
    {
        using return_type = typename std::result_of<F(Args...)>::type;

        auto task = std::make_shared<std::packaged_task<return_type()>>(
            std::bind(std::forward<F>(f), std::forward<Args>(args)...)
            );

        std::future<return_type> res = task->get_future();
        {
            std::unique_lock<std::mutex> lock(queue_mutex);

            if (stop)
                throw std::runtime_error("enqueue on stopped ThreadPool");

            tasks.emplace([task](){ (*task)(); });
        }
        condition.notify_one();
        return res;
    }

private:
    std::vector<std::thread> workers;
    std::queue<std::function<void()>> tasks;

    std::mutex queue_mutex;
    std::condition_variable condition;
    bool stop;
};

// Function to create a dump file in the standard Windows format
bool CreateDumpFile(const TCHAR* dumpFilePath, DWORD processId)
{
    HANDLE hDumpFile = CreateFile(dumpFilePath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hDumpFile == INVALID_HANDLE_VALUE)
        return false;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (hProcess == NULL)
    {
        CloseHandle(hDumpFile);
        return false;
    }

    bool result = MiniDumpWriteDump(hProcess, processId, hDumpFile, MiniDumpWithFullMemory, NULL, NULL, NULL);

    CloseHandle(hProcess);
    CloseHandle(hDumpFile);

    return result;
}

// Function to scan a chunk of process memory and write it to dump file
void scan_process_memory_chunk(HANDLE process, HANDLE hDumpFile, DWORD address)
{
    if (address == 0)
        return;

    // Read a page of memory at a time and write it to the dump file
char buffer[kPageSize];
SIZE_T bytes_read;
if (ReadProcessMemory(process, reinterpret_cast<LPVOID>(static_cast<uintptr_t>(address)), buffer, kPageSize, &bytes_read))

{
    DWORD bytes_written;
    WriteFile(hDumpFile, buffer, bytes_read, &bytes_written, NULL);
}
}
// Function to scan process memory and write it to dump file
void scan_process_memory(HANDLE process, const TCHAR* dumpFilePath, DWORD start_address, DWORD end_address)
{
HANDLE hDumpFile = CreateFile(dumpFilePath, GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
if (hDumpFile == INVALID_HANDLE_VALUE)
return;
// Divide the memory space into chunks and assign each chunk to a worker thread
DWORD chunk_size = (end_address - start_address) / 4;
ThreadPool thread_pool(4);
for (DWORD address = start_address; address < end_address; address += chunk_size)
{
    thread_pool.enqueue(scan_process_memory_chunk, process, hDumpFile, address);
}

CloseHandle(hDumpFile);

// Create a dump file in the standard Windows format
CreateDumpFile(dumpFilePath, GetProcessId(process));
}
int main()
{
// Get the minimum and maximum memory addresses used by the process
SYSTEM_INFO system_info;
GetSystemInfo(&system_info);

uintptr_t start_address = reinterpret_cast<uintptr_t>(system_info.lpMinimumApplicationAddress);
uintptr_t end_address = reinterpret_cast<uintptr_t>(system_info.lpMaximumApplicationAddress);

TCHAR dumpFilePath[MAX_PATH];
GetModuleFileName(NULL, dumpFilePath, MAX_PATH);
_tcscat_s(dumpFilePath, MAX_PATH, _T(".dmp"));


scan_process_memory(GetCurrentProcess(), dumpFilePath, start_address, end_address);

return 0;
}
