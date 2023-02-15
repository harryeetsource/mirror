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
#include <iostream>

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
void scan_process_memory(HANDLE process, const TCHAR* const dumpFilePath, DWORD start_address, DWORD end_address, ThreadPool& thread_pool)
{
    // Divide the memory space into chunks and assign each chunk to a worker thread
    DWORD chunk_size = (end_address - start_address) / 4;
    for (DWORD address = start_address; address < end_address; address += chunk_size)
    {
        thread_pool.enqueue(scan_process_memory_chunk, process, (void*)dumpFilePath, address);

    }
}

int _tmain(int argc, TCHAR* argv[]) {
    if (argc < 2) {
        std::cerr << "Usage: mirror <dump_file_path>\n";
        return 1;
    }

   // Convert command-line argument to dump file path to wide string
    TCHAR dumpFilePath[MAX_PATH];
    size_t size = strlen(argv[1]) + 1;
    MultiByteToWideChar(CP_UTF8, 0, argv[1], -1, reinterpret_cast<LPWSTR>(dumpFilePath), size);



    // Get system information
    SYSTEM_INFO system_info;
    GetSystemInfo(&system_info);

    // Calculate memory chunk size
    size_t chunk_size = 256 * 1024 * 1024;  // 256 MB

    // Create a thread pool with 8 worker threads
    ThreadPool thread_pool(8);

    // Iterate over all memory chunks and scan them in parallel
    uintptr_t start_address = reinterpret_cast<uintptr_t>(system_info.lpMinimumApplicationAddress);
    uintptr_t end_address = reinterpret_cast<uintptr_t>(system_info.lpMaximumApplicationAddress);
    while (start_address < end_address) {
        uintptr_t chunk_end_address = start_address + chunk_size;
        if (chunk_end_address > end_address) {
            chunk_end_address = end_address;
        }
        scan_process_memory(GetCurrentProcess(), dumpFilePath, start_address, chunk_end_address, thread_pool);
        start_address = chunk_end_address;
    }

    return 0;
}






