/*
KNetInjector
Written by Aleksander Krimsky
25 May 2017 - 06 Jan 2023
*/
//#define PSAPI_VERSION 1
#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <winternl.h>
#include <conio.h>
#pragma comment(lib, "ntdll")

void PrintGetLastError()
{
  DWORD errorMessageID = GetLastError();
  if (errorMessageID == 0)
    return;

  LPSTR messageBuffer = NULL;
  DWORD size = FormatMessageA(
    FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
    NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
    (LPSTR)&messageBuffer, 0, NULL);
  printf("GetLastError: %d\n", errorMessageID);
  if (messageBuffer)
  {
    printf("%s\n", messageBuffer);
    LocalFree(messageBuffer);
  }
}

enum ThreadControl { SUSPEND, RESUME };

void thread_control(DWORD processId, ThreadControl ctrl)
{
  HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  THREADENTRY32 threadEntry;
  threadEntry.dwSize = sizeof(THREADENTRY32);
  Thread32First(hThreadSnapshot, &threadEntry);
  do
  {
    if (threadEntry.th32OwnerProcessID == processId)
    {
      HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE,
        threadEntry.th32ThreadID);
      if (hThread)
      {
        if (ctrl == SUSPEND)
        {
          printf("Suspend thread: %d\n", threadEntry.th32ThreadID);
          SuspendThread(hThread);
        }
        else
        {
          printf("Resuming thread: %d\n", threadEntry.th32ThreadID);
          ResumeThread(hThread);
        }
        CloseHandle(hThread);
      }
    }
  } while (Thread32Next(hThreadSnapshot, &threadEntry));
  CloseHandle(hThreadSnapshot);
}

void GetPidForName(const char* name, int& pid)
{
  HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
  PROCESSENTRY32 entry;
  entry.dwSize = sizeof(PROCESSENTRY32);
  if (Process32First(snapshot, &entry) == TRUE)
  {
    while (Process32Next(snapshot, &entry) == TRUE)
    {
      if (strcmp(entry.szExeFile, name) == 0)
      {
        pid = entry.th32ProcessID;
        return;
      }
    }
  }
}


void ToggleRWXPageProtection(HANDLE hProcess, PVOID BaseAddress)
{
  PVOID CurrentAddress = BaseAddress;
  MEMORY_BASIC_INFORMATION mbi2;
  do
  {
    ZeroMemory(&mbi2, sizeof(mbi2));
    VirtualQueryEx(hProcess, (LPCVOID)CurrentAddress, &mbi2, sizeof(mbi2));
    if (mbi2.AllocationBase != BaseAddress)
      break;
    printf("Scanning: BaseAddr:%p, AllocAddr:%p, RegionSz:0x%lX, Current:0x%p, Protect: 0x%X\n",
      mbi2.BaseAddress, mbi2.AllocationBase, mbi2.RegionSize, CurrentAddress, mbi2.Protect);

    DWORD nextProtect = 0;
    if (mbi2.Protect == PAGE_EXECUTE_READ)
    {
      printf("Updating Current:0x%lX (0x%lX) to PAGE_EXECUTE_READWRITE (0x%X)\n",
        CurrentAddress, mbi2.RegionSize, PAGE_EXECUTE_READWRITE);
      nextProtect = PAGE_EXECUTE_READWRITE;
    }
    else if (mbi2.Protect == PAGE_EXECUTE_READWRITE ||
             mbi2.Protect == PAGE_EXECUTE_WRITECOPY) //No idea why post-load it does this
    {
      printf("Updating Current:0x%p (0x%lX) to PAGE_EXECUTE_READ (0x%lX)\n",
        CurrentAddress, mbi2.RegionSize, PAGE_EXECUTE_READ);
      nextProtect = PAGE_EXECUTE_READ;
    }
    else
      goto next_iter;
    DWORD oldProtect;
    if (VirtualProtectEx(hProcess,(LPVOID)CurrentAddress, mbi2.RegionSize, nextProtect, &oldProtect) == 0)
    {
      PrintGetLastError();
    }
  next_iter:
    intptr_t ptr_arith = (intptr_t)CurrentAddress;
    ptr_arith += mbi2.RegionSize;
    CurrentAddress = (PVOID)ptr_arith;
  } while (mbi2.AllocationBase == BaseAddress);
}

enum InjectStyle { NONE, INJECT_AFTER_LOAD, LOAD_AND_INJECT };
int main(int argc, char* argv[])
{
  bool wait_for_inject = true;
  bool rwx = false;
  int pid = 0;
  char* dllname = nullptr;
  char* exename = nullptr;
  char* args = nullptr;
  int argslength = 0;
  int dlllength = 0;
  int exelength = 0;
  InjectStyle style = InjectStyle::NONE;
  if (argc < 2)
  {
    printf("KNetInjector v1.1 written by Aleksander Krimsky - www.krimsky.net\n");
    printf("Arguments:\n");
    printf("-load <target.exe>\tLoads an executable for injection, safest approach\n");
    printf("-find <target.exe>\tFinds process by name for attaching\n");
    printf("-pid <pid>\tFinds process by pid for attaching\n");
    printf("-dll <dll>\t The dll to inject\n");
    printf("--rwx\tSets executable pages to RWX prior to dll injection, then resets\n");
    printf("--nowait\tDoes not wait for Dll to return before resuming program threads\n");
    return 0;
  }
  for (int i = 1; i < argc; ++i)
  {
    if (strcmp(argv[i], "-find") == 0)
    {
      style = InjectStyle::INJECT_AFTER_LOAD;
      GetPidForName(argv[i + 1], pid);
      if (pid == 0)
      {
        printf("Unable to find pid for: %s\n", argv[i + 1]);
        return 0;
      }
      ++i;
    }
    else if (strcmp(argv[i], "-pid") == 0)
    {
      style = InjectStyle::INJECT_AFTER_LOAD;
      pid = atoi(argv[i + 1]);
      if (pid == 0)
      {
        printf("The pid you entered is invalid\n");
        return 0;
      }
      ++i;
    }
    else if (strcmp(argv[i], "--rwx") == 0)
    {
      rwx = true;
    }
    else if (strcmp(argv[i], "-args") == 0)
    {
      argslength = strlen(argv[i + 1]);
      args = new char[argslength + 1];
      args[argslength] = 0;
      memcpy(args, argv[i + 1], argslength);
      ++i;
    }
    else if (strcmp(argv[i], "-dll") == 0)
    {
      dlllength = strlen(argv[i + 1]);
      dllname = new char[dlllength + 1];
      dllname[dlllength] = 0;
      memcpy(dllname, argv[i + 1], dlllength);
      ++i;
    }
    else if (strcmp(argv[i], "-load") == 0)
    {
      style = LOAD_AND_INJECT;
      exelength = strlen(argv[i + 1]);
      exename = new char[exelength + 1];
      exename[exelength] = 0;
      memcpy(exename, argv[i + 1], exelength);
      ++i;
    }
    else if (strcmp(argv[i], "--nowait") == 0)
    {
      wait_for_inject = false;
    }
  }

  if (dllname == nullptr || dlllength == 0)
  {
    printf("No dll was specified for injection, please use -dll <path>\n");
    return 0;
  }

  if (argslength > 0 && style != InjectStyle::LOAD_AND_INJECT)
    printf("Ignoring -args option, you can only use this with -load\n");

#if defined(_WIN64)
  printf("Running in 64-bit mode, ensure you are using a 64-bit dll and target\n");
#else
  printf("Running in 32-bit mode, ensure you are using a 32-bit dll and target\n");
#endif

  PROCESS_INFORMATION pi;
  PPEB threadContextPEBAddress = NULL;
  if (style == InjectStyle::LOAD_AND_INJECT)
  {
    if (exename == nullptr || exelength == 0)
    {
      printf("No exe name was specified with -load <target.exe>\n");
      return 0;
    }
    
    STARTUPINFOA si;
    ZeroMemory(&si, sizeof(STARTUPINFOA));
    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
    si.cb = sizeof(STARTUPINFOA);
    int size = argslength + exelength + 2;//space + null terminator
    char* cmd = new char[size];
    memset(cmd, 0, size);
    snprintf(cmd, size, "%s %s", exename, args);
    printf("cmd = %s\n", cmd);
    if (!CreateProcessA(NULL, cmd, NULL, NULL, false,
      CREATE_SUSPENDED, NULL, NULL, &si, &pi))
    {
      printf("CreateProcessA has failed: %s\n", exename);
      PrintGetLastError();
      return 0;
    }
    pid = pi.dwProcessId;
    printf("Created process %s with pid %d in suspend state\n", exename, pid);


    CONTEXT context;
    ZeroMemory(&context, sizeof(context));
    context.ContextFlags = CONTEXT_INTEGER;
    if (!GetThreadContext(pi.hThread, &context))
    {
      PrintGetLastError();
      return 0;
    }

#if defined(_WIN64)
    printf("(64-bit) GetThreadContext::Rdx 0x%zX\n", context.Rdx);
    threadContextPEBAddress = (PPEB)context.Rdx;
#else
    printf("(32-bit) GetThreadContext::Ebx 0x%X\n", context.Ebx);
    threadContextPEBAddress = (PPEB)context.Ebx;
#endif

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
  }

  if (pid == 0)
  {
    printf("No pid was specified please use -pid <pid> or -find <target.exe>\n");
    return 0;
  }

  HANDLE ProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
  if (ProcessHandle == NULL)
  {
    printf("Failed to open process with pid: %d\n", pid);
    PrintGetLastError();
    return 0;
  }
  if (style == InjectStyle::INJECT_AFTER_LOAD)
  {
    thread_control(pid, SUSPEND);
  }


  PVOID BaseAddress = NULL;
  PROCESS_BASIC_INFORMATION pbi;
  ZeroMemory(&pbi, sizeof(PROCESS_BASIC_INFORMATION));
  ULONG returnLength = 0;
  NtQueryInformationProcess(ProcessHandle, ProcessBasicInformation, &pbi,
    sizeof(PROCESS_BASIC_INFORMATION), &returnLength);
  printf("NtQueryInformationProcess::PebBaseAddress %p\n", pbi.PebBaseAddress);

  PPEB pebBaseAddress = NULL;
  if (threadContextPEBAddress != NULL)
  {
    if (pbi.PebBaseAddress == NULL)
    {
      printf("PROCESS_BASIC_INFORMATION has null entry value, defaulting to CONTEXT\n");
      pebBaseAddress = threadContextPEBAddress;
    }
    else if (threadContextPEBAddress != pbi.PebBaseAddress)
    {
      printf("PROCESS_BASIC_INFORMATION does not match CONTEXT, defaulting to PROCESS_BASIC_INFORMATION\n");
      pebBaseAddress = pbi.PebBaseAddress;
    }
    else
    {
      printf("PROCESS_BASIC_INFORMATION matches CONTEXT\n");
      pebBaseAddress = pbi.PebBaseAddress;
    }
  }
  else
  {
    if (pbi.PebBaseAddress == NULL)
    {
      printf("Both PROCESS_BASIC_INFORMATION and CONTEXT do not have an entry point\n");
      return 0;
    }
    else
    {
      printf("CONTEXT has null entry value, defaulting to PROCESS_BASIC_INFORMATION\n");
      pebBaseAddress = pbi.PebBaseAddress;
    }
  }

  printf("PEB Base Address: %p\n", pebBaseAddress);

  PEB peb;
  if (!ReadProcessMemory(ProcessHandle, pebBaseAddress, &peb, sizeof(PEB), NULL))
  {
    PrintGetLastError();
    return 0;
  }

  BaseAddress = peb.Reserved3[1];
  printf("Module Base Address (entry): %p\n", BaseAddress);


  HMODULE Kernel32Module = GetModuleHandle("kernel32.dll");
  if (Kernel32Module == NULL)
  {
    printf("Failed to get a module handle to kernel32.dll\n");
    PrintGetLastError();
    return 0;
  }

  //This works because kernel32.dll has the same virtual address for every
  //process on boot. Won't work statically since the virtual address will change
  FARPROC ProcAddress = GetProcAddress(Kernel32Module, "LoadLibraryA");
  if (ProcAddress == NULL)
  {
    printf("Failed to get process address for LoadLibraryA");
    PrintGetLastError();
    return 0;
  }

  LPVOID DllNameAddress = VirtualAllocEx(
    ProcessHandle, NULL, 1,
    MEM_COMMIT | MEM_RESERVE,
    PAGE_READWRITE
  );

  if (BaseAddress == NULL)
  {
    printf("Failed to allocate in target process\n");;
    PrintGetLastError();
    return 0;
  }

  BOOL WriteProcessMemoryResult = WriteProcessMemory(ProcessHandle,
    DllNameAddress, dllname, dlllength, NULL);
  if (WriteProcessMemoryResult == FALSE)
  {
    printf("Failed to WriteProcessMemory\n");
    PrintGetLastError();
    return 0;
  }

  printf("LoadLibraryA: %p\n", ProcAddress);
  printf("Dll Name: %p\n", DllNameAddress);
 
  if(rwx)
    ToggleRWXPageProtection(ProcessHandle, BaseAddress);

  //https://msdn.microsoft.com/en-us/library/aa964928.aspx
  HANDLE ThreadHandle = CreateRemoteThread(
    ProcessHandle, NULL, 0,
    (LPTHREAD_START_ROUTINE)ProcAddress,
    DllNameAddress, NULL, 0);

  if (ThreadHandle == NULL)
  {
    printf("Failed to create a remote thread in the target process.");
    PrintGetLastError();
    return 0;
  }

  if (wait_for_inject)
  {
    DWORD ThreadId = GetThreadId(ThreadHandle);
    printf("Waiting on thread used for injection: %d\n", ThreadId);
    WaitForSingleObject(ThreadHandle, INFINITE);
  }

  if (rwx)
    ToggleRWXPageProtection(ProcessHandle, BaseAddress);

  VirtualFreeEx(ProcessHandle, DllNameAddress, 0, MEM_RELEASE);
  thread_control(pid, RESUME);
  CloseHandle(ProcessHandle);

  printf("Successfully injected %s into process: %d\n", dllname, pid);
  printf("Press any key to exit...\n");
  _getch();
  return 1;
}