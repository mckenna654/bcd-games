/* GPL-3.0-or-later with the Madeira Converter Exception (LICENSE-EXCEPTION.md).
 * Run in BCD, directly and as a child. The build script obtains the probe RVA
 * from this build's unstripped ntdll symbols; no production offsets are fixed.
 */
#include <windows.h>
#include <stdio.h>
#include <string.h>

#ifndef NTDLL_DATA_PROBE_RVA
#error Build with tools/build-ntdll-data-regression.py
#endif

extern ULONGLONG exception_ud2_site(ULONGLONG value);
extern ULONGLONG exception_int3_sites(ULONGLONG value);
extern unsigned char exception_int3_end[];
__asm__(".text\n"
        ".globl exception_ud2_site\n"
        "exception_ud2_site:\n"
        "ud2\n"
        "movq %rcx, %rax\n"
        "ret\n"
        ".globl exception_int3_sites\n"
        "exception_int3_sites:\n"
        ".rept 96\n"
        "int3\n"
        ".endr\n"
        ".globl exception_int3_end\n"
        "exception_int3_end:\n"
        "movq %rcx, %rax\n"
        "ret\n");

static const ULONGLONG cookie = 0x12345678abcdef01ULL;
static volatile LONG handled;
static volatile LONG breakpoints;

static LONG CALLBACK handler(EXCEPTION_POINTERS *p)
{
    if (p->ExceptionRecord->ExceptionCode == EXCEPTION_BREAKPOINT)
    {
        ULONG_PTR at = (ULONG_PTR)p->ExceptionRecord->ExceptionAddress;
        if (at < (ULONG_PTR)exception_int3_sites || at >= (ULONG_PTR)exception_int3_end ||
            p->ContextRecord->Rcx != cookie ||
            (p->ContextRecord->Rip != at && p->ContextRecord->Rip != at + 1))
            return EXCEPTION_CONTINUE_SEARCH;
        /* Accept either breakpoint context convention, resuming only after
         * the exact intentional one-byte trap in this test's code range. */
        p->ContextRecord->Rip = at + 1;
        InterlockedIncrement(&breakpoints);
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    if (p->ExceptionRecord->ExceptionCode != EXCEPTION_ILLEGAL_INSTRUCTION)
        return EXCEPTION_CONTINUE_SEARCH;
    if (p->ExceptionRecord->ExceptionAddress != (void *)exception_ud2_site ||
        p->ContextRecord->Rip != (DWORD64)exception_ud2_site ||
        p->ContextRecord->Rcx != cookie)
    {
        printf("FAIL: guest context addr=%p RIP=%llx RCX=%llx\n",
               p->ExceptionRecord->ExceptionAddress,
               (unsigned long long)p->ContextRecord->Rip,
               (unsigned long long)p->ContextRecord->Rcx);
        return EXCEPTION_CONTINUE_SEARCH;
    }
    p->ContextRecord->Rip += 2; /* skip only the intentional UD2 */
    InterlockedIncrement(&handled);
    return EXCEPTION_CONTINUE_EXECUTION;
}

static int check_exception(const char *phase)
{
    LONG before = handled;
    if (exception_ud2_site(cookie) != cookie || handled != before + 1)
    {
        printf("FAIL: exception continuation (%s)\n", phase);
        return 0;
    }
    printf("PASS: guest exception context and continuation (%s)\n", phase);
    return 1;
}

static int protect_probe(HMODULE ntdll, SIZE_T length)
{
    typedef LONG (NTAPI *protect_fn)(HANDLE, void **, SIZE_T *, ULONG, ULONG *);
    protect_fn protect = (protect_fn)(void *)GetProcAddress(ntdll, "NtProtectVirtualMemory");
    void *slot = (char *)ntdll + NTDLL_DATA_PROBE_RVA, *base = slot;
    SIZE_T size = length;
    ULONG old = 0, ignored;
    if (!protect || protect(GetCurrentProcess(), &base, &size, PAGE_READWRITE, &old)) return 0;
    /* A protect rounds its output to a page. Submit the original byte range
     * on restoration too, as a program patching an individual slot does. */
    base = slot;
    size = length;
    if (protect(GetCurrentProcess(), &base, &size, old, &ignored)) return 0;
    return 1;
}

static int run_test(void)
{
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    IMAGE_NT_HEADERS *nt;
    void *veh;
    int ok;
    if (!ntdll) return 0;
    nt = (void *)((char *)ntdll + ((IMAGE_DOS_HEADER *)ntdll)->e_lfanew);
    if (nt->OptionalHeader.SizeOfImage != NTDLL_IMAGE_SIZE ||
        NTDLL_DATA_PROBE_RVA > NTDLL_IMAGE_SIZE - sizeof(void *))
    {
        puts("FAIL: this probe must run with the ntdll it was built against");
        return 0;
    }
    veh = AddVectoredExceptionHandler(1, handler);
    if (!veh) return 0;
    ok = check_exception("before data protection change") &&
         protect_probe(ntdll, 8) && check_exception("after 8-byte data protection change") &&
         protect_probe(ntdll, 1) && check_exception("after 1-byte data protection change");
    if (ok)
    {
        LONG before = breakpoints;
        ok = exception_int3_sites(cookie) == cookie && breakpoints == before + 96;
        puts(ok ? "PASS: 96 distinct handled guest breakpoints" : "FAIL: guest breakpoint progress");
    }
    RemoveVectoredExceptionHandler(veh);
    return ok;
}

int main(int argc, char **argv)
{
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    char path[MAX_PATH], command[MAX_PATH + 32];
    DWORD result;
    setvbuf(stdout, NULL, _IONBF, 0);
    if (!run_test()) return 1;
    if (argc > 1 && !strcmp(argv[1], "--child"))
    {
        puts("ntdll-data-exception: child PASS");
        return 0;
    }
    if (!GetModuleFileNameA(NULL, path, sizeof(path))) return 1;
    snprintf(command, sizeof(command), "\"%s\" --child", path);
    si.cb = sizeof(si);
    if (!CreateProcessA(path, command, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
    {
        printf("FAIL: child creation error %lu\n", GetLastError());
        return 1;
    }
    result = WaitForSingleObject(pi.hProcess, 60000);
    if (result != WAIT_OBJECT_0)
    {
        puts("FAIL: child timed out");
        TerminateProcess(pi.hProcess, 1);
        result = 1;
    }
    else if (!GetExitCodeProcess(pi.hProcess, &result)) result = 1;
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    puts(result ? "ntdll-data-exception: FAIL" : "ntdll-data-exception: PASS");
    return result ? 1 : 0;
}
