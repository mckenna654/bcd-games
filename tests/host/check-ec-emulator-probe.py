#!/usr/bin/env python3
"""Check Wine's integration fallback against the pinned emulator's real probe.

Compiles the unmodified FEX assembly prefix and exercises the production Wine
helper under ASan/UBSan. Does not execute iOS or replace the device regression.
"""
import os
from pathlib import Path
import struct
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
source = (root / 'wine/dlls/ntdll/signal_arm64ec.c').read_text()
start = source.index('static BOOL recover_emulator_code_probe(')
helper = source[start:source.index('\n}', start) + 2]
start = source.index('static BOOL emulator_probe_recovery_enabled(')
gate = source[start:source.index('\n}', start) + 2]
assembly = (root / 'FEX/Source/Windows/ARM64EC/Module.S').read_text()
# Read the existing optional probe unchanged; substitute only the external
# branch destination so it can assemble independently for this fixture.
start = assembly.index('  ldr x16, [x9]')
end = assembly.index('  add x17, x9, x16', start)
prefix = assembly[start:end].replace('ios_ffs_no_bypass', 'fixture_end')

with tempfile.TemporaryDirectory() as tmp:
    directory = Path(tmp)
    asm = directory / 'prefix.S'
    obj = directory / 'prefix.o'
    asm.write_text('.text\n.global probe\nprobe:\n' + prefix + 'fixture_end:\nret\n')
    subprocess.run([os.environ.get('CLANG', 'clang'), '--target=aarch64-linux-gnu',
                    '-c', str(asm), '-o', str(obj)], check=True)
    data = obj.read_bytes()
    assert data[:6] == b'\x7fELF\x02\x01'
    section_offset, = struct.unpack_from('<Q', data, 40)
    section_size, section_count, names_index = struct.unpack_from('<HHH', data, 58)
    names_header = section_offset + names_index * section_size
    names_offset, names_size = struct.unpack_from('<QQ', data, names_header + 24)
    names = data[names_offset:names_offset + names_size]
    text = None
    for index in range(section_count):
        at = section_offset + index * section_size
        name_index, = struct.unpack_from('<I', data, at)
        if names[name_index:].split(b'\0', 1)[0] == b'.text':
            offset, size = struct.unpack_from('<QQ', data, at + 24)
            text = data[offset:offset + size]
    assert text is not None and len(text) == 52, 'Optional FFS probe layout changed'
    words = struct.unpack('<13I', text)
    code = ','.join(hex(word) for word in words)
    program = r'''
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
typedef int BOOL;
typedef uint32_t ULONG;
typedef uintptr_t ULONG_PTR;
typedef uint16_t WCHAR;
typedef struct { WCHAR *Buffer; unsigned short Length, MaximumLength; } UNICODE_STRING;
static const char *setting = "1";
static void RtlInitUnicodeString(UNICODE_STRING *s, const wchar_t *name)
{ (void)s; assert(!wcscmp(name,L"MADEIRA_D2R_PROBE_RECOVERY")); }
static int RtlQueryEnvironmentVariable_U(void *env, UNICODE_STRING *name, UNICODE_STRING *value)
{
    (void)env; (void)name;
    if (!setting || strlen(setting)*sizeof(WCHAR) > value->MaximumLength) return -1;
    value->Length=strlen(setting)*sizeof(WCHAR);
    for (unsigned i=0;i<strlen(setting);i++) value->Buffer[i]=setting[i];
    return 0;
}
#define TRUE 1
#define FALSE 0
#define ARRAY_SIZE(a) (sizeof(a)/sizeof((a)[0]))
#define STATUS_ACCESS_VIOLATION 0xc0000005u
typedef struct { uint32_t ExceptionCode, NumberParameters; uintptr_t ExceptionInformation[2]; } EXCEPTION_RECORD;
typedef struct { uint64_t Pc, Lr, X9, X10, X11, preserved[48]; } ARM64_NT_CONTEXT;
static ULONG dispatcher[] = { WORDS };
static void *ios_exit_to_x64 = dispatcher, *ios_dispatch_jump = (void *)0x8000;
static void *p_ios_jit_reverse_translate_addr = (void *)1, *pBeginSimulation = (void *)1;
static struct { int InSimulation; } area;
static int have_area = 1, is_ec;
static void *get_arm64ec_cpu_area(void) { return have_area ? &area : NULL; }
#define get_arm64ec_cpu_area() ((typeof(&area))get_arm64ec_cpu_area())
static int RtlIsEcCode(ULONG_PTR p) { (void)p; return is_ec; }
/* Keep genuine host pointers intact; mark artificial aliases in the top bit. */
#define ALIAS (UINT64_C(1) << 63)
static void *xlate_ios_jit_rev(void *p) { return (void *)((uintptr_t)p & ~ALIAS); }
static void *xlate_ios_jit(void *p) { return (void *)((uintptr_t)p | ALIAS); }
''' .replace('WORDS', code) + gate + helper + r'''
static EXCEPTION_RECORD av = { STATUS_ACCESS_VIOLATION, 2, {0, 0x10000} };
static ARM64_NT_CONTEXT initial(unsigned index)
{
    ARM64_NT_CONTEXT c;
    memset(&c, 0xa5, sizeof(c));
    c.Pc = (uintptr_t)&dispatcher[index]; c.Lr = 0x4000; c.X9 = 0x10000;
    return c;
}
static void rejected(EXCEPTION_RECORD rec, ARM64_NT_CONTEXT c)
{
    ARM64_NT_CONTEXT before = c;
    assert(!recover_emulator_code_probe(&rec, &c));
    assert(!memcmp(&before, &c, sizeof(c)));
}
int main(void)
{
    const unsigned indexes[] = {0,7,11}, offsets[] = {0,8,10}, lengths[] = {8,2,4};
    ARM64_NT_CONTEXT c, expected;
    EXCEPTION_RECORD rec;
    for (unsigned n=0;n<3;n++)
    {
        for (unsigned alias=0;alias<2;alias++)
        for (unsigned byte=0;byte<lengths[n];byte++)
        {
            c=initial(indexes[n]); if (alias) c.Pc |= ALIAS;
            expected=c; expected.Pc=(uintptr_t)ios_dispatch_jump | ALIAS;
            rec=av; rec.ExceptionInformation[1]=c.X9+offsets[n]+byte;
            assert(recover_emulator_code_probe(&rec,&c));
            assert(!memcmp(&c,&expected,sizeof(c)));
        }
        c=initial(indexes[n]); rec=av;
        rec.ExceptionInformation[1]=c.X9+offsets[n]-1; rejected(rec,c);
        rec.ExceptionInformation[1]=c.X9+offsets[n]+lengths[n]; rejected(rec,c);
    }
    puts("PASS: all three target reads, including cross-page fault bytes and PE/RX aliases, preserve every register except PC");
    for (unsigned n=0;n<ARRAY_SIZE(dispatcher);n++)
        if (n!=0 && n!=7 && n!=11) rejected(av,initial(n));
    c=initial(0); c.Pc+=2; rejected(av,c);
    c=initial(0); c.Pc=0x9000; rejected(av,c);
    for (unsigned n=0;n<12;n++)
    {
        ULONG saved=dispatcher[n]; dispatcher[n]^=1;
        rejected(av,initial(0)); dispatcher[n]=saved;
    }
    ULONG saved=dispatcher[6]; dispatcher[6]^=32; rejected(av,initial(0)); dispatcher[6]=saved;
    dispatcher[6]|=0x800000; rejected(av,initial(0)); dispatcher[6]=saved;
    puts("PASS: unrelated PCs, misaligned PCs, changed instructions and incompatible branches are rejected");
    const char *disabled[] = {NULL,"","0","00","01","10","true"," 1"};
    for (unsigned n=0;n<ARRAY_SIZE(disabled);n++)
    { setting=disabled[n]; rejected(av,initial(0)); }
    setting="1";
    puts("PASS: new recovery defaults off and requires the exact per-game opt-in value 1");
    rec=av; rec.ExceptionCode=0x80000001; rejected(rec,initial(0));
    rec=av; rec.ExceptionCode=0xc000001d; rejected(rec,initial(0));
    rec=av; rec.NumberParameters=1; rejected(rec,initial(0));
    rec=av; rec.ExceptionInformation[0]=1; rejected(rec,initial(0));
    rec.ExceptionInformation[0]=8; rejected(rec,initial(0));
    c=initial(0); c.Lr=0; rejected(av,c); c.Lr=2; rejected(av,c);
    c=initial(0); c.X9=UINT64_C(1)<<39; rejected(av,c);
    area.InSimulation=1; rejected(av,initial(0)); area.InSimulation=0;
    have_area=0; rejected(av,initial(0)); have_area=1;
    is_ec=1; rejected(av,initial(0)); is_ec=0;
    pBeginSimulation=NULL; rejected(av,initial(0)); pBeginSimulation=(void *)1;
    p_ios_jit_reverse_translate_addr=NULL; rejected(av,initial(0)); p_ios_jit_reverse_translate_addr=(void *)1;
    ios_exit_to_x64=NULL; rejected(av,initial(0)); ios_exit_to_x64=dispatcher;
    ios_dispatch_jump=NULL; rejected(av,initial(0)); ios_dispatch_jump=(void *)0x8000;
    puts("PASS: guard/write/execute faults, emulated/native EC targets and uninitialised/non-iOS paths remain exceptions");
}
'''
    c = directory / 'test.c'
    exe = directory / 'test'
    c.write_text(program)
    # The IPA workflow puts LLVM-Mingw first on PATH. Its clang can assemble
    # AArch64 above, but does not ship the host ASan/UBSan runtime. Use the
    # native compiler, as the other host fixtures do; keep sanitizers enabled.
    subprocess.run([os.environ.get('CC', 'cc'), '-std=gnu11', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', str(c), '-o', str(exe)], check=True)
    subprocess.run([str(exe)], check=True)

assert 'ios_exit_to_x64 = __os_arm64x_dispatch_call_no_redirect;' in source
assert 'ios_dispatch_jump = __os_arm64x_dispatch_fptr;' in source
assert 'if (recover_emulator_code_probe( rec, &probe_ctx ))' in source
assert '[ec-emulator-probe-fallback]' in source
print('PASS: exported dispatcher registration and native continuation recovery are wired into Wine')

# Exercise the unmodified exported fallback itself when the existing emulator
# test dependency is available. Targets are deliberately outside mapped memory:
# any attempt to inspect their bytes makes this execution fail.
import fexstub_emu as emu
if emu.missing():
    print('SKIP: DispatchJump execution needs ' + emu.missing())
else:
    body, data, symbols, _ = emu.link(emu.assemble(assembly))
    for target in (0x7028850000, 0x12448f3d0, 0x12448ffff):
        memory = emu.blank_memory()
        memory[emu.DATA][:len(data)] = data
        def put(base, offset, fmt, value):
            struct.pack_into(fmt, memory[base], offset, value)
        put(emu.TSD, 0x898, '<Q', emu.TEB)
        put(emu.TEB, 0x1788, '<Q', emu.CPUAREA)
        put(emu.TEB, 0x60, '<Q', emu.TEB + 0x1000)
        put(emu.TEB, 0x1000 + 0x368, '<Q',
            (emu.NATIVE - ((target >> 18) << 3)) % (1 << 64))
        put(emu.NATIVE, 0, '<Q', 0)
        stop = emu.STUBS + 0x800
        put(emu.CPUAREA, 0x40, '<Q', stop)
        registers = [0x5000 + r for r in range(31)]
        registers[9] = target
        sp = emu.STACK + 0x8000
        state = {'mem': memory, 'regs': registers, 'sp': sp}
        result = emu.run(body, data, symbols['DispatchJump'], state,
                         {stop, symbols['ExitFunctionEC']})
        assert result[0] == stop and result[1][9] == target
        assert result[1][31] == sp - 8 and result[3][emu.CPUAREA][0] == 1
        assert struct.unpack_from('<Q', result[3][emu.STACK], sp - 8 - emu.STACK)[0] == registers[30]
        assert all(result[1][r] == registers[r] for r in range(31) if r not in (16, 17))
    print('PASS: actual DispatchJump reaches emulation without target reads, preserving arguments and one return-address push')
