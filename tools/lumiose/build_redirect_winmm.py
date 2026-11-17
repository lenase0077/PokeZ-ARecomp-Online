"""Generate winmm.dll export forwarding stubs and compile winmm.dll using Zig."""
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]


def read_winmm_exports(dll_path: Path):
    pe = dll_path.read_bytes()
    e_lfanew = struct.unpack_from('<I', pe, 0x3C)[0]
    num_sec = struct.unpack_from('<H', pe, e_lfanew + 6)[0]
    opt_sz = struct.unpack_from('<H', pe, e_lfanew + 20)[0]
    exp_rva, _ = struct.unpack_from('<II', pe, e_lfanew + 24 + 112)
    sec_off = e_lfanew + 24 + opt_sz

    def rva2off(rva):
        for i in range(num_sec):
            o = sec_off + i * 40
            vsz, va, rsz, ra = struct.unpack_from('<IIII', pe, o + 8)
            if va <= rva < va + max(vsz, rsz):
                return ra + (rva - va)
        raise ValueError(f'RVA 0x{rva:x} not mapped')

    off = rva2off(exp_rva)
    _, _, _, _, base, nfunc, nname, addr_rva, name_rva, ord_rva = struct.unpack_from('<IIIIIIIIII', pe, off)
    addr_off = rva2off(addr_rva)
    name_off = rva2off(name_rva)
    ord_off = rva2off(ord_rva)

    by_ord = {}
    for i in range(nfunc):
        rva = struct.unpack_from('<I', pe, addr_off + i * 4)[0]
        if rva:
            by_ord[base + i] = None

    for i in range(nname):
        nrva = struct.unpack_from('<I', pe, name_off + i * 4)[0]
        ordi = struct.unpack_from('<H', pe, ord_off + i * 2)[0]
        s = rva2off(nrva)
        end = pe.index(b'\x00', s)
        by_ord[base + ordi] = pe[s:end].decode('ascii')

    return [(ord_num, by_ord[ord_num]) for ord_num in sorted(by_ord)]


def emit_generated_sources(exports, out_dir: Path):
    inc_lines = [
        f'static const WinmmExportEntry g_winmm_exports[] = {{',
    ]
    def_lines = [
        'LIBRARY winmm.dll',
        'EXPORTS',
    ]
    asm_lines = [
        '.text',
        '.extern g_winmm_fwd',
    ]

    for idx, (ord_num, name) in enumerate(exports):
        sym = f'lumiose_winmm_fwd_{idx}'
        c_name = f'"{name}"' if name is not None else 'NULL'
        inc_lines.append(f'    {{ {c_name}, {ord_num} }},')
        if name is not None:
            def_lines.append(f'    {name} = {sym} @{ord_num}')
        else:
            def_lines.append(f'    {sym} @{ord_num} NONAME')
        asm_lines.append(f'.globl {sym}')
        asm_lines.append(f'.def {sym}; .scl 2; .type 32; .endef')
        asm_lines.append(f'{sym}:')
        asm_lines.append(f'    movq g_winmm_fwd+{idx * 8}(%rip), %rax')
        asm_lines.append('    testq %rax, %rax')
        asm_lines.append('    jz 1f')
        asm_lines.append('    jmp *%rax')
        asm_lines.append('1:')
        asm_lines.append('    xorl %eax, %eax')
        asm_lines.append('    ret')

    inc_lines.append('};')
    inc_lines.append(f'static const size_t g_winmm_export_count = {len(exports)};')

    inc_path = out_dir / 'redirect_winmm_table.inc'
    def_path = out_dir / 'redirect_winmm.def'
    asm_path = out_dir / 'redirect_winmm_stubs.S'
    inc_path.write_text('\n'.join(inc_lines) + '\n', encoding='utf-8')
    def_path.write_text('\n'.join(def_lines) + '\n', encoding='utf-8')
    asm_path.write_text('\n'.join(asm_lines) + '\n', encoding='utf-8')
    return inc_path, def_path, asm_path


def _find_zig_root() -> Path:
    candidates = []
    env_dir = os.environ.get('LUMIOSE_ZIG_DIR', '').strip()
    if env_dir:
        candidates.append(Path(env_dir))
    candidates.extend([ROOT / 'zig', ROOT / 'build' / 'zig-slim', ROOT / 'build' / 'zig'])
    for d in candidates:
        if (d / 'zig.exe').is_file():
            return d
    which = shutil.which('zig')
    if which:
        return Path(which).resolve().parent
    raise FileNotFoundError(f'Zig compiler not found in {[str(c) for c in candidates]}')


def build_dll(output_path: Path | None = None):
    if output_path is None:
        output_path = ROOT / 'winmm.dll'
    zig_root = _find_zig_root()
    zig = zig_root / 'zig.exe'
    if not zig.is_file():
        zig = Path(shutil.which('zig') or zig)

    sys_winmm = Path(os.environ.get('SystemRoot', r'C:\Windows')) / 'System32' / 'winmm.dll'
    if not sys_winmm.is_file():
        raise FileNotFoundError(f'System winmm.dll not found at {sys_winmm}')

    exports = read_winmm_exports(sys_winmm)
    c_src = HERE / 'redirect_winmm.c'
    zig_env = os.environ.copy()
    if (zig_root / 'lib').is_dir():
        zig_env['ZIG_LIB_DIR'] = str(zig_root / 'lib')
    zig_rt = zig_root / 'rt'

    with tempfile.TemporaryDirectory(prefix='winmm-build-') as tmp:
        tmp_dir = Path(tmp)
        _, def_path, asm_path = emit_generated_sources(exports, tmp_dir)
        c_obj = tmp_dir / 'redirect_winmm.o'
        asm_obj = tmp_dir / 'redirect_winmm_stubs.o'
        stage_out = tmp_dir / 'winmm.dll'

        for src, obj, extra in (
            (c_src, c_obj, ['-Os', '-ffreestanding', '-fno-builtin', '-Wall', '-Wextra', '-I', str(tmp_dir)]),
            (asm_path, asm_obj, []),
        ):
            cmd = [str(zig), 'cc', '-target', 'x86_64-windows-gnu', *extra, '-c', str(src), '-o', str(obj)]
            res = subprocess.run(cmd, env=zig_env, capture_output=True, text=True)
            if res.returncode != 0:
                raise RuntimeError(f'Failed to compile {src.name}:\n{res.stdout}\n{res.stderr}')

        lib_path = zig_rt
        if not (zig_rt / 'kernel32.lib').is_file():
            kdef = tmp_dir / 'kernel32.def'
            kdef.write_text(
                'LIBRARY KERNEL32.dll\nEXPORTS\n'
                ' DisableThreadLibraryCalls\n GetSystemDirectoryW\n LoadLibraryW\n LoadLibraryA\n FreeLibrary\n'
                ' GetModuleHandleW\n GetModuleHandleA\n GetProcAddress\n GetEnvironmentVariableA\n'
                ' InitOnceExecuteOnce\n InitializeCriticalSection\n EnterCriticalSection\n LeaveCriticalSection\n'
                ' DeleteCriticalSection\n VirtualProtect\n GetTickCount64\n OutputDebugStringA\n',
                encoding='utf-8',
            )
            subprocess.run(
                [str(zig), 'dlltool', '-m', 'i386:x86-64', '-d', str(kdef), '-l', str(tmp_dir / 'kernel32.lib')],
                env=zig_env,
                check=True,
            )
            lib_path = tmp_dir

        link_cmd = [
            str(zig), 'lld-link',
            '-NOLOGO',
            '-MACHINE:X64',
            '-DLL',
            '-DYNAMICBASE',
            '-NXCOMPAT',
            '-NOIMPLIB',
            '-ENTRY:DllMain',
            '-LIBPATH:' + str(lib_path),
            '-DEF:' + str(def_path),
            '-OUT:' + str(stage_out),
            str(c_obj),
            str(asm_obj),
            'kernel32.lib',
        ]
        res = subprocess.run(link_cmd, env=zig_env, capture_output=True, text=True)
        if res.returncode != 0:
            raise RuntimeError(f'Failed to link winmm.dll:\n{res.stdout}\n{res.stderr}')
        shutil.copy2(stage_out, output_path)
    return output_path, len(exports)


if __name__ == '__main__':
    out = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else None
    built, count = build_dll(out)
    print(f'Built {built} ({built.stat().st_size} bytes, {count} winmm exports forwarded)')
