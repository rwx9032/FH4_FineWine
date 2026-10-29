#!/usr/bin/env python3
"""Offline FH4 payload import and transactional CrossOver installation.

The tool never downloads anything. It validates locally supplied PE payloads,
patches a known CrossOver 26.3 kernelbase.dll deterministically, and installs
the Apple GPTK 4.x runtime selected by the user into a full application
snapshot. `check` is read-only; `install` and `rollback` are explicit.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent
PAYLOADS = ROOT / 'payloads'
SHA = {'d3d12.dll': 'bc9d107e70aeb7e401b77303896b17d53c274fd92415b181f58ace378fb81a44',
       'apd12.dll': 'f1bcaa4d79e4353e075e7f284ebcb2d44a1b0cb2aa88f01f6341dc3c518b976f',
       'kernelbase.dll': '313a9d07019422fe0f56a579667d005d756728e13b66329aaa15321d92b0f182'}
STOCK_D3D12 = 'bbda1c4e94ee70255c528c5689b28333ca9bece2d755ede7c4197977a534704f'
STOCK = 'ca72a76ce5770996cc9cba6989031a79eb1e63b6d9fca90d59eebab22e39191b'
EXPORTS = ['GetBehaviorValue','D3D12CreateDevice','D3D12GetDebugInterface','D3D12CoreCreateLayeredDevice',
           'D3D12CoreGetLayeredDeviceSize','D3D12CoreRegisterLayers','D3D12CreateRootSignatureDeserializer',
           'D3D12CreateVersionedRootSignatureDeserializer','D3D12EnableExperimentalFeatures',
           'D3D12SerializeRootSignature','D3D12SerializeVersionedRootSignature']
STUB = bytes.fromhex('56574885d27406c702010000004d85c97447418339397c324d85c0742d488b4424384885c07423498900488d352d0000004889c748c7c13900000066f3a541c7013900000031c05f5ec341c70139000000b87a0000005f5ec331c05f5ec3') + ('Microsoft.VCLibs.140.00_14.0.30704.0_x64__8wekyb3d8bbwe\0').encode('utf-16le')
CXR = Path('Contents/SharedSupport/CrossOver')
KB = Path('lib/wine/x86_64-windows/kernelbase.dll')
WIN = Path('lib64/apple_gptk/wine/x86_64-windows')
UNIX = Path('lib64/apple_gptk/wine/x86_64-unix')
EXT = Path('lib64/apple_gptk/external')
ALIAS_TARGET = '../../external/libd3dshared.dylib'
ENV = {'CX_GRAPHICS_BACKEND':'d3dmetal','HB_D3D12_REAL':'apd12.dll','HB_TSSHIM_FIX_WORLD_ENTRY':'1',
       'HB_TSSHIM_EXPLICIT_INPUT_OFFSETS':'1','D3DM_VENDOR_ID':'0x8086','D3DM_DEVICE_ID':'0x56a1'}
MARK_BEGIN = ';; ---- FH4 FineWine BEGIN ----'
MARK_END = ';; ---- FH4 FineWine END ----'
MANAGED = [WIN / 'd3d12.dll', WIN / 'apd12.dll', UNIX / 'apd12.so']
REG_SECTION = b'[Software\\\\Wine\\\\DllOverrides]'
REG_NAME = 'apd12'
REG_VALUE = 'builtin'


def digest(data): return hashlib.sha256(data).hexdigest()
def readhash(p): return digest(Path(p).read_bytes())
def require(test, msg):
    if not test: raise ValueError(msg)


def run(args):
    args = [str(x) for x in args]
    try:
        result = subprocess.run(args, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except subprocess.CalledProcessError as e:
        detail = (e.stderr or e.stdout or '').strip()
        raise ValueError('Command failed (%s): %s\n%s' % (e.returncode, ' '.join(args), detail[-2000:])) from e
    return result


def pe(data):
    require(len(data) > 0x40 and data[:2] == b'MZ', 'Not a PE file')
    def u16(o): return struct.unpack_from('<H', data, o)[0]
    def u32(o): return struct.unpack_from('<I', data, o)[0]
    p = u32(0x3c); require(p + 24 < len(data) and data[p:p+4] == b'PE\0\0', 'Invalid PE header')
    require(u16(p+4) == 0x8664 and u16(p+24) == 0x20b, 'Expected AMD64 PE32+')
    opt = p + 24; sec = opt + u16(p+20); sections = []
    for i in range(u16(p+6)):
        o = sec + 40*i; require(o + 40 <= len(data), 'Invalid section table')
        sections.append((data[o:o+8].split(b'\0')[0], u32(o+8), u32(o+12), u32(o+16), u32(o+20), o))
    def off(r, size=1):
        for _, vs, va, rs, raw, _ in sections:
            if va <= r and r + size <= va + rs and raw + r - va + size <= len(data): return raw + r - va
        raise ValueError('RVA outside raw section')
    ex = u32(opt+112); size = u32(opt+116); require(ex and size, 'No exports')
    o = off(ex, 40); ordinal = u32(o+16); nf = u32(o+20); nn = u32(o+24)
    require(nf < 100000 and nn <= nf, 'Invalid exports')
    fa = off(u32(o+28), nf*4); na = off(u32(o+32), nn*4); oa = off(u32(o+36), nn*2)
    names = {}
    for i in range(nn):
        n = off(u32(na + i*4)); end = data.find(b'\0', n)
        require(end >= 0, 'Invalid export string')
        idx = u16(oa + i*2); require(idx < nf, 'Invalid ordinal')
        name = data[n:end].decode('ascii'); r = u32(fa + idx*4)
        names[name] = (ordinal + idx, r, ex <= r < ex + size)
    return sections, off, names


def pe_imports(data):
    require(len(data) > 0x40 and data[:2] == b'MZ', 'Not a PE file')
    p = struct.unpack_from('<I', data, 0x3c)[0]
    rva, size = struct.unpack_from('<II', data, p + 24 + 120)
    if not rva: return []
    _, off, _ = pe(data); o = off(rva); names = []
    while True:
        _, _, _, name, _ = struct.unpack_from('<IIIII', data, o)
        if not name: break
        start = off(name); end = data.find(b'\0', start)
        require(end >= 0, 'Invalid import string')
        names.append(data[start:end].decode('ascii', 'replace')); o += 20
    return names


def coff_symbols(data):
    """Inventory COFF file and function symbols (names only; not source)."""
    p = struct.unpack_from('<I', data, 0x3c)[0]
    table = struct.unpack_from('<I', data, p + 12)[0]; count = struct.unpack_from('<I', data, p + 16)[0]
    if not table or not count: return [], []
    start = table + count * 18
    require(start + 4 <= len(data), 'Invalid COFF string table')
    size = struct.unpack_from('<I', data, start)[0]
    require(size >= 4 and start + size <= len(data), 'Truncated COFF string table')
    strings = data[start + 4:start + size]; files = []; functions = []; i = 0
    while i < count:
        o = table + i * 18; raw = data[o:o + 8]
        _, section, _, storage, aux = struct.unpack_from('<IhHBB', data, o + 8)
        if raw == b'.file\0\0\0':
            files.append(data[o + 18:o + 36].split(b'\0')[0].decode('latin1'))
        else:
            if raw[:4] == b'\0\0\0\0':
                name = strings[struct.unpack_from('<I', raw, 4)[0]:].split(b'\0')[0].decode('latin1')
            else:
                name = raw.split(b'\0')[0].decode('latin1')
            if section > 0 and storage == 2: functions.append(name)
        i += 1 + aux
    return files, functions


def inspect_payload(path):
    p = existing(path, 'Payload file'); data = p.read_bytes()
    sections, _, exports = pe(data)
    files, functions = coff_symbols(data)
    return {'path': str(p), 'sha256': digest(data), 'size': len(data), 'sections': len(sections),
            'imports': pe_imports(data), 'exports': len(exports),
            'export_ordinals': {n: exports[n][0] for n in sorted(exports)},
            'coff_modules': files, 'coff_symbols': len(functions),
            'coff_functions': sorted(set(functions))}


def macho_archs(data):
    be = struct.unpack_from('>I', data, 0)[0]; le = struct.unpack_from('<I', data, 0)[0]
    if be in (0xcafebabe, 0xcafebabf):
        count = struct.unpack_from('>I', data, 4)[0]; archs = []; off = 8
        for i in range(count):
            archs.append(struct.unpack_from('>I', data, off)[0]); off += 20
        return archs
    if le in (0xfeedface, 0xfeedfacf): return [struct.unpack_from('<I', data, 4)[0]]
    if be in (0xfeedface, 0xfeedfacf): return [struct.unpack_from('>I', data, 4)[0]]
    return []


def validate_payload(name, data):
    require(digest(data) == SHA[name], name + ' SHA-256 mismatch')
    _, _, exports = pe(data)
    if name != 'kernelbase.dll':
        require(all(exports.get(n, (None, None, True))[0] == 100+i and not exports[n][2] for i, n in enumerate(EXPORTS)) and len(exports) == 11,
                name + ' export/ordinal mismatch')
    else:
        require(exports.get('GetPackagesByPackageFamily') == (500, 0x2ce30, False), 'Unexpected kernelbase export')


def patch_kernel(data):
    require(digest(data) == STOCK, 'Unsupported stock kernelbase SHA-256')
    sections, off, exports = pe(data)
    require(exports.get('GetPackagesByPackageFamily') == (500, 0x2ce30, False), 'Unexpected kernelbase export')
    entry = off(0x2ce30, 8); require(data[entry:entry+8] == bytes.fromhex('488da42400000000'), 'Patch signature mismatch')
    sec = next((s for s in sections if s[0] == b'.data'), None); require(sec is not None, 'No .data')
    _, vs, va, rs, raw, h = sec; target = va + vs; cave = raw + vs
    require(target == 0x8bf20 and cave == 0x8ab20 and rs-vs >= len(STUB) and cave+len(STUB) <= len(data), 'Unexpected cave')
    require(data[cave:cave+len(STUB)] == bytes(len(STUB)), 'Cave is not zero')
    flags = struct.unpack_from('<I', data, h+36)[0]; require(flags == 0xc0000040, 'Unexpected section flags')
    result = bytearray(data); struct.pack_into('<I', result, h+36, flags | 0x20000000)
    result[entry:entry+8] = b'\xe9' + struct.pack('<i', target - (0x2ce30 + 5)) + b'\0\0\0'
    result[cave:cave+len(STUB)] = STUB
    require(sum(a != b for a, b in zip(data, result)) == 135 and digest(result) == SHA['kernelbase.dll'],
            'Generated patch differs from supplied original')
    return bytes(result)


def atomic(path, data, mode=None):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    if path.is_symlink(): raise ValueError('Refusing to write through symlink: ' + str(path))
    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as f:
        tmp = Path(f.name)
        try:
            f.write(data); f.flush(); os.fsync(f.fileno())
        except BaseException:
            tmp.unlink(missing_ok=True); raise
    try:
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True); raise
    if mode is not None: os.chmod(path, mode)


def existing(p, what):
    p = Path(p).expanduser()
    try: r = p.resolve(strict=True)
    except OSError as e: raise ValueError('%s not found: %s' % (what, p)) from e
    return r


def within(p, root):
    try: return Path(p).resolve(strict=False).is_relative_to(Path(root).resolve(strict=True))
    except OSError: return False


def parent_within(p, root):
    """True when the parent directory really lives under root.

    The final path component may be a symlink: callers unlink it before writing,
    so only its parent namespace has to be contained.
    """
    try: return Path(p).parent.resolve(strict=True).is_relative_to(Path(root).resolve(strict=True))
    except OSError: return False


def tree_digest(root):
    root = Path(root); h = hashlib.sha256()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort(); filenames.sort()
        base = Path(dirpath)
        for name in dirnames + filenames:
            p = base / name; rel = str(p.relative_to(root)).encode('utf-8')
            if p.is_symlink():
                h.update(b'L\0' + rel + b'\0' + os.readlink(p).encode('utf-8') + b'\0')
            elif p.is_dir():
                h.update(b'D\0' + rel + b'\0')
            elif p.is_file():
                h.update(b'F\0' + rel + b'\0' + str(stat.S_IMODE(p.stat().st_mode)).encode() + b'\0')
                with p.open('rb') as f:
                    for chunk in iter(lambda: f.read(1 << 20), b''): h.update(chunk)
                h.update(b'\0')
            else:
                raise ValueError('Unsupported file in app snapshot: ' + str(p))
    return h.hexdigest()


def import_payloads(source):
    source = existing(source, 'Payload source')
    source = source / 'Contents/Resources/patches' if source.suffix == '.app' else source
    require(source.is_dir(), 'Payload directory not found')
    data = {n: (source / n).read_bytes() for n in SHA}
    for n, d in data.items(): validate_payload(n, d)
    PAYLOADS.mkdir(exist_ok=True)
    for n, d in data.items(): atomic(PAYLOADS / n, d)
    print('Validated and imported three locally supplied DLLs to', PAYLOADS)


def ext_info(external):
    p = existing(external, 'GPTK external')
    framework = p / 'D3DMetal.framework'; lib = p / 'libd3dshared.dylib'
    binary = framework / 'Versions/A/D3DMetal'
    require(lib.is_file() and binary.is_file(), 'GPTK external must contain libd3dshared.dylib and D3DMetal.framework')
    with (framework / 'Resources/Info.plist').open('rb') as f: version = plistlib.load(f).get('CFBundleShortVersionString', '')
    require(str(version).startswith('4.'), 'Expected D3DMetal 4.x external; got ' + str(version))
    lb = lib.read_bytes(); fb = binary.read_bytes()
    require(0x01000007 in macho_archs(lb) and 0x01000007 in macho_archs(fb), 'GPTK 4.x external is not x86_64')
    return {'version': str(version), 'libd3dshared_sha256': digest(lb), 'framework_sha256': digest(fb),
            'libd3dshared_size': len(lb), 'framework_size': len(fb)}


def active():
    """List blocking processes without reading or revealing their arguments."""
    try:
        result = subprocess.run(['/bin/ps', '-axo', 'pid=,comm='], capture_output=True, text=True, check=False)
    except OSError as e:
        raise ValueError('Cannot inspect processes; refusing to modify: ' + str(e)) from e
    require(result.returncode == 0 and bool(result.stdout.strip()), 'Empty process list; refusing to modify')
    bad = []; parsed = 0
    wine_commands = {'wineserver', 'wine', 'wine64', 'wineloader', 'wine-preloader', 'wine64-preloader'}
    for line in result.stdout.splitlines():
        parts = line.strip().split(None, 1)
        if len(parts) != 2 or not parts[0].isdigit(): continue
        pid, command = parts; parsed += 1; low = command.lower()
        if low.rsplit('/', 1)[-1] in wine_commands:
            bad.append('%s (Wine)' % pid)
        elif re.search(r'/cross_?over[^/]*\.app/contents/', low) or 'crossover-hosted application' in low:
            bad.append('%s (CrossOver)' % pid)
    require(parsed > 0, 'Unrecognized process list; refusing to modify')
    return bad


def config(original):
    text = original.decode('utf-8')
    require(text.count(MARK_BEGIN) == text.count(MARK_END) and text.count(MARK_BEGIN) <= 1, 'Malformed FH4 config markers')
    require(len(re.findall(r'(?m)^\[EnvironmentVariables\][ \t]*$', text)) == 1, 'Expected exactly one [EnvironmentVariables] section')
    pattern = r'(?ms)^' + re.escape(MARK_BEGIN) + r'\n.*?^' + re.escape(MARK_END) + r'\n?'
    require(MARK_BEGIN not in text or re.search(pattern, text), 'Malformed FH4 config marker order')
    text = re.sub(pattern, '', text)
    match = re.search(r'(?m)^\[EnvironmentVariables\][ \t]*$', text)
    require(match is not None, 'No [EnvironmentVariables] section')
    end = re.search(r'(?m)^\[[^\]]+\][ \t]*$', text[match.end():]); stop = match.end() + end.start() if end else len(text)
    section = text[match.end():stop]
    if section.startswith('\n'): section = section[1:]
    for key in ENV:
        section = re.sub(r'(?m)^[ \t]*"' + re.escape(key) + r'"[ \t]*=.*(?:\n|$)', '', section)
    lines = '\n' + MARK_BEGIN + '\n' + ''.join('"%s" = "%s"\n' % (k, v) for k, v in ENV.items()) + MARK_END + '\n'
    return (text[:match.end()] + lines + section + text[stop:]).encode('utf-8')


def _reg_span(lines):
    for i, line in enumerate(lines):
        text = line.rstrip(b'\r\n')
        if text == REG_SECTION or text.startswith(REG_SECTION + b' ') or text.startswith(REG_SECTION + b'\t'):
            end = len(lines)
            for j in range(i + 1, len(lines)):
                if lines[j].lstrip().startswith(b'['): end = j; break
            return i, end
    return None


def _reg_line(lines, start, end, name):
    needle = b'"' + name.encode('ascii') + b'"'
    for i in range(start + 1, end):
        text = lines[i].lstrip(b' \t')
        if text.startswith(needle):
            rest = text[len(needle):].lstrip(b' \t')
            if rest.startswith(b'='): return i
    return None


def reg_override_value(data, name=REG_NAME):
    lines = data.splitlines(keepends=True); span = _reg_span(lines)
    if span is None: return None
    i = _reg_line(lines, *span, name)
    if i is None: return None
    text = lines[i].lstrip(b' \t')
    rest = text[len(b'"' + name.encode('ascii') + b'"'):].lstrip(b' \t')
    require(rest.startswith(b'='), 'Malformed DllOverrides entry for ' + name)
    value = rest[1:].lstrip(b' \t')
    require(value.startswith(b'"'), 'Malformed DllOverrides value for ' + name)
    out = bytearray(); escaped = False; closed = False
    for byte in value[1:]:
        char = bytes([byte])
        if escaped: out += char; escaped = False
        elif char == b'\\': escaped = True
        elif char == b'"': closed = True; break
        else: out += char
    require(closed, 'Unterminated DllOverrides value for ' + name)
    return out.decode('utf-8', 'surrogateescape')


def _override_apply(data, name, raw):
    lines = data.splitlines(keepends=True); span = _reg_span(lines)
    if span is None:
        if raw is None: return data
        prefix = data if not data or data.endswith(b'\n') else data + b'\n'
        return prefix + b'\n' + REG_SECTION + b' ' + str(int(time.time())).encode() + b'\n' + raw + b'\n'
    start, end = span; i = _reg_line(lines, start, end, name)
    if i is not None:
        if raw is None: del lines[i]
        else: lines[i] = raw + b'\n'
    elif raw is not None:
        at = start + 1
        if at < end and lines[at].startswith(b'#time='): at += 1
        lines.insert(at, raw + b'\n')
    return b''.join(lines)


def dll_override(data, name=REG_NAME, value=REG_VALUE):
    """Return (new user.reg bytes, previous apd12 line or None)."""
    lines = data.splitlines(keepends=True); span = _reg_span(lines)
    previous = None
    if span is not None:
        i = _reg_line(lines, *span, name)
        if i is not None:
            previous = lines[i].rstrip(b'\r\n')
            require(re.fullmatch(rb'[ \t]*"' + re.escape(name.encode('ascii')) + rb'"[ \t]*=[ \t]*".*"', previous),
                    'Unsupported DllOverrides line for ' + name)
    raw = b'"' + name.encode('ascii') + b'"="' + value.encode('ascii') + b'"'
    return _override_apply(data, name, raw), previous


def validate_override(entry, bottle):
    """Return the raw line to restore (or None) after validating the manifest."""
    if entry is None: return None
    require(isinstance(entry, dict) and entry.get('path') == 'user.reg' and entry.get('name') == REG_NAME,
            'Invalid registry override entry')
    p = Path(bottle) / 'user.reg'
    require(p.is_file() and not p.is_symlink() and parent_within(p, bottle), 'Invalid bottle registry')
    encoded = entry.get('previous')
    if encoded is None: return None
    require(isinstance(encoded, str), 'Invalid registry override value')
    try: raw = base64.b64decode(encoded.encode('ascii'), validate=True)
    except (ValueError, UnicodeError) as error: raise ValueError('Invalid registry override encoding') from error
    raw = raw.rstrip(b'\r\n')
    require(re.fullmatch(rb'[ \t]*"' + re.escape(REG_NAME.encode('ascii')) + rb'"[ \t]*=[ \t]*".*"', raw) is not None,
            'Invalid registry override line')
    return raw


def write_override(bottle, raw):
    p = Path(bottle) / 'user.reg'
    require(p.is_file() and not p.is_symlink() and parent_within(p, bottle), 'Invalid bottle registry')
    data = p.read_bytes()
    if raw is None and _reg_span(data.splitlines(keepends=True)) is None: return
    atomic(p, _override_apply(data, REG_NAME, raw), p.stat().st_mode & 0o7777)


def target_under(root, rel, label):
    p = Path(root) / rel
    parent = p.parent.resolve(strict=True)
    require(parent.is_relative_to(Path(root).resolve(strict=True)), label + ' escapes ' + str(root))
    require(not p.is_symlink(), 'Refusing symlink target: ' + str(p))
    require(not p.exists() or p.is_file(), 'Unexpected non-file target: ' + str(p))
    return p


def state(cx, bottle):
    def h(p):
        if p.is_symlink(): return 'symlink:' + os.readlink(p)
        if not p.exists(): return 'absent'
        if not p.is_file(): return 'other'
        return readhash(p)
    kb = h(cx / KB); d12 = h(cx / WIN / 'd3d12.dll'); apd = h(cx / WIN / 'apd12.dll')
    alias = h(cx / UNIX / 'apd12.so')
    sysd = bottle / 'drive_c/windows/system32'
    sysmap = {n: h(sysd / n) for n in SHA}
    conf = (bottle / 'cxbottle.conf').read_bytes()
    marker = MARK_BEGIN.encode() in conf
    reg = bottle / 'user.reg'
    override = reg_override_value(reg.read_bytes()) if reg.is_file() and not reg.is_symlink() else None
    # A real bottle already contains Wine's own system32 DLLs. Pristine therefore
    # means "no FH4 payload and no marker", not "those paths are absent".
    app_pristine = kb == STOCK and d12 == STOCK_D3D12 and apd == 'absent' and alias == 'absent'
    app_installed = (kb == SHA['kernelbase.dll'] and d12 == SHA['d3d12.dll'] and apd == SHA['apd12.dll']
                     and alias == 'symlink:' + ALIAS_TARGET)
    bottle_clean = not marker and all(v != SHA[n] for n, v in sysmap.items())
    bottle_installed = (marker and override == REG_VALUE
                        and all(v == SHA[n] for n, v in sysmap.items()))
    pristine = app_pristine and bottle_clean
    installed = app_installed and bottle_installed
    return {'kind': 'pristine' if pristine else 'installed' if installed else 'foreign',
            'kernelbase': kb, 'd3d12': d12, 'apd12': apd, 'apd12_so': alias,
            'system32': sysmap, 'config_marker': marker, 'dll_override': override}


def preflight(app, bottle, external, need_idle=False):
    app = existing(app, 'CrossOver app'); bottle = existing(bottle, 'Bottle')
    cx = app / CXR
    require(app.suffix == '.app' and app.is_dir(), 'CrossOver app not found')
    require(cx.is_dir() and cx.resolve(strict=True) == cx and cx.resolve(strict=True).is_relative_to(app),
            'CrossOver runtime is missing, symlinked, or escapes the app')
    with (app / 'Contents/Info.plist').open('rb') as f: info = plistlib.load(f)
    require(str(info.get('CFBundleShortVersionString')) == '26.3' and str(info.get('CFBundleVersion', '')).startswith('26.3.0.'),
            'Expected CrossOver 26.3.0')
    system = bottle / 'drive_c/windows/system32'
    require(system.is_dir() and not system.is_symlink() and (bottle / 'cxbottle.conf').is_file(), 'Invalid bottle or symlinked system32')
    require(system.resolve(strict=True).is_relative_to(bottle), 'Bottle system32 escapes the bottle')
    for n in SHA: validate_payload(n, (PAYLOADS / n).read_bytes())
    for rel in (KB, WIN / 'd3d12.dll', WIN / 'apd12.dll', WIN / 'd3d12core.dll', UNIX / 'd3d12.so', UNIX / 'apd12.so'):
        require(parent_within(cx / rel, cx), 'CrossOver target escapes the runtime: ' + str(rel))
    kb = cx / KB; require(kb.is_file() and not kb.is_symlink(), 'CrossOver kernelbase missing or symlinked')
    require(readhash(kb) in (STOCK, SHA['kernelbase.dll']), 'Unsupported CrossOver kernelbase; restore stock first')
    require(not (cx / WIN / 'd3d12.dll').is_symlink() and not (cx / WIN / 'apd12.dll').is_symlink(), 'CrossOver DLL target is a symlink')
    glue = cx / UNIX / 'd3d12.so'
    require(glue.is_symlink() and os.readlink(glue) == ALIAS_TARGET, 'Unexpected d3d12 Unix glue')
    alias = cx / UNIX / 'apd12.so'
    if alias.exists() or alias.is_symlink():
        require(alias.is_symlink() and os.readlink(alias) == ALIAS_TARGET, 'Unexpected existing apd12.so')
    ext = ext_info(external if external else cx / EXT)
    if external:
        src = existing(external, 'GPTK external'); dest = (cx / EXT).resolve(strict=True)
        require(src == dest or not src.is_relative_to(dest), 'GPTK source is inside the external directory being replaced')
    conf = (bottle / 'cxbottle.conf'); require(not conf.is_symlink(), 'Bottle config is a symlink')
    config(conf.read_bytes())
    reg = bottle / 'user.reg'
    require(reg.is_file() and not reg.is_symlink() and parent_within(reg, bottle), 'Invalid bottle registry')
    dll_override(reg.read_bytes())
    for n in SHA:
        p = system / n
        require(not p.is_symlink(), 'Bottle DLL target is a symlink: ' + n)
    st = state(cx, bottle)
    if need_idle:
        pids = active(); require(not pids, 'Wine/CrossOver processes detected; close them before proceeding: ' + ', '.join(pids))
    return app, bottle, cx, ext, st


def game_evidence(exe, expected, allow_unverified):
    """Pinning a file only proves identity; no game build is verified for the VEH."""
    require(not expected or exe, '--fh4-sha256 requires --fh4-exe')
    if exe:
        p = existing(exe, 'FH4 executable')
        require(p.is_file(), 'FH4 executable is not a file')
        data = p.read_bytes(); require(len(data) > 0x40 and data[:2] == b'MZ', 'FH4 executable is not a PE file')
        require(expected and re.fullmatch(r'[0-9a-fA-F]{64}', expected), 'Provide a 64-digit expected SHA-256 with --fh4-sha256')
        sha = digest(data); require(sha == expected.lower(), 'FH4 SHA-256 mismatch: %s != %s' % (sha, expected.lower()))
        return {'status': 'unverified' if allow_unverified else 'pinned-unverified', 'path': str(p), 'sha256': sha,
                'size': len(data), 'note': 'Hash pins identity only; fixed-RVA VEH compatibility is unverified'}
    if allow_unverified: return {'status': 'unverified', 'note': 'fixed-RVA VEH enabled without a verified game build'}
    return {'status': 'none'}


def backup_entry(p, dst):
    p = Path(p)
    if p.is_symlink(): return {'kind': 'symlink', 'target': os.readlink(p)}
    if not p.exists(): return {'kind': 'absent'}
    require(p.is_file(), 'Unexpected non-file in bottle: ' + str(p))
    shutil.copy2(p, dst, follow_symlinks=False)
    return {'kind': 'file', 'backup': Path(dst).name, 'mode': p.stat().st_mode & 0o7777, 'sha256': readhash(dst)}


def rel_entries(paths, bottle, destdir):
    bottle = Path(bottle).resolve(strict=True); out = []
    for i, p in enumerate(paths):
        p = Path(p)
        require(p.is_absolute() and parent_within(p, bottle), 'Path outside bottle: ' + str(p))
        rel = str((p.parent.resolve(strict=True) / p.name).relative_to(bottle))
        out.append(dict(path=rel, **backup_entry(p, Path(destdir) / str(i))))
    return out


def validate_entries(entries, backup, bottle):
    bottle = Path(bottle).resolve(strict=True); backup = Path(backup).resolve(strict=True)
    seen = set(); checked = []
    require(isinstance(entries, list) and entries, 'Invalid backup entries')
    for item in entries:
        require(isinstance(item, dict), 'Invalid backup entry')
        rel = item.get('path'); require(isinstance(rel, str) and rel and not os.path.isabs(rel), 'Invalid backup path')
        require('..' not in Path(rel).parts, 'Backup path escapes bottle: ' + rel)
        p = bottle / rel
        require(parent_within(p, bottle), 'Backup path escapes bottle: ' + rel)
        require(not p.is_dir() or p.is_symlink(), 'Backup path is a directory: ' + rel)
        require(rel not in seen, 'Duplicate backup path: ' + rel); seen.add(rel)
        kind = item.get('kind')
        if kind == 'file':
            name = item.get('backup')
            require(isinstance(name, str) and name and Path(name).name == name, 'Invalid backup file name for ' + rel)
            b = backup / name
            require(b.is_file() and not b.is_symlink(), 'Missing backup file for ' + rel)
            require(readhash(b) == item.get('sha256'), 'Backup file hash mismatch for ' + rel)
            require(isinstance(item.get('mode'), int) and 0 <= item['mode'] <= 0o7777, 'Invalid mode for ' + rel)
        elif kind == 'symlink':
            require(isinstance(item.get('target'), str) and item['target'] and '\0' not in item['target'], 'Invalid symlink target for ' + rel)
        elif kind != 'absent':
            raise ValueError('Invalid backup kind for ' + rel)
        checked.append((p, item))
    return checked


def restore_entries(entries, backup, bottle):
    for p, item in validate_entries(entries, backup, bottle):
        if p.is_symlink() or p.exists():
            require(not p.is_dir() or p.is_symlink(), 'Refusing to replace directory ' + str(p))
            p.unlink()
        if item['kind'] == 'symlink': os.symlink(item['target'], p)
        elif item['kind'] == 'file':
            atomic(p, (Path(backup) / item['backup']).read_bytes(), item['mode'])
            require(readhash(p) == item['sha256'], 'Restored file hash mismatch for ' + str(p))
    for p, item in validate_entries(entries, backup, bottle):
        if item['kind'] == 'absent': require(not p.exists() and not p.is_symlink(), 'Failed to remove ' + str(p))
        elif item['kind'] == 'symlink':
            require(p.is_symlink() and os.readlink(p) == item['target'], 'Restored symlink mismatch for ' + str(p))
        else: require(p.is_file() and not p.is_symlink() and readhash(p) == item['sha256'], 'Restored file mismatch for ' + str(p))


def rollback(backup, check_idle=True):
    backup = existing(backup, 'Backup')
    require((backup / 'app').is_dir() and not (backup / 'app').is_symlink(), 'Backup app snapshot missing')
    manifest = json.loads((backup / 'manifest.json').read_text())
    require(isinstance(manifest, dict) and manifest.get('format') == 2, 'Invalid backup manifest')
    app = Path(manifest.get('app', '')); bottle = Path(manifest.get('bottle', ''))
    require(app.is_absolute() and bottle.is_absolute() and app.suffix == '.app', 'Invalid backup paths')
    require(app.exists() and not app.is_symlink() and app.is_dir(), 'App missing or symlink; restore manually')
    require(bottle.is_dir() and not bottle.is_symlink(), 'Bottle missing or symlink; restore manually')
    entries = manifest.get('bottle_entries')
    checked = validate_entries(entries, backup, bottle)
    override_previous = validate_override(manifest.get('bottle_override'), bottle)
    if check_idle:
        pids = active(); require(not pids, 'Wine/CrossOver processes detected; close them before rollback: ' + ', '.join(pids))
    tree_hash = tree_digest(backup / 'app')
    require(tree_hash == manifest.get('app_tree_sha256'), 'App snapshot integrity check failed; refusing rollback')
    info_hash = readhash(backup / 'app/Contents/Info.plist')
    require(info_hash == manifest.get('app_info_sha256'), 'App snapshot Info.plist mismatch')
    stage = app.with_name(app.name + '.fh4-rollback-stage'); require(not stage.exists() and not stage.is_symlink(), 'Rollback stage already exists')
    pre = backup / 'pre-rollback'; require(not pre.exists() and not pre.is_symlink(), 'Previous rollback staging exists'); pre.mkdir(mode=0o700)
    current = rel_entries([p for p, _ in checked], bottle, pre)
    current_override = None
    if manifest.get('bottle_override') is not None:
        _, current_override = dll_override((bottle / 'user.reg').read_bytes())
    os.rename(app, stage)
    try:
        run(['/usr/bin/ditto', backup / 'app', app])
        require(tree_digest(app) == tree_hash, 'Restored app tree mismatch')
        restore_entries(entries, backup, bottle)
        if manifest.get('bottle_override') is not None: write_override(bottle, override_previous)
    except BaseException as error:
        try:
            if app.exists(): shutil.rmtree(app)
            os.rename(stage, app)
            restore_entries(current, pre, bottle)
            if manifest.get('bottle_override') is not None:
                write_override(bottle, current_override)
        except BaseException as revert:
            raise ValueError('Rollback failed and automatic revert failed; previous app kept at %s: %s; revert: %s' % (stage, error, revert)) from error
        raise
    shutil.rmtree(stage); shutil.rmtree(pre)
    print('Restored app snapshot and bottle files from', backup)


def prepare_backup(app, bottle, backup):
    raw = Path(backup).expanduser(); require(raw.name not in ('', '.', '..'), 'Invalid backup path')
    parent = raw.parent.resolve(strict=True); require(parent.is_dir(), 'Backup parent is not a directory')
    target = parent / raw.name
    require(not target.exists() and not target.is_symlink(), 'Backup path already exists')
    require(not within(target, app) and not within(target, bottle), 'Backup must be outside app and bottle')
    target.mkdir(mode=0o700); real = target.resolve(strict=True)
    require(real == target, 'Backup path traverses a symlink')
    require(not within(real, app) and not within(real, bottle), 'Backup must be outside app and bottle')
    return real


def install(app, bottle, external, backup, replace=False, evidence=None):
    app, bottle, cx, info, st = preflight(app, bottle, external, need_idle=True)
    require(isinstance(evidence, dict) and evidence.get('status') == 'unverified',
            'No game build is verified for this VEH; explicit --allow-unverified-game is required')
    if st['kind'] != 'pristine' and not replace:
        raise ValueError('Target is already installed or modified (%s); use --replace to back it up and reinstall' % st['kind'])
    if st['kind'] == 'foreign':
        raise ValueError('Unrecognized existing state; restore the stock app/bottle before installing')
    backup = prepare_backup(app, bottle, backup)
    print('Creating complete application snapshot; this may take time.')
    try:
        run(['/usr/bin/ditto', app, backup / 'app'])
        require((backup / 'app/Contents/Info.plist').is_file(), 'Application snapshot is incomplete')
        source_tree = tree_digest(app); snapshot_tree = tree_digest(backup / 'app')
        require(source_tree == snapshot_tree, 'Application snapshot differs from the source; refusing install')
        paths = [bottle / 'cxbottle.conf'] + [bottle / 'drive_c/windows/system32' / n for n in SHA]
        entries = rel_entries(paths, bottle, backup)
        reg = bottle / 'user.reg'
        reg_data = reg.read_bytes(); _, reg_previous = dll_override(reg_data)
        manifest = {'format': 2, 'app': str(app), 'bottle': str(bottle), 'gptk': info, 'fh4': evidence,
                    'app_info_sha256': readhash(app / 'Contents/Info.plist'),
                    'app_tree_sha256': snapshot_tree,
                    'payload_sha256': SHA, 'bottle_entries': entries,
                    'bottle_override': {'path': 'user.reg', 'name': REG_NAME,
                                        'previous': base64.b64encode(reg_previous).decode('ascii') if reg_previous else None}}
        atomic(backup / 'manifest.json', json.dumps(manifest, indent=2).encode())
    except BaseException:
        shutil.rmtree(backup); raise
    try:
        if external and Path(external).resolve() != (cx / EXT).resolve():
            dst = cx / EXT; require(not dst.is_symlink(), 'GPTK external target is a symlink')
            if dst.exists(): shutil.rmtree(dst)
            run(['/usr/bin/ditto', '--noextattr', '--noqtn', external, dst])
            require(ext_info(dst) == info, 'Copied GPTK external mismatch')
        kb = cx / KB
        if readhash(kb) == STOCK: atomic(kb, patch_kernel(kb.read_bytes()), kb.stat().st_mode & 0o7777)
        for name, rel in (('d3d12.dll', WIN / 'd3d12.dll'), ('apd12.dll', WIN / 'apd12.dll')):
            p = target_under(cx, rel, name); mode = p.stat().st_mode & 0o7777 if p.exists() else 0o644
            atomic(p, (PAYLOADS / name).read_bytes(), mode)
        alias = cx / UNIX / 'apd12.so'
        if alias.is_symlink(): require(os.readlink(alias) == ALIAS_TARGET, 'Unexpected apd12.so')
        elif alias.exists(): raise ValueError('apd12.so exists and is not a symlink')
        else: os.symlink(ALIAS_TARGET, alias)
        system = bottle / 'drive_c/windows/system32'
        require(not system.is_symlink() and system.resolve(strict=True).is_relative_to(bottle), 'system32 escapes bottle')
        for n in SHA:
            p = system / n
            require(not p.is_symlink(), 'Bottle DLL target is a symlink: ' + n)
            atomic(p, (PAYLOADS / n).read_bytes(), 0o644)
        conf = bottle / 'cxbottle.conf'; require(not conf.is_symlink(), 'Bottle config is a symlink')
        atomic(conf, config(conf.read_bytes()), conf.stat().st_mode & 0o7777)
        write_override(bottle, b'"' + REG_NAME.encode('ascii') + b'"="' + REG_VALUE.encode('ascii') + b'"')
        run(['/usr/bin/codesign', '--force', '--deep', '--sign', '-', '--preserve-metadata=entitlements', app])
        run(['/usr/bin/codesign', '--verify', '--all-architectures', '--deep', '--strict', app])
    except BaseException as error:
        print('Installation failed; restoring snapshot.', file=sys.stderr)
        try: rollback(backup, check_idle=False)
        except BaseException as revert:
            raise ValueError('Install failed (%s); automatic rollback also failed (%s). Backup kept at %s' % (error, revert, backup)) from error
        raise
    print('Installed. FH4 loading and gameplay remain unverified. Backup:', backup)


def main():
    ap = argparse.ArgumentParser(description=__doc__); sp = ap.add_subparsers(dest='cmd', required=True)
    x = sp.add_parser('import-payloads'); x.add_argument('source')
    x = sp.add_parser('patch-kernelbase'); x.add_argument('source'); x.add_argument('output')
    x = sp.add_parser('inspect'); x.add_argument('paths', nargs='+')
    for command in ('check', 'install'):
        x = sp.add_parser(command); x.add_argument('--app', required=True); x.add_argument('--bottle', required=True)
        x.add_argument('--gptk-external'); x.add_argument('--fh4-exe'); x.add_argument('--fh4-sha256')
        x.add_argument('--allow-unverified-game', action='store_true')
        if command == 'install':
            x.add_argument('--backup', required=True); x.add_argument('--replace', action='store_true')
    x = sp.add_parser('rollback'); x.add_argument('backup')
    args = ap.parse_args()
    try:
        if args.cmd == 'import-payloads': import_payloads(args.source)
        elif args.cmd == 'patch-kernelbase':
            dest = Path(args.output); require(not dest.exists(), 'Output already exists')
            atomic(dest, patch_kernel(Path(args.source).read_bytes())); print('SHA-256:', readhash(dest))
        elif args.cmd == 'inspect':
            print(json.dumps([inspect_payload(p) for p in args.paths], indent=2))
        elif args.cmd == 'check':
            _, _, _, info, st = preflight(args.app, args.bottle, args.gptk_external, need_idle=False)
            evidence = game_evidence(args.fh4_exe, args.fh4_sha256, args.allow_unverified_game)
            print(json.dumps({'status': 'preflight passed', 'state': st['kind'], 'gptk': info, 'fh4': evidence,
                              'note': 'Loading and FH4 gameplay have not been tested.'}, indent=2))
        elif args.cmd == 'install':
            evidence = game_evidence(args.fh4_exe, args.fh4_sha256, args.allow_unverified_game)
            require(evidence['status'] == 'unverified', 'No game build is verified for this VEH; explicit --allow-unverified-game is required even when a SHA-256 is supplied')
            install(args.app, args.bottle, args.gptk_external, args.backup, args.replace, evidence)
        else: rollback(args.backup)
    except (ValueError, OSError, struct.error, UnicodeError) as e:
        print('Error:', e, file=sys.stderr); return 1
    return 0


if __name__ == '__main__': sys.exit(main())
