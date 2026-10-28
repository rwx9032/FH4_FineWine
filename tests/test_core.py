import contextlib
import importlib.util
import json
import os
from pathlib import Path
import plistlib
import shutil
import struct
import subprocess
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('fh4', Path(__file__).resolve().parents[1] / 'tools/fh4.py')
fh4 = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fh4)

CONF = (b'[Bottle]\n"WineArch" = "win64"\n[EnvironmentVariables]\n"WINEMSYNC" = "0"\n'
        b'"CX_GRAPHICS_BACKEND" = "dxmt"\n[Other]\n"x" = "y"\n')
USER_REG = (b'WINE REGISTRY Version 2\n\n'
            b'[Software\\\\Wine\\\\DllOverrides] 1793220789\n#time=1dd671e56b4dde4\n'
            b'"apd12"="native"\n"d3d12"="native,builtin"\n\n'
            b'[Software\\\\Wine\\\\Fonts] 1793222305\n#time=1dd6721de88ed0c\n'
            b'"LogPixels"=dword:00000060\n')


def write(p, data, mode=0o644):
    p = Path(p); p.parent.mkdir(parents=True, exist_ok=True); p.write_bytes(data); os.chmod(p, mode)


def fake_macho(cpu=0x01000007):
    return struct.pack('<II', 0xfeedfacf, cpu) + b'\0' * 16


class Fixture:
    """A synthetic CrossOver 26.3 app, private bottle and validated payloads."""

    def __init__(self, base):
        self.base = base
        self.app = base / 'CrossOver.app'
        self.cx = self.app / fh4.CXR
        self.bottle = base / 'bottle'
        self.system = self.bottle / 'drive_c/windows/system32'
        self.payloads = base / 'payloads'
        self.stock_kernel = b'stock-kernelbase-26.3'
        self.stock_d3d12 = b'stock-apple-d3d12-26.3'
        self.payload_data = {'d3d12.dll': b'payload-d3d12',
                             'apd12.dll': b'payload-apd12',
                             'kernelbase.dll': b'patched-kernelbase'}
        self.sha = {n: fh4.digest(d) for n, d in self.payload_data.items()}
        self.info = {'version': '4.0b3', 'libd3dshared_sha256': 'a' * 64,
                     'framework_sha256': 'b' * 64, 'libd3dshared_size': 1, 'framework_size': 1}
        self.calls = []
        self.fail_codesign = False

    def build(self):
        self.base.mkdir(parents=True, exist_ok=True)
        (self.app / 'Contents').mkdir(parents=True)
        with (self.app / 'Contents/Info.plist').open('wb') as f:
            plistlib.dump({'CFBundleShortVersionString': '26.3', 'CFBundleVersion': '26.3.0.12345'}, f)
        write(self.cx / fh4.KB, self.stock_kernel)
        write(self.cx / fh4.WIN / 'd3d12.dll', self.stock_d3d12)
        (self.cx / fh4.UNIX).mkdir(parents=True, exist_ok=True)
        (self.cx / fh4.UNIX / 'd3d12.so').symlink_to(fh4.ALIAS_TARGET)
        write(self.bottle / 'cxbottle.conf', CONF)
        write(self.bottle / 'user.reg', USER_REG)
        write(self.system / 'kernelbase.dll', b'wine-kernelbase')
        write(self.system / 'd3d12.dll', b'wine-wined3d-d3d12')
        for name, data in self.payload_data.items():
            write(self.payloads / name, data)

    def fake_run(self, args):
        args = [str(a) for a in args]; self.calls.append(args)
        if args[0] == '/usr/bin/ditto':
            src, dst = Path(args[-2]), Path(args[-1])
            if dst.exists(): shutil.rmtree(dst)
            shutil.copytree(src, dst, symlinks=True)
        elif args[0] == '/usr/bin/codesign':
            if '--verify' not in args and self.fail_codesign:
                raise ValueError('simulated signing failure')
        else:
            raise ValueError('unexpected command: ' + ' '.join(args))

    @contextlib.contextmanager
    def patched(self):
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(fh4, 'PAYLOADS', self.payloads))
            stack.enter_context(mock.patch.object(fh4, 'SHA', self.sha))
            stack.enter_context(mock.patch.object(fh4, 'STOCK', fh4.digest(self.stock_kernel)))
            stack.enter_context(mock.patch.object(fh4, 'STOCK_D3D12', fh4.digest(self.stock_d3d12)))
            stack.enter_context(mock.patch.object(fh4, 'patch_kernel', lambda data: self.payload_data['kernelbase.dll']))
            stack.enter_context(mock.patch.object(fh4, 'validate_payload', lambda name, data: None))
            stack.enter_context(mock.patch.object(fh4, 'ext_info', lambda p: dict(self.info)))
            stack.enter_context(mock.patch.object(fh4, 'active', lambda: []))
            stack.enter_context(mock.patch.object(fh4, 'run', self.fake_run))
            yield

    def install(self, backup, **kw):
        kw.setdefault('evidence', {'status': 'unverified', 'note': 'test'})
        return fh4.install(self.app, self.bottle, None, backup, **kw)

    def assert_installed(self, test):
        test.assertEqual((self.cx / fh4.KB).read_bytes(), self.payload_data['kernelbase.dll'])
        test.assertEqual((self.cx / fh4.WIN / 'd3d12.dll').read_bytes(), self.payload_data['d3d12.dll'])
        test.assertEqual((self.cx / fh4.WIN / 'apd12.dll').read_bytes(), self.payload_data['apd12.dll'])
        test.assertTrue((self.cx / fh4.UNIX / 'apd12.so').is_symlink())
        test.assertEqual(os.readlink(self.cx / fh4.UNIX / 'apd12.so'), fh4.ALIAS_TARGET)
        test.assertEqual((self.system / 'kernelbase.dll').read_bytes(), self.payload_data['kernelbase.dll'])
        test.assertEqual((self.system / 'd3d12.dll').read_bytes(), self.payload_data['d3d12.dll'])
        test.assertIn(fh4.MARK_BEGIN.encode(), (self.bottle / 'cxbottle.conf').read_bytes())
        test.assertEqual(fh4.reg_override_value((self.bottle / 'user.reg').read_bytes()), 'builtin')
        test.assertEqual(fh4.state(self.cx, self.bottle)['kind'], 'installed')

    def assert_pristine(self, test):
        test.assertEqual((self.cx / fh4.KB).read_bytes(), self.stock_kernel)
        test.assertEqual((self.cx / fh4.WIN / 'd3d12.dll').read_bytes(), self.stock_d3d12)
        test.assertFalse((self.cx / fh4.WIN / 'apd12.dll').exists())
        test.assertFalse((self.cx / fh4.UNIX / 'apd12.so').exists())
        test.assertEqual((self.system / 'kernelbase.dll').read_bytes(), b'wine-kernelbase')
        test.assertEqual((self.system / 'd3d12.dll').read_bytes(), b'wine-wined3d-d3d12')
        test.assertEqual((self.bottle / 'cxbottle.conf').read_bytes(), CONF)
        test.assertEqual((self.bottle / 'user.reg').read_bytes(), USER_REG)
        test.assertEqual(fh4.state(self.cx, self.bottle)['kind'], 'pristine')


@contextlib.contextmanager
def environment():
    with tempfile.TemporaryDirectory() as d:
        f = Fixture(Path(d)); f.build()
        with f.patched(): yield f


class Core(unittest.TestCase):
    def test_config_preserves_msync_and_is_idempotent(self):
        a = fh4.config(CONF)
        self.assertEqual(a, fh4.config(a))
        self.assertIn(b'"WINEMSYNC" = "0"', a)
        self.assertEqual(a.count(b'"CX_GRAPHICS_BACKEND"'), 1)
        self.assertIn(b'[Other]\n"x" = "y"', a)
        self.assertEqual(a.count(fh4.MARK_BEGIN.encode()), 1)

    def test_dll_override_is_merged_idempotent_and_restorable(self):
        first, previous = fh4.dll_override(USER_REG)
        self.assertEqual(previous, b'"apd12"="native"')
        self.assertEqual(fh4.reg_override_value(first), 'builtin')
        again, previous_again = fh4.dll_override(first)
        self.assertEqual(again, first)
        self.assertEqual(previous_again, b'"apd12"="builtin"')
        self.assertIn(b'"d3d12"="native,builtin"', again)
        self.assertIn(b'"LogPixels"=dword:00000060', again)
        self.assertEqual(fh4._override_apply(first, fh4.REG_NAME, previous), USER_REG)
        with tempfile.TemporaryDirectory() as d:
            user = Path(d) / 'user.reg'; write(user, b'WINE REGISTRY Version 2\n')
            fh4.write_override(Path(d), b'"apd12"="native"')
            self.assertIn(fh4.REG_SECTION, user.read_bytes())
            self.assertEqual(fh4.reg_override_value(user.read_bytes()), 'native')
            fh4.write_override(Path(d), None)
            self.assertIsNone(fh4.reg_override_value(user.read_bytes()))

    def test_installed_state_requires_builtin_override(self):
        with environment() as f:
            f.install(f.base / 'backup')
            f.assert_installed(self)
            data = (f.bottle / 'user.reg').read_bytes()
            (f.bottle / 'user.reg').write_bytes(data.replace(b'"apd12"="builtin"', b'"apd12"="native"'))
            self.assertEqual(fh4.state(f.cx, f.bottle)['kind'], 'foreign')

    def test_invalid_kernel_cannot_produce_output(self):
        with self.assertRaises(ValueError): fh4.patch_kernel(b'invalid')
        with self.assertRaises(ValueError): fh4.validate_payload('d3d12.dll', b'not a dll')

    def test_original_kernel_when_present(self):
        source = Path(os.environ.get('FH4_STOCK_KERNEL', '/nonexistent'))
        if not source.is_file(): self.skipTest('Set FH4_STOCK_KERNEL to the 26.3 stock DLL')
        result = fh4.patch_kernel(source.read_bytes())
        self.assertEqual(fh4.digest(result), fh4.SHA['kernelbase.dll'])
        supplied = os.environ.get('FH4_PATCHED_KERNEL')
        if supplied: self.assertEqual(result, Path(supplied).read_bytes())

    def test_ext_info_requires_4x_x86_64(self):
        with tempfile.TemporaryDirectory() as d:
            ext = Path(d); (ext / 'D3DMetal.framework/Versions/A').mkdir(parents=True)
            (ext / 'D3DMetal.framework/Resources').mkdir(parents=True)
            write(ext / 'libd3dshared.dylib', fake_macho())
            write(ext / 'D3DMetal.framework/Versions/A/D3DMetal', fake_macho())
            with (ext / 'D3DMetal.framework/Resources/Info.plist').open('wb') as f:
                plistlib.dump({'CFBundleShortVersionString': '4.0b3'}, f)
            self.assertEqual(fh4.ext_info(ext)['version'], '4.0b3')
            with (ext / 'D3DMetal.framework/Resources/Info.plist').open('wb') as f:
                plistlib.dump({'CFBundleShortVersionString': '3.0'}, f)
            with self.assertRaises(ValueError): fh4.ext_info(ext)
            with (ext / 'D3DMetal.framework/Resources/Info.plist').open('wb') as f:
                plistlib.dump({'CFBundleShortVersionString': '4.0b3'}, f)
            write(ext / 'libd3dshared.dylib', fake_macho(0x0100000c))
            with self.assertRaises(ValueError): fh4.ext_info(ext)

    def test_backup_restore_file_symlink_and_absence(self):
        with environment() as f:
            backup = f.base / 'backup'; backup.mkdir()
            one = f.bottle / 'one'; write(one, b'original', 0o640)
            link = f.bottle / 'link'; link.symlink_to('one')
            absent = f.bottle / 'absent'
            entries = fh4.rel_entries([one, link, absent], f.bottle, backup)
            write(one, b'changed'); link.unlink(); write(link, b'new'); write(absent, b'created')
            fh4.restore_entries(entries, backup, f.bottle)
            self.assertEqual(one.read_bytes(), b'original')
            self.assertEqual(one.stat().st_mode & 0o777, 0o640)
            self.assertTrue(link.is_symlink()); self.assertEqual(os.readlink(link), 'one')
            self.assertFalse(absent.exists())

    def test_backup_rejects_escape_tamper_and_symlinked_parent(self):
        with environment() as f:
            backup = f.base / 'backup'; backup.mkdir()
            one = f.bottle / 'one'; write(one, b'original')
            entries = fh4.rel_entries([one], f.bottle, backup)
            for bad in ('../outside', '/etc/passwd', 'drive_c/../../outside'):
                manifest = [dict(entries[0], path=bad)]
                with self.assertRaises(ValueError): fh4.validate_entries(manifest, backup, f.bottle)
            write(backup / entries[0]['backup'], b'tampered')
            with self.assertRaises(ValueError): fh4.validate_entries(entries, backup, f.bottle)

            (f.app / 'inside').mkdir()
            alias = f.base / 'alias'; alias.symlink_to(f.app / 'inside')
            with self.assertRaises(ValueError): fh4.prepare_backup(f.app, f.bottle, alias / 'backup')
            final = f.base / 'backup-link'; final.symlink_to(f.base / 'real'); (f.base / 'real').mkdir()
            with self.assertRaises(ValueError): fh4.prepare_backup(f.app, f.bottle, final)
            made = fh4.prepare_backup(f.app, f.bottle, f.base / 'good-backup')
            self.assertEqual(made.stat().st_mode & 0o777, 0o700)

    def test_atomic_and_targets_refuse_symlinks(self):
        with environment() as f:
            outside = f.base / 'outside'; write(outside, b'untouched')
            link = f.cx / fh4.WIN / 'apd12.dll'; link.symlink_to(outside)
            with self.assertRaises(ValueError): fh4.target_under(f.cx, fh4.WIN / 'apd12.dll', 'apd12.dll')
            with self.assertRaises(ValueError): fh4.atomic(link, b'evil')
            self.assertEqual(outside.read_bytes(), b'untouched')

    def test_bottle_symlink_is_rejected_before_install(self):
        with environment() as f:
            outside = f.base / 'outside'; write(outside, b'untouched')
            (f.system / 'kernelbase.dll').unlink()
            (f.system / 'kernelbase.dll').symlink_to(outside)
            with self.assertRaises(ValueError):
                fh4.preflight(f.app, f.bottle, None, need_idle=False)
            with self.assertRaises(ValueError): f.install(f.base / 'backup')
            self.assertEqual(outside.read_bytes(), b'untouched')
            self.assertFalse((f.base / 'backup').exists())

    def test_process_query_failure_and_occupancy_are_not_idle(self):
        failed = subprocess.CompletedProcess(['ps'], 1, '', 'denied')
        with mock.patch.object(fh4.subprocess, 'run', return_value=failed):
            with self.assertRaises(ValueError): fh4.active()
        with mock.patch.object(fh4.subprocess, 'run', side_effect=OSError('no ps')):
            with self.assertRaises(ValueError): fh4.active()
        empty = subprocess.CompletedProcess(['ps'], 0, '', '')
        with mock.patch.object(fh4.subprocess, 'run', return_value=empty):
            with self.assertRaises(ValueError): fh4.active()
        busy = subprocess.CompletedProcess(
            ['ps'], 0, '  42 /Applications/CrossOver.app/Contents/SharedSupport/CrossOver/bin/wineserver\n'
                      '  43 /usr/bin/python3\n', '')
        with mock.patch.object(fh4.subprocess, 'run', return_value=busy):
            self.assertEqual(len(fh4.active()), 1)
        quiet = subprocess.CompletedProcess(['ps'], 0, '  43 /usr/bin/python3\n', '')
        with mock.patch.object(fh4.subprocess, 'run', return_value=quiet):
            self.assertEqual(fh4.active(), [])

        with environment() as f:
            with mock.patch.object(fh4, 'active', side_effect=AssertionError('check must not query processes')):
                _, _, _, _, st = fh4.preflight(f.app, f.bottle, None, need_idle=False)
                self.assertEqual(st['kind'], 'pristine')
            with mock.patch.object(fh4, 'active', return_value=['42 wineserver']):
                with self.assertRaises(ValueError): fh4.preflight(f.app, f.bottle, None, need_idle=True)
                with self.assertRaises(ValueError): f.install(f.base / 'backup')
            self.assertFalse((f.base / 'backup').exists())

    def test_game_evidence_gate(self):
        with environment() as f:
            none = fh4.game_evidence(None, None, False)
            self.assertEqual(none['status'], 'none')
            self.assertEqual(fh4.game_evidence(None, None, True)['status'], 'unverified')
            exe = f.base / 'ForzaHorizon4.exe'; write(exe, b'MZ' + b'\0' * 80)
            with self.assertRaises(ValueError): fh4.game_evidence(exe, None, False)
            with self.assertRaises(ValueError): fh4.game_evidence(exe, '0' * 64, False)
            pinned = fh4.game_evidence(exe, fh4.digest(exe.read_bytes()), False)
            self.assertEqual(pinned['status'], 'pinned')
            with self.assertRaises(ValueError): f.install(f.base / 'backup', evidence={'status': 'none'})
            self.assertFalse((f.base / 'backup').exists())

    def test_install_then_rollback(self):
        with environment() as f:
            backup = f.base / 'backup'
            f.install(backup)
            f.assert_installed(self)
            self.assertTrue(any(c[0] == '/usr/bin/codesign' and '--verify' in c for c in f.calls))
            fh4.rollback(backup, check_idle=False)
            f.assert_pristine(self)
            self.assertTrue((backup / 'manifest.json').is_file())

    def test_rollback_preserves_unrelated_registry_changes(self):
        with environment() as f:
            backup = f.base / 'backup'; f.install(backup)
            reg = f.bottle / 'user.reg'; reg.write_bytes(reg.read_bytes() + b'\n[Software\\\\Vendor\\\\App] 1\n"keep"="yes"\n')
            fh4.rollback(backup, check_idle=False)
            data = reg.read_bytes()
            self.assertEqual(fh4.reg_override_value(data), 'native')
            self.assertIn(b'"keep"="yes"', data)

    def test_failure_restores_app_and_bottle(self):
        with environment() as f:
            backup = f.base / 'backup'; f.fail_codesign = True
            with self.assertRaises(ValueError): f.install(backup)
            f.assert_pristine(self)
            self.assertTrue((backup / 'manifest.json').is_file())

    def test_mid_rollback_failure_reverts_both_sides(self):
        with environment() as f:
            backup = f.base / 'backup'; f.install(backup)
            installed_tree = fh4.tree_digest(f.app)
            real = fh4.restore_entries; calls = []

            def flaky(entries, backup_dir, bottle):
                calls.append(1)
                if len(calls) == 1:
                    real(entries[:1], backup_dir, bottle)
                    raise ValueError('simulated mid-rollback failure')
                return real(entries, backup_dir, bottle)

            with mock.patch.object(fh4, 'restore_entries', flaky):
                with self.assertRaises(ValueError): fh4.rollback(backup, check_idle=False)
            self.assertEqual(fh4.tree_digest(f.app), installed_tree)
            f.assert_installed(self)
            self.assertFalse((f.app.parent / (f.app.name + '.fh4-rollback-stage')).exists())
            self.assertTrue((backup / 'pre-rollback').is_dir())

    def test_manifest_and_snapshot_tampering_is_detected(self):
        with environment() as f:
            backup = f.base / 'backup'; f.install(backup)
            manifest_path = backup / 'manifest.json'
            original = json.loads(manifest_path.read_text())

            bad = json.loads(json.dumps(original)); bad['bottle_entries'][0]['path'] = '../escape'
            manifest_path.write_text(json.dumps(bad))
            with self.assertRaises(ValueError): fh4.rollback(backup, check_idle=False)
            f.assert_installed(self)

            bad = json.loads(json.dumps(original)); entry = bad['bottle_entries'][0]
            write(backup / entry['backup'], b'tampered')
            manifest_path.write_text(json.dumps(bad))
            with self.assertRaises(ValueError): fh4.rollback(backup, check_idle=False)
            f.assert_installed(self)

            bad = json.loads(json.dumps(original)); bad['bottle_override']['path'] = 'cxbottle.conf'
            manifest_path.write_text(json.dumps(bad))
            with self.assertRaises(ValueError): fh4.rollback(backup, check_idle=False)
            f.assert_installed(self)

            bad = json.loads(json.dumps(original))
            bad['bottle_override']['previous'] = '!!!not-base64!!!'
            manifest_path.write_text(json.dumps(bad))
            with self.assertRaises(ValueError): fh4.rollback(backup, check_idle=False)
            f.assert_installed(self)

            manifest_path.write_text(json.dumps(original))
            write(backup / 'app/Contents/Injected', b'evil')
            with self.assertRaises(ValueError): fh4.rollback(backup, check_idle=False)
            f.assert_installed(self)

    def test_repeat_install_requires_replace_and_is_reversible(self):
        with environment() as f:
            first = f.base / 'backup-1'; f.install(first)
            f.assert_installed(self)
            with self.assertRaises(ValueError): f.install(f.base / 'backup-2')
            self.assertFalse((f.base / 'backup-2').exists())
            second = f.base / 'backup-2'; f.install(second, replace=True)
            f.assert_installed(self)
            fh4.rollback(second, check_idle=False)
            f.assert_installed(self)
            fh4.rollback(first, check_idle=False)
            f.assert_pristine(self)

    def test_foreign_state_is_never_overwritten(self):
        with environment() as f:
            write(f.cx / fh4.WIN / 'apd12.dll', b'unexpected')
            _, _, _, _, st = fh4.preflight(f.app, f.bottle, None, need_idle=False)
            self.assertEqual(st['kind'], 'foreign')
            with self.assertRaises(ValueError): f.install(f.base / 'backup', replace=True)
            self.assertEqual((f.cx / fh4.WIN / 'apd12.dll').read_bytes(), b'unexpected')
            self.assertFalse((f.base / 'backup').exists())

    def test_missing_or_wrong_d3d12_unix_glue_is_rejected(self):
        with environment() as f:
            glue = f.cx / fh4.UNIX / 'd3d12.so'; glue.unlink(); write(glue, b'regular file')
            with self.assertRaises(ValueError):
                fh4.preflight(f.app, f.bottle, None, need_idle=False)

    def test_real_payload_inventory_when_present(self):
        root = Path(__file__).resolve().parents[1] / 'payloads'
        if not all((root / n).is_file() for n in fh4.SHA): self.skipTest('Local payloads are not present')
        for name in ('d3d12.dll', 'apd12.dll'):
            info = fh4.inspect_payload(root / name)
            self.assertEqual(info['sha256'], fh4.SHA[name])
            self.assertEqual(info['exports'], 11)
            self.assertEqual(set(info['export_ordinals'].values()), set(range(100, 111)))
        shim = fh4.inspect_payload(root / 'd3d12.dll')
        self.assertIn('d3d12.c', shim['coff_modules'])
        self.assertIn('DllMain', shim['coff_functions'])
        self.assertIn('KERNEL32.dll', shim['imports'])
        unix = fh4.inspect_payload(root / 'apd12.dll')
        self.assertIn('ne_init_unix_call', unix['coff_functions'])
        self.assertIn('ne_unix_call_dispatcher', unix['coff_functions'])
        self.assertIn('user32.dll', unix['imports'])
        self.assertNotIn('d3d12core.dll', [n.lower() for n in unix['imports']])

    def test_import_payloads_from_original_tool_layout(self):
        with environment() as f:
            source = f.base / 'Original.app/Contents/Resources/patches'
            for name, data in f.payload_data.items(): write(source / name, data)
            target = f.base / 'imported'
            with mock.patch.object(fh4, 'PAYLOADS', target):
                fh4.import_payloads(f.base / 'Original.app')
            for name, data in f.payload_data.items():
                self.assertEqual((target / name).read_bytes(), data)


if __name__ == '__main__':
    unittest.main()
