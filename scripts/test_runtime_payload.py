#!/usr/bin/env python3
"""Portable integrity and dependency regression tests. Owner: @DNPMBHC."""
import ast
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import plistlib
import tempfile
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location('runtime_payload', Path(__file__).with_name('runtime_payload.py'))
payload = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(payload)


class PayloadIntegrityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='runtime-payload-test-')
        self.addCleanup(self.temporary.cleanup)
        self.app = Path(self.temporary.name) / 'demo-app.app'
        self.required = {
            'helperBinary': 'Contents/Helpers/Container.app/Contents/MacOS/container',
            'helperInfo': 'Contents/Helpers/Container.app/Contents/Info.plist',
            'containerControlBinary': 'Contents/Helpers/Container.app/Contents/MacOS/utmctl',
            'pythonExecutable': 'Contents/Frameworks/Python.framework/Versions/3.12/bin/python3.12',
            'pythonLicense': 'Contents/Frameworks/Python.framework/Versions/3.12/Resources/LICENSE.txt',
            'managerScript': 'Contents/Resources/RuntimeScripts/golden_guest_manager.py',
            'kioskScript': 'Contents/Resources/RuntimeScripts/kiosk-app-shell.ps1',
            'optimizerApplyScript': 'Contents/Resources/RuntimeScripts/apply-optimizer.ps1',
            'optimizerRollbackScript': 'Contents/Resources/RuntimeScripts/rollback-optimizer.ps1',
            'optimizerProfile': 'Contents/Resources/RuntimeScripts/anticheat-minimal-win11-arm64.json',
            'cursorBridgeScript': 'Contents/Resources/RuntimeScripts/malt-cursor-bridge.ps1',
            'provisioningGuide': 'Contents/Resources/RuntimeScripts/PROVISIONING.md',
            'provisioningGuideChinese': 'Contents/Resources/RuntimeScripts/PROVISIONING.zh-Hans.md',
            'networkHelper': 'Contents/Library/HelperTools/network-bridge',
            'networkService': 'Contents/Library/LaunchDaemons/com.example.network-bridge.plist',
            'userNetProxy': 'Contents/Helpers/malt-net-proxy',
        }
        for key, relative in self.required.items():
            path = self.app / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(key)
            if key in ('helperBinary', 'containerControlBinary', 'pythonExecutable',
                       'networkHelper', 'userNetProxy'):
                path.chmod(0o755)
        (self.app / self.required['helperInfo']).write_bytes(plistlib.dumps({
            'CFBundleExecutable': 'container', payload.HELPER_SETTINGS_CONTRACT_KEY: 1}))
        (self.app / self.required['networkService']).write_bytes(plistlib.dumps({
            'Label': 'com.example.network-bridge', 'BundleProgram': self.required['networkHelper']}))
        self.manifest = {
            'schema': payload.SCHEMA,
            'prerequisites': {'guestImageBundled': False, 'wineRuntimeBundled': False,
                              'externalSetupRequired': True,
                              'nativeNetworkDistributionRequiresNotarization': True},
            'requiredResources': self.required.copy(),
            'managedRoots': list(self.required.values()),
            'files': payload.inventory_files(self.app, list(self.required.values())),
        }

    def test_outer_signing_preserves_all_inventoried_code_including_network_bridge(self):
        manifest_path = self.app / payload.MANIFEST_RELATIVE
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(json.dumps(self.manifest))
        exclusions = payload.outer_signing_exclusions(self.app)
        self.assertTrue(set(self.manifest['managedRoots']).issubset(exclusions))
        self.assertIn(self.required['networkHelper'], exclusions)

    def test_outer_signing_refuses_to_preserve_a_changed_payload(self):
        manifest_path = self.app / payload.MANIFEST_RELATIVE
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        manifest_path.write_text(json.dumps(self.manifest))
        (self.app / self.required['networkHelper']).write_text('modified')
        with self.assertRaises(payload.PayloadError):
            payload.outer_signing_exclusions(self.app)

    def test_complete_payload_passes_portable_integrity_check(self):
        self.assertEqual(payload.verify_manifest(self.app, self.manifest), [])

    def test_each_required_resource_is_independently_enforced(self):
        for key, relative in self.required.items():
            with self.subTest(resource=key):
                path = self.app / relative
                original = path.read_bytes()
                mode = path.stat().st_mode
                path.unlink()
                self.assertIn('missing_required_' + key, payload.verify_manifest(self.app, self.manifest))
                path.write_bytes(original)
                path.chmod(mode)

    def test_legacy_helper_is_rejected_even_with_matching_inventory(self):
        info = self.app / self.required['helperInfo']
        info.write_bytes(plistlib.dumps({'CFBundleExecutable': 'container'}))
        self.manifest['files'] = payload.inventory_files(self.app, self.manifest['managedRoots'])
        self.assertEqual(payload.verify_manifest(self.app, self.manifest),
                         ['unsupported_helper_settings_contract'])

    def test_modified_file_is_rejected(self):
        (self.app / self.required['managerScript']).write_text('tampered')
        self.assertIn('file_hash_mismatch', payload.verify_manifest(self.app, self.manifest))

    def test_false_ready_claim_is_rejected(self):
        for key in self.manifest['prerequisites']:
            with self.subTest(claim=key):
                data = copy.deepcopy(self.manifest)
                data['prerequisites'][key] = not data['prerequisites'][key]
                self.assertIn('invalid_prerequisite_' + key, payload.verify_manifest(self.app, data))

    def test_missing_requirement_cannot_be_hidden_by_inventory(self):
        del self.manifest['requiredResources']['pythonLicense']
        self.assertIn('incomplete_required_resources', payload.verify_manifest(self.app, self.manifest))

    def test_required_file_cannot_be_removed_from_inventory(self):
        del self.manifest['files'][self.required['pythonLicense']]
        self.assertIn('missing_required_pythonLicense', payload.verify_manifest(self.app, self.manifest))

    def test_program_executable_bit_is_enforced(self):
        (self.app / self.required['networkHelper']).chmod(0o644)
        self.assertIn('not_executable_networkHelper', payload.verify_manifest(self.app, self.manifest))

    def test_user_net_proxy_executable_bit_and_tampering_are_enforced(self):
        proxy = self.app / self.required['userNetProxy']
        proxy.chmod(0o644)
        self.assertIn('not_executable_userNetProxy', payload.verify_manifest(self.app, self.manifest))
        proxy.chmod(0o755)
        proxy.write_text('tampered-proxy')
        self.assertIn('file_hash_mismatch', payload.verify_manifest(self.app, self.manifest))

    def test_service_cannot_point_to_another_binary(self):
        service = self.app / self.required['networkService']
        service.write_bytes(plistlib.dumps({'BundleProgram': 'Contents/MacOS/other'}))
        self.assertIn('service_program_mismatch', payload.verify_manifest(self.app, self.manifest))

    def test_absolute_or_parent_paths_are_rejected(self):
        for path in ('/tmp/outside', '../outside', 'Contents/../../outside', 'Contents//bad',
                     'Contents/./bad', 'Contents/bad\\name', 'Library/bad'):
            with self.subTest(path=path), self.assertRaises(payload.PayloadError):
                payload.contained_path(self.app, path)

    def test_symlink_escape_is_rejected(self):
        link = self.app / 'Contents/escape'
        link.symlink_to(Path(self.temporary.name))
        with self.assertRaises(payload.PayloadError):
            payload.contained_path(self.app, 'Contents/escape/outside')

    def test_relative_symlink_hash_is_checked(self):
        link = self.app / 'Contents/Resources/RuntimeScripts/manager-link'
        link.symlink_to('golden_guest_manager.py')
        self.manifest['managedRoots'].append(link.relative_to(self.app).as_posix())
        self.manifest['files'].update(payload.inventory_files(self.app, [link.relative_to(self.app).as_posix()]))
        self.assertEqual(payload.verify_manifest(self.app, self.manifest), [])
        link.unlink()
        link.symlink_to('kiosk-app-shell.ps1')
        self.assertIn('symlink_mismatch', payload.verify_manifest(self.app, self.manifest))

    def test_untracked_file_is_rejected(self):
        root = 'Contents/Resources/RuntimeScripts'
        self.manifest['managedRoots'].append(root)
        (self.app / root / 'extra.py').write_text('unexpected')
        self.assertIn('untracked_or_missing_payload_files', payload.verify_manifest(self.app, self.manifest))

    def test_development_cache_in_helper_is_rejected(self):
        helper = 'Contents/Helpers/Container.app'
        self.manifest['managedRoots'].append(helper)
        (self.app / helper / '.git').mkdir()
        self.assertIn('development_artifact_in_payload', payload.verify_manifest(self.app, self.manifest))

    def test_runtime_logs_are_rejected_even_when_inventoried_under_managed_roots(self):
        for root in ('Contents/Helpers/Container.app',
                     'Contents/Frameworks/Python.framework',
                     'Contents/Resources/RuntimeScripts'):
            for suffix in ('.log', '.jsonl', '.ndjson', '.crash', '.ips', '.dmp'):
                with self.subTest(root=root, suffix=suffix):
                    path = self.app / root / ('session' + suffix)
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text('synthetic diagnostic event')
                    self.assertIn('runtime_log_in_payload', payload.audit_payload_tree(self.app, [root]))
                    path.unlink()

    def test_guest_disks_and_bundles_are_rejected_without_rejecting_firmware(self):
        root = 'Contents/Helpers/Container.app'
        for suffix in ('.qcow', '.qcow2', '.vdi', '.vmdk', '.vhd', '.vhdx', '.vmem', '.vmss', '.vmsn'):
            with self.subTest(suffix=suffix):
                path = self.app / root / ('disk' + suffix)
                path.write_bytes(b'synthetic guest data')
                self.assertIn('guest_data_in_payload', payload.audit_payload_tree(self.app, [root]))
                path.unlink()
        for suffix in ('.utm', '.pvm', '.vmwarevm'):
            with self.subTest(suffix=suffix):
                bundle = self.app / root / ('guest' + suffix)
                bundle.mkdir()
                self.assertIn('guest_data_in_payload', payload.audit_payload_tree(self.app, [root]))
                bundle.rmdir()
        firmware = self.app / root / 'firmware.img'
        firmware.write_bytes(b'synthetic release firmware')
        self.assertEqual(payload.audit_payload_tree(self.app, [root]), [])

    def test_user_preferences_caches_and_environment_files_are_rejected(self):
        root = 'Contents/Helpers/Container.app'
        for relative in ('Contents/Library/Preferences/com.example.synthetic.plist',
                         'Contents/Library/Caches/cache.bin',
                         'Contents/Library/Saved Application State/state.data',
                         'Contents/Resources/.cache/state', 'Contents/Resources/.config/settings',
                         'Contents/Resources/.local/state', 'Contents/Resources/Logs/session.txt',
                         'Contents/Resources/.env', 'Contents/Resources/.env.local'):
            with self.subTest(relative=relative):
                with tempfile.TemporaryDirectory(prefix='payload-state-test-') as temporary:
                    app = Path(temporary) / 'demo-app.app'
                    path = app / root / relative
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_text('synthetic user state')
                    self.assertIn('user_state_in_payload', payload.audit_payload_tree(app, [root]))

    def test_required_release_metadata_and_standard_library_remain_allowed(self):
        root = 'Contents/Resources/RuntimeScripts'
        for name in ('Info.plist', 'LICENSE.txt', 'settings.json', 'cache.py', 'logging/__init__.py'):
            path = self.app / root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('synthetic release content')
        self.assertEqual(payload.audit_payload_tree(self.app, [root]), [])

    def test_managed_payload_verification_rejects_inventoried_user_data(self):
        root = 'Contents/Helpers/Container.app'
        data = self.app / root / 'session.log'
        data.write_text('synthetic diagnostic event')
        self.manifest['managedRoots'].append(root)
        self.manifest['files'] = payload.inventory_files(self.app, self.manifest['managedRoots'])
        self.assertEqual(payload.verify_manifest(self.app, self.manifest), ['runtime_log_in_payload'])

    def test_finder_metadata_is_rejected_under_managed_roots(self):
        root = 'Contents/Helpers/Container.app'
        (self.app / root / '.DS_Store').write_bytes(b'synthetic finder state')
        self.assertIn('development_artifact_in_payload', payload.audit_payload_tree(self.app, [root]))

    def test_private_build_paths_are_rejected_without_recording_them(self):
        script = self.app / self.required['managerScript']
        script.write_text('/private/synthetic-user/workspace')
        result = payload.audit_payload_tree(self.app, [self.required['managerScript']],
                                            [Path('/private/synthetic-user')])
        self.assertEqual(result, ['private_build_path_in_payload'])

    def test_cyclic_symlink_is_rejected_without_a_raw_path_error(self):
        link = self.app / 'Contents/cycle'
        link.symlink_to('cycle')
        with self.assertRaises(payload.PayloadError):
            payload.contained_path(self.app, 'Contents/cycle')

    def test_private_python_sources_are_rejected(self):
        with self.assertRaises(payload.PayloadError):
            payload.official_python_prefix(Path(self.temporary.name) / 'private-runtime/3.12')

    def test_source_layout_requires_both_scripts_and_service(self):
        workspace = Path(self.temporary.name) / 'workspace'
        (workspace / 'graphics-lab').mkdir(parents=True)
        (workspace / 'graphics-lab/golden_guest_manager.py').write_text('manager')
        (workspace / 'demo-app/.git').mkdir(parents=True)
        with self.assertRaises(payload.PayloadError):
            payload.source_layout(workspace)

    def test_inventory_contains_only_relative_paths(self):
        serialized = json.dumps(self.manifest)
        self.assertNotIn(self.temporary.name, serialized)
        self.assertNotIn('/Users/', serialized)

    def test_unknown_manifest_schema_fails_closed(self):
        self.manifest['schema'] = 'unrecognized'
        self.assertEqual(payload.verify_manifest(self.app, self.manifest), ['unsupported_manifest_schema'])

    def test_malformed_inventory_fails_closed(self):
        self.manifest['files'][self.required['managerScript']] = 'invalid'
        self.assertIn('unsafe_or_unreadable_inventory_file', payload.verify_manifest(self.app, self.manifest))


class HelperSettingsContractTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='helper-contract-test-')
        self.addCleanup(self.temporary.cleanup)
        self.app = Path(self.temporary.name) / 'demo-app.app'
        self.helper = self.app / 'Contents/Helpers/Container.app'
        self.info = self.helper / 'Contents/Info.plist'
        binary = self.helper / 'Contents/MacOS/container'
        binary.parent.mkdir(parents=True)
        for path in (binary, binary.with_name('utmctl')):
            path.write_text('synthetic executable')
            path.chmod(0o755)
        self.write_info(1)

    def write_info(self, version=None):
        info = {'CFBundleExecutable': 'container'}
        if version is not None:
            info[payload.HELPER_SETTINGS_CONTRACT_KEY] = version
        self.info.write_bytes(plistlib.dumps(info))

    def test_current_and_future_integer_contracts_are_supported(self):
        for version in (1, 2, 10):
            with self.subTest(version=version):
                self.write_info(version)
                self.assertEqual(payload.helper_settings_contract_version(self.info), version)
                self.assertEqual(payload.select_helper(self.app)[0], self.helper)

    def test_missing_legacy_and_wrong_type_versions_fail_closed(self):
        for version in (None, 0, -1, True, False, 1.0, '1', [], {}):
            with self.subTest(version=version):
                self.write_info(version)
                with self.assertRaises(payload.PayloadError):
                    payload.helper_settings_contract_version(self.info)
                with self.assertRaises(payload.PayloadError):
                    payload.select_helper(self.app)

    def test_unreadable_or_invalid_plist_has_no_private_path_in_error(self):
        for data in (None, b'invalid plist', plistlib.dumps(['not-a-dictionary'])):
            with self.subTest(data=data):
                if data is None:
                    self.info.unlink(missing_ok=True)
                else:
                    self.info.write_bytes(data)
                with self.assertRaises(payload.PayloadError) as error:
                    payload.helper_settings_contract_version(self.info)
                self.assertNotIn(self.temporary.name, str(error.exception))

    def test_embedding_rejects_legacy_helper_before_signing_or_payload_changes(self):
        self.write_info()
        before = sorted(path.relative_to(self.app).as_posix() for path in self.app.rglob('*'))
        with mock.patch.object(payload.sys, 'platform', 'darwin'), \
             mock.patch.object(payload, 'resign_nested_code') as signer, \
             mock.patch.object(payload, 'source_layout') as sources, \
             mock.patch.object(payload, 'run') as command:
            with self.assertRaises(payload.PayloadError):
                payload.embed(self.app, Path(self.temporary.name) / 'workspace')
        signer.assert_not_called()
        sources.assert_not_called()
        command.assert_not_called()
        self.assertEqual(before, sorted(path.relative_to(self.app).as_posix()
                                       for path in self.app.rglob('*')))

    def test_command_reports_supported_contract_without_executing_code(self):
        with mock.patch('builtins.print') as output, mock.patch.object(payload, 'run') as command:
            result = payload.main(['check-helper-settings', '--helper-app', str(self.helper)])
        self.assertEqual(result, 0)
        self.assertEqual(json.loads(output.call_args.args[0]), {
            'minimumRuntimeSettingsContractVersion': 1,
            'runtimeSettingsContractVersion': 1, 'passed': True})
        command.assert_not_called()

    def test_command_rejects_legacy_helper_without_disclosing_its_location(self):
        self.write_info()
        with mock.patch('builtins.print') as output:
            result = payload.main(['check-helper-settings', '--helper-app', str(self.helper)])
        self.assertEqual(result, 1)
        report = json.loads(output.call_args.args[0])
        self.assertFalse(report['passed'])
        self.assertNotIn(self.temporary.name, json.dumps(report))


class DependencyTests(unittest.TestCase):
    def test_universal_otool_listing_is_deduplicated(self):
        listing = ('binary (architecture arm64):\n'
                   '\t/Library/Frameworks/Python.framework/Versions/3.12/Python (compatibility version 3.12.0, current version 3.12.0)\n'
                   'binary (architecture x86_64):\n'
                   '\t/Library/Frameworks/Python.framework/Versions/3.12/Python (compatibility version 3.12.0, current version 3.12.0)\n')
        self.assertEqual(len(payload.dependency_paths(listing)), 1)

    def test_framework_dependency_becomes_loader_relative(self):
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / 'Python.framework/Versions/3.12'
            (destination / 'bin').mkdir(parents=True)
            (destination / 'Python').write_text('framework')
            source = Path('/Library/Frameworks/Python.framework/Versions/3.12')
            self.assertEqual(payload.relocated_dependency(destination / 'bin/python3.12',
                             str(source / 'Python'), source, destination), '@loader_path/../Python')

    def test_unbundled_external_dependency_is_rejected(self):
        with self.assertRaises(payload.PayloadError):
            payload.relocated_dependency(Path('/tmp/app/binary'), '/opt/homebrew/lib/libprivate.dylib',
                                         Path('/Library/Frameworks/Python.framework/Versions/3.12'), Path('/tmp/app'))

    def test_system_dependencies_are_preserved(self):
        for dependency in ('/usr/lib/libSystem.B.dylib', '/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation'):
            self.assertIsNone(payload.relocated_dependency(Path('/tmp/app/binary'), dependency,
                              Path('/Library/Frameworks/Python.framework/Versions/3.12'), Path('/tmp/app')))

    def test_python_exclusions_remove_caches_packages_and_gui(self):
        names = ['site-packages', '__pycache__', 'test', 'tests', 'idlelib', 'tkinter', 'ensurepip',
                 '_tkinter.cpython-312-darwin.so', 'socket.py', 'ssl.py']
        ignored = payload.ignored_python_files('lib', names)
        self.assertEqual(set(names) - set(ignored), {'socket.py', 'ssl.py'})

    def test_clean_environment_ignores_developer_overrides(self):
        env = payload.clean_environment(Path('/tmp/isolated-home'))
        self.assertNotIn('PYTHONPATH', env)
        self.assertNotIn('PYTHONHOME', env)
        self.assertNotIn('DYLD_LIBRARY_PATH', env)
        self.assertEqual(env['PATH'], '/usr/bin:/bin:/usr/sbin:/sbin')

    def test_ad_hoc_interpreter_does_not_require_relaxed_entitlements(self):
        with mock.patch.object(payload, 'run') as command:
            payload.sign(Path('/tmp/interpreter'), '-', hardened=False)
        args = command.call_args.args[0]
        self.assertNotIn('--options', args)
        self.assertNotIn('--entitlements', args)
        self.assertIn('--sign', args)

    def test_regular_release_signature_keeps_hardened_runtime(self):
        with mock.patch.object(payload, 'run') as command:
            payload.sign(Path('/tmp/interpreter'), 'certificate-id')
        self.assertIn('runtime', command.call_args.args[0])

    def test_macho_magic_recognizes_universal_binary(self):
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / 'binary'
            binary.write_bytes(b'\xca\xfe\xba\xbe' + b'placeholder')
            self.assertTrue(payload.is_macho(binary))


class PayloadDependencyTests(unittest.TestCase):
    def test_load_commands_exclude_own_install_name(self):
        listing = ("Load command 1\n      cmd LC_ID_DYLIB\n  cmdsize 80\n"
                   "     name /private/synthetic-build/libmodule.dylib (offset 24)\n"
                   "Load command 2\n      cmd LC_LOAD_DYLIB\n  cmdsize 80\n"
                   "     name @rpath/libmodule.dylib (offset 24)\n")
        self.assertEqual(payload.load_dependency_paths(listing), ['@rpath/libmodule.dylib'])

    def test_all_dylib_load_command_variants_are_checked(self):
        for command in ('LC_LOAD_DYLIB', 'LC_LOAD_WEAK_DYLIB', 'LC_REEXPORT_DYLIB',
                        'LC_LOAD_UPWARD_DYLIB', 'LC_LAZY_LOAD_DYLIB'):
            with self.subTest(command=command):
                listing = f'      cmd {command}\n     name /opt/third-party/libmodule.dylib (offset 24)\n'
                self.assertEqual(payload.load_dependency_paths(listing), ['/opt/third-party/libmodule.dylib'])

    def test_helper_absolute_dependency_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            app = Path(directory) / 'demo-app.app'
            helper = app / 'Contents/Helpers/Container.app/Contents/MacOS/container'
            helper.parent.mkdir(parents=True)
            helper.write_bytes(b'\xca\xfe\xba\xbe' + b'placeholder')
            listing = '      cmd LC_LOAD_DYLIB\n     name /opt/third-party/libmodule.dylib (offset 24)\n'
            with mock.patch.object(payload, 'run', return_value=listing), self.assertRaises(payload.PayloadError):
                payload.verify_payload_dependencies(app, ['Contents/Helpers'])

    def test_system_and_relative_dependencies_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            app = Path(directory) / 'demo-app.app'
            helper = app / 'Contents/Helpers/Container.app/Contents/MacOS/container'
            helper.parent.mkdir(parents=True)
            helper.write_bytes(b'\xca\xfe\xba\xbe' + b'placeholder')
            names = ['/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation',
                     '/usr/lib/libSystem.B.dylib', '@rpath/libmodule.dylib', '@loader_path/libmodule.dylib']
            listing = ''.join(f'      cmd LC_LOAD_DYLIB\n     name {name} (offset 24)\n' for name in names)
            with mock.patch.object(payload, 'run', return_value=listing):
                report = payload.verify_payload_dependencies(app, ['Contents/Helpers', helper.relative_to(app).as_posix()])
            self.assertEqual(report['machOCount'], 1)
            self.assertTrue(report['systemOrRelativeDependenciesOnly'])


class SigningAndDistributionTests(unittest.TestCase):
    def result(self, *, output='', code=0):
        from types import SimpleNamespace
        return SimpleNamespace(returncode=code, stdout='', stderr=output)

    def details(self, *, timestamp=True, team=True):
        text = 'Authority=Developer ID Application: Example Publisher\n'
        text += 'TeamIdentifier=SYNTHETIC1\n' if team else 'TeamIdentifier=not set\n'
        if timestamp:
            text += 'Timestamp=Jan 1, 2026 at 00:00:00\n'
        return self.result(output=text)

    def assess(self, *, details=None, gatekeeper=None, staple=None, signature=None):
        results = [details or self.details(), gatekeeper or self.result(
                   output='accepted\nsource=Notarized Developer ID\n'),
                   staple or self.result(), signature or self.result()]
        with mock.patch.object(payload, 'assessment_result', side_effect=results):
            return payload.assess_distribution(Path('/tmp/demo-app.app'))

    def test_developer_id_signature_requests_secure_timestamp(self):
        with mock.patch.object(payload, 'run') as command:
            payload.sign(Path('/tmp/interpreter'), 'certificate-id')
        self.assertIn('--timestamp', command.call_args.args[0])
        self.assertNotIn('--timestamp=none', command.call_args.args[0])

    def test_ad_hoc_signature_keeps_timestamp_disabled(self):
        with mock.patch.object(payload, 'run') as command:
            payload.sign(Path('/tmp/interpreter'), '-')
        self.assertIn('--timestamp=none', command.call_args.args[0])

    def test_complete_distribution_evidence_passes(self):
        self.assertTrue(self.assess()['distributable'])

    def test_local_policy_acceptance_is_insufficient(self):
        details = self.result(output='Signature=adhoc\nTeamIdentifier=not set\n')
        with mock.patch.object(payload, 'assessment_result', side_effect=[details, self.result(), self.result()]):
            report = payload.assess_distribution(Path('/tmp/demo-app.app'))
        self.assertTrue(report['gatekeeperAccepted'])
        self.assertFalse(report['distributable'])
        self.assertFalse(report['notarizationVerified'])

    def test_missing_timestamp_blocks_distribution(self):
        self.assertFalse(self.assess(details=self.details(timestamp=False))['distributable'])

    def test_missing_team_blocks_distribution(self):
        self.assertFalse(self.assess(details=self.details(team=False))['distributable'])

    def test_missing_notarization_blocks_distribution(self):
        report = self.assess(gatekeeper=self.result(output='accepted\nsource=Developer ID\n'),
                             staple=self.result(code=1))
        self.assertFalse(report['notarizationVerified'])
        self.assertFalse(report['distributable'])

    def test_notarized_gatekeeper_source_can_verify_without_staple(self):
        report = self.assess(staple=self.result(code=1))
        self.assertTrue(report['gatekeeperNotarizedSource'])
        self.assertTrue(report['distributable'])

    def test_invalid_nested_signature_blocks_distribution(self):
        self.assertFalse(self.assess(signature=self.result(code=1))['distributable'])

    def test_entitlements_are_preserved_for_each_signing_target(self):
        with tempfile.TemporaryDirectory() as directory:
            app = Path(directory) / 'Container.app'
            executable = app / 'Contents/MacOS/container'
            executable.parent.mkdir(parents=True)
            executable.write_bytes(b'\xca\xfe\xba\xbe' + b'placeholder')
            info = app / 'Contents/Info.plist'
            info.write_bytes(plistlib.dumps({'CFBundleExecutable': 'container'}))
            capabilities = {'com.example.synthetic-capability': True}
            with mock.patch.object(payload, 'existing_entitlements', return_value=capabilities), \
                 mock.patch.object(payload, 'sign') as signer, mock.patch.object(payload, 'run'):
                result = payload.resign_nested_code(app, '-', include_root=True)
            self.assertEqual([call.args[0] for call in signer.call_args_list], [executable, app])
            self.assertTrue(all(call.kwargs['entitlements'] == capabilities for call in signer.call_args_list))
            self.assertEqual(result['signedCodeCount'], 2)

    def test_payload_managed_code_is_not_resigned_by_outer_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            app = Path(directory) / 'demo-app.app'
            binary = app / 'Contents/Helpers/Container.app/Contents/MacOS/container'
            binary.parent.mkdir(parents=True)
            binary.write_bytes(b'\xca\xfe\xba\xbe' + b'placeholder')
            with mock.patch.object(payload, 'existing_entitlements'), mock.patch.object(payload, 'sign') as signer:
                payload.resign_nested_code(app, '-', exclusions=('Contents/Helpers',))
            signer.assert_not_called()


class PackagingManifestPathTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        scripts = [path for path in Path(__file__).parent.glob('*dmg.sh')
                   if 'def artifact_manifest_location(' in path.read_text()]
        if len(scripts) != 1:
            raise AssertionError('Expected one packaging manifest producer')
        embedded = scripts[0].read_text().rsplit("<<'PY'\n", 1)[1].split('\nPY\n', 1)[0]
        cls.manifest_tree = ast.parse(embedded)
        function = next(node for node in cls.manifest_tree.body
                        if isinstance(node, ast.FunctionDef) and node.name == 'artifact_manifest_location')
        namespace = {'pathlib': importlib.import_module('pathlib')}
        exec(compile(ast.Module(body=[function], type_ignores=[]), '<packaging-manifest>', 'exec'), namespace)
        cls.location = staticmethod(namespace['artifact_manifest_location'])

    def test_workspace_output_uses_actual_relative_location(self):
        with tempfile.TemporaryDirectory(prefix='manifest-path-test-') as directory:
            workspace = Path(directory)
            for output in ('my-project/build/release/demo-app.dmg', 'my-project/build/custom/demo-app.dmg'):
                with self.subTest(output=output):
                    self.assertEqual(self.location(workspace / output, workspace), {
                        'relativePath': output, 'pathScope': 'workspace-relative'})

    def test_workspace_location_normalizes_relative_components(self):
        with tempfile.TemporaryDirectory(prefix='manifest-path-test-') as directory:
            workspace = Path(directory)
            output = workspace / 'my-project/build/staging/../custom output/demo-app.dmg'
            self.assertEqual(self.location(output, workspace), {
                'relativePath': 'my-project/build/custom output/demo-app.dmg',
                'pathScope': 'workspace-relative'})

    def test_external_output_uses_filename_only_and_explicit_scope(self):
        with tempfile.TemporaryDirectory(prefix='manifest-path-test-') as directory:
            root = Path(directory)
            output = root / 'external/demo-app.dmg'
            location = self.location(output, root / 'my-project')
            self.assertEqual(location, {'relativePath': 'demo-app.dmg', 'pathScope': 'filename-only'})
            self.assertNotIn(str(root), json.dumps(location))

    def test_workspace_symlink_to_external_output_does_not_expose_target(self):
        with tempfile.TemporaryDirectory(prefix='manifest-path-test-') as directory:
            root = Path(directory)
            workspace = root / 'my-project'
            workspace.mkdir()
            external = root / 'external'
            external.mkdir()
            (workspace / 'output').symlink_to(external, target_is_directory=True)
            self.assertEqual(self.location(workspace / 'output/demo-app.dmg', workspace), {
                'relativePath': 'demo-app.dmg', 'pathScope': 'filename-only'})

    def test_dmg_report_uses_location_contract(self):
        dictionaries = [node.value for node in ast.walk(self.manifest_tree)
                        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Dict)
                        and any(isinstance(target, ast.Name) and target.id == 'dmg_info'
                                for target in node.targets)]
        self.assertEqual(len(dictionaries), 1)
        unpacked = [value for key, value in zip(dictionaries[0].keys, dictionaries[0].values) if key is None]
        self.assertEqual(len(unpacked), 1)
        self.assertEqual(ast.unparse(unpacked[0]), 'artifact_manifest_location(dmg_path, repo.parent)')


class ProvisioningGuideTests(unittest.TestCase):
    def test_guides_explain_explicit_import_without_engine_launch(self):
        for guide in (payload.PROVISIONING, payload.PROVISIONING_ZH):
            self.assertIn("import-playable", guide)
            self.assertIn("--confirmed-stopped", guide)
            self.assertIn("requiredResources.pythonExecutable", guide)
            self.assertIn("Developer ID", guide)
            self.assertIn("SMAppService", guide)
            self.assertIn("@DNPMBHC", guide)
        self.assertIn("engine registration if needed without starting the guest", payload.PROVISIONING)
        self.assertIn("应用会按需仅准备引擎登记，不启动来宾", payload.PROVISIONING_ZH)

    def test_guides_scope_notarization_to_distribution_and_registration_to_user_action(self):
        self.assertIn("distribution policy, not an unconditional notarization", payload.PROVISIONING)
        self.assertIn("packaging process itself does not install", payload.PROVISIONING)
        self.assertIn("explicitly enable native networking", payload.PROVISIONING)
        self.assertNotIn("signed and notarized\nLaunchDaemon", payload.PROVISIONING)
        self.assertIn("打包过程本身不会安装、注册、批准或启动服务", payload.PROVISIONING_ZH)
        self.assertIn("管理员必须在 macOS 系统设置", payload.PROVISIONING_ZH)


if __name__ == '__main__':
    unittest.main()
