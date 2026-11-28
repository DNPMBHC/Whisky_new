#!/usr/bin/env python3
"""Build and verify a relocatable application payload without installing services.

Owner: @DNPMBHC
Only public system-installed Python may be embedded; guest images, Wine engines,
and administrator approval remain explicit external prerequisites.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
import time

MANIFEST_RELATIVE = 'Contents/Resources/runtime-payload.json'
SCHEMA = 'runtime-payload-v1'
HELPER_SETTINGS_CONTRACT_KEY = 'UTMRuntimeSettingsContractVersion'
MIN_HELPER_SETTINGS_CONTRACT_VERSION = 1
SCRIPT_NAMES = (
    'golden_guest_manager.py',
    'kiosk-app-shell.ps1',
    'apply-optimizer.ps1',
    'rollback-optimizer.ps1',
    'anticheat-minimal-win11-arm64.json',
    'malt-cursor-bridge.ps1',
)
USER_NET_PROXY_RELATIVE = 'Contents/Helpers/malt-net-proxy'
BLOCKED_DIRECTORIES = {'site-packages', '__pycache__', 'test', 'tests', 'idlelib',
                       'tkinter', 'turtledemo', 'ensurepip', 'include'}
MACHO_MAGIC = {b'\xfe\xed\xfa\xce', b'\xce\xfa\xed\xfe', b'\xfe\xed\xfa\xcf',
               b'\xcf\xfa\xed\xfe', b'\xca\xfe\xba\xbe', b'\xbe\xba\xfe\xca',
               b'\xca\xfe\xba\xbf', b'\xbf\xba\xfe\xca'}
PROVISIONING = """# Runtime prerequisites

Owner: @DNPMBHC

The application contains its container helper, private Python standard library,
management scripts, and native network helper. It does not include a Windows image,
a Windows license, Wine engines, installed games, or game licenses. A developer
workspace is never required; an external volume for your own guest is optional.

For a container, provide your own correctly licensed Windows ARM64 QEMU instance
with the required guest tools. In the application's native-network settings,
explicitly import the existing .utm working instance and confirm that it is fully
shut down and is not a template or cold backup. Close other container runtimes too.
Import checks identity, local writable disks, runtime processes, locks and suspend
state before creating private management metadata. It does not start, register,
copy, move or reconfigure the guest. Suspended guests must first shut down normally.

When you explicitly apply or restore native networking, the application prepares
engine registration if needed without starting the guest, then requires the engine
to confirm that the selected instance is stopped. There is no need to boot Windows
once just to obtain network permission. If a running control helper does not know
the selected instance, close its existing control windows and retry. Import
confirmation never bypasses the stopped-state check; network setup never boots a guest.
Before apply or restore, fully shut down the guest. Suspended or saved-state instances
are refused before writing; their configuration and saved network backup remain unchanged.
For Wine, configure a supported runtime, select its container, then save the actual
game executable; completing an installer is not proof of game readiness.

Diagnostic CLI alternative (replace the example application and instance paths):

```sh
APP="/Applications/demo-app.app"
PYTHON_REL=$(/usr/bin/plutil -extract requiredResources.pythonExecutable raw -o - "$APP/Contents/Resources/runtime-payload.json")
"$APP/$PYTHON_REL" -I "$APP/Contents/Resources/RuntimeScripts/golden_guest_manager.py" import-playable --playable "/path/to/playable-demo.utm" --confirmed-stopped
```

Only pass --confirmed-stopped after verifying a complete guest shutdown. This
import command needs no running helper and never registers or starts the engine.
The manager's default development profile is not a provisioning wizard.

Our normal distribution policy requires the complete application/release artifact
to be Developer ID signed and notarized, and its embedded LaunchDaemon to have a
valid signature. This is a distribution policy, not an unconditional notarization
requirement of the SMAppService API. Install the application in /Applications and
explicitly enable native networking. The application uses the system service API
to register its bundled daemon; an administrator must approve it in macOS System
Settings before it can run. The packaging process itself does not install,
register, approve or start a service. This is background-service approval, not Full
Disk Access; do not disable SIP or run the graphical application as root.

Ad-hoc packages prove local payload checks only, not Gatekeeper acceptance or
permission on another Mac. Resource checks and interpreter startup do not prove
commercial game launch, online service support or operation on another computer.
Packaging does not modify any game or anti-cheat files.
"""


PROVISIONING_ZH = """# 首次运行与环境准备

署名：@DNPMBHC

本应用已内嵌容器启动器、独立 Python 标准库、管理脚本与原生网络辅助程序。
本包没有内嵌 Windows 镜像、Windows 许可证、Wine 运行时、游戏或游戏许可证。
开发工作区不是运行前提；您自己的实例可保存在本机或外置磁盘。

容器方式：准备您有合法使用许可、已配置必要 guest tools 的 Windows ARM64
QEMU 实例。在应用的原生网络设置中明确导入已有 .utm 可玩工作实例，并确认
它已完全关闭，且不是模板或冷备。请同时退出其他容器运行环境。导入会检查
UUID、可写本地磁盘、活动进程、锁和挂起状态，然后建立私有管理标记，不会
启动、注册、复制、移动实例，也不会修改来宾配置或磁盘。挂起状态不算关闭，
应先让来宾正常关机。

您明确应用或恢复原生网络配置时，应用会按需仅准备引擎登记，不启动来宾，
随后要求引擎明确确认所选实例已停止，无需为获取网络权限先启动一次 Windows。
若已运行的控制程序尚未登记所选实例，请先关闭其现有控制窗口，再重试配置。
导入时的关闭确认不会绕过停止状态检查，网络配置也不会启动来宾。
应用或恢复网络前必须完全关机；存在挂起或保存状态时会在写入前拒绝操作，
实例配置和已有网络备份均不会改写。
Wine 方式请先配置受支持的 Wine 运行时，
再选择对应容器并保存实际游戏入口；安装器结束不等于游戏已经配置完成。

诊断命令行替代方式（请替换示例应用和实例路径）：

```sh
APP="/Applications/demo-app.app"
PYTHON_REL=$(/usr/bin/plutil -extract requiredResources.pythonExecutable raw -o - "$APP/Contents/Resources/runtime-payload.json")
"$APP/$PYTHON_REL" -I "$APP/Contents/Resources/RuntimeScripts/golden_guest_manager.py" import-playable --playable "/path/to/playable-demo.utm" --confirmed-stopped
```

只有核实来宾已完全关机后才可传入 --confirmed-stopped。此导入命令无需启动
辅助程序，不会注册或启动引擎。附带管理脚本的默认开发配置不是安装向导。

正式跨机分发策略：完整应用或发行制品须经过 Developer ID 签名和公证，内嵌
LaunchDaemon 须具备有效签名。这是本项目的发行要求，并非 SMAppService API
在所有场景下都无条件要求公证。将应用安装到 /Applications 后，主动启用原生
网络；应用通过系统服务 API 注册内嵌 daemon，管理员必须在 macOS 系统设置
中批准后它才能运行。打包过程本身不会安装、注册、批准或启动服务。此项是
后台服务授权，不是完全磁盘访问权限；无需关闭 SIP，也不应把图形界面提升
为 root。拒绝授权时应保留明确状态，不应显示原生网络已经启用。

ad-hoc 本地包只证明本机资源检查，不能证明其他 Mac 的 Gatekeeper 或特权服务
授权可用。资源校验和解释器启动通过，也不能代替真实游戏、在线服务及另一台
电脑的实际验证。打包不会修改游戏或反作弊文件。
"""


class PayloadError(RuntimeError):
    """A failure safe to show without private filesystem paths."""


def run(command, *, env=None, timeout=120):
    try:
        result = subprocess.run([str(item) for item in command], capture_output=True,
                                env=env, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise PayloadError('required system tool unavailable or timed out') from error
    if result.returncode:
        raise PayloadError('system tool failed: ' + Path(str(command[0])).name)
    return result.stdout.decode('utf-8', errors='replace')


def sha256_file(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def relative_path(value):
    if not isinstance(value, str) or not value or '\\' in value:
        raise PayloadError('invalid relative payload path')
    path = PurePosixPath(value)
    if path.is_absolute() or '..' in path.parts or str(path) != value:
        raise PayloadError('unsafe relative payload path')
    if not path.parts or path.parts[0] != 'Contents':
        raise PayloadError('payload paths must remain inside Contents')
    return path


def contained_path(app, value):
    relative_path(value)
    target = app / value
    try:
        target.resolve().relative_to(app.resolve())
    except (ValueError, RuntimeError, OSError) as error:
        raise PayloadError('payload path resolves outside application') from error
    return target


def is_macho(path):
    try:
        with Path(path).open('rb') as handle:
            return handle.read(4) in MACHO_MAGIC
    except OSError:
        return False


def dependency_paths(output):
    result = []
    for line in output.splitlines():
        match = re.match(r'^\s+(.+?) \(compatibility version ', line)
        if match and match.group(1) not in result:
            result.append(match.group(1))
    return result


def is_system_dependency(value):
    return value.startswith(('/usr/lib/', '/System/Library/'))


def relocated_dependency(binary, dependency, source_prefix, target_prefix):
    try:
        suffix = Path(dependency).relative_to(source_prefix)
    except ValueError:
        if dependency.startswith('/') and not is_system_dependency(dependency):
            raise PayloadError('Python contains an unbundled non-system dependency')
        return None
    target = target_prefix / suffix
    if not target.is_file():
        raise PayloadError('Python dependency closure is incomplete')
    return '@loader_path/' + os.path.relpath(target, Path(binary).parent).replace(os.sep, '/')


def official_python_prefix(requested=None):
    base = Path('/Library/Frameworks/Python.framework/Versions').resolve()
    if requested:
        candidates = [Path(requested).resolve()]
    else:
        candidates = []
        current = Path(sys.base_prefix).resolve()
        if current.parent == base:
            candidates.append(current)
        if base.is_dir():
            candidates.extend(sorted((p.resolve() for p in base.iterdir()
                                      if re.fullmatch(r'3\.\d+', p.name)), reverse=True))
    for prefix in candidates:
        if prefix.parent != base or not re.fullmatch(r'3\.\d+', prefix.name):
            continue
        if (prefix / 'Python').is_file() and (prefix / 'bin' / ('python' + prefix.name)).is_file():
            return prefix
    raise PayloadError('official system Python.framework is required; private tool runtimes are not accepted')


def ignored_python_files(directory, names):
    return [name for name in names if name in BLOCKED_DIRECTORIES or name.endswith(('.pyc', '.pyo', '.a', '.o')) or name.startswith(('_sysconfigdata', '_test', 'config-'))
            or name.startswith(('_tkinter.', 'libtk', 'libtcl'))]


def sign(path, identity, *, hardened=True, entitlements=None):
    command = ['codesign', '--force', '--sign', identity,
               '--timestamp=none' if identity == '-' else '--timestamp']
    if hardened:
        command.extend(['--options', 'runtime'])
    if entitlements:
        with tempfile.TemporaryDirectory(prefix='runtime-signing-') as temporary:
            document = Path(temporary) / 'entitlements.plist'
            document.write_bytes(plistlib.dumps(entitlements))
            run(command + ['--entitlements', document, path])
    else:
        run(command + [path])


def existing_entitlements(path):
    try:
        result = subprocess.run(['codesign', '-d', '--entitlements', ':-', str(path)],
                                capture_output=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise PayloadError('unable to inspect nested code entitlements') from error
    if not result.stdout.strip():
        return None
    try:
        data = plistlib.loads(result.stdout)
    except plistlib.InvalidFileException as error:
        raise PayloadError('nested code has unreadable entitlements') from error
    if not isinstance(data, dict):
        raise PayloadError('nested code entitlements must be a dictionary')
    return data


def code_bundle(path):
    if path.suffix.lower() not in ('.app', '.framework', '.xpc', '.appex', '.bundle'):
        return False
    candidates = [path / 'Contents/Info.plist', path / 'Resources/Info.plist', path / 'Info.plist']
    for info in candidates:
        if info.is_file():
            try:
                executable = plistlib.loads(info.read_bytes()).get('CFBundleExecutable')
                return isinstance(executable, str) and bool(executable)
            except (OSError, plistlib.InvalidFileException):
                raise PayloadError('nested code bundle has an invalid property list')
    return False


def resign_nested_code(app, identity, *, include_root=False, exclusions=()):
    def excluded(path):
        relative = path.relative_to(app)
        return any(relative == PurePosixPath(prefix) or PurePosixPath(prefix) in relative.parents
                   for prefix in exclusions)
    targets = []
    for path in app.rglob('*'):
        if path.is_symlink() or excluded(path):
            continue
        if (path.is_file() and is_macho(path)) or (path.is_dir() and code_bundle(path)):
            targets.append(path)
    if include_root:
        targets.append(app)
    # Read all original entitlements before signing a file can change its bundle metadata.
    preserved = {path: existing_entitlements(path) for path in targets}
    for path in sorted(set(targets), key=lambda item: (-len(item.parts), item.as_posix())):
        sign(path, identity, entitlements=preserved[path])
    if include_root:
        run(['codesign', '--verify', '--deep', '--strict', app])
    return {'signedCodeCount': len(set(targets)), 'entitlementsPreserved': True,
            'insideOut': True, 'secureTimestampRequested': identity != '-'}


def assessment_result(command):
    try:
        return subprocess.run([str(item) for item in command], capture_output=True,
                              text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return None


def assess_distribution(app):
    details = assessment_result(['codesign', '-dvvv', app])
    detail_text = (details.stdout + details.stderr) if details is not None else ''
    developer_id = details is not None and details.returncode == 0 and bool(
        re.search(r'^Authority=Developer ID Application:', detail_text, re.MULTILINE))
    team = re.search(r'^TeamIdentifier=(.+)$', detail_text, re.MULTILINE)
    team_present = team is not None and team.group(1).strip() not in ('', 'not set')
    timestamp_present = bool(re.search(r'^Timestamp=.+$', detail_text, re.MULTILINE))
    gatekeeper = assessment_result(['/usr/sbin/spctl', '--assess', '--type', 'execute', '-vv', app])
    gatekeeper_ok = gatekeeper is not None and gatekeeper.returncode == 0
    gatekeeper_text = (gatekeeper.stdout + gatekeeper.stderr) if gatekeeper is not None else ''
    source_notarized = bool(re.search(r'^source=Notarized Developer ID\s*$', gatekeeper_text, re.MULTILINE))
    staple = assessment_result(['xcrun', 'stapler', 'validate', app]) if developer_id else None
    staple_ok = staple is not None and staple.returncode == 0
    notarization = staple_ok or (gatekeeper_ok and source_notarized)
    signature = assessment_result(['codesign', '--verify', '--deep', '--strict', app])
    signature_ok = signature is not None and signature.returncode == 0
    ready = developer_id and team_present and timestamp_present and gatekeeper_ok and notarization and signature_ok
    return {
        'gatekeeperAccepted': gatekeeper_ok,
        'assessmentExitCode': gatekeeper.returncode if gatekeeper is not None else None,
        'developerIDAuthorityVerified': developer_id,
        'deepStrictSignatureVerified': signature_ok,
        'teamIdentifierPresent': team_present,
        'secureTimestampPresent': timestamp_present,
        'stapledNotarizationValidated': staple_ok,
        'gatekeeperNotarizedSource': source_notarized,
        'notarizationVerified': notarization,
        'distributable': ready,
        'scope': 'Build-host policy and signing evidence; no other physical Mac verification',
    }



def copy_python_dependency_closure(target, prefix):
    pending = [p for p in target.rglob('*') if p.is_file() and not p.is_symlink() and is_macho(p)]
    checked = set()
    while pending:
        binary = pending.pop()
        if binary in checked:
            continue
        checked.add(binary)
        for dependency in dependency_paths(run(['otool', '-L', binary])):
            try:
                relative = Path(dependency).relative_to(prefix)
            except ValueError:
                if dependency.startswith('/') and not is_system_dependency(dependency):
                    raise PayloadError('official Python requires an external non-system library')
                continue
            destination = target / relative
            if destination.is_file():
                continue
            original = prefix / relative
            if not original.is_file() or original.suffix != '.dylib':
                raise PayloadError('official Python dependency is unavailable')
            if original.name.startswith(('libtk', 'libtcl')):
                raise PayloadError('unexpected GUI toolkit dependency in headless Python')
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(original, destination)
            pending.append(destination)


def embed_python(app, prefix, identity):
    version = prefix.name
    framework = app / 'Contents/Frameworks/Python.framework'
    if framework.exists():
        raise PayloadError('Python payload already exists; use a fresh staging application')
    target = framework / 'Versions' / version
    (target / 'bin').mkdir(parents=True)
    (target / 'Resources').mkdir()
    executable = target / 'bin' / ('python' + version)
    # python.org bin/python3.x is often a posix_spawn trampoline into Python.app.
    # Relocate the real native interpreter into bin without embedding a second GUI app.
    native_interpreter = prefix / 'Resources/Python.app/Contents/MacOS/Python'
    executable_source = native_interpreter if native_interpreter.is_file() else prefix / 'bin' / executable.name
    shutil.copy2(executable_source, executable)
    shutil.copy2(prefix / 'Python', target / 'Python')
    shutil.copy2(prefix / 'Resources/Info.plist', target / 'Resources/Info.plist')
    standard_library = prefix / 'lib' / ('python' + version)
    if not standard_library.is_dir():
        raise PayloadError('Python standard library is missing')
    shutil.copytree(standard_library, target / 'lib' / standard_library.name,
                    ignore=ignored_python_files, symlinks=False)
    # Restrict dependencies to the official framework, never arbitrary tool libraries.
    copy_python_dependency_closure(target, prefix)
    license_candidates = [standard_library / 'LICENSE.txt', prefix / 'LICENSE.txt',
                          prefix / 'Resources/LICENSE.txt', prefix / 'Resources/LICENSE']
    license_source = next((p for p in license_candidates if p.is_file()), None)
    if license_source is None:
        raise PayloadError('official Python license text is missing')
    shutil.copy2(license_source, target / 'Resources/LICENSE.txt')
    (target / 'bin/python3').symlink_to(executable.name)
    (framework / 'Versions/Current').symlink_to(version)
    (framework / 'Python').symlink_to('Versions/Current/Python')
    (framework / 'Resources').symlink_to('Versions/Current/Resources')
    binaries = [p for p in target.rglob('*') if p.is_file() and not p.is_symlink() and is_macho(p)]
    if not binaries:
        raise PayloadError('Python Mach-O payload is empty')
    for binary in binaries:
        for dependency in dependency_paths(run(['otool', '-L', binary])):
            replacement = relocated_dependency(binary, dependency, prefix, target)
            if replacement:
                run(['install_name_tool', '-change', dependency, replacement, binary])
        if binary.name == 'Python' or binary.suffix == '.dylib':
            run(['install_name_tool', '-id', '@loader_path/' + binary.name, binary])
        listing = run(['otool', '-l', binary])
        for path in re.findall(r'cmd LC_RPATH\n.*?\n\s*path (.+?) \(offset', listing):
            if path.startswith(str(prefix)):
                run(['install_name_tool', '-delete_rpath', path, binary])
        # Local ad-hoc executables have no Team ID for Hardened Runtime library validation.
        # Keep the main application hardened and avoid any library-validation entitlement.
        sign(binary, identity, hardened=identity != '-' or binary != executable)
    sign(framework, identity)
    run(['codesign', '--verify', '--deep', '--strict', framework])
    return executable.relative_to(app).as_posix(), version


def helper_settings_contract_version(info_path):
    """Reject legacy helpers without executing application or guest code."""
    message = ('container helper settings contract is missing or unsupported; '
               'rebuild the helper from the current patches')
    try:
        info = plistlib.loads(Path(info_path).read_bytes())
    except (OSError, ValueError, TypeError) as error:
        raise PayloadError(message) from error
    version = info.get(HELPER_SETTINGS_CONTRACT_KEY) if isinstance(info, dict) else None
    if type(version) is not int or version < MIN_HELPER_SETTINGS_CONTRACT_VERSION:
        raise PayloadError(message)
    return version


def select_helper(app):
    helpers = []
    for helper in sorted((app / 'Contents/Helpers').glob('*.app')):
        try:
            info = plistlib.loads((helper / 'Contents/Info.plist').read_bytes())
            name = info['CFBundleExecutable']
            if not isinstance(name, str) or '/' in name or name in ('.', '..'):
                continue
            binary = helper / 'Contents/MacOS' / name
            if binary.is_file() and os.access(binary, os.X_OK):
                control = helper / 'Contents/MacOS/utmctl'
                if control.is_file() and os.access(control, os.X_OK):
                    helpers.append((helper, binary))
        except (OSError, KeyError, plistlib.InvalidFileException):
            continue
    if len(helpers) != 1:
        raise PayloadError('exactly one executable container helper application is required')
    helper_settings_contract_version(helpers[0][0] / 'Contents/Info.plist')
    return helpers[0]


def source_layout(workspace):
    manager = workspace / 'graphics-lab/golden_guest_manager.py'
    repos = [p for p in workspace.iterdir() if p.is_dir() and not p.is_symlink() and (p / '.git').exists()]
    if not manager.is_file() or len(repos) != 1:
        raise PayloadError('workspace must contain a manager and exactly one application source repository')
    modules = repos[0] / 'Modules'
    kiosk = list(modules.glob('*/scripts/kiosk-app-shell.ps1'))
    apply_opt = list(modules.glob('*/scripts/apply-optimizer.ps1'))
    rollback_opt = list(modules.glob('*/scripts/rollback-optimizer.ps1'))
    profile_opt = list(modules.glob('*/profiles/anticheat-minimal-win11-arm64.json'))
    cursor_bridge = list(modules.glob('*/scripts/malt-cursor-bridge.ps1'))
    daemons = list(modules.glob('*/vmnet-bridge/SMAppService.plist'))
    proxy_go = repos[0] / 'scripts/malt_net_proxy.go'
    if (len(kiosk) != 1 or len(apply_opt) != 1 or len(rollback_opt) != 1
            or len(profile_opt) != 1 or len(cursor_bridge) != 1
            or len(daemons) != 1 or not proxy_go.is_file()):
        raise PayloadError('required guest script, proxy source, or service manifest is missing or ambiguous')
    sources = list(daemons[0].parent.glob('*.c'))
    if len(sources) != 1:
        raise PayloadError('exactly one native network bridge source is required')
    return (manager, kiosk[0], apply_opt[0], rollback_opt[0], profile_opt[0],
            cursor_bridge[0], daemons[0], sources[0], proxy_go)


def resolve_go_binary():
    found = shutil.which('go')
    if found:
        return found
    for candidate in ('/opt/homebrew/bin/go', '/usr/local/go/bin/go'):
        if Path(candidate).is_file() and os.access(candidate, os.X_OK):
            return candidate
    raise PayloadError('Go toolchain is required to build the zero-privilege TCP/UDP network proxy')


def embed_user_net_proxy(app, go_source, identity):
    (go_bytes,) = read_stable_files([go_source])
    target = contained_path(app, USER_NET_PROXY_RELATIVE)
    target.parent.mkdir(parents=True, exist_ok=True)
    go_bin = resolve_go_binary()
    with tempfile.TemporaryDirectory(prefix='runtime-net-proxy-build-') as temporary:
        stable_source = Path(temporary) / 'malt_net_proxy.go'
        stable_source.write_bytes(go_bytes)
        build_env = os.environ.copy()
        build_env['CGO_ENABLED'] = '1'
        build_env['GOARCH'] = 'arm64'
        build_env['GOCACHE'] = str(Path(temporary) / 'go-cache')
        build_env['GOPATH'] = str(Path(temporary) / 'go-path')
        run([go_bin, 'build', '-trimpath', '-ldflags=-s -w', '-o', target, stable_source],
            env=build_env, timeout=180)
    target.chmod(0o755)
    sign(target, identity)
    run(['codesign', '--verify', '--strict', target])
    check_raw = run([target, '--self-check'], timeout=15)
    try:
        check = json.loads(check_raw.strip())
    except ValueError as error:
        raise PayloadError('bundled zero-privilege network proxy self-check returned invalid JSON') from error
    if not (check.get('passed') is True and check.get('qosUserInteractive') is True):
        raise PayloadError('bundled zero-privilege network proxy self-check failed')
    return target.relative_to(app).as_posix()


def read_stable_files(paths):
    for _ in range(3):
        try:
            first = [p.read_bytes() for p in paths]
            time.sleep(0.05)
            if first == [p.read_bytes() for p in paths]:
                return first
        except OSError:
            pass
    raise PayloadError('payload sources changed during packaging; retry after the active edit finishes')


def embed_bridge(app, plist_source, c_source, identity):
    plist_bytes, c_bytes = read_stable_files([plist_source, c_source])
    try:
        service = plistlib.loads(plist_bytes)
        label = service['Label']
        program = service['BundleProgram']
    except (plistlib.InvalidFileException, KeyError, TypeError) as error:
        raise PayloadError('invalid bundled service manifest') from error
    if not isinstance(label, str) or not re.fullmatch(r'[A-Za-z0-9.-]+', label):
        raise PayloadError('invalid service label')
    target = contained_path(app, program)
    if not program.startswith('Contents/Library/HelperTools/'):
        raise PayloadError('service BundleProgram must name a bundled HelperTools executable')
    target.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='runtime-network-build-') as temporary:
        stable_source = Path(temporary) / 'network_bridge.c'
        stable_source.write_bytes(c_bytes)
        run(['xcrun', 'clang', '-O2', '-Wall', '-Wextra', '-arch', 'arm64', stable_source,
             '-framework', 'vmnet', '-framework', 'CoreFoundation', '-o', target])
    target.chmod(0o755)
    sign(target, identity)
    run([target, '--self-check'])
    plist_target = app / 'Contents/Library/LaunchDaemons' / (label + '.plist')
    plist_target.parent.mkdir(parents=True, exist_ok=True)
    plist_target.write_bytes(plist_bytes)
    run(['plutil', '-lint', plist_target])
    return target.relative_to(app).as_posix(), plist_target.relative_to(app).as_posix()


def clean_environment(home):
    return {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': str(home),
            'TMPDIR': str(home), 'LC_ALL': 'C', 'PYTHONDONTWRITEBYTECODE': '1'}


def verify_python(app, executable_relative, manager_relative):
    executable = contained_path(app, executable_relative)
    with tempfile.TemporaryDirectory(prefix='runtime-python-check-') as temporary:
        env = clean_environment(Path(temporary))
        code = ('import ssl,socket,plistlib,json,hashlib,sqlite3,ctypes,subprocess,sys,os; '
                'assert sys.flags.isolated; '
                'assert os.path.realpath(sys.prefix).startswith(os.path.realpath(sys.argv[1])); '
                'print("stdlib-ok")')
        run([executable, '-I', '-B', '-c', code, app], env=env)
        help_output = run([executable, '-I', '-B', contained_path(app, manager_relative), '--help'], env=env)
        if 'usage:' not in help_output.lower():
            raise PayloadError('bundled manager did not produce help output')
    return {'isolatedEnvironment': True, 'standardLibraryImportsPassed': True,
            'managerHelpPassed': True}


def inventory_files(app, roots):
    items = {}
    for relative in roots:
        path = contained_path(app, relative)
        candidates = [path] + (list(path.rglob('*')) if path.is_dir() and not path.is_symlink() else [])
        for candidate in candidates:
            rel = candidate.relative_to(app).as_posix()
            if candidate.is_symlink():
                link = os.readlink(candidate)
                if Path(link).is_absolute():
                    raise PayloadError('absolute payload symlinks are forbidden')
                contained_path(app, rel)
                items[rel] = {'type': 'symlink', 'target': link,
                              'sha256': hashlib.sha256(link.encode()).hexdigest()}
            elif candidate.is_file():
                items[rel] = {'type': 'file', 'sizeBytes': candidate.stat().st_size,
                              'sha256': sha256_file(candidate)}
    return dict(sorted(items.items()))


def audit_payload_tree(app, roots, private_prefixes=()):
    problems = []
    blocked = {'.git', '.build', '.dev-logs', '__pycache__', 'site-packages', 'node_modules'}
    user_state_directories = {'logs', 'caches', 'preferences', 'saved application state',
                              '.cache', '.config', '.local'}
    log_suffixes = {'.log', '.jsonl', '.ndjson', '.crash', '.ips', '.dmp'}
    guest_suffixes = {'.utm', '.pvm', '.vmwarevm', '.qcow', '.qcow2', '.vdi', '.vmdk',
                      '.vhd', '.vhdx', '.vmem', '.vmss', '.vmsn'}
    private_bytes = [str(p).encode() for p in private_prefixes if str(p) not in ('', '/')]
    for relative in roots:
        try:
            path = contained_path(app, relative)
            candidates = [path] + (list(path.rglob('*')) if path.is_dir() and not path.is_symlink() else [])
            for candidate in candidates:
                rel = candidate.relative_to(app).as_posix()
                if blocked.intersection(PurePosixPath(rel).parts):
                    problems.append('development_artifact_in_payload')
                parts = {part.lower() for part in PurePosixPath(rel).parts}
                name = candidate.name.lower()
                if user_state_directories.intersection(parts) or name == '.env' or name.startswith('.env.'):
                    problems.append('user_state_in_payload')
                if name == '.ds_store':
                    problems.append('development_artifact_in_payload')
                if candidate.suffix.lower() in log_suffixes:
                    problems.append('runtime_log_in_payload')
                if any(PurePosixPath(part).suffix in guest_suffixes for part in parts):
                    problems.append('guest_data_in_payload')
                if candidate.is_symlink():
                    if Path(os.readlink(candidate)).is_absolute():
                        problems.append('absolute_payload_symlink')
                    contained_path(app, rel)
                elif candidate.is_file() and private_bytes:
                    # Scan shipped bytes, not diagnostic output, without recording private prefixes.
                    data = candidate.read_bytes()
                    if any(token in data for token in private_bytes):
                        problems.append('private_build_path_in_payload')
        except (OSError, PayloadError):
            problems.append('unsafe_payload_tree')
    return sorted(set(problems))


def load_dependency_paths(output):
    """Read actual load commands, excluding a dylib's own LC_ID_DYLIB."""
    commands = {'LC_LOAD_DYLIB', 'LC_LOAD_WEAK_DYLIB', 'LC_REEXPORT_DYLIB',
                'LC_LOAD_UPWARD_DYLIB', 'LC_LAZY_LOAD_DYLIB'}
    dependencies = []
    current = None
    for line in output.splitlines():
        command = re.match(r'^\s*cmd\s+(LC_\S+)\s*$', line)
        if command:
            current = command.group(1)
            continue
        if current in commands:
            name = re.match(r'^\s*name\s+(.+?)\s+\(offset\s+\d+\)\s*$', line)
            if name and name.group(1) not in dependencies:
                dependencies.append(name.group(1))
    return dependencies


def verify_payload_dependencies(app, roots):
    """Reject external absolute load paths throughout the managed payload."""
    binaries = set()
    for relative in roots:
        path = contained_path(app, relative)
        candidates = [path] + (list(path.rglob('*')) if path.is_dir() else [])
        for candidate in candidates:
            if candidate.is_file() and not candidate.is_symlink() and is_macho(candidate):
                binaries.add(candidate)
    if not binaries:
        raise PayloadError('managed payload Mach-O files are missing')
    for binary in sorted(binaries):
        for dependency in load_dependency_paths(run(['otool', '-l', binary])):
            if dependency.startswith('/') and not is_system_dependency(dependency):
                raise PayloadError('payload loads an external non-system absolute dependency')
    return {'machOCount': len(binaries), 'externalAbsoluteDependencyCount': 0,
            'systemOrRelativeDependenciesOnly': True}


def verify_python_dependencies(app):
    framework = app / 'Contents/Frameworks/Python.framework'
    count = 0
    for binary in framework.rglob('*'):
        if not binary.is_file() or binary.is_symlink() or not is_macho(binary):
            continue
        count += 1
        for dependency in dependency_paths(run(['otool', '-L', binary])):
            if dependency.startswith('/') and not is_system_dependency(dependency):
                raise PayloadError('bundled Python still loads an external framework dependency')
            if dependency.startswith('@loader_path/'):
                target = binary.parent / dependency.removeprefix('@loader_path/')
                try:
                    target.resolve().relative_to(app.resolve())
                except ValueError as error:
                    raise PayloadError('Python loader dependency escapes application') from error
                if not target.is_file():
                    raise PayloadError('Python loader dependency is missing')
    if not count:
        raise PayloadError('bundled Python Mach-O files are missing')
    return count


def verify_manifest(app, manifest):
    problems = []
    if not isinstance(manifest, dict) or manifest.get('schema') != SCHEMA:
        return ['unsupported_manifest_schema']
    prerequisites = manifest.get('prerequisites', {})
    if not isinstance(prerequisites, dict):
        return ['invalid_prerequisites']
    expected = {'guestImageBundled': False, 'wineRuntimeBundled': False,
                'externalSetupRequired': True, 'nativeNetworkDistributionRequiresNotarization': True}
    for key, value in expected.items():
        if prerequisites.get(key) is not value:
            problems.append('invalid_prerequisite_' + key)
    files = manifest.get('files')
    required = manifest.get('requiredResources')
    if not isinstance(files, dict) or not files or not isinstance(required, dict):
        return problems + ['missing_inventory_or_requirements']
    expected_keys = {'helperBinary', 'helperInfo', 'containerControlBinary', 'pythonExecutable', 'pythonLicense',
                     'managerScript', 'kioskScript', 'optimizerApplyScript', 'optimizerRollbackScript',
                     'optimizerProfile', 'cursorBridgeScript', 'provisioningGuide', 'provisioningGuideChinese',
                     'networkHelper', 'networkService', 'userNetProxy'}
    if set(required) != expected_keys:
        problems.append('incomplete_required_resources')
    executable_keys = ('helperBinary', 'containerControlBinary', 'pythonExecutable',
                       'networkHelper', 'userNetProxy')
    for key, relative in required.items():
        try:
            path = contained_path(app, relative)
            if relative not in files or not path.is_file():
                problems.append('missing_required_' + key)
            elif key in executable_keys and not os.access(path, os.X_OK):
                problems.append('not_executable_' + key)
        except (PayloadError, TypeError):
            problems.append('unsafe_required_' + str(key))
    try:
        helper_settings_contract_version(contained_path(app, required['helperInfo']))
    except (PayloadError, KeyError, TypeError):
        problems.append('unsupported_helper_settings_contract')
    for relative, entry in files.items():
        try:
            path = contained_path(app, relative)
            if not isinstance(entry, dict):
                raise PayloadError('invalid inventory entry')
            if entry.get('type') == 'symlink':
                if not path.is_symlink() or os.readlink(path) != entry.get('target'):
                    problems.append('symlink_mismatch')
                elif hashlib.sha256(os.readlink(path).encode()).hexdigest() != entry.get('sha256'):
                    problems.append('symlink_hash_mismatch')
            elif entry.get('type') == 'file':
                if not path.is_file() or path.is_symlink():
                    problems.append('missing_inventory_file')
                elif path.stat().st_size != entry.get('sizeBytes') or sha256_file(path) != entry.get('sha256'):
                    problems.append('file_hash_mismatch')
            else:
                problems.append('invalid_inventory_type')
        except (PayloadError, OSError, TypeError):
            problems.append('unsafe_or_unreadable_inventory_file')
    roots = manifest.get('managedRoots')
    if not isinstance(roots, list) or not roots or any(not isinstance(p, str) for p in roots):
        problems.append('missing_managed_roots')
    else:
        try:
            actual = inventory_files(app, roots)
            if set(actual) != set(files):
                problems.append('untracked_or_missing_payload_files')
            problems.extend(audit_payload_tree(app, roots))
        except (OSError, PayloadError):
            problems.append('unsafe_managed_roots')
    try:
        service = plistlib.loads(contained_path(app, required['networkService']).read_bytes())
        if service.get('BundleProgram') != required['networkHelper']:
            problems.append('service_program_mismatch')
    except (OSError, KeyError, TypeError, PayloadError, plistlib.InvalidFileException):
        problems.append('invalid_network_service')
    return sorted(set(problems))


def embed(app, workspace, python_source=None, sign_identity='-'):
    if sys.platform != 'darwin':
        raise PayloadError('embedding requires macOS system build and signing tools')
    helper, helper_binary = select_helper(app)
    helper_signing = resign_nested_code(helper, sign_identity, include_root=True)
    manager, kiosk, apply_opt, rollback_opt, profile_opt, cursor_bridge, service, bridge, proxy_go = source_layout(workspace)
    prefix = official_python_prefix(python_source)
    scripts = app / 'Contents/Resources/RuntimeScripts'
    scripts.mkdir(parents=True, exist_ok=True)
    script_sources = (manager, kiosk, apply_opt, rollback_opt, profile_opt, cursor_bridge)
    for source, content in zip(script_sources, read_stable_files(script_sources)):
        (scripts / source.name).write_bytes(content)
    (scripts / 'PROVISIONING.md').write_text(PROVISIONING, encoding='utf-8')
    (scripts / 'PROVISIONING.zh-Hans.md').write_text(PROVISIONING_ZH, encoding='utf-8')
    interpreter, version = embed_python(app, prefix, sign_identity)
    network_binary, network_service = embed_bridge(app, service, bridge, sign_identity)
    user_net_proxy = embed_user_net_proxy(app, proxy_go, sign_identity)
    required = {
        'helperBinary': helper_binary.relative_to(app).as_posix(),
        'helperInfo': (helper / 'Contents/Info.plist').relative_to(app).as_posix(),
        'containerControlBinary': (helper / 'Contents/MacOS/utmctl').relative_to(app).as_posix(),
        'pythonExecutable': interpreter,
        'pythonLicense': f'Contents/Frameworks/Python.framework/Versions/{version}/Resources/LICENSE.txt',
        'managerScript': 'Contents/Resources/RuntimeScripts/' + SCRIPT_NAMES[0],
        'kioskScript': 'Contents/Resources/RuntimeScripts/' + SCRIPT_NAMES[1],
        'optimizerApplyScript': 'Contents/Resources/RuntimeScripts/' + SCRIPT_NAMES[2],
        'optimizerRollbackScript': 'Contents/Resources/RuntimeScripts/' + SCRIPT_NAMES[3],
        'optimizerProfile': 'Contents/Resources/RuntimeScripts/' + SCRIPT_NAMES[4],
        'cursorBridgeScript': 'Contents/Resources/RuntimeScripts/' + SCRIPT_NAMES[5],
        'provisioningGuide': 'Contents/Resources/RuntimeScripts/PROVISIONING.md',
        'provisioningGuideChinese': 'Contents/Resources/RuntimeScripts/PROVISIONING.zh-Hans.md',
        'networkHelper': network_binary,
        'networkService': network_service,
        'userNetProxy': user_net_proxy,
    }
    python_checks = verify_python(app, interpreter, required['managerScript'])
    roots = ['Contents/Frameworks/Python.framework', 'Contents/Resources/RuntimeScripts',
             helper.relative_to(app).as_posix(), network_binary, network_service, user_net_proxy]
    pollution = audit_payload_tree(app, roots, [Path.home(), workspace.resolve()])
    if pollution:
        raise PayloadError('payload contains development artifacts or private build paths')
    verify_python_dependencies(app)
    dependency_checks = verify_payload_dependencies(app, roots)
    manifest = {'schema': SCHEMA, 'owner': '@DNPMBHC', 'pythonVersion': version,
                'pythonInterpreterHardenedRuntime': sign_identity != '-',
                'helperSigning': helper_signing,
                'requiredResources': required, 'managedRoots': roots,
                'prerequisites': {'guestImageBundled': False, 'wineRuntimeBundled': False,
                                  'externalSetupRequired': True,
                                  'nativeNetworkDistributionRequiresNotarization': True},
                'pythonChecks': python_checks, 'dependencyChecks': dependency_checks,
                'files': inventory_files(app, roots)}
    manifest_path = app / MANIFEST_RELATIVE
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + '\n', encoding='utf-8')
    return verify(app, check_signatures=True)


def verify(app, check_signatures=True):
    try:
        manifest = json.loads((app / MANIFEST_RELATIVE).read_text(encoding='utf-8'))
    except (OSError, ValueError) as error:
        raise PayloadError('runtime payload manifest is missing or invalid') from error
    if not isinstance(manifest, dict):
        raise PayloadError('runtime payload manifest must be an object')
    problems = verify_manifest(app, manifest)
    signature_checks = False
    python_checks = None
    dependency_checks = None
    if not problems and check_signatures:
        if sys.platform != 'darwin':
            problems.append('signature_verification_requires_macos')
        else:
            try:
                required = manifest['requiredResources']
                helper = contained_path(app, required['helperInfo']).parents[1]
                run(['codesign', '--verify', '--deep', '--strict', helper])
                run(['codesign', '--verify', '--deep', '--strict', app / 'Contents/Frameworks/Python.framework'])
                run(['codesign', '--verify', '--strict', contained_path(app, required['networkHelper'])])
                run(['codesign', '--verify', '--strict', contained_path(app, required['userNetProxy'])])
                signature_checks = True
                dependency_checks = verify_payload_dependencies(app, manifest['managedRoots'])
                verify_python_dependencies(app)
                python_checks = verify_python(app, required['pythonExecutable'], required['managerScript'])
            except PayloadError:
                problems.append('runtime_signature_or_interpreter_check_failed')
    return {'schema': SCHEMA + '-verification', 'owner': '@DNPMBHC',
            'resourceCount': len(manifest['files']) if isinstance(manifest.get('files'), dict) else 0, 'problems': sorted(set(problems)),
            'requiredResourcesVerified': not problems, 'signatureChecksPassed': signature_checks,
            'pythonChecks': python_checks, 'dependencyChecks': dependency_checks,
            'prerequisites': manifest.get('prerequisites', {}),
            'daemonInstalledOrRegistered': False, 'gameLaunchVerified': False,
            'cleanMachineVerified': False, 'passed': not problems}


def outer_signing_exclusions(app):
    # Locked optional drivers retain their approved bytes. Every inventoried payload
    # root was already signed before hashing and must remain byte-for-byte stable.
    exclusions = ['Contents/Frameworks/libvulkan.1.dylib',
                  'Contents/Frameworks/libvulkan_kosmickrisp.dylib']
    manifest_path = app / MANIFEST_RELATIVE
    if manifest_path.exists():
        try:
            manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
        except (OSError, ValueError) as error:
            raise PayloadError('cannot preserve an invalid runtime payload manifest') from error
        if verify_manifest(app, manifest):
            raise PayloadError('runtime payload changed before outer signing')
        exclusions.extend(manifest['managedRoots'])
    return tuple(exclusions)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest='action', required=True)
    build = subparsers.add_parser('embed')
    build.add_argument('--app', required=True, type=Path)
    build.add_argument('--workspace', required=True, type=Path)
    build.add_argument('--python-source', type=Path)
    build.add_argument('--sign-identity', default='-')
    build.add_argument('--output', type=Path)
    check = subparsers.add_parser('verify')
    check.add_argument('--app', required=True, type=Path)
    check.add_argument('--output', type=Path)
    helper_check = subparsers.add_parser('check-helper-settings')
    helper_check.add_argument('--helper-app', required=True, type=Path)
    nested = subparsers.add_parser('sign-nested')
    nested.add_argument('--app', required=True, type=Path)
    nested.add_argument('--sign-identity', default='-')
    assess = subparsers.add_parser('assess-distribution')
    assess.add_argument('--app', required=True, type=Path)
    assess.add_argument('--output', type=Path)
    assess.add_argument('--require-distributable', action='store_true')
    args = parser.parse_args(argv)
    try:
        if args.action == 'check-helper-settings':
            version = helper_settings_contract_version(args.helper_app / 'Contents/Info.plist')
            report = {'runtimeSettingsContractVersion': version,
                      'minimumRuntimeSettingsContractVersion': MIN_HELPER_SETTINGS_CONTRACT_VERSION,
                      'passed': True}
        elif args.action == 'sign-nested':
            report = resign_nested_code(args.app, args.sign_identity,
                                        exclusions=outer_signing_exclusions(args.app))
            report['passed'] = True
        elif args.action == 'assess-distribution':
            report = assess_distribution(args.app)
            report['passed'] = report['distributable'] or not args.require_distributable
        else:
            report = (embed(args.app, args.workspace, args.python_source, args.sign_identity)
                      if args.action == 'embed' else verify(args.app))
        if getattr(args, 'output', None):
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
        print(json.dumps(report, sort_keys=True))
        return 0 if report['passed'] else 1
    except (PayloadError, OSError, ValueError) as error:
        message = str(error) if isinstance(error, PayloadError) else 'payload file operation failed'
        print(json.dumps({'passed': False, 'error': message}), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
