# SPDX-License-Identifier: GPL-3.0-or-later
"""Offline contracts for runtime options consumed by the bundled helper patches."""

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parent.parent


def patch_text(prefix):
    matches = list(ROOT.glob(f"*/utm-custom/patches/{prefix}*.patch"))
    if len(matches) != 1:
        raise AssertionError("Expected exactly one helper patch for " + prefix)
    return matches[0].read_text()


def added_source(prefix):
    return "\n".join(
        line[1:] for line in patch_text(prefix).splitlines()
        if line.startswith("+") and not line.startswith("+++")
    )


class RuntimeOptionContracts(unittest.TestCase):
    def test_mouse_coalescing_has_existing_1500_microsecond_default_and_zero_disables(self):
        source = added_source("06")
        self.assertIn('environment["UTM_MOUSE_COALESCE_US"]', source)
        self.assertIn("let defaultUs = 1500", source)
        self.assertRegex(source, r"if parsed <= 0 \{\s*return 0")
        self.assertRegex(source, r"if mouseCoalesceWindowNs == 0 \{[\s\S]*?inputDelegate\?\.mouseMove")

    def test_both_key_guard_layers_only_enable_for_explicit_one_or_absent_value(self):
        source = added_source("07")
        overrides = re.findall(
            r'environment\["UTM_GAME_SHELL_KEY_GUARD"\]\s*'
            r'\.map \{ \$0 == "1" \} \?\? true\)', source
        )
        self.assertEqual(len(overrides), 2)
        self.assertEqual(source.count('arguments.contains("--app-shell-vm")'), 2)
        self.assertEqual(source.count('environment["UTM_APP_SHELL_VM"]'), 2)
        self.assertEqual(source.count('arguments.contains("--game-shell-vm")'), 2)
        self.assertEqual(source.count('environment["UTM_GAME_SHELL_VM"]'), 2)

    def test_key_guard_layers_require_fullscreen_shell_context_even_when_enabled(self):
        source = added_source("07")
        self.assertRegex(
            source,
            r'let guardEnabled = isGameShell && isFullScreen\s*&& '
            r'\(ProcessInfo\.processInfo\.environment\["UTM_GAME_SHELL_KEY_GUARD"\]'
        )
        self.assertRegex(
            source,
            r'private var shouldGuardGameShellShortcuts: Bool \{\s*'
            r'isGameShellFullScreenActive\s*&& '
            r'\(ProcessInfo\.processInfo\.environment\["UTM_GAME_SHELL_KEY_GUARD"\]'
        )

    def test_app_shell_monitor_uses_the_same_explicit_value_and_fullscreen_contract(self):
        source = added_source("08")
        monitor = source.split("func installAppShellKeyGuardIfNeeded()", 1)[1]
        self.assertRegex(
            monitor,
            r'let guardEnabled = ProcessInfo\.processInfo\.environment\["UTM_GAME_SHELL_KEY_GUARD"\]\s*'
            r'\.map \{ \$0 == "1" \} \?\? true'
        )
        self.assertRegex(
            monitor,
            r'guard guardEnabled, self\?\.window\?\.styleMask\.contains\(\.fullScreen\) == true '
            r'else \{\s*return event'
        )
        self.assertIn('{ [weak self] event in', monitor)

    def test_shortcut_filters_keep_escape_combinations_and_only_block_expected_keys(self):
        for prefix, expected_guarded, expected_control_checks, expected_option_checks in (
            ("07", 2, 2, 3),
            ("08", 1, 2, 2),
        ):
            source = added_source(prefix)
            self.assertEqual(source.count("!flags.contains(.option)"), expected_option_checks)
            self.assertEqual(source.count("!flags.contains(.control)"), expected_control_checks)
            guarded_cases = re.findall(r"case (kVK_ANSI_W[^:]+):", source)
            self.assertEqual(len(guarded_cases), expected_guarded)
            for keys in guarded_cases:
                self.assertEqual(
                    [key.strip() for key in keys.split(",")],
                    ["kVK_ANSI_W", "kVK_ANSI_Q", "kVK_ANSI_H", "kVK_ANSI_M"]
                )

    def test_phase_a_and_b_engine_and_mailbox_contracts(self):
        p01 = added_source("01-default-dxmt-backend")
        self.assertIn('UTM_DIRECTX_BACKEND', p01)
        p05 = added_source("05-render-thread-qos-and-dxmt-cache")
        self.assertIn('DXMT_METALFX_SPATIAL_SWAPCHAIN', p05)
        self.assertIn('NPT_PROFILE_PERIOD_MS', p05)
        self.assertIn('QOS_CLASS_USER_INTERACTIVE', p05)
        self.assertIn('NSActivityLatencyCritical', p05)
        self.assertIn('.latencyCritical', p05)
        p07 = added_source("07-game-shell-key-guard-and-mapping")
        self.assertIn('NSAppSleepDisabled', p07)
        p09_utm = added_source("09-iosurface-direct-present-and-virtio-input")
        self.assertIn('UTM_HVF_TSO', p09_utm)
        self.assertIn('kernel-irqchip=on', p09_utm)
        p09_spice = added_source("09-cocoaspice-iosurface-direct-present")
        self.assertIn('UTM_DISPLAY_PRESENT_MODE', p09_spice)
        self.assertIn('UTM_NEPTUNE_PROFILE_LOG', p09_spice)
        self.assertIn('mailboxCopyQueue', p09_spice)
        self.assertIn('ringTextures', p09_spice)
        self.assertIn('ring_bypass', p09_spice)
        self.assertIn('[Malt-Present]', p09_spice)
        self.assertIn('[Malt-Renderer]', p09_spice)
        p05_spice = added_source("05-cocoaspice-frame-backpressure")
        self.assertIn('QOS_CLASS_USER_INTERACTIVE', p05_spice)
        self.assertIn('_residual_dx', p05_spice)
        p06_utm = added_source("06-high-polling-mouse-coalescing")
        self.assertIn('GCMouse', p06_utm)
        self.assertIn('isMouseCoalescingEnabled = false', p06_utm)
        self.assertIn('UTM_RAW_MOUSE_INPUT', p06_utm)

    def test_left_command_guard_still_accepts_explicit_off(self):
        source = added_source("07")
        block = source.split("private var shouldBlockLeftWinKey: Bool", 1)[1]
        block = block.split("override func performKeyEquivalent", 1)[0]
        self.assertIn('if let env = ProcessInfo.processInfo.environment["UTM_BLOCK_WIN_KEY"]', block)
        self.assertIn('return env == "1"', block)
        self.assertIn("return isGameShellFullScreenActive", block)

    def test_cache_disable_is_consumed_without_creating_or_exposing_a_cache_path(self):
        source = added_source("05-render-thread-qos-and-dxmt-cache")
        self.assertIn('environment[@"UTM_DXMT_SHADER_CACHE_ENABLED"]', source)
        disabled = source.split('if ([cacheEnabled isEqualToString:@"0"]) {', 1)[1]
        disabled = disabled.split("} else {", 1)[0]
        self.assertIn('self.mutableEnvironment[@"DXMT_SHADER_CACHE"] = @"0";', disabled)
        self.assertIn('removeObjectForKey:@"DXMT_SHADER_CACHE_PATH"', disabled)
        self.assertNotIn("createDirectoryAtURL", disabled)
        self.assertIn('self.mutableEnvironment[@"DXMT_SHADER_CACHE"] = @"1";', source)

    def test_helper_metadata_declares_the_runtime_settings_contract(self):
        source = added_source("07")
        self.assertRegex(
            source,
            r'<key>UTMRuntimeSettingsContractVersion</key>\s*<integer>1</integer>'
        )

    def test_prepare_only_registers_lifecycle_and_returns_before_vm_start(self):
        source = added_source("08")
        launch = source.split("private func launchAppShellVM", 1)[1]
        launch = launch.split("private extension AppDelegate", 1)[0]
        prepare = re.search(
            r'if CommandLine\.arguments\.contains\("--app-shell-prepare-only"\) \{\s*return\s*\}',
            launch
        )
        self.assertIsNotNone(prepare)
        self.assertLess(launch.index("guard let resolvedVM = vm"), prepare.start())
        self.assertLess(launch.index("self.stopObserver = resolvedVM.$state"), prepare.start())
        self.assertLess(launch.index("self.hasStarted = false"), prepare.start())
        self.assertLess(prepare.end(), launch.index("data.run(vm: resolvedVM)"))
        self.assertIn("else if self.hasStarted && state == .stopped", launch)
        self.assertIn("NSApp.terminate(nil)", launch)

    def test_configuration_reload_rejects_live_or_saved_state_and_invalid_manifest(self):
        source = patch_text("08").split(
            "diff --git a/Scripting/UTMScriptingVirtualMachineImpl.swift", 1
        )[1]
        self.assertIn("+            guard vm.state == .stopped,", source)
        self.assertIn("+                  !vm.registryEntry.isSuspended,", source)
        self.assertIn(
            "+                  try UTMSnapshotManifest.load(from: vm.pathUrl)?.suspendIdentifier == nil else {",
            source
        )
        self.assertIn("throw ScriptingError.notStopped", source)
        self.assertNotIn("try?", source)

    def test_periodic_screenshot_disabled_and_neptune_profiler_wired(self):
        patch05 = patch_text("05-render-thread-qos-and-dxmt-cache")
        patch08 = patch_text("08")
        patch09 = patch_text("09-cocoaspice-iosurface-direct-present")
        settings = (ROOT / "WhiskyKit/Sources/WhiskyKit/Orchestration/UnifiedLaunchSettings.swift").read_text(
            encoding="utf-8"
        )
        self.assertIn('self.mutableEnvironment[@"NPT_DEBUG"] = @"profile";', patch05)
        self.assertIn('self.mutableEnvironment[@"VIRGL_LOG_FILE"] = profileLogURL.path;', patch05)
        self.assertIn('UserDefaults.standard.set(true, forKey: "NoScreenshot")', patch08)
        self.assertIn('UTM_DISABLE_SCREENSHOT', patch09)
        self.assertIn('"UTM_DISABLE_SCREENSHOT": "1"', settings)

    def test_fullscreen_resilience_cursor_and_dxmt_fidelity_contracts(self):
        patch02 = patch_text("02-cursor-and-fps-capture")
        patch03 = patch_text("03-clean-fullscreen-game-shell")
        patch05 = patch_text("05-render-thread-qos-and-dxmt-cache")
        patch06 = patch_text("06-high-polling-mouse-coalescing")
        patch08 = patch_text("08")
        patch02_cs = patch_text("02-cocoaspice-cursor-overlay")
        patch09_cs = patch_text("09-cocoaspice-iosurface-direct-present")
        self.assertIn('CommandLine.arguments.contains("--app-shell-vm")', patch02)
        self.assertIn("shouldAutoCaptureInShellOrRelativeMode || metalView?.isMouseCaptured == true", patch03)
        self.assertIn('@"dxgi.handleAltTab=False"', patch05)
        self.assertIn('@"d3d11.sampleNaNToZero=True"', patch05)
        self.assertIn('@"d3d11.defuseFma=True"', patch05)
        self.assertIn("display?.cursor?.applyRelativeFallback(delta: delta)", patch06)
        self.assertIn("flags.contains([.option, .command])", patch08)
        self.assertIn("self?.window?.performClose(nil)", patch08)
        self.assertIn("[Malt-Cursor] event=set", patch02_cs)
        self.assertIn("[Malt-Cursor-Render]", patch09_cs)

    def test_cursor_bridge_and_dxmt_map_nowait_contracts(self):
        patch05 = patch_text("05-render-thread-qos-and-dxmt-cache")
        patch09 = patch_text("09-iosurface-direct-present-and-virtio-input")
        patch02_cs = patch_text("02-cocoaspice-cursor-overlay")
        self.assertIn('@"d3d11.ignoreMapFlagNoWait=True"', patch05)
        self.assertIn("applyExternalCursorShape(data:width:height:hotspot:at:visible:)", patch02_cs)
        self.assertIn("applyExternalCursorMove(to:visible:)", patch02_cs)
        self.assertIn("hideExternalCursor()", patch02_cs)
        self.assertIn("[Malt-Cursor] event=bridge_set", patch02_cs)
        self.assertIn("com.malt.cursor.0", patch09)
        self.assertIn("cursorSocketURL", patch09)
        self.assertIn("MaltCursorBridgeManager", patch09)
        self.assertIn("UTM_DISABLE_CURSOR_BRIDGE", patch09)
        self.assertIn('if physMem <= 10_737_418_240 { return "2G" }', patch09)
        self.assertIn("num-queues=\\(blkQueues)", patch09)

    def test_performance_architecture_storage_and_memory_contracts(self):
        patch09 = patch_text("09-iosurface-direct-present-and-virtio-input")
        settings = (ROOT / "WhiskyKit/Sources/WhiskyKit/Orchestration/UnifiedLaunchSettings.swift").read_text(
            encoding="utf-8"
        )
        self.assertIn('UTM_VIRGL_HOSTMEM', patch09)
        self.assertIn('iothread=malt_io_\\(busindex)', patch09)
        self.assertIn('queue-size=256', patch09)
        self.assertIn('l2-cache-size=16777216', patch09)
        self.assertIn('refcount-cache-size=4194304', patch09)
        self.assertIn('"UTM_VIRGL_HOSTMEM": hostmemSize', settings)
        self.assertIn('"UTM_QCOW2_L2_CACHE": "1"', settings)
        self.assertIn('"UTM_PER_DISK_IOTHREAD": "1"', settings)

    def test_modified_patch_hunk_counts_remain_valid(self):
        for prefix in (
            "02-cursor-and-fps-capture",
            "03-clean-fullscreen-game-shell",
            "05-render-thread-qos-and-dxmt-cache",
            "06-high-polling-mouse-coalescing",
            "07",
            "08",
            "09-iosurface-direct-present-and-virtio-input",
            "02-cocoaspice-cursor-overlay",
            "09-cocoaspice-iosurface-direct-present",
        ):
            lines = patch_text(prefix).splitlines()
            for index, line in enumerate(lines):
                match = re.match(r"@@ -(\d+),(\d+) \+(\d+),(\d+) @@", line)
                if not match:
                    continue
                body = []
                for following in lines[index + 1:]:
                    if following.startswith(("@@ ", "diff --git ")):
                        break
                    body.append(following)
                with self.subTest(patch=prefix, hunk=index):
                    self.assertEqual(sum(part.startswith((" ", "-")) for part in body), int(match[2]))
                    self.assertEqual(sum(part.startswith((" ", "+")) for part in body), int(match[4]))


if __name__ == "__main__":
    unittest.main()
