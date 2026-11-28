#!/usr/bin/env python3
"""Offline schema, whitelist protection, and safety lock unit tests for guest-optimizer.

Owner: @DNPMBHC
"""
from __future__ import annotations

import copy
import importlib.util
import json
import sys
import unittest
from pathlib import Path

MODULE_DIR = Path(__file__).resolve().parent.parent
PROFILE_PATH = MODULE_DIR / "profiles" / "anticheat-minimal-win11-arm64.json"
APPLY_SCRIPT_PATH = MODULE_DIR / "scripts" / "apply-optimizer.ps1"
ROLLBACK_SCRIPT_PATH = MODULE_DIR / "scripts" / "rollback-optimizer.ps1"
KIOSK_SCRIPT_PATH = MODULE_DIR / "scripts" / "kiosk-app-shell.ps1"
CURSOR_BRIDGE_SCRIPT_PATH = MODULE_DIR / "scripts" / "malt-cursor-bridge.ps1"
RUNNER_PATH = MODULE_DIR / "scripts" / "benchmark-optimizer-clone.py"

spec = importlib.util.spec_from_file_location("benchmark_optimizer_clone", RUNNER_PATH)
assert spec is not None and spec.loader is not None
runner = importlib.util.module_from_spec(spec)
sys.modules["benchmark_optimizer_clone"] = runner
spec.loader.exec_module(runner)


class GuestOptimizerProfileTests(unittest.TestCase):
    def load_profile(self) -> dict:
        return json.loads(PROFILE_PATH.read_text(encoding="utf-8"))

    def test_official_profile_passes_schema_and_whitelist_validation(self):
        profile = self.load_profile()
        runner.validate_profile(profile)
        self.assertEqual(profile["owner"], "@DNPMBHC")
        self.assertEqual(profile["profile_id"], "anticheat-minimal-win11-arm64")
        self.assertGreaterEqual(profile.get("profile_revision", 1), 2)
        self.assertGreaterEqual(len(profile["optimization_blacklist"]["services"]), 20)
        self.assertGreaterEqual(len(profile["optimization_blacklist"]["registry_tweaks"]), 12)
        self.assertGreaterEqual(len(profile["optimization_blacklist"]["uwp_packages"]), 15)

    def test_protected_core_and_anticheat_services_cannot_enter_blacklist(self):
        for service in (
            "CryptSvc",
            "cryptsvc",
            "TBS",
            "Winmgmt",
            "EventLog",
            "QEMU-GA",
            "vgc",
            "ACE-BASE",
            "ACE-CORE10405",
            "ACE-CORE20405",
            "AntiCheatExpert",
            "BEService",
        ):
            profile = self.load_profile()
            profile["optimization_blacklist"]["services"].append({
                "name": service,
                "target_start_type": "Disabled",
                "stop_running": True,
                "reason": "malicious test entry",
            })
            with self.subTest(service=service):
                with self.assertRaisesRegex(ValueError, "whitelist violation"):
                    runner.validate_profile(profile)

    def test_protected_uwp_runtimes_cannot_enter_blacklist(self):
        for pkg in ("Microsoft.VCLibs.140.00", "Microsoft.DirectX.Runtime", "Microsoft.Windows.SecHealthUI"):
            profile = self.load_profile()
            profile["optimization_blacklist"]["uwp_packages"].append(pkg)
            with self.subTest(pkg=pkg):
                with self.assertRaisesRegex(ValueError, "whitelist violation"):
                    runner.validate_profile(profile)

    def test_protected_security_tasks_cannot_enter_blacklist(self):
        profile = self.load_profile()
        profile["optimization_blacklist"]["scheduled_tasks"].append({
            "task_path": "\\Microsoft\\Windows\\Windows Defender\\",
            "task_name": "Windows Defender Verification",
            "reason": "bad entry",
        })
        with self.assertRaisesRegex(ValueError, "whitelist violation"):
            runner.validate_profile(profile)

    def test_non_hkcu_or_security_registry_tweaks_are_rejected(self):
        for path in (
            "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard",
            "HKCU:\\Software\\Policies\\System",
        ):
            profile = self.load_profile()
            profile["optimization_blacklist"]["registry_tweaks"].append({
                "path": path,
                "name": "BadValue",
                "kind": "DWord",
                "value": 0,
            })
            with self.subTest(path=path):
                with self.assertRaisesRegex(ValueError, "whitelist violation"):
                    runner.validate_profile(profile)

    def test_missing_prism_files_or_weakened_compliance_is_rejected(self):
        profile = self.load_profile()
        profile["protected_whitelist"]["prism_files"] = ["System32\\wow64.dll"]
        with self.assertRaisesRegex(ValueError, "Prism"):
            runner.validate_profile(profile)

        profile = self.load_profile()
        profile["compliance"]["forbid_virtualization_hiding"] = False
        with self.assertRaisesRegex(ValueError, "compliance flag"):
            runner.validate_profile(profile)

    def test_duplicate_blacklist_service_or_invalid_start_type_is_rejected(self):
        profile = self.load_profile()
        first = copy.deepcopy(profile["optimization_blacklist"]["services"][0])
        profile["optimization_blacklist"]["services"].append(first)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            runner.validate_profile(profile)

        profile = self.load_profile()
        profile["optimization_blacklist"]["services"][0]["target_start_type"] = "Automatic"
        with self.assertRaisesRegex(ValueError, "invalid target_start_type"):
            runner.validate_profile(profile)

    def test_primary_vm_uuid_is_hard_blocked_from_clone_runner(self):
        primary = "11111111-2222-3333-4444-555555555555"
        clone = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        runner.assert_clone_vm_safe(clone, primary)
        with self.assertRaisesRegex(ValueError, "primary clean vm-a"):
            runner.assert_clone_vm_safe(primary, primary)
        with self.assertRaisesRegex(ValueError, "primary clean vm-a"):
            runner.assert_clone_vm_safe(primary.upper(), primary.lower())

    def test_redaction_strips_volume_names_home_and_uuids(self):
        raw = "/Volumes/SecretDisk/vms/11111111-2222-3333-4444-555555555555/config.plist"
        cleaned = runner.redact_text(raw)
        self.assertNotIn("SecretDisk", cleaned)
        self.assertNotIn("11111111-2222-3333-4444-555555555555", cleaned)
        self.assertIn("/Volumes/<EXTERNAL_VOLUME>", cleaned)
        self.assertIn("vm-clone", cleaned)

    def test_powershell_scripts_contain_whitelist_guard_and_no_forbidden_primitives(self):
        apply_text = APPLY_SCRIPT_PATH.read_text(encoding="utf-8")
        rollback_text = ROLLBACK_SCRIPT_PATH.read_text(encoding="utf-8")
        self.assertIn("$HardProtectedServices", apply_text)
        self.assertIn("Assert-ProfileSafe", apply_text)
        self.assertIn("snapshot-initial.json", apply_text)
        self.assertIn("snapshot-initial.json", rollback_text)
        self.assertIn("rollback_consistent", rollback_text)
        for text in (apply_text, rollback_text):
            for forbidden in ("testsigning on", "nointegritychecks on", "kvm=off", "hv_vendor_id"):
                self.assertNotIn(forbidden, text.lower())
        self.assertIn("Capture-GamingSessionSnapshot", apply_text)
        self.assertIn("Win32PrioritySeparation", apply_text)
        self.assertIn("Win32PrioritySeparation", rollback_text)
        self.assertIn("AutomaticManagedPagefile", apply_text)
        self.assertIn("AutomaticManagedPagefile", rollback_text)

    def test_v3_gaming_session_controls_validation_and_guards(self):
        profile = self.load_profile()
        self.assertGreaterEqual(profile.get("profile_revision", 1), 3)
        gc = profile["gaming_session_controls"]
        self.assertTrue(gc["locale_and_ime"]["enabled"])
        self.assertEqual(gc["locale_and_ime"]["ui_language"], "zh-CN")
        self.assertEqual(gc["pagefile"]["initial_size_mb"], 8192)
        self.assertEqual(gc["pagefile"]["maximum_size_mb"], 12288)
        self.assertEqual(gc["cpu_and_memory_tuning"]["win32_priority_separation"], 38)

        # Reject ACE/security service in update_pause_services
        bad_svc = copy.deepcopy(profile)
        bad_svc["gaming_session_controls"]["update_pause_services"].append({
            "name": "ACE-CORE10405",
            "target_start_type": "Manual",
            "stop_running": True,
        })
        with self.assertRaisesRegex(ValueError, "whitelist violation"):
            runner.validate_profile(bad_svc)

        # Reject Disabled start type in update_pause_services (must be Manual)
        bad_mode = copy.deepcopy(profile)
        bad_mode["gaming_session_controls"]["update_pause_services"][0]["target_start_type"] = "Disabled"
        with self.assertRaisesRegex(ValueError, "Manual"):
            runner.validate_profile(bad_mode)

        # Reject unsafe pagefile bounds
        bad_pf = copy.deepcopy(profile)
        bad_pf["gaming_session_controls"]["pagefile"]["initial_size_mb"] = 512
        with self.assertRaisesRegex(ValueError, "pagefile"):
            runner.validate_profile(bad_pf)

        # Reject invalid memory_compression or Win32PrioritySeparation
        bad_mc = copy.deepcopy(profile)
        bad_mc["gaming_session_controls"]["cpu_and_memory_tuning"]["memory_compression"] = "invalid"
        with self.assertRaisesRegex(ValueError, "memory_compression"):
            runner.validate_profile(bad_mc)

        bad_prio = copy.deepcopy(profile)
        bad_prio["gaming_session_controls"]["cpu_and_memory_tuning"]["win32_priority_separation"] = 999
        with self.assertRaisesRegex(ValueError, "win32_priority_separation"):
            runner.validate_profile(bad_prio)

    def test_v31_disables_crashing_spice_webdavd_and_clamps_pagefile(self):
        profile = self.load_profile()
        self.assertGreaterEqual(profile.get("profile_revision", 1), 6)
        self.assertEqual(profile.get("profile_version"), "3.3")
        svc_map = {s["name"]: s for s in profile["optimization_blacklist"]["services"]}
        self.assertIn("spice-webdavd", svc_map)
        self.assertEqual(svc_map["spice-webdavd"]["target_start_type"], "Disabled")
        self.assertTrue(svc_map["spice-webdavd"]["stop_running"])
        self.assertEqual(
            profile["gaming_session_controls"]["cpu_and_memory_tuning"]["memory_compression"],
            "preserve",
        )
        apply_text = APPLY_SCRIPT_PATH.read_text(encoding="utf-8")
        self.assertIn("effective_available_mb", apply_text)
        self.assertIn("current_pagefile_mb", apply_text)

    def test_v33_real_user_hive_display_stability_and_cursor_bridge_contracts(self):
        profile = self.load_profile()
        tweak_map = {
            (entry["path"], entry["name"]): entry["value"]
            for entry in profile["optimization_blacklist"]["registry_tweaks"]
        }
        self.assertEqual(tweak_map[("HKCU:\\System\\GameConfigStore", "GameDVR_FSEBehaviorMode")], 2)
        self.assertEqual(tweak_map[("HKCU:\\System\\GameConfigStore", "GameDVR_HonorUserFSEBehaviorMode")], 1)
        self.assertEqual(tweak_map[("HKCU:\\Control Panel\\Mouse", "MouseTrails")], "0")
        self.assertEqual(tweak_map[("HKCU:\\Control Panel\\Desktop", "DragFullWindows")], "1")
        self.assertEqual(tweak_map[("HKCU:\\Control Panel\\Desktop", "FontSmoothing")], "2")

        fd = profile["gaming_session_controls"]["footprint_and_display_controls"]
        self.assertTrue(fd["disable_dwm_mpo_overlay"])
        self.assertTrue(fd["disable_graphics_overlays"])
        self.assertTrue(fd["disable_pointer_shadow_and_fade_animations"])
        self.assertTrue(fd["ensure_hd_display_mode"])
        self.assertTrue(fd["install_cursor_bridge"])

        apply_text = APPLY_SCRIPT_PATH.read_text(encoding="utf-8")
        rollback_text = ROLLBACK_SCRIPT_PATH.read_text(encoding="utf-8")
        for required in (
            "Get-LoadedRealUserHiveRoots",
            "MaltDefaultUser",
            "DisableOverlays",
            "SPI_SETCURSORSHADOW",
            "EnsureHdDisplayMode",
            "MaltCursorBridge",
        ):
            self.assertIn(required, apply_text)
        self.assertIn("Get-LoadedRealUserHiveRoots", rollback_text)
        self.assertIn("MaltCursorBridge", rollback_text)

        self.assertTrue(CURSOR_BRIDGE_SCRIPT_PATH.is_file())
        bridge_text = CURSOR_BRIDGE_SCRIPT_PATH.read_text(encoding="utf-8")
        bridge_lower = bridge_text.lower()
        for required in (
            "GetCursorInfo",
            "GetIconInfo",
            "GetDIBits",
            "SHQueryUserNotificationState",
            "com.malt.cursor.0",
            "MCB1",
        ):
            self.assertIn(required, bridge_text)
        for forbidden in (
            "setwindowshookex",
            "createremotethread",
            "writeprocessmemory",
            "virtualallocex",
            "ntinject",
            "openprocess",
            "readprocessmemory",
            "testsigning on",
            "nointegritychecks on",
            "kvm=off",
            "hv_vendor_id",
        ):
            self.assertNotIn(forbidden, bridge_lower)

    def test_kiosk_app_shell_script_is_compliant_reversible_and_zero_injection(self):
        self.assertTrue(KIOSK_SCRIPT_PATH.is_file())
        kiosk_text = KIOSK_SCRIPT_PATH.read_text(encoding="utf-8")
        lowered = kiosk_text.lower()

        # Required compliant Win32 APIs and restoration lifecycle
        for required in (
            "Shell_TrayWnd",
            "SHELLDLL_DefView",
            "SPI_SETDESKWALLPAPER",
            "GetForegroundWindow",
            "GetWindowThreadProcessId",
            "game_foreground_detected",
            "enter_fullscreen_gamemode",
            "PriorityClass = 'High'",
            "Restore-KioskDesktop",
            "Save-DesktopState",
            "ProtectedProcessPrefixes",
            "Win32_Process",
            "ParentProcessId",
            "CreationDate",
            "IsWindowFullscreen",
            "GetWindowRect",
            "Resolve-ProcessLineageChain",
            "lineage_chain",
        ):
            self.assertIn(required, kiosk_text)

        # Forbidden DWM hook, injection, or security-weakening primitives
        for forbidden in (
            "setwindowshookex",
            "createremotethread",
            "writeprocessmemory",
            "virtualallocex",
            "ntinject",
            "dwm.exe",
            "testsigning on",
            "nointegritychecks on",
            "kvm=off",
            "hv_vendor_id",
        ):
            self.assertNotIn(forbidden, lowered)


if __name__ == "__main__":
    unittest.main()
