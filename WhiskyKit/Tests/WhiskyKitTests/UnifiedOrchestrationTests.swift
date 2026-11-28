// SPDX-License-Identifier: GPL-3.0-or-later
// Unit tests for unified game library, hardware auto-tuner, embedded discovery, and orchestrator.

// These integration fixtures intentionally share one isolated orchestration harness.
// swiftlint:disable file_length type_body_length

import Foundation
import XCTest

@testable import WhiskyKit

private struct RecordedInvocation: Sendable {
  let executable: String
  let arguments: [String]
  let environment: [String: String]
}

private actor RecordedCommands {
  private(set) var invocations: [RecordedInvocation] = []
  func record(executable: String, arguments: [String], environment: [String: String]) {
    invocations.append(
      RecordedInvocation(executable: executable, arguments: arguments, environment: environment))
  }
  func all() -> [RecordedInvocation] { invocations }
}

private struct StagedEmbeddedApp {
  let app: URL
  let helper: URL
  let golden: URL
  let kiosk: URL
}

final class UnifiedOrchestrationTests: XCTestCase {
  private var tempDir: URL?

  override func setUpWithError() throws {
    let dir = FileManager.default.temporaryDirectory
      .appending(path: "whisky-p15b-tests-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    tempDir = dir
  }

  override func tearDownWithError() throws {
    if let dir = tempDir { try? FileManager.default.removeItem(at: dir) }
  }

  func testUnifiedGameLibraryStorePersistsUpsertAndRemove() throws {
    let dir = try XCTUnwrap(tempDir)
    let storeURL = dir.appending(path: "UnifiedGameLibrary.json")
    let store = UnifiedGameLibraryStore(storageURL: storeURL)
    let wineEntry = UnifiedGameEntry(
      name: "Hades II", executablePath: "/Games/Hades2.exe",
      engineKind: .nativeWine, presetTier: .balanced, bottleURL: dir.appending(path: "Bottles/Main")
    )
    let vmEntry = UnifiedGameEntry(
      name: "Valorant", executablePath: "C:\\Riot Games\\VALORANT\\live\\VALORANT.exe",
      engineKind: .antiCheatVM, presetTier: .lowSpecCompatible,
      vmBundlePath: "/Volumes/External/playable.utm"
    )
    store.upsert(wineEntry)
    store.upsert(vmEntry)
    XCTAssertEqual(store.entries.count, 2)

    var updatedWine = wineEntry
    updatedWine.presetTier = .maxPerformance
    store.upsert(updatedWine)
    let reloaded = UnifiedGameLibraryStore(storageURL: storeURL)
    reloaded.load()
    XCTAssertEqual(
      reloaded.entries.first(where: { $0.id == wineEntry.id })?.presetTier, .maxPerformance)

    reloaded.remove(id: vmEntry.id)
    let afterRemove = UnifiedGameLibraryStore(storageURL: storeURL)
    afterRemove.load()
    XCTAssertEqual(afterRemove.entries.map(\.id), [wineEntry.id])
  }

  func testPerformancePresetTierBackwardCompatibleWithLegacyJSON() throws {
    let legacyJSON = """
      ["nativeQuality","balancedRecommended","competitiveHighFPS","maxPerformance","balanced","lowSpecCompatible"]
      """
    let decoded = try JSONDecoder().decode(
      [PerformancePresetTier].self, from: Data(legacyJSON.utf8))
    XCTAssertEqual(
      decoded,
      [
        .maxPerformance, .balanced, .lowSpecCompatible, .maxPerformance, .balanced,
        .lowSpecCompatible
      ]
    )
    XCTAssertEqual(PerformancePresetTier.maxPerformance.displayName, "最高性能")
    XCTAssertEqual(PerformancePresetTier.balanced.displayName, "平衡")
    XCTAssertEqual(PerformancePresetTier.lowSpecCompatible.displayName, "低配置兼容")
  }

  func testClassifyInstallerRecommendsAntiCheatVMOrNativeWine() throws {
    let dir = try XCTUnwrap(tempDir)
    let store = UnifiedGameLibraryStore(storageURL: dir.appending(path: "lib.json"))
    XCTAssertEqual(
      store.classifyInstaller(url: dir.appending(path: "Install VALORANT.exe")), .antiCheatVM)
    XCTAssertEqual(
      store.classifyInstaller(url: dir.appending(path: "DeltaForce_WeGame_Setup.exe")), .antiCheatVM
    )

    let indieURL = dir.appending(path: "HollowKnightSetup.exe")
    try Data("standard unity installer payload".utf8).write(to: indieURL)
    XCTAssertEqual(store.classifyInstaller(url: indieURL), .nativeWine)

    let embeddedACURL = dir.appending(path: "GenericLauncher.exe")
    try Data("MZ...AntiCheatExpertService...".utf8).write(to: embeddedACURL)
    XCTAssertEqual(store.classifyInstaller(url: embeddedACURL), .antiCheatVM)
  }

  func testHardwareAutoTunerSafeMemoryAndVCPUOptionsAcrossMacTiers() {
    let p16 = makeProfile(chip: "Apple M4", cores: 10, memGiB: 16)
    XCTAssertEqual(HardwareAutoTuner.safeMemoryOptionsGiB(for: p16), [6, 8, 10, 12])
    XCTAssertEqual(HardwareAutoTuner.recommendedMemoryGiB(for: p16), 10)
    XCTAssertEqual(HardwareAutoTuner.clampedMemoryGiB(24, for: p16), 12)
    XCTAssertEqual(HardwareAutoTuner.safeVCPUOptions(for: p16), [4, 6, 8])

    let rec16 = HardwareAutoTuner.recommend(for: p16, benchmarkScore: 72.0, durationSeconds: 11.2)
    XCTAssertEqual(rec16.recommendedVCPU, 8)
    XCTAssertEqual(rec16.recommendedRAMGiB, 10)
    XCTAssertEqual(rec16.recommendedTier, .balanced)
    XCTAssertEqual(rec16.mouseCoalesceMicros, 1500)

    let p24 = makeProfile(chip: "Apple M4 Pro", cores: 12, memGiB: 24)
    XCTAssertEqual(HardwareAutoTuner.safeMemoryOptionsGiB(for: p24), [8, 12, 16])
    let rec24 = HardwareAutoTuner.recommend(for: p24, benchmarkScore: 85.0, durationSeconds: 10.5)
    XCTAssertEqual(rec24.recommendedTier, .maxPerformance)
    XCTAssertEqual(rec24.recommendedRAMGiB, 12)

    let p36 = makeProfile(chip: "Apple M4 Max", cores: 16, memGiB: 36)
    XCTAssertEqual(HardwareAutoTuner.safeMemoryOptionsGiB(for: p36), [8, 12, 16, 20])
    XCTAssertEqual(HardwareAutoTuner.recommendedMemoryGiB(for: p36), 16)

    let profile8 = makeProfile(chip: "Apple M1", cores: 8, memGiB: 8, refreshHz: 60)
    XCTAssertEqual(HardwareAutoTuner.safeMemoryOptionsGiB(for: profile8), [4, 6])
    let rec8 = HardwareAutoTuner.recommend(
      for: profile8, benchmarkScore: 45.0, durationSeconds: 12.0)
    XCTAssertEqual(rec8.recommendedTier, .lowSpecCompatible)
    XCTAssertEqual(rec8.mouseCoalesceMicros, 1500)
  }

  func testHardwareAutoTunerDetectAndQuickBenchmark() async {
    let tuner = HardwareAutoTuner(benchmarkDurationSeconds: 0.15)
    let snapshot = tuner.detectHardwareProfile()
    XCTAssertFalse(snapshot.chipName.isEmpty)
    let rec = await tuner.runQuickBenchmarkAndRecommend()
    XCTAssertEqual(rec.hardware.chipName, snapshot.chipName)
    XCTAssertGreaterThan(rec.benchmarkScore, 0.0)
    XCTAssertGreaterThanOrEqual(rec.recommendedRAMMiB, 4096)
  }

  func testOrchestratorWineUsesNativeWhiskyWineAndGraphicsRouting() async throws {
    let dir = try XCTUnwrap(tempDir)
    let bottleURL = dir.appending(path: "Bottles/Main")
    let libFolder = dir.appending(path: "Libraries")
    let dxmtWin = libFolder.appending(path: "DXMT/wine/x86_64-windows")
    let dxmtUnix = libFolder.appending(path: "DXMT/wine/x86_64-unix")
    let wineBin = libFolder.appending(path: "Wine/bin/wine64")
    let installerExe = dir.appending(path: "IndieSetup.exe")
    for folder in [bottleURL, dxmtWin, dxmtUnix, wineBin.deletingLastPathComponent()] {
      try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
    }
    try Data("dll".utf8).write(to: dxmtWin.appending(path: "d3d11.dll"))
    try Data("dll".utf8).write(to: dxmtWin.appending(path: "dxgi.dll"))
    try Data("so".utf8).write(to: dxmtUnix.appending(path: "winemetal.so"))
    try Data("bin".utf8).write(to: wineBin)
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: wineBin.path)
    try Data("setup".utf8).write(to: installerExe)

    let recorder = RecordedCommands()
    let config = UnifiedOrchestratorConfiguration(
      utmCustomAppPath: dir.appending(path: "Missing.app").path(percentEncoded: false),
      utmAppPath: dir.appending(path: "MissingUTM.app").path(percentEncoded: false),
      defaultBottleURL: bottleURL, appBundleURL: dir.appending(path: "NoMalt.app"),
      volumesRootURL: dir.appending(path: "EmptyVolumes"),
      wineBinaryURL: wineBin, wineLibraryFolderURL: libFolder
    )
    let orchestrator = UnifiedRuntimeOrchestrator(
      libraryStore: UnifiedGameLibraryStore(storageURL: dir.appending(path: "store.json")),
      configuration: config,
      commandRunner: { exe, args, env in
        await recorder.record(executable: exe, arguments: args, environment: env)
        return OrchestratorCommandResult(exitCode: 0, stdout: "GUEST_AGENT_READY")
      }
    )
    _ = try await orchestrator.install(
      installerURL: installerExe, engineKind: .nativeWine, title: "Indie Title")
    let recorded = await recorder.all()
    let first = try XCTUnwrap(recorded.first)
    XCTAssertEqual(first.executable, wineBin.path(percentEncoded: false))
    XCTAssertNotEqual(first.executable, "/usr/bin/env")
    XCTAssertEqual(first.environment["WINEPREFIX"], bottleURL.path(percentEncoded: false))
    XCTAssertEqual(first.environment["DXMT_SHADER_CACHE"], "1")
    XCTAssertTrue(first.environment["WINEDLLPATH"]?.contains("DXMT/wine") == true)
  }

  func testOrchestratorMultiTierDiscoveryEmbeddedHelperScriptsAndSSD() throws {
    let dir = try XCTUnwrap(tempDir)
    let staged = try stageEmbeddedApp(in: dir)
    let fakeVolumes = dir.appending(path: "Volumes")
    let ssdGuest = fakeVolumes.appending(path: "FastSSD/whisky-phase2-guest")
    let playableVM = ssdGuest.appending(path: "win11-playable-main.utm")
    for bundle in [
      ssdGuest.appending(path: "golden-win11-arm64-v1.utm"),
      ssdGuest.appending(path: "vm-a.utm"),
      playableVM
    ] {
      try stagePlayableVM(at: bundle)
    }

    let config = UnifiedOrchestratorConfiguration(
      utmCustomAppPath: dir.appending(path: "NoExt.app").path(percentEncoded: false),
      utmAppPath: dir.appending(path: "NoUTM.app").path(percentEncoded: false),
      appBundleURL: staged.app, volumesRootURL: fakeVolumes,
      playableSelectionStorageURL: dir.appending(path: "selected-container.json")
    )
    let resolved = UnifiedRuntimeDiscovery.resolve(configuration: config)
    XCTAssertEqual(resolved.containerHelperBinaryPath, staged.helper.path(percentEncoded: false))
    XCTAssertTrue(resolved.isEmbeddedHelper)
    XCTAssertEqual(resolved.goldenManagerScriptPath, staged.golden.path(percentEncoded: false))
    XCTAssertEqual(resolved.kioskShellScriptPath, staged.kiosk.path(percentEncoded: false))
    XCTAssertEqual(resolved.playableVMBundlePath, playableVM.path(percentEncoded: false))

    let fallbackNet = UnifiedRuntimeDiscovery.detectNativeVMNetStatus(
      socketCandidates: [dir.appending(path: "missing_vmnet").path(percentEncoded: false)],
      daemonPlistCandidates: []
    )
    XCTAssertEqual(fallbackNet.activeMode, .notVerified)

    let activeSocket = dir.appending(path: "malt_vmnet")
    try Data("sock".utf8).write(to: activeSocket)
    let directNet = UnifiedRuntimeDiscovery.detectNativeVMNetStatus(
      socketCandidates: [activeSocket.path(percentEncoded: false)], daemonPlistCandidates: []
    )
    XCTAssertFalse(directNet.socketActive)
    XCTAssertEqual(directNet.activeMode, .notVerified)
  }

  func testOrchestratorInstallViaAntiCheatVMForwardsAppShellFlagsAndInstallerExe() async throws {
    let dir = try XCTUnwrap(tempDir)
    let staged = try stageEmbeddedApp(in: dir)
    let playableVM = dir.appending(path: "Volumes/SSD/whisky-phase2-guest/playable-game.utm")
    let installerExe = dir.appending(path: "DeltaForceSetup.exe")
    try stagePlayableVM(at: playableVM)
    try Data("installer".utf8).write(to: installerExe)

    let recorder = RecordedCommands()
    let config = UnifiedOrchestratorConfiguration(
      utmCustomAppPath: dir.appending(path: "Missing.app").path(percentEncoded: false),
      utmAppPath: dir.appending(path: "MissingUTM.app").path(percentEncoded: false),
      appBundleURL: staged.app, volumesRootURL: dir.appending(path: "Volumes"),
      appShellWindowSize: "1024x680", appShellStateDirectory: dir.appending(path: "state"),
      playableSelectionStorageURL: dir.appending(path: "selected-container.json")
    )
    let orchestrator = UnifiedRuntimeOrchestrator(
      libraryStore: UnifiedGameLibraryStore(storageURL: dir.appending(path: "store.json")),
      configuration: config,
      commandRunner: { exe, args, env in
        await recorder.record(executable: exe, arguments: args, environment: env)
        return OrchestratorCommandResult(exitCode: 0, stdout: "GUEST_AGENT_READY")
      }
    )
    let entry = try await orchestrator.install(
      installerURL: installerExe, engineKind: .antiCheatVM, title: "Delta Force"
    )
    XCTAssertEqual(entry.vmBundlePath, playableVM.path(percentEncoded: false))

    let recorded = await recorder.all()
    let call = try XCTUnwrap(
      recorded.first { $0.executable == staged.helper.path(percentEncoded: false) })
    XCTAssertEqual(call.executable, staged.helper.path(percentEncoded: false))
    for flag in [
      "--app-shell-vm", "--window-title", "Delta Force", "--window-size", "1024x680",
      "--app-shell-state-file"
    ] {
      XCTAssertTrue(call.arguments.contains(flag))
    }
    XCTAssertEqual(call.environment["__DEMOAPP_DETACHED"], "1")
    XCTAssertEqual(entry.installationState, .installerRequested)
    XCTAssertTrue(recorded.contains { $0.arguments.starts(with: ["file", "push", "--hide"]) })
    let installerPush = try XCTUnwrap(
      recorded.first {
        $0.environment["__DEMOAPP_STDIN_FILE"] == installerExe.path(percentEncoded: false)
      })
    XCTAssertTrue(installerPush.arguments.last?.hasSuffix("installer.exe") == true)
    XCTAssertTrue(recorded.contains { $0.arguments.contains("-EncodedCommand") })
    XCTAssertFalse(orchestrator.lastStatusMessage.contains("Installed"))
    XCTAssertEqual(orchestrator.healthStatus()["embedded_helper_ready"], true)
  }

  func testOrchestratorRejectsMissingInstallerOrVMBundle() async throws {
    let dir = try XCTUnwrap(tempDir)
    let orchestrator = UnifiedRuntimeOrchestrator(
      libraryStore: UnifiedGameLibraryStore(storageURL: dir.appending(path: "store.json"))
    )
    let missingInstaller = dir.appending(path: "NoSuchInstaller.exe")
    do {
      _ = try await orchestrator.install(
        installerURL: missingInstaller, engineKind: .nativeWine, title: "Broken")
      XCTFail("Expected missingInstaller error")
    } catch let error as UnifiedOrchestrationError {
      XCTAssertEqual(error, .missingInstaller(missingInstaller.path(percentEncoded: false)))
    }

    let brokenVM = UnifiedGameEntry(
      name: "Broken VM", executablePath: "C:\\game.exe", engineKind: .antiCheatVM,
      vmBundlePath: dir.appending(path: "missing.utm").path(percentEncoded: false)
    )
    do {
      try await orchestrator.launch(entry: brokenVM)
      XCTFail("Expected missingVMBundle error")
    } catch let error as UnifiedOrchestrationError {
      XCTAssertEqual(
        error, .missingVMBundle(dir.appending(path: "missing.utm").path(percentEncoded: false)))
    }
  }
  func testMissingContainerDoesNotPersistSuccessfulInstall() async throws {
    let dir = try XCTUnwrap(tempDir)
    let installer = dir.appending(path: "setup.exe")
    try Data("MZ".utf8).write(to: installer)
    let store = UnifiedGameLibraryStore(storageURL: dir.appending(path: "store.json"))
    let orchestrator = UnifiedRuntimeOrchestrator(
      libraryStore: store,
      configuration: UnifiedOrchestratorConfiguration(
        utmCustomAppPath: "", utmAppPath: "", appBundleURL: dir.appending(path: "missing.app"),
        volumesRootURL: dir.appending(path: "volumes"), localVMSearchRoots: []
      )
    )
    do {
      _ = try await orchestrator.install(
        installerURL: installer, engineKind: .antiCheatVM, title: "Sample")
      XCTFail("Missing guest must not be reported as installed")
    } catch is UnifiedOrchestrationError {
      XCTAssertTrue(store.entries.isEmpty)
      XCTAssertFalse(orchestrator.healthStatus()["anti_cheat_vm_ready"] ?? true)
    }
  }

  func testLocalVMDiscoveryWorksWithoutExternalVolumes() throws {
    let dir = try XCTUnwrap(tempDir)
    let local = dir.appending(path: "Application Support/Containers")
    let playable = local.appending(path: "playable.utm")
    try stagePlayableVM(at: playable)
    let config = UnifiedOrchestratorConfiguration(
      utmCustomAppPath: "", utmAppPath: "", appBundleURL: dir.appending(path: "none.app"),
      volumesRootURL: dir.appending(path: "missing-volumes"), localVMSearchRoots: [local],
      playableSelectionStorageURL: dir.appending(path: "selected-container.json")
    )
    XCTAssertEqual(
      UnifiedRuntimeDiscovery.resolve(configuration: config).playableVMBundlePath, playable.path)
  }

  func testExplicitMissingOrProtectedVMNeverSilentlyLaunchesAnotherGame() throws {
    let dir = try XCTUnwrap(tempDir)
    let local = dir.appending(path: "containers")
    try stagePlayableVM(at: local.appending(path: "playable.utm"))
    let template = local.appending(path: "golden-template.utm")
    try stagePlayableVM(at: template)
    let alias = local.appending(path: "innocent.utm")
    try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: template)
    for selected in [local.appending(path: "missing.utm"), template, alias] {
      let config = UnifiedOrchestratorConfiguration(
        defaultPlayableVMBundlePath: selected.path, volumesRootURL: dir.appending(path: "volumes"),
        localVMSearchRoots: [local]
      )
      XCTAssertNil(UnifiedRuntimeDiscovery.resolve(configuration: config).playableVMBundlePath)
    }
  }

  func testNonExecutableEmbeddedHelperIsNotReady() throws {
    let dir = try XCTUnwrap(tempDir)
    let staged = try stageEmbeddedApp(in: dir)
    try FileManager.default.setAttributes(
      [.posixPermissions: 0o644], ofItemAtPath: staged.helper.path)
    let config = UnifiedOrchestratorConfiguration(
      utmCustomAppPath: "", utmAppPath: "", appBundleURL: staged.app,
      volumesRootURL: dir.appending(path: "volumes"), localVMSearchRoots: []
    )
    XCTAssertNil(UnifiedRuntimeDiscovery.resolve(configuration: config).containerHelperBinaryPath)
  }

  func testPendingInstallerCannotMasqueradeAsConfiguredGame() async throws {
    let dir = try XCTUnwrap(tempDir)
    let recorder = RecordedCommands()
    let orchestrator = UnifiedRuntimeOrchestrator(
      libraryStore: UnifiedGameLibraryStore(storageURL: dir.appending(path: "store.json")),
      commandRunner: { exe, args, env in
        await recorder.record(executable: exe, arguments: args, environment: env)
        return OrchestratorCommandResult(exitCode: 0, stdout: "GUEST_AGENT_READY")
      }
    )
    let pending = UnifiedGameEntry(
      name: "Sample", executablePath: "/tmp/setup.exe", engineKind: .nativeWine,
      installationState: .installerRequested
    )
    do {
      try await orchestrator.launch(entry: pending)
      XCTFail("Installer must not be launched again as a game")
    } catch is UnifiedOrchestrationError {
      let calls = await recorder.all()
      XCTAssertTrue(calls.isEmpty)
    }
  }

  func testLegacyEntryDecodesWithoutInstallationState() throws {
    let data = Data(
      """
      {"id":"00000000-0000-0000-0000-000000000001","name":"Sample",
      "executablePath":"/tmp/game.exe","engineKind":"nativeWine","presetTier":"balanced"}
      """.utf8)
    XCTAssertNil(try JSONDecoder().decode(UnifiedGameEntry.self, from: data).installationState)
  }

  func testGuestLaunchPassesSelectedTargetThroughEncodedInteractiveTask() async throws {
    let recorder = RecordedCommands()
    let dispatcher = ContainerGuestDispatcher(
      controlBinaryPath: "/tmp/control", vmIdentifier: UUID().uuidString,
      commandRunner: { exe, args, env in
        await recorder.record(executable: exe, arguments: args, environment: env)
        return OrchestratorCommandResult(exitCode: 0, stdout: "GUEST_AGENT_READY")
      }
    )
    let selected = #"C:\Games\Sample's Game\game.exe"#
    try await dispatcher.submit(
      targetExecutable: selected, targetArguments: "--profile sample's",
      targetWorkingDirectory: #"C:\Games\Sample's Game"#, kioskScriptPath: "/tmp/kiosk.ps1")
    let calls = await recorder.all()
    XCTAssertTrue(calls.allSatisfy { $0.arguments.contains("--hide") })
    let scripts = calls.compactMap { call -> String? in
      guard let index = call.arguments.firstIndex(of: "-EncodedCommand"),
        index + 1 < call.arguments.count,
        let data = Data(base64Encoded: call.arguments[index + 1])
      else { return nil }
      return String(data: data, encoding: .utf16LittleEndian)
    }
    let schedule = try XCTUnwrap(scripts.last)
    XCTAssertTrue(schedule.contains("-LogonType Interactive -RunLevel Limited"))
    XCTAssertTrue(schedule.contains("Sample''s Game"))
    XCTAssertTrue(schedule.contains("Test-Path -LiteralPath"))
    XCTAssertTrue(schedule.contains("Unregister-ScheduledTask"))
    XCTAssertTrue(schedule.contains("$receipt.state -eq 'started'"))
    XCTAssertTrue(schedule.contains("[int]$receipt.pid -gt 0"))
    XCTAssertFalse(schedule.contains("267011"))
    XCTAssertFalse(schedule.contains("-RunLevel Highest"))
    XCTAssertTrue(schedule.contains("AddSeconds(180)"))
    XCTAssertEqual(calls.last?.environment["__DEMOAPP_TIMEOUT_SECONDS"], "195.0")
    let actionMatch = try XCTUnwrap(
      schedule.range(of: "-EncodedCommand ([A-Za-z0-9+/=]+)", options: .regularExpression))
    let actionData = try XCTUnwrap(
      Data(
        base64Encoded: String(schedule[actionMatch]).replacingOccurrences(
          of: "-EncodedCommand ", with: "")))
    let action = try XCTUnwrap(String(data: actionData, encoding: .utf16LittleEndian))
    XCTAssertTrue(action.contains("-PreserveDesktopState"))
    XCTAssertTrue(action.contains("-TargetArguments '--profile sample''s'"))
    XCTAssertTrue(action.contains(#"-TargetWorkingDirectory 'C:\Games\Sample''s Game'"#))
  }

  func testGuestRejectsHostPathAndInvalidTargetsBeforeInvokingCommands() async throws {
    for path in ["/tmp/setup.exe", "game.exe", "C:\\game.exe\nRemove-Item C:\\*"] {
      XCTAssertFalse(ContainerGuestDispatcher.isWindowsExecutablePath(path))
    }
    XCTAssertTrue(ContainerGuestDispatcher.isWindowsExecutablePath(#"C:\Games\game.exe"#))
    XCTAssertTrue(ContainerGuestDispatcher.isWindowsExecutablePath(#"\\server\games\game.exe"#))
    let recorder = RecordedCommands()
    let dispatcher = ContainerGuestDispatcher(
      controlBinaryPath: "/tmp/control", vmIdentifier: UUID().uuidString,
      commandRunner: { exe, args, env in
        await recorder.record(executable: exe, arguments: args, environment: env)
        return OrchestratorCommandResult(exitCode: 0, stdout: "GUEST_AGENT_READY")
      }
    )
    do {
      try await dispatcher.submit(
        targetExecutable: "/tmp/setup.exe", kioskScriptPath: "/tmp/kiosk.ps1")
      XCTFail("Host path must not be treated as guest executable")
    } catch is UnifiedOrchestrationError {
      let calls = await recorder.all()
      XCTAssertTrue(calls.isEmpty)
    }
  }

  func testInstallerTransferFailureDoesNotPersistEntryOrRunTask() async throws {
    let dir = try XCTUnwrap(tempDir)
    let staged = try stageEmbeddedApp(in: dir)
    let playable = dir.appending(path: "playable.utm")
    try stagePlayableVM(at: playable)
    let installer = dir.appending(path: "setup.exe")
    try Data("MZ".utf8).write(to: installer)
    let recorder = RecordedCommands()
    let store = UnifiedGameLibraryStore(storageURL: dir.appending(path: "store.json"))
    let orchestrator = UnifiedRuntimeOrchestrator(
      libraryStore: store,
      configuration: UnifiedOrchestratorConfiguration(
        defaultPlayableVMBundlePath: playable.path, appBundleURL: staged.app,
        volumesRootURL: dir.appending(path: "volumes"), localVMSearchRoots: []
      ),
      commandRunner: { exe, args, env in
        await recorder.record(executable: exe, arguments: args, environment: env)
        return OrchestratorCommandResult(
          exitCode: env["__DEMOAPP_STDIN_FILE"] == installer.path ? 1 : 0,
          stdout: "GUEST_AGENT_READY")
      }
    )
    do {
      _ = try await orchestrator.install(
        installerURL: installer, engineKind: .antiCheatVM, title: "Sample")
      XCTFail("Transfer failure must stop installation")
    } catch is UnifiedOrchestrationError {
      XCTAssertTrue(store.entries.isEmpty)
      let calls = await recorder.all()
      XCTAssertFalse(
        calls.contains { call in
          guard let index = call.arguments.firstIndex(of: "-EncodedCommand"),
            index + 1 < call.arguments.count,
            let data = Data(base64Encoded: call.arguments[index + 1]),
            let script = String(data: data, encoding: .utf16LittleEndian)
          else { return false }
          return script.contains("Register-ScheduledTask -TaskName")
        })
    }
  }

  func testGuestAgentReadinessTimeoutIsBounded() async throws {
    let dispatcher = ContainerGuestDispatcher(
      controlBinaryPath: "/tmp/control", vmIdentifier: UUID().uuidString,
      commandRunner: { _, _, _ in OrchestratorCommandResult(exitCode: 1) }, readinessTimeout: 0.01
    )
    let started = Date()
    do {
      try await dispatcher.waitUntilReady()
      XCTFail("Missing guest tools must not wait indefinitely")
    } catch is UnifiedOrchestrationError {
      XCTAssertLessThan(Date().timeIntervalSince(started), 2)
    }
  }

  func testGuestAgentReadinessRetriesTransientProbeErrors() async throws {
    let recorder = RecordedCommands()
    let dispatcher = ContainerGuestDispatcher(
      controlBinaryPath: "/tmp/control", vmIdentifier: UUID().uuidString,
      commandRunner: { exe, args, env in
        await recorder.record(executable: exe, arguments: args, environment: env)
        if await recorder.all().count == 1 {
          throw UnifiedOrchestrationError.commandFailed("Temporary guest-agent timeout")
        }
        return OrchestratorCommandResult(exitCode: 0, stdout: "GUEST_AGENT_READY")
      }, readinessTimeout: 2
    )
    try await dispatcher.waitUntilReady()
    let calls = await recorder.all()
    XCTAssertEqual(calls.count, 2)
  }

  func testGuestAgentReadinessPropagatesCancellationImmediately() async throws {
    let recorder = RecordedCommands()
    let dispatcher = ContainerGuestDispatcher(
      controlBinaryPath: "/tmp/control", vmIdentifier: UUID().uuidString,
      commandRunner: { exe, args, env in
        await recorder.record(executable: exe, arguments: args, environment: env)
        throw CancellationError()
      }, readinessTimeout: 90
    )
    do {
      try await dispatcher.waitUntilReady()
      XCTFail("Cancellation must stop readiness probes")
    } catch is CancellationError {
      let calls = await recorder.all()
      XCTAssertEqual(calls.count, 1)
    }
  }

  func testGuestReadinessRejectsZeroExitWithoutExpectedToken() async throws {
    let dispatcher = ContainerGuestDispatcher(
      controlBinaryPath: "/tmp/control", vmIdentifier: UUID().uuidString,
      commandRunner: { _, _, _ in OrchestratorCommandResult(exitCode: 0, stdout: "unrelated output")
      },
      readinessTimeout: 0.01
    )
    do {
      try await dispatcher.waitUntilReady()
      XCTFail("A zero exit status alone does not prove guest readiness")
    } catch is UnifiedOrchestrationError {}
  }

  func testGuestAgentAutomationDenialFailsImmediatelyWithSettingsGuidance() async throws {
    let recorder = RecordedCommands()
    let dispatcher = ContainerGuestDispatcher(
      controlBinaryPath: "/tmp/control", vmIdentifier: UUID().uuidString,
      commandRunner: { exe, args, env in
        await recorder.record(executable: exe, arguments: args, environment: env)
        return OrchestratorCommandResult(exitCode: 1, stderr: "Error from event: -1743")
      }, readinessTimeout: 90
    )
    do {
      try await dispatcher.waitUntilReady()
      XCTFail("Automation denial must not be retried as guest startup")
    } catch {
      XCTAssertTrue(error.localizedDescription.contains("自动化"))
      XCTAssertTrue(error.localizedDescription.contains("系统设置"))
      let calls = await recorder.all()
      XCTAssertEqual(calls.count, 1)
    }
  }

  func testColdContainerLaunchDoesNotSendScriptingStatusBeforeHelperStarts() async throws {
    let calls = try await exerciseContainerStartup(helperRunning: false, status: "started")
    XCTAssertFalse(calls.contains { $0.arguments.first == "status" })
    XCTAssertEqual(calls.filter { $0.arguments.contains("--app-shell-vm") }.count, 1)
  }

  func testWarmContainerStatusTimeoutContinuesGuestReadinessWithoutDuplicateHelper() async throws {
    let calls = try await exerciseContainerStartup(helperRunning: true, status: nil)
    XCTAssertEqual(calls.filter { $0.arguments.first == "status" }.count, 1)
    XCTAssertFalse(calls.contains { $0.arguments.contains("--app-shell-vm") })
    XCTAssertTrue(calls.contains { $0.arguments.contains("GUEST_AGENT_READY") })
  }

  func testStoppedWarmContainerStartsThroughExistingControlApplication() async throws {
    let calls = try await exerciseContainerStartup(helperRunning: true, status: "stopped")
    XCTAssertEqual(calls.filter { $0.arguments.first == "start" }.count, 1)
    XCTAssertFalse(calls.contains { $0.arguments.contains("--app-shell-vm") })
  }

  func testWarmContainerPreflightPreservesCancellation() async throws {
    do {
      _ = try await exerciseContainerStartup(helperRunning: true, status: "cancel")
      XCTFail("Cancellation must stop before guest dispatch")
    } catch is CancellationError {}
  }

  private func exerciseContainerStartup(helperRunning: Bool, status: String?) async throws
    -> [RecordedInvocation] {
    let dir = try XCTUnwrap(tempDir)
    let staged = try stageEmbeddedApp(in: dir)
    let playable = dir.appending(path: "playable.utm")
    try stagePlayableVM(at: playable)
    let installer = dir.appending(path: "setup.exe")
    try Data("MZ".utf8).write(to: installer)
    let recorder = RecordedCommands()
    let bridge = AppShellSessionBridge()
    if helperRunning {
      let binding = try await bridge.createBinding(
        vmIdentifier: ContainerGuestDispatcher.vmIdentifier(bundlePath: playable.path),
        helper: staged.helper.path, directory: dir.appending(path: "shell-state"),
        title: "Sample", windowSize: "1024x680")
      await bridge.recordHelperIdentity("fixture-helper", bindingID: binding.id)
    }
    let orchestrator = UnifiedRuntimeOrchestrator(
      libraryStore: UnifiedGameLibraryStore(storageURL: dir.appending(path: "store.json")),
      configuration: UnifiedOrchestratorConfiguration(
        defaultPlayableVMBundlePath: playable.path, appBundleURL: staged.app,
        volumesRootURL: dir.appending(path: "volumes"), localVMSearchRoots: []
      ),
      commandRunner: { exe, args, env in
        await recorder.record(executable: exe, arguments: args, environment: env)
        if args.first == "status" {
          guard let status else {
            throw UnifiedOrchestrationError.commandFailed("Temporary control timeout")
          }
          if status == "cancel" { throw CancellationError() }
          return OrchestratorCommandResult(exitCode: 0, stdout: status)
        }
        return OrchestratorCommandResult(exitCode: 0, stdout: "GUEST_AGENT_READY")
      },
      helperRunningProbe: { _ in helperRunning }, appShellSessionBridge: bridge,
      helperIdentityProbe: { _ in "fixture-helper" }
    )
    _ = try await orchestrator.install(
      installerURL: installer, engineKind: .antiCheatVM, title: "Sample")
    return await recorder.all()
  }

  func testProcessRunnerDrainsLargeOutputWithoutPipeDeadlock() async throws {
    let result = try await OrchestratorProcessRunner.run(
      executable: "/bin/sh",
      arguments: ["-c", "head -c 262144 /dev/zero; head -c 262144 /dev/zero >&2"],
      environment: ["__DEMOAPP_TIMEOUT_SECONDS": "3"]
    )
    XCTAssertEqual(result.exitCode, 0)
    XCTAssertEqual(result.stdout.utf8.count, 262_144)
    XCTAssertEqual(result.stderr.utf8.count, 262_144)
  }

  func testProcessRunnerTimeoutTerminatesStalledCommand() async throws {
    let started = Date()
    do {
      _ = try await OrchestratorProcessRunner.run(
        executable: "/bin/sleep", arguments: ["20"],
        environment: ["__DEMOAPP_TIMEOUT_SECONDS": "1"]
      )
      XCTFail("Stalled command must time out")
    } catch is UnifiedOrchestrationError {
      XCTAssertLessThan(Date().timeIntervalSince(started), 3)
    }
  }

  func testDetachedRuntimeSubmissionDoesNotWaitForApplicationExit() async throws {
    let started = Date()
    let result = try await OrchestratorProcessRunner.run(
      executable: "/bin/sleep", arguments: ["1"], environment: ["__DEMOAPP_DETACHED": "1"]
    )
    XCTAssertEqual(result.exitCode, 0)
    XCTAssertLessThan(Date().timeIntervalSince(started), 0.9)
  }

  func testManagementPythonNeverFallsBackToDeveloperTools() throws {
    let dir = try XCTUnwrap(tempDir)
    let staged = try stageEmbeddedApp(in: dir)
    var config = UnifiedOrchestratorConfiguration(appBundleURL: staged.app, localVMSearchRoots: [])
    XCTAssertNil(UnifiedRuntimeDiscovery.resolve(configuration: config).pythonExecutablePath)
    let python = staged.app.appending(
      path: "Contents/Frameworks/Python.framework/Versions/Current/bin/python3")
    try FileManager.default.createDirectory(
      at: python.deletingLastPathComponent(), withIntermediateDirectories: true)
    try Data("#!/bin/sh\n".utf8).write(to: python)
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: python.path)
    config = UnifiedOrchestratorConfiguration(appBundleURL: staged.app, localVMSearchRoots: [])
    XCTAssertEqual(
      UnifiedRuntimeDiscovery.resolve(configuration: config).pythonExecutablePath, python.path)
  }

  func testNetworkRestoreRequiresVerifiedReadBack() async throws {
    let dir = try XCTUnwrap(tempDir)
    let staged = try stageEmbeddedApp(in: dir)
    let playable = dir.appending(path: "playable.utm")
    try stagePlayableVM(at: playable)
    let recorder = RecordedCommands()
    let entry = UnifiedGameEntry(
      name: "Sample", executablePath: #"C:\game.exe"#, engineKind: .antiCheatVM,
      vmBundlePath: playable.path
    )
    let report = """
      {"network_mode":"restored","configured":true,"config_verified":true,
      "restored":true,"changed":true,"dry_run":false}
      """
    let config = UnifiedOrchestratorConfiguration(
      appBundleURL: staged.app, runtimePythonURL: staged.helper)
    let orchestrator = UnifiedRuntimeOrchestrator(
      libraryStore: UnifiedGameLibraryStore(storageURL: dir.appending(path: "store.json")),
      configuration: config,
      commandRunner: { exe, args, env in
        await recorder.record(executable: exe, arguments: args, environment: env)
        if args.first == "status" { return OrchestratorCommandResult(exitCode: 0, stdout: "stopped") }
        return OrchestratorCommandResult(exitCode: 0, stdout: report)
      }, helperRunningProbe: { _ in true }
    )
    let result = try await orchestrator.configureNativeNetwork(for: entry, restore: true)
    XCTAssertTrue(result.restored)
    XCTAssertTrue(result.changed)
    let calls = await recorder.all()
    let call = try XCTUnwrap(calls.first { $0.arguments.contains("configure-network") })
    XCTAssertEqual(call.arguments.first, "-I")
    XCTAssertTrue(call.arguments.contains("configure-network"))
    XCTAssertTrue(call.arguments.contains("--restore"))
    XCTAssertEqual(call.environment["PYTHONNOUSERSITE"], "1")
    let unverified = UnifiedRuntimeOrchestrator(
      libraryStore: UnifiedGameLibraryStore(storageURL: dir.appending(path: "other.json")),
      configuration: config,
      commandRunner: { _, args, _ in
        OrchestratorCommandResult(exitCode: 0, stdout: args.first == "status" ? "stopped" : "{}")
      }, helperRunningProbe: { _ in true }
    )
    do {
      _ = try await unverified.configureNativeNetwork(for: entry, restore: true)
      XCTFail("Exit zero without a verified configuration must not pass")
    } catch is UnifiedOrchestrationError {}
  }

  func testFutureBundledWineUsesItsSiblingGraphicsLibraries() async throws {
    let dir = try XCTUnwrap(tempDir)
    let app = dir.appending(path: "Demo.app")
    let wine = app.appending(path: "Contents/Resources/Libraries/Wine/bin/wine64")
    try FileManager.default.createDirectory(
      at: wine.deletingLastPathComponent(), withIntermediateDirectories: true)
    try Data("#!/bin/sh\n".utf8).write(to: wine)
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: wine.path)
    let installer = dir.appending(path: "setup.exe")
    try Data("MZ".utf8).write(to: installer)
    let recorder = RecordedCommands()
    let orchestrator = UnifiedRuntimeOrchestrator(
      libraryStore: UnifiedGameLibraryStore(storageURL: dir.appending(path: "store.json")),
      configuration: UnifiedOrchestratorConfiguration(appBundleURL: app),
      commandRunner: { exe, args, env in
        await recorder.record(executable: exe, arguments: args, environment: env)
        return OrchestratorCommandResult(exitCode: 0, stdout: "GUEST_AGENT_READY")
      }
    )
    _ = try await orchestrator.install(
      installerURL: installer, engineKind: .nativeWine, title: "Sample")
    let calls = await recorder.all()
    XCTAssertEqual(calls.first?.executable, wine.path)
    XCTAssertFalse(calls.first?.arguments.contains("/wait") ?? true)
  }

}

extension UnifiedOrchestrationTests {
  fileprivate func stagePlayableVM(at url: URL) throws {
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    let config: [String: Any] = ["Information": ["UUID": UUID().uuidString]]
    let data = try PropertyListSerialization.data(
      fromPropertyList: config, format: .xml, options: 0)
    try data.write(to: url.appending(path: "config.plist"))
  }

  fileprivate func makeProfile(chip: String, cores: Int, memGiB: Int, refreshHz: Int = 120)
    -> HardwareProfileSnapshot {
    HardwareProfileSnapshot(
      chipName: chip, totalCores: cores, performanceCores: cores / 2,
      efficiencyCores: cores - cores / 2, physicalMemoryGiB: memGiB,
      displayRefreshRateHz: refreshHz,
      recommendedStoragePath: "/Volumes/FastSSD/whisky-phase2-guest"
    )
  }

  fileprivate func stageEmbeddedApp(in dir: URL) throws -> StagedEmbeddedApp {
    let app = dir.appending(path: "Malt.app")
    let helper = app.appending(path: "Contents/Helpers/MaltContainerHelper.app/Contents/MacOS/UTM")
    let golden = app.appending(path: "Contents/Resources/RuntimeScripts/golden_guest_manager.py")
    let kiosk = app.appending(path: "Contents/Resources/RuntimeScripts/kiosk-app-shell.ps1")
    for parent in [helper.deletingLastPathComponent(), golden.deletingLastPathComponent()] {
      try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true)
    }
    try Data("#!/bin/sh\n".utf8).write(to: helper)
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: helper.path)
    let helperInfo = helper.deletingLastPathComponent().deletingLastPathComponent().appending(path: "Info.plist")
    try PropertyListSerialization.data(
      fromPropertyList: ["UTMRuntimeSettingsContractVersion": 1], format: .xml, options: 0
    ).write(to: helperInfo)
    let control = helper.deletingLastPathComponent().appending(path: "utmctl")
    try Data("#!/bin/sh\n".utf8).write(to: control)
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: control.path)
    try Data("# golden\n".utf8).write(to: golden)
    try Data("# kiosk\n".utf8).write(to: kiosk)
    return StagedEmbeddedApp(app: app, helper: helper, golden: golden, kiosk: kiosk)
  }
}

extension UnifiedOrchestrationTests {
  func testLaunchSettingsLoadKeepsMissingResourcesAndSeparatesFixedDisplay() throws {
    let suite = "settings-contract-\(UUID().uuidString)"
    let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
    defer { defaults.removePersistentDomain(forName: suite) }
    defaults.set("2560x1440", forKey: "unifiedRecommendedResolution")
    let legacy = UnifiedLaunchSettings.load(defaults: defaults)
    XCTAssertNil(legacy.virtualCPUCount)
    XCTAssertNil(legacy.memoryMiB)
    XCTAssertEqual(legacy.displayPolicy, .automatic)
    defaults.set("fixed", forKey: "unifiedDisplayMode")
    defaults.set(false, forKey: "unifiedEnableMouseCoalescing")
    defaults.set(false, forKey: "unifiedBlockAccidentalShortcuts")
    defaults.set(false, forKey: "unifiedEnableKeyMapping")
    defaults.set(false, forKey: "unifiedEnablePersistentCache")
    let fixed = UnifiedLaunchSettings.load(defaults: defaults)
    XCTAssertEqual(fixed.displayPolicy, .fixed(width: 2560, height: 1440))
    XCTAssertEqual(fixed.containerEnvironment["UTM_MOUSE_COALESCE_US"], "0")
    XCTAssertEqual(fixed.containerEnvironment["UTM_GAME_SHELL_KEY_GUARD"], "0")
    XCTAssertEqual(fixed.containerEnvironment["UTM_BLOCK_WIN_KEY"], "0")
    XCTAssertEqual(fixed.containerEnvironment["UTM_DXMT_SHADER_CACHE_ENABLED"], "0")
    XCTAssertEqual(fixed.containerEnvironment["UTM_KEEP_CURSOR_VISIBLE_ON_INHIBIT"], "1")
    XCTAssertEqual(fixed.containerEnvironment["UTM_PURE_RELATIVE_MOUSE"], "1")
    defaults.set(Int.min, forKey: "unifiedRecommendedVCPU")
    defaults.set(Int.max, forKey: "unifiedRecommendedRAMMiB")
    let bounded = UnifiedLaunchSettings.load(defaults: defaults)
    XCTAssertEqual(bounded.virtualCPUCount, 1)
    XCTAssertEqual(bounded.memoryMiB, 1_048_576)
    defaults.set("invalid", forKey: "unifiedRecommendedResolution")
    XCTAssertEqual(UnifiedLaunchSettings.load(defaults: defaults).displayPolicy, .automatic)
    XCTAssertEqual(
      UnifiedDisplayPolicy.fixedResolution("1920×1080"), .fixed(width: 1920, height: 1080))
    XCTAssertNil(UnifiedDisplayPolicy.fixedResolution("999999999999999999999x1080"))
  }

  func testEntryResourceOverrideOnlyChangesCPUAndMemoryUsingSupportedIntersection() {
    let hardware = makeProfile(chip: "Sample", cores: 12, memGiB: 32)
    XCTAssertEqual(
      UnifiedLaunchSettings.supportedContainerMemoryOptionsGiB(for: hardware), [8, 12, 16, 20])
    let global = UnifiedLaunchSettings(
      enableMouseCoalescing: false, blockAccidentalShortcuts: false,
      enableKeyMapping: false, enablePersistentCache: false,
      displayPolicy: .fixed(width: 1280, height: 720), virtualCPUCount: 6, memoryMiB: 8192)
    var entry = UnifiedGameEntry(
      name: "Sample", executablePath: #"C:\game.exe"#, engineKind: .antiCheatVM,
      presetTier: .lowSpecCompatible)
    XCTAssertEqual(global.resolved(for: entry, hardware: hardware), global)
    entry.inheritsGlobalPerformanceSettings = false
    let overridden = global.resolved(for: entry, hardware: hardware)
    XCTAssertEqual(overridden.virtualCPUCount, 4)
    XCTAssertEqual(overridden.memoryMiB, 8192)
    XCTAssertEqual(overridden.containerEnvironment, global.containerEnvironment)
    XCTAssertEqual(overridden.displayPolicy, global.displayPolicy)
    entry.engineKind = .nativeWine
    XCTAssertEqual(global.resolved(for: entry, hardware: hardware), global)
    let high = UnifiedLaunchSettings.containerPreset(.maxPerformance, hardware: hardware)
    XCTAssertEqual(high.virtualCPUCount, 10)
    XCTAssertEqual(high.memoryMiB, 20 * 1024)
  }

  func testWineCachePolicyAppliesWithoutContainerResourceValidation() {
    let snapshot = UnifiedLaunchSettings(
      enablePersistentCache: false, displayPolicy: .fixed(width: 1, height: 1),
      virtualCPUCount: Int.max, memoryMiB: Int.min)
    let environment = snapshot.applyingWineCachePolicy(to: [
      "DXMT_SHADER_CACHE_PATH": "cache-a", "DXVK_STATE_CACHE_PATH": "cache-b", "KEEP": "value"
    ])
    XCTAssertEqual(environment["DXMT_SHADER_CACHE"], "0")
    XCTAssertEqual(environment["DXVK_STATE_CACHE"], "0")
    XCTAssertNil(environment["DXMT_SHADER_CACHE_PATH"])
    XCTAssertNil(environment["DXVK_STATE_CACHE_PATH"])
    XCTAssertEqual(environment["KEEP"], "value")
  }

  func testContainerResourceUpdateRequiresStoppedStateAndPreservesOtherMetadata() async throws {
    let dir = try XCTUnwrap(tempDir)
    let bundle = dir.appending(path: "resources.utm")
    try stagePlayableVM(at: bundle)
    let configURL = bundle.appending(path: "config.plist")
    let identifier = try ContainerGuestDispatcher.vmIdentifier(bundlePath: bundle.path)
    let original: [String: Any] = [
      "Information": ["UUID": identifier, "Name": "Sample"],
      "System": ["CPUCount": 4, "MemorySize": 8192, "Architecture": "aarch64"],
      "Drive": [["ImageName": "disk.qcow2"]], "Display": [["Hardware": "virtio-gpu"]]
    ]
    let bytes = try PropertyListSerialization.data(
      fromPropertyList: original, format: .binary, options: 0)
    try bytes.write(to: configURL)
    let hardware = makeProfile(chip: "Sample", cores: 12, memGiB: 24)
    let settings = UnifiedLaunchSettings(virtualCPUCount: 8, memoryMiB: 12288)
    for state in ["started", "paused", "suspended", "unknown", ""] {
      do {
        try await ContainerResourceConfigurator.apply(
          settings, bundlePath: bundle.path, controlBinaryPath: "/tmp/control",
          commandRunner: { _, _, _ in OrchestratorCommandResult(exitCode: 0, stdout: state) },
          hardware: hardware)
        XCTFail("Only an affirmative stopped state may modify resources")
      } catch is UnifiedOrchestrationError {}
      XCTAssertEqual(try Data(contentsOf: configURL), bytes)
    }
    let recorder = RecordedCommands()
    try await ContainerResourceConfigurator.apply(
      settings, bundlePath: bundle.path, controlBinaryPath: "/tmp/control",
      commandRunner: { exe, args, env in
        await recorder.record(executable: exe, arguments: args, environment: env)
        return OrchestratorCommandResult(exitCode: 0, stdout: "stopped\n")
      }, hardware: hardware)
    let calls = await recorder.all()
    XCTAssertEqual(calls.count, 1)
    XCTAssertEqual(calls.first?.arguments.first, "status")
    let updated = try XCTUnwrap(
      PropertyListSerialization.propertyList(from: Data(contentsOf: configURL), format: nil)
        as? [String: Any])
    let system = try XCTUnwrap(updated["System"] as? [String: Any])
    XCTAssertEqual(system["CPUCount"] as? Int, 8)
    XCTAssertEqual(system["MemorySize"] as? Int, 12288)
    XCTAssertEqual(system["Architecture"] as? String, "aarch64")
    XCTAssertEqual((updated["Information"] as? [String: Any])?["UUID"] as? String, identifier)
    XCTAssertEqual((updated["Drive"] as? [[String: String]])?.first?["ImageName"], "disk.qcow2")
    XCTAssertEqual((updated["Display"] as? [[String: String]])?.first?["Hardware"], "virtio-gpu")
    XCTAssertEqual(
      try Data(contentsOf: bundle.appending(path: ".resource-settings-backup.plist")), bytes)
  }

  func testContainerResourceUpdateRejectsUnsafeValuesAndConcurrentConfigChange() async throws {
    let dir = try XCTUnwrap(tempDir)
    let bundle = dir.appending(path: "guarded.utm")
    try stagePlayableVM(at: bundle)
    let configURL = bundle.appending(path: "config.plist")
    let bytes = try Data(contentsOf: configURL)
    let hardware = makeProfile(chip: "Sample", cores: 12, memGiB: 24)
    let recorder = RecordedCommands()
    for settings in [
      UnifiedLaunchSettings(virtualCPUCount: Int.max),
      UnifiedLaunchSettings(memoryMiB: 20480)
    ] {
      do {
        try await ContainerResourceConfigurator.apply(
          settings, bundlePath: bundle.path, controlBinaryPath: "/tmp/control",
          commandRunner: { exe, args, env in
            await recorder.record(executable: exe, arguments: args, environment: env)
            return OrchestratorCommandResult(exitCode: 0, stdout: "stopped")
          }, hardware: hardware)
        XCTFail("Unsafe resources must not be written")
      } catch is UnifiedOrchestrationError {}
    }
    let invalidCalls = await recorder.all()
    XCTAssertTrue(invalidCalls.isEmpty)
    XCTAssertEqual(try Data(contentsOf: configURL), bytes)
    let externallyChanged = Data("changed by another configuration operation".utf8)
    do {
      try await ContainerResourceConfigurator.apply(
        UnifiedLaunchSettings(virtualCPUCount: 8), bundlePath: bundle.path,
        controlBinaryPath: "/tmp/control",
        commandRunner: { _, _, _ in
          try externallyChanged.write(to: configURL)
          return OrchestratorCommandResult(exitCode: 0, stdout: "stopped")
        }, hardware: hardware)
      XCTFail("A concurrent configuration change must not be overwritten")
    } catch is UnifiedOrchestrationError {}
    XCTAssertEqual(try Data(contentsOf: configURL), externallyChanged)
  }

  func testFixedGuestDisplayRequiresReadbackAndAutomaticModeDoesNotChangeDisplay() async throws {
    XCTAssertNil(try ContainerGuestDispatcher.displayApplyScript(for: .automatic))
    let apply = try XCTUnwrap(
      ContainerGuestDispatcher.displayApplyScript(for: .fixed(width: 1920, height: 1080)))
    XCTAssertTrue(apply.contains("[uint32]1920, [uint32]1080, [uint32]$before.frequency"))
    XCTAssertTrue(apply.contains("$session -ne 1"))
    XCTAssertTrue(apply.contains("current_width"))
    XCTAssertThrowsError(
      try ContainerGuestDispatcher.displayApplyScript(for: .fixed(width: 1, height: 1)))
    let recorder = RecordedCommands()
    let dispatcher = ContainerGuestDispatcher(
      controlBinaryPath: "/tmp/control", vmIdentifier: UUID().uuidString,
      commandRunner: { exe, args, env in
        await recorder.record(executable: exe, arguments: args, environment: env)
        return OrchestratorCommandResult(exitCode: 0)
      })
    try await dispatcher.submit(
      targetExecutable: #"C:\game.exe"#, kioskScriptPath: "/tmp/kiosk.ps1",
      displayPolicy: .fixed(width: 1920, height: 1080))
    let calls = await recorder.all()
    let displayPush = try XCTUnwrap(
      calls.first { $0.arguments.last?.hasSuffix(#"\display.ps1"#) == true })
    let localScript = try XCTUnwrap(displayPush.environment["__DEMOAPP_STDIN_FILE"])
    XCTAssertFalse(FileManager.default.fileExists(atPath: localScript))
    let scheduleCall = try XCTUnwrap(calls.last)
    let schedule = try decodedPowerShell(scheduleCall)
    XCTAssertTrue(schedule.contains("$display.current_width -ne 1920"))
    XCTAssertTrue(schedule.contains("$display.current_height -ne 1080"))
    XCTAssertTrue(schedule.contains("FIXED_DISPLAY_POLICY_FAILED"))
    let actionRange = try XCTUnwrap(
      schedule.range(of: "-EncodedCommand ([A-Za-z0-9+/=]+)", options: .regularExpression))
    let data = try XCTUnwrap(
      Data(
        base64Encoded: String(schedule[actionRange]).replacingOccurrences(
          of: "-EncodedCommand ", with: "")))
    let action = try XCTUnwrap(String(data: data, encoding: .utf16LittleEndian))
    XCTAssertTrue(action.contains("failureStage='display'"))
    XCTAssertTrue(action.contains("$displaySnapshot.current_width -ne 1920"))
    XCTAssertTrue(action.contains("[GuestDisplayModeHelper]::Apply"))
    XCTAssertTrue(action.contains("previous_refresh_hz"))
  }

  func testFixedDisplayFailureIsReportedAndNeverMarkedAsSuccessfulLaunch() async throws {
    let recorder = RecordedCommands()
    let dispatcher = ContainerGuestDispatcher(
      controlBinaryPath: "/tmp/control", vmIdentifier: UUID().uuidString,
      commandRunner: { exe, args, env in
        await recorder.record(executable: exe, arguments: args, environment: env)
        if env["__DEMOAPP_TIMEOUT_SECONDS"] == "195.0" {
          return OrchestratorCommandResult(exitCode: 1, stdout: "FIXED_DISPLAY_POLICY_FAILED")
        }
        return OrchestratorCommandResult(exitCode: 0)
      })
    do {
      try await dispatcher.submit(
        targetExecutable: #"C:\game.exe"#, kioskScriptPath: "/tmp/kiosk.ps1",
        displayPolicy: .fixed(width: 1920, height: 1080))
      XCTFail("A failed display readback must reject the launch")
    } catch let error as UnifiedOrchestrationError {
      XCTAssertTrue(error.localizedDescription.contains("固定分辨率"))
    }
    let calls = await recorder.all()
    let cleanup = try decodedPowerShell(XCTUnwrap(calls.last))
    XCTAssertTrue(cleanup.contains("Stop-ScheduledTask"))
    XCTAssertTrue(cleanup.contains("Remove-Item"))
  }

  fileprivate func decodedPowerShell(_ call: RecordedInvocation) throws -> String {
    let index = try XCTUnwrap(call.arguments.firstIndex(of: "-EncodedCommand"))
    let data = try XCTUnwrap(Data(base64Encoded: call.arguments[index + 1]))
    return try XCTUnwrap(String(data: data, encoding: .utf16LittleEndian))
  }
}

extension UnifiedOrchestrationTests {
  func testContainerResourcesUseInjectedStoppedVerifierBeforeAnyWrite() async throws {
    let dir = try XCTUnwrap(tempDir)
    let bundle = dir.appending(path: "offline.utm")
    try stagePlayableVM(at: bundle)
    let configURL = bundle.appending(path: "config.plist")
    let original = try Data(contentsOf: configURL)
    let hardware = makeProfile(chip: "Sample", cores: 12, memGiB: 24)
    let recorder = RecordedCommands()
    let runner: UnifiedRuntimeOrchestrator.CommandRunner = { exe, args, env in
      await recorder.record(executable: exe, arguments: args, environment: env)
      return OrchestratorCommandResult(exitCode: 0)
    }
    do {
      try await ContainerResourceConfigurator.apply(
        UnifiedLaunchSettings(virtualCPUCount: 8), bundlePath: bundle.path,
        controlBinaryPath: "/tmp/control", commandRunner: runner, hardware: hardware,
        verifyStopped: { throw UnifiedOrchestrationError.backendUnavailable("saved state") })
      XCTFail("An unverified cold stop must prevent resource changes")
    } catch is UnifiedOrchestrationError {}
    XCTAssertEqual(try Data(contentsOf: configURL), original)
    try await ContainerResourceConfigurator.apply(
      UnifiedLaunchSettings(virtualCPUCount: 8), bundlePath: bundle.path,
      controlBinaryPath: "/tmp/control", commandRunner: runner, hardware: hardware,
      verifyStopped: {})
    let calls = await recorder.all()
    XCTAssertTrue(calls.isEmpty)
    let readBack = try XCTUnwrap(
      PropertyListSerialization.propertyList(from: Data(contentsOf: configURL), format: nil)
        as? [String: Any])
    XCTAssertEqual((readBack["System"] as? [String: Any])?["CPUCount"] as? Int, 8)
  }
}

// swiftlint:enable type_body_length

extension UnifiedOrchestrationTests {
  func testColdResourceChangePreparesHelperWithSnapshotBeforeReloadAndStart() async throws {
    let dir = try XCTUnwrap(tempDir)
    let staged = try stageEmbeddedApp(in: dir)
    let playable = dir.appending(path: "cold.utm")
    try stagePlayableVM(at: playable)
    let recorder = RecordedCommands()
    let cpu = try XCTUnwrap(HardwareAutoTuner.safeVCPUOptions(for: HardwareAutoTuner().detectHardwareProfile()).first)
    let settings = UnifiedLaunchSettings(
      enableMouseCoalescing: false, blockAccidentalShortcuts: false,
      enableKeyMapping: false, enablePersistentCache: false, virtualCPUCount: cpu)
    let orchestrator = UnifiedRuntimeOrchestrator(
      libraryStore: UnifiedGameLibraryStore(storageURL: dir.appending(path: "store.json")),
      configuration: UnifiedOrchestratorConfiguration(appBundleURL: staged.app),
      commandRunner: { exe, args, env in
        await recorder.record(executable: exe, arguments: args, environment: env)
        if args.first == "status" { return OrchestratorCommandResult(exitCode: 0, stdout: "stopped") }
        return OrchestratorCommandResult(exitCode: 0, stdout: "GUEST_AGENT_READY")
      },
      helperRunningProbe: { _ in
        await recorder.all().contains { $0.arguments.contains("--app-shell-prepare-only") }
      }, helperIdentityProbe: { _ in "fixture-helper" })
    try await orchestrator.launch(
      entry: UnifiedGameEntry(name: "Sample", executablePath: #"C:\game.exe"#,
        engineKind: .antiCheatVM, vmBundlePath: playable.path), settings: settings)
    let calls = await recorder.all()
    let preparation = try XCTUnwrap(calls.first { $0.arguments.contains("--app-shell-prepare-only") })
    XCTAssertEqual(preparation.executable, staged.helper.path)
    XCTAssertEqual(preparation.environment["UTM_MOUSE_COALESCE_US"], "0")
    XCTAssertEqual(preparation.environment["UTM_GAME_SHELL_KEY_GUARD"], "0")
    XCTAssertEqual(preparation.environment["UTM_BLOCK_WIN_KEY"], "0")
    XCTAssertEqual(preparation.environment["UTM_DXMT_SHADER_CACHE_ENABLED"], "0")
    let reloads = calls.indices.filter { calls[$0].executable == "/usr/bin/osascript" }
    XCTAssertEqual(reloads.count, 2)
    let start = try XCTUnwrap(calls.firstIndex { $0.arguments.first == "start" })
    XCTAssertLessThan(try XCTUnwrap(reloads.last), start)
    XCTAssertTrue(calls[reloads[0]].arguments.contains { $0.contains("«event UTMcReLd»") })
    XCTAssertEqual(calls.filter { $0.executable == staged.helper.path }.count, 1)
    let readBack = try XCTUnwrap(PropertyListSerialization.propertyList(
      from: Data(contentsOf: playable.appending(path: "config.plist")), format: nil) as? [String: Any])
    XCTAssertEqual((readBack["System"] as? [String: Any])?["CPUCount"] as? Int, cpu)
  }

  func testSavedStateReloadPreflightRejectsResourceChangeWithoutWritingOrStarting() async throws {
    let dir = try XCTUnwrap(tempDir)
    let staged = try stageEmbeddedApp(in: dir)
    let playable = dir.appending(path: "suspended.utm")
    try stagePlayableVM(at: playable)
    let configURL = playable.appending(path: "config.plist")
    let original = try Data(contentsOf: configURL)
    let recorder = RecordedCommands()
    let cpu = try XCTUnwrap(HardwareAutoTuner.safeVCPUOptions(for: HardwareAutoTuner().detectHardwareProfile()).first)
    let orchestrator = UnifiedRuntimeOrchestrator(
      libraryStore: UnifiedGameLibraryStore(storageURL: dir.appending(path: "store.json")),
      configuration: UnifiedOrchestratorConfiguration(appBundleURL: staged.app),
      commandRunner: { exe, args, env in
        await recorder.record(executable: exe, arguments: args, environment: env)
        if exe == "/usr/bin/osascript" {
          return OrchestratorCommandResult(exitCode: 1, stderr: "saved state requires a cold shutdown")
        }
        return OrchestratorCommandResult(exitCode: 0, stdout: "stopped")
      }, helperRunningProbe: { _ in true })
    do {
      try await orchestrator.launch(
        entry: UnifiedGameEntry(name: "Sample", executablePath: #"C:\game.exe"#,
          engineKind: .antiCheatVM, vmBundlePath: playable.path),
        settings: UnifiedLaunchSettings(virtualCPUCount: cpu))
      XCTFail("Saved-state preflight must prevent resource writes")
    } catch let error as UnifiedOrchestrationError {
      XCTAssertTrue(error.localizedDescription.contains("资源配额未修改"))
    }
    XCTAssertEqual(try Data(contentsOf: configURL), original)
    let calls = await recorder.all()
    XCTAssertFalse(calls.contains { $0.arguments.first == "start" })
    XCTAssertFalse(calls.contains { $0.arguments.contains("--app-shell-prepare-only") })
    XCTAssertFalse(
      FileManager.default.fileExists(atPath: playable.appending(path: ".resource-settings-backup.plist").path))
  }

  func testLegacyHelperFailsCapabilityReadinessAndLaunchBeforeAnyCommands() async throws {
    let dir = try XCTUnwrap(tempDir)
    let staged = try stageEmbeddedApp(in: dir)
    let playable = dir.appending(path: "legacy.utm")
    try stagePlayableVM(at: playable)
    let infoURL = staged.helper.deletingLastPathComponent().deletingLastPathComponent().appending(path: "Info.plist")
    try FileManager.default.removeItem(at: infoURL)
    let recorder = RecordedCommands()
    let orchestrator = UnifiedRuntimeOrchestrator(
      libraryStore: UnifiedGameLibraryStore(storageURL: dir.appending(path: "store.json")),
      configuration: UnifiedOrchestratorConfiguration(
        defaultPlayableVMBundlePath: playable.path, appBundleURL: staged.app),
      commandRunner: { exe, args, env in
        await recorder.record(executable: exe, arguments: args, environment: env)
        return OrchestratorCommandResult(exitCode: 0)
      })
    XCTAssertEqual(orchestrator.healthStatus()["container_settings_contract_ready"], false)
    XCTAssertEqual(orchestrator.healthStatus()["anti_cheat_vm_ready"], false)
    do {
      try await orchestrator.launch(
        entry: UnifiedGameEntry(name: "Sample", executablePath: #"C:\game.exe"#,
          engineKind: .antiCheatVM, vmBundlePath: playable.path), settings: UnifiedLaunchSettings())
      XCTFail("Legacy helpers must not silently ignore new settings")
    } catch let error as UnifiedOrchestrationError {
      XCTAssertTrue(error.localizedDescription.contains("新版容器引擎"))
    }
    let calls = await recorder.all()
    XCTAssertTrue(calls.isEmpty)
  }
}

extension UnifiedOrchestrationTests {
  func testColdNetworkConfigurationRegistersWithoutBootAndReloadsAfterVerifiedWrite() async throws {
    let dir = try XCTUnwrap(tempDir)
    let staged = try stageEmbeddedApp(in: dir)
    let playable = dir.appending(path: "network.utm")
    try stagePlayableVM(at: playable)
    let recorder = RecordedCommands()
    let entry = UnifiedGameEntry(name: "Sample", executablePath: #"C:\game.exe"#,
      engineKind: .antiCheatVM, vmBundlePath: playable.path)
    let report = """
      {"network_mode":"restored","configured":true,"config_verified":true,
      "restored":true,"changed":true,"dry_run":false}
      """
    let config = UnifiedOrchestratorConfiguration(
      appBundleURL: staged.app, appShellStateDirectory: dir.appending(path: "state"), runtimePythonURL: staged.helper)
    let orchestrator = UnifiedRuntimeOrchestrator(
      libraryStore: UnifiedGameLibraryStore(storageURL: dir.appending(path: "library.json")),
      configuration: config, commandRunner: { exe, args, env in
        await recorder.record(executable: exe, arguments: args, environment: env)
        return OrchestratorCommandResult(exitCode: 0, stdout: args.first == "status" ? "stopped" : report)
      }, helperRunningProbe: { _ in
        await recorder.all().contains { $0.arguments.contains("--app-shell-prepare-only") }
      })
    _ = try await orchestrator.configureNativeNetwork(for: entry, restore: true)
    let calls = await recorder.all()
    let operations = calls.map { call in
      if call.arguments.contains("--app-shell-prepare-only") { return "prepare" }
      if call.arguments.first == "status" { return "status" }
      if call.arguments.contains("configure-network") { return "configure" }
      if call.executable == "/usr/bin/osascript" { return "reload" }
      return "unexpected"
    }
    XCTAssertEqual(operations, ["prepare", "status", "reload", "configure", "reload"])
    XCTAssertFalse(calls.contains { $0.arguments.first == "start" || $0.arguments.first == "exec" })

    let reloadRecorder = RecordedCommands()
    let reloadFailure = UnifiedRuntimeOrchestrator(
      libraryStore: UnifiedGameLibraryStore(storageURL: dir.appending(path: "other.json")),
      configuration: config, commandRunner: { exe, args, env in
        await reloadRecorder.record(executable: exe, arguments: args, environment: env)
        let reloads = await reloadRecorder.all().filter { $0.executable == "/usr/bin/osascript" }.count
        if exe == "/usr/bin/osascript" && reloads == 2 { return OrchestratorCommandResult(exitCode: 1) }
        return OrchestratorCommandResult(exitCode: 0, stdout: args.first == "status" ? "stopped" : report)
      }, helperRunningProbe: { _ in true })
    do {
      _ = try await reloadFailure.configureNativeNetwork(for: entry, restore: true)
      XCTFail("A failed post-write reload must be reported")
    } catch {
      XCTAssertTrue(error.localizedDescription.contains("网络配置已写入"))
      XCTAssertTrue(error.localizedDescription.contains("关闭容器控制组件"))
    }
  }

  func testWarmUnregisteredNetworkSelectionDoesNotLaunchAnotherHelperOrWriteConfiguration() async throws {
    let dir = try XCTUnwrap(tempDir)
    let staged = try stageEmbeddedApp(in: dir)
    let playable = dir.appending(path: "unregistered.utm")
    try stagePlayableVM(at: playable)
    let recorder = RecordedCommands()
    let orchestrator = UnifiedRuntimeOrchestrator(
      libraryStore: UnifiedGameLibraryStore(storageURL: dir.appending(path: "library.json")),
      configuration: UnifiedOrchestratorConfiguration(appBundleURL: staged.app, runtimePythonURL: staged.helper),
      commandRunner: { exe, args, env in
        await recorder.record(executable: exe, arguments: args, environment: env)
        return OrchestratorCommandResult(exitCode: 1, stderr: "not registered")
      }, helperRunningProbe: { _ in true })
    let entry = UnifiedGameEntry(name: "Sample", executablePath: #"C:\game.exe"#,
      engineKind: .antiCheatVM, vmBundlePath: playable.path)
    do {
      _ = try await orchestrator.configureNativeNetwork(for: entry, restore: true)
      XCTFail("An unknown warm selection must fail closed")
    } catch {
      XCTAssertTrue(error.localizedDescription.contains("关闭现有容器控制窗口"))
    }
    let calls = await recorder.all()
    XCTAssertEqual(calls.count, 1)
    XCTAssertEqual(calls.first?.arguments.first, "status")
  }

  func testNetworkPreparationRejectsEveryStateExceptExactStopped() async throws {
    let dir = try XCTUnwrap(tempDir)
    let staged = try stageEmbeddedApp(in: dir)
    let playable = dir.appending(path: "active.utm")
    try stagePlayableVM(at: playable)
    let entry = UnifiedGameEntry(name: "Sample", executablePath: #"C:\game.exe"#,
      engineKind: .antiCheatVM, vmBundlePath: playable.path)
    for state in ["running", "paused", "stopped extra", ""] {
      let recorder = RecordedCommands()
      let orchestrator = UnifiedRuntimeOrchestrator(
        libraryStore: UnifiedGameLibraryStore(storageURL: dir.appending(path: "library.json")),
        configuration: UnifiedOrchestratorConfiguration(appBundleURL: staged.app, runtimePythonURL: staged.helper),
        commandRunner: { exe, args, env in
          await recorder.record(executable: exe, arguments: args, environment: env)
          return OrchestratorCommandResult(exitCode: 0, stdout: state)
        }, helperRunningProbe: { _ in true })
      do {
        _ = try await orchestrator.configureNativeNetwork(for: entry, restore: true)
        XCTFail("Only the exact stopped state can permit a network write")
      } catch {
        XCTAssertTrue(error.localizedDescription.contains("完全关闭"))
      }
      let calls = await recorder.all()
      XCTAssertEqual(calls.count, 1)
      XCTAssertEqual(calls.first?.arguments.first, "status")
    }
  }
}

extension UnifiedOrchestrationTests {
  func testNetworkSavedStatePreflightRefusesWriteDespiteReportedStopped() async throws {
    let dir = try XCTUnwrap(tempDir)
    let staged = try stageEmbeddedApp(in: dir)
    let playable = dir.appending(path: "saved-network.utm")
    try stagePlayableVM(at: playable)
    let original = try Data(contentsOf: playable.appending(path: "config.plist"))
    let recorder = RecordedCommands()
    let orchestrator = UnifiedRuntimeOrchestrator(
      libraryStore: UnifiedGameLibraryStore(storageURL: dir.appending(path: "library.json")),
      configuration: UnifiedOrchestratorConfiguration(appBundleURL: staged.app, runtimePythonURL: staged.helper),
      commandRunner: { exe, args, env in
        await recorder.record(executable: exe, arguments: args, environment: env)
        if exe == "/usr/bin/osascript" {
          return OrchestratorCommandResult(exitCode: 1, stderr: "registry entry is suspended")
        }
        return OrchestratorCommandResult(exitCode: 0, stdout: "stopped")
      }, helperRunningProbe: { _ in true })
    let entry = UnifiedGameEntry(name: "Sample", executablePath: #"C:\game.exe"#,
      engineKind: .antiCheatVM, vmBundlePath: playable.path)
    do {
      _ = try await orchestrator.configureNativeNetwork(for: entry, restore: true)
      XCTFail("A saved-state registry entry must fail before invoking the network writer")
    } catch {
      XCTAssertTrue(error.localizedDescription.contains("保存状态"))
      XCTAssertTrue(error.localizedDescription.contains("网络配置尚未修改"))
    }
    let calls = await recorder.all()
    XCTAssertEqual(calls.count, 2)
    XCTAssertEqual(calls.first?.arguments.first, "status")
    XCTAssertEqual(calls.last?.executable, "/usr/bin/osascript")
    XCTAssertFalse(calls.contains { $0.arguments.contains("configure-network") || $0.arguments.first == "start" })
    XCTAssertEqual(try Data(contentsOf: playable.appending(path: "config.plist")), original)
  }
}
