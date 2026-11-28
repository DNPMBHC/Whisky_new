// SPDX-License-Identifier: GPL-3.0-or-later

import Foundation
import XCTest

@testable import WhiskyKit

private struct ProvisioningRuntimeFixtures {
    let appBundle: URL
    let controlBinary: URL
    let proxyBinary: URL
}

final class ContainerProvisioningServiceTests: XCTestCase {
    private var tempDir = FileManager.default.temporaryDirectory.resolvingSymlinksInPath()
        .appending(path: "malt-provisioning-tests-\(UUID().uuidString)")

    override func setUpWithError() throws {
        try super.setUpWithError()
        tempDir = FileManager.default.temporaryDirectory.resolvingSymlinksInPath()
            .appending(path: "malt-provisioning-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: tempDir)
        try super.tearDownWithError()
    }

    func testOfficialWindowsARM64GuideURLIsMicrosoftHTTPS() {
        let url = ContainerProvisioningService.officialWindowsARM64GuideURL()
        XCTAssertEqual(url.scheme, "https")
        XCTAssertEqual(url.host, "www.microsoft.com")
    }

    func testFullFourStageProvisioningAndLosslessRollback() async throws {
        let bundle = try makeUTMBundle(name: "playable-e2e.utm")
        let fixtures = try makeFakeRuntimeFixtures()
        let shaderCacheDir = tempDir.appending(path: "shader-cache")
        let originalConfig = try Data(contentsOf: bundle.appending(path: "config.plist"))

        let service = makeService(
            fixtures: fixtures, shaderCacheDir: shaderCacheDir,
            vmnetSocketActive: false, runner: Self.makeMockRunner()
        )
        let settings = UnifiedLaunchSettings(presetTier: .balanced, virtualCPUCount: 6, memoryMiB: 8192)
        let report = try await service.provisionAndOptimize(
            containerPath: bundle.path(percentEncoded: false), settings: settings
        )

        XCTAssertTrue(report.allPassed)
        XCTAssertEqual(report.steps.count, 4)
        XCTAssertTrue(report.steps.allSatisfy { $0.state == .succeeded })
        XCTAssertEqual(service.lastReport?.allPassed, true)
        XCTAssertFalse(service.isRunning)
        try assertHardwareConfigApplied(at: bundle, cpu: 6, memoryMiB: 8192)
        XCTAssertTrue(FileManager.default.fileExists(atPath: shaderCacheDir.path(percentEncoded: false)))

        try await service.rollbackOptimization(containerPath: bundle.path(percentEncoded: false))
        let restoredConfig = try Data(contentsOf: bundle.appending(path: "config.plist"))
        XCTAssertEqual(restoredConfig, originalConfig)
    }

    func testProtectedGoldenAndColdBackupContainersAreRejected() async throws {
        let protectedURLs = [
            try makeUTMBundle(name: "golden-win11-arm64-v1.utm"),
            try makeUTMBundle(name: "Windows11-ARM64.utm"),
            try makeUTMBundle(name: "vm-a.utm")
        ]
        let service = ContainerProvisioningService(hardwareProfileProvider: { Self.makeHardware() })
        for protectedURL in protectedURLs {
            do {
                _ = try await service.provisionAndOptimize(
                    containerPath: protectedURL.path(percentEncoded: false),
                    settings: UnifiedLaunchSettings()
                )
                XCTFail("Expected protected container \(protectedURL.lastPathComponent) to be rejected")
            } catch {
                XCTAssertEqual(service.lastReport?.allPassed, false)
                XCTAssertEqual(service.steps.first?.state, .failed)
            }
        }
    }

    func testResumableCheckpointSkipsCompletedHardwareStageOnRetry() async throws {
        let bundle = try makeUTMBundle(name: "playable-retry.utm")
        let fixtures = try makeFakeRuntimeFixtures()
        let shaderCacheDir = tempDir.appending(path: "shader-cache-retry")
        let attemptCounter = LockedAttemptCounter()
        let service = makeService(
            fixtures: fixtures, shaderCacheDir: shaderCacheDir,
            vmnetSocketActive: true, runner: Self.makeMockRunner(failFirstApply: attemptCounter)
        )

        do {
            _ = try await service.provisionAndOptimize(
                containerPath: bundle.path(percentEncoded: false), settings: UnifiedLaunchSettings()
            )
            XCTFail("First attempt should fail at applyGuestOptimization")
        } catch {
            XCTAssertEqual(service.steps[1].state, .succeeded)
            XCTAssertEqual(service.steps[2].state, .failed)
        }

        let second = try await service.provisionAndOptimize(
            containerPath: bundle.path(percentEncoded: false), settings: UnifiedLaunchSettings()
        )
        XCTAssertTrue(second.allPassed)
        XCTAssertEqual(second.steps[1].state, .skipped)
        XCTAssertEqual(second.steps[2].state, .succeeded)
        XCTAssertEqual(second.steps[3].state, .succeeded)
    }

    func testDeriveManagedCopyCreatesFreshUUIDAndPlayableMetadata() async throws {
        let goldenID = "11111111-2222-3333-4444-555555555555"
        let golden = try makeUTMBundle(name: "golden-win11-arm64-v1.utm", uuid: goldenID)
        let destination = tempDir.appending(path: "playable-derived.utm")
        let service = ContainerProvisioningService(
            commandRunner: { executable, args, _ in
                XCTAssertEqual(executable, "/bin/cp")
                XCTAssertEqual(args.first, "-cR")
                try FileManager.default.copyItem(atPath: args[1], toPath: args[2])
                return OrchestratorCommandResult(exitCode: 0)
            }
        )

        let derivedPath = try await service.deriveManagedCopy(
            fromGoldenPath: golden.path(percentEncoded: false),
            destinationPath: destination.path(percentEncoded: false)
        )
        XCTAssertEqual(derivedPath, destination.path(percentEncoded: false))
        XCTAssertNotEqual(try ContainerGuestDispatcher.vmIdentifier(bundlePath: derivedPath), goldenID)
        let goldenUUID = try ContainerGuestDispatcher.vmIdentifier(bundlePath: golden.path(percentEncoded: false))
        XCTAssertEqual(goldenUUID, goldenID)
        let verified = PlayableContainerSelection.verifiedIdentifier(
            at: URL(filePath: derivedPath), fileManager: .default
        )
        XCTAssertNotNil(verified)
    }

    func testV33GraphicsProbeAndSiblingCursorBridgeDiscovery() throws {
        let script = ContainerProvisioningGuestExecutor.graphicsProbeScript()
        XCTAssertTrue(script.contains("OverlayTestMode") && script.contains("DisableOverlays"))
        XCTAssertTrue(script.contains("EnableTransparency") && script.contains("GameDVR_FSEBehaviorMode"))
        XCTAssertTrue(script.contains("MaltCursorBridge"))

        let fixtures = try makeFakeRuntimeFixtures()
        let applyPath = fixtures.appBundle
            .appending(path: "Contents/Resources/RuntimeScripts/apply-optimizer.ps1")
            .path(percentEncoded: false)
        let bridgeURL = ContainerProvisioningGuestExecutor.siblingCursorBridgeURL(
            nextTo: applyPath, fileManager: .default
        )
        XCTAssertEqual(bridgeURL?.lastPathComponent, "malt-cursor-bridge.ps1")
    }

    func testVerifyGraphicsRejectsUnappliedRealUserTransparencyOrOverlay() async throws {
        let fixtures = try makeFakeRuntimeFixtures()
        let bundle = try makeUTMBundle(name: "playable-unapplied-ui.utm")
        let shaderCache = tempDir.appending(path: "shader-cache")
        let service = makeService(
            fixtures: fixtures, shaderCacheDir: shaderCache, vmnetSocketActive: false
        ) { _, args, _ in
            if args.first == "status" { return OrchestratorCommandResult(exitCode: 0, stdout: "stopped\n") }
            if args.first == "file" { return OrchestratorCommandResult(exitCode: 0, stdout: "") }
            if args.contains("GUEST_AGENT_READY") {
                return OrchestratorCommandResult(exitCode: 0, stdout: "GUEST_AGENT_READY\n")
            }
            if let idx = args.firstIndex(of: "-EncodedCommand"), idx + 1 < args.count,
               let data = Data(base64Encoded: args[idx + 1]),
               let script = String(data: data, encoding: .utf16LittleEndian),
               script.contains("MALT_GFX_PROBE_V1=") {
                let json = #"{"viogpu3dPresent":true,"driverName":"viogpu3d","secureBootEnabled":true,"#
                    + #""overlayDisabled":true,"userTransparencyDisabled":false,"fseDisabled":true}"#
                return OrchestratorCommandResult(exitCode: 0, stdout: "MALT_GFX_PROBE_V1=" + json)
            }
            return try await Self.makeMockRunner()("", args, [:])
        }
        do {
            _ = try await service.provisionAndOptimize(containerPath: bundle.path(percentEncoded: false))
            XCTFail("Expected unapplied real-user transparency to fail graphics verification")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("清晰渲染"))
        }
    }
}

private extension ContainerProvisioningServiceTests {
    static func makeHardware() -> HardwareProfileSnapshot {
        HardwareProfileSnapshot(
            chipName: "Apple M4", totalCores: 10, performanceCores: 4, efficiencyCores: 6,
            physicalMemoryGiB: 16, displayRefreshRateHz: 120, recommendedStoragePath: "/Volumes/Test"
        )
    }

    static func makeMockRunner(
        failFirstApply: LockedAttemptCounter? = nil
    ) -> UnifiedRuntimeOrchestrator.CommandRunner {
        { _, args, _ in
            if args.first == "status" { return OrchestratorCommandResult(exitCode: 0, stdout: "stopped\n") }
            if args.first == "file" { return OrchestratorCommandResult(exitCode: 0, stdout: "") }
            if args.contains("GUEST_AGENT_READY") {
                return OrchestratorCommandResult(exitCode: 0, stdout: "GUEST_AGENT_READY\n")
            }
            if let idx = args.firstIndex(of: "-EncodedCommand"), idx + 1 < args.count,
               let decodedData = Data(base64Encoded: args[idx + 1]),
               let script = String(data: decodedData, encoding: .utf16LittleEndian) {
                return Self.mockPowerShellOutput(for: script, failFirstApply: failFirstApply)
            }
            return OrchestratorCommandResult(exitCode: 0, stdout: "")
        }
    }

    static func mockPowerShellOutput(
        for script: String, failFirstApply: LockedAttemptCounter?
    ) -> OrchestratorCommandResult {
        if script.contains("MALT_OPT_APPLY_V1=") {
            if let counter = failFirstApply, counter.next() == 1 {
                return OrchestratorCommandResult(exitCode: 1, stdout: "", stderr: "transient qga error")
            }
            let json = #"{"applied":true,"secure_boot_enabled":true,"bcd_safe":true,"#
                + #""prism_signatures_valid":true,"ui_language":"zh-CN"}"#
            return OrchestratorCommandResult(exitCode: 0, stdout: "MALT_OPT_APPLY_V1=" + json)
        }
        if script.contains("MALT_OPT_ROLLBACK_V1=") {
            return OrchestratorCommandResult(
                exitCode: 0,
                stdout: #"MALT_OPT_ROLLBACK_V1={"rollback_consistent":true,"secure_boot_enabled":true}"#
            )
        }
        if script.contains("MALT_GFX_PROBE_V1=") {
            let json = #"{"viogpu3dPresent":true,"driverName":"viogpu3d","secureBootEnabled":true}"#
            return OrchestratorCommandResult(exitCode: 0, stdout: "MALT_GFX_PROBE_V1=" + json)
        }
        return OrchestratorCommandResult(exitCode: 0, stdout: "")
    }

    func makeService(
        fixtures: ProvisioningRuntimeFixtures,
        shaderCacheDir: URL,
        vmnetSocketActive: Bool,
        runner: @escaping UnifiedRuntimeOrchestrator.CommandRunner
    ) -> ContainerProvisioningService {
        let config = UnifiedOrchestratorConfiguration(
            appBundleURL: fixtures.appBundle,
            containerControlBinaryURL: fixtures.controlBinary,
            guestAgentReadinessTimeout: 5
        )
        let vmnet = NativeVMNetStatus(
            daemonInstalled: vmnetSocketActive,
            socketActive: vmnetSocketActive,
            socketPath: vmnetSocketActive ? "/var/run/malt-vmnet-bridge.sock" : nil,
            activeMode: vmnetSocketActive ? .vmnetKernelDirect : .notVerified
        )
        return ContainerProvisioningService(
            configuration: config,
            commandRunner: runner,
            hardwareProfileProvider: { Self.makeHardware() },
            vmnetStatusProvider: { vmnet },
            shaderCacheOverrideURL: shaderCacheDir
        )
    }

    func makeUTMBundle(
        name: String, uuid: String = UUID().uuidString.uppercased(), uefiBoot: Bool = true
    ) throws -> URL {
        let bundle = tempDir.appending(path: name)
        try FileManager.default.createDirectory(at: bundle.appending(path: "Data"), withIntermediateDirectories: true)
        let config: [String: Any] = [
            "Backend": "QEMU", "ConfigurationVersion": 4,
            "Information": ["Name": name, "UUID": uuid],
            "System": ["CPUCount": 4, "MemorySize": 4096, "UEFIBoot": uefiBoot],
            "Input": ["MaximumUsbShare": 3, "UsbSharing": true],
            "Sound": [],
            "Drive": [["Identifier": UUID().uuidString.uppercased(), "ImageName": "disk.qcow2",
                       "ImageType": "Disk", "Interface": "VirtIO", "ReadOnly": false]],
            "QEMU": ["AdditionalArguments": []]
        ]
        let data = try PropertyListSerialization.data(fromPropertyList: config, format: .xml, options: 0)
        try data.write(to: bundle.appending(path: "config.plist"), options: .atomic)
        return bundle
    }

    func makeFakeRuntimeFixtures() throws -> ProvisioningRuntimeFixtures {
        let app = tempDir.appending(path: "Malt.app")
        let scriptsDir = app.appending(path: "Contents/Resources/RuntimeScripts")
        let helpersDir = app.appending(path: "Contents/Helpers")
        let helperMacOS = helpersDir.appending(path: "MaltContainerHelper.app/Contents/MacOS")
        try FileManager.default.createDirectory(at: scriptsDir, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: helperMacOS, withIntermediateDirectories: true)
        try Data("# apply".utf8).write(to: scriptsDir.appending(path: "apply-optimizer.ps1"))
        try Data("# bridge".utf8).write(to: scriptsDir.appending(path: "malt-cursor-bridge.ps1"))
        try Data("# rollback".utf8).write(to: scriptsDir.appending(path: "rollback-optimizer.ps1"))
        try Data("{\"schema_version\":1}".utf8)
            .write(to: scriptsDir.appending(path: "anticheat-minimal-win11-arm64.json"))
        let control = helperMacOS.appending(path: "utmctl")
        let helper = helperMacOS.appending(path: "UTM")
        let proxy = helpersDir.appending(path: "malt-net-proxy")
        for binary in [control, helper, proxy] {
            try Data("#!/bin/sh\nexit 0\n".utf8).write(to: binary)
            try FileManager.default.setAttributes(
                [.posixPermissions: 0o755], ofItemAtPath: binary.path(percentEncoded: false)
            )
        }
        return ProvisioningRuntimeFixtures(appBundle: app, controlBinary: control, proxyBinary: proxy)
    }

    func assertHardwareConfigApplied(at bundle: URL, cpu: Int, memoryMiB: Int) throws {
        let plist = try XCTUnwrap(
            PropertyListSerialization.propertyList(
                from: Data(contentsOf: bundle.appending(path: "config.plist")), options: [], format: nil
            ) as? [String: Any]
        )
        let system = try XCTUnwrap(plist["System"] as? [String: Any])
        XCTAssertEqual(system["CPUCount"] as? Int, cpu)
        XCTAssertEqual(system["MemorySize"] as? Int, memoryMiB)
        let input = try XCTUnwrap(plist["Input"] as? [String: Any])
        XCTAssertEqual(input["VirtioMouse"] as? Bool, true)
        XCTAssertEqual(input["DisableUsbRedir"] as? Bool, true)
        XCTAssertEqual(input["MaximumUsbShare"] as? Int, 0)
        let sounds = try XCTUnwrap(plist["Sound"] as? [[String: Any]])
        XCTAssertTrue(sounds.contains { ($0["Hardware"] as? String) == "intel-hda" })
        let qemu = try XCTUnwrap(plist["QEMU"] as? [String: Any])
        XCTAssertEqual(qemu["QEMURendererFPSLimit"] as? Int, 120)
        XCTAssertEqual(qemu["TripleBuffering"] as? Bool, true)
        let extra = qemu["AdditionalArguments"] as? [String] ?? []
        XCTAssertTrue(extra.contains("virtio-blk-pci.num-queues=4"))
        XCTAssertTrue(extra.contains("virtio-blk-pci.iothread=iothread0"))
        let drives = try XCTUnwrap(plist["Drive"] as? [[String: Any]])
        XCTAssertEqual(drives.first?["Interface"] as? String, "VirtIO")
    }
}

private final class LockedAttemptCounter: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0

    func next() -> Int {
        lock.lock()
        defer { lock.unlock() }
        count += 1
        return count
    }
}
