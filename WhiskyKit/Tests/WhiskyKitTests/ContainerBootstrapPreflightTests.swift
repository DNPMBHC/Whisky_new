// SPDX-License-Identifier: GPL-3.0-or-later

import Foundation
import XCTest

@testable import WhiskyKit

final class ContainerBootstrapPreflightTests: XCTestCase {
    private var tempDir = FileManager.default.temporaryDirectory.resolvingSymlinksInPath()
        .appending(path: "malt-preflight-tests-\(UUID().uuidString)")

    override func setUpWithError() throws {
        try super.setUpWithError()
        tempDir = FileManager.default.temporaryDirectory.resolvingSymlinksInPath()
            .appending(path: "malt-preflight-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: tempDir)
        try super.tearDownWithError()
    }

    func testAppleSiliconMatrixAcrossM1ToM4RAMAndRefreshTiers() throws {
        let m1Air8 = HardwareProfileSnapshot(
            chipName: "Apple M1", totalCores: 8, performanceCores: 4, efficiencyCores: 4,
            physicalMemoryGiB: 8, displayRefreshRateHz: 60, recommendedStoragePath: "/tmp"
        )
        XCTAssertEqual(UnifiedLaunchSettings.supportedContainerMemoryOptionsGiB(for: m1Air8), [4, 6])
        XCTAssertEqual(HardwareAutoTuner.recommendedMemoryGiB(for: m1Air8), 4)
        let m1Preset = UnifiedLaunchSettings.containerPreset(.balanced, hardware: m1Air8)
        XCTAssertEqual(m1Preset.memoryMiB, 4 * 1024)
        XCTAssertEqual(m1Preset.virtualCPUCount, 6)

        let m2Base16 = HardwareProfileSnapshot(
            chipName: "Apple M2", totalCores: 8, performanceCores: 4, efficiencyCores: 4,
            physicalMemoryGiB: 16, displayRefreshRateHz: 60, recommendedStoragePath: "/tmp"
        )
        XCTAssertEqual(UnifiedLaunchSettings.supportedContainerMemoryOptionsGiB(for: m2Base16), [6, 8, 10, 12])

        let m3Pro18 = HardwareProfileSnapshot(
            chipName: "Apple M3 Pro", totalCores: 12, performanceCores: 6, efficiencyCores: 6,
            physicalMemoryGiB: 18, displayRefreshRateHz: 120, recommendedStoragePath: "/tmp"
        )
        XCTAssertEqual(HardwareAutoTuner.recommendedMemoryGiB(for: m3Pro18), 10)

        let m4Max64 = HardwareProfileSnapshot(
            chipName: "Apple M4 Max", totalCores: 16, performanceCores: 12, efficiencyCores: 4,
            physicalMemoryGiB: 64, displayRefreshRateHz: 120, recommendedStoragePath: "/tmp"
        )
        XCTAssertEqual(UnifiedLaunchSettings.supportedContainerMemoryOptionsGiB(for: m4Max64), [8, 12, 16, 20])
        XCTAssertEqual(UnifiedLaunchSettings.containerPreset(.balanced, hardware: m4Max64).memoryMiB, 16 * 1024)

        XCTAssertEqual(HardwareAutoTuner.recommendedVirglHostmem(forPhysicalMemoryBytes: 8 * 1_073_741_824), "2G")
        XCTAssertEqual(HardwareAutoTuner.recommendedVirglHostmem(forPhysicalMemoryBytes: 16 * 1_073_741_824), "4G")
        XCTAssertEqual(HardwareAutoTuner.recommendedVirglHostmem(forPhysicalMemoryBytes: 18 * 1_073_741_824), "4G")
        XCTAssertEqual(HardwareAutoTuner.recommendedVirglHostmem(forPhysicalMemoryBytes: 24 * 1_073_741_824), "8G")
        XCTAssertEqual(HardwareAutoTuner.recommendedVirtIOBlockQueues(forVCPUCount: 2), 2)
        XCTAssertEqual(HardwareAutoTuner.recommendedVirtIOBlockQueues(forVCPUCount: 4), 4)
        XCTAssertEqual(HardwareAutoTuner.recommendedVirtIOBlockQueues(forVCPUCount: 10), 4)
    }

    func testHardwarePipelineRespects60HzMacRefreshRateAnd4GiBRAM() throws {
        let m1Air8 = HardwareProfileSnapshot(
            chipName: "Apple M1", totalCores: 8, performanceCores: 4, efficiencyCores: 4,
            physicalMemoryGiB: 8, displayRefreshRateHz: 60, recommendedStoragePath: "/tmp"
        )
        let bundle = tempDir.appending(path: "m1-60hz.utm")
        try FileManager.default.createDirectory(at: bundle.appending(path: "Data"), withIntermediateDirectories: true)
        let cfg: [String: Any] = [
            "Backend": "QEMU", "ConfigurationVersion": 4,
            "Information": ["Name": "m1-60hz", "UUID": UUID().uuidString.uppercased()],
            "System": ["CPUCount": 4, "MemorySize": 4096, "UEFIBoot": true],
            "Input": ["MaximumUsbShare": 0, "UsbSharing": false],
            "Sound": [], "QEMU": ["AdditionalArguments": []],
            "Drive": [["Identifier": UUID().uuidString.uppercased(), "ImageName": "d.qcow2",
                       "ImageType": "Disk", "Interface": "VirtIO", "ReadOnly": false]]
        ]
        try PropertyListSerialization.data(fromPropertyList: cfg, format: .xml, options: 0)
            .write(to: bundle.appending(path: "config.plist"))
        let res = try ContainerProvisioningPipeline.configureHardwarePipeline(
            bundlePath: bundle.path(percentEncoded: false),
            settings: UnifiedLaunchSettings(),
            hardware: m1Air8,
            fileManager: .default
        )
        XCTAssertEqual(res.fpsLimit, 60)
        XCTAssertEqual(res.memoryMiB, 4096)
    }

    func testDetectSetupUILanguageFromFilenameAndISO9660VolumeLabel() throws {
        let zhByName = tempDir.appending(path: "Win11_24H2_Chinese_Simplified_Arm64.iso")
        try Data("stub".utf8).write(to: zhByName)
        XCTAssertEqual(ContainerBootstrapPreflight.detectSetupUILanguage(for: zhByName), "zh-CN")

        let enByName = tempDir.appending(path: "Win11_24H2_English_Arm64.iso")
        try Data("stub".utf8).write(to: enByName)
        XCTAssertEqual(ContainerBootstrapPreflight.detectSetupUILanguage(for: enByName), "en-US")

        let renamedISO = tempDir.appending(path: "custom-windows-image.iso")
        var header = Data(repeating: 0, count: 0x9000)
        header.replaceSubrange(0x8001..<0x8006, with: Data("CD001".utf8))
        let label = Data("CCCOMA_A64FRE_ZH-CN_DV9         ".utf8)
        header.replaceSubrange(0x8028..<(0x8028 + 32), with: label.prefix(32))
        try header.write(to: renamedISO)
        XCTAssertEqual(ContainerBootstrapPreflight.detectSetupUILanguage(for: renamedISO), "zh-CN")

        let autoConfig = ContainerBootstrapPreflight.resolvedUnattendedConfig(
            UnattendedWindowsConfig(setupUILanguage: "en-US", autoDetectSetupLanguage: true),
            for: renamedISO
        )
        XCTAssertEqual(autoConfig.setupUILanguage, "zh-CN")

        let manualConfig = ContainerBootstrapPreflight.resolvedUnattendedConfig(
            UnattendedWindowsConfig(setupUILanguage: "en-US", autoDetectSetupLanguage: false),
            for: renamedISO
        )
        XCTAssertEqual(manualConfig.setupUILanguage, "en-US")
    }

    func testDriverDiscoveryPriorityAndMissingDriverBlocking() async throws {
        let isoDir = tempDir.appending(path: "isos", directoryHint: .isDirectory)
        let cacheDir = tempDir.appending(path: "cache", directoryHint: .isDirectory)
        let dlDir = tempDir.appending(path: "downloads", directoryHint: .isDirectory)
        for dir in [isoDir, cacheDir, dlDir] {
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        }
        let winISO = isoDir.appending(path: "Win11.iso")
        try Data("iso".utf8).write(to: winISO)

        // Undersized corrupt driver ISO must be ignored.
        let tinyDriver = isoDir.appending(path: "utm-guest-tools-corrupt.iso")
        try Data(repeating: 0, count: 1024).write(to: tinyDriver)
        XCTAssertNil(
            ContainerBootstrapPreflight.discoverLocalDriverSource(
                beside: winISO, cacheDirectoryOverride: cacheDir, downloadsDirectoryOverride: dlDir
            )
        )

        // Valid cached driver (>=8 MiB) must be discovered automatically.
        let cachedDriver = cacheDir.appending(path: "utm-guest-tools-0.1.271.iso")
        FileManager.default.createFile(atPath: cachedDriver.path(percentEncoded: false), contents: nil)
        let handle = try FileHandle(forWritingTo: cachedDriver)
        try handle.truncate(atOffset: UInt64(ContainerBootstrapPreflight.minimumDriverISOSizeBytes))
        try handle.close()
        XCTAssertEqual(
            ContainerBootstrapPreflight.discoverLocalDriverSource(
                beside: winISO, cacheDirectoryOverride: cacheDir, downloadsDirectoryOverride: dlDir
            )?.lastPathComponent,
            "utm-guest-tools-0.1.271.iso"
        )

        // Missing drivers with autoDownload=false & requireDrivers=true must fail fast.
        let emptyDir = tempDir.appending(path: "empty", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: emptyDir, withIntermediateDirectories: true)
        do {
            _ = try await ContainerBootstrapPreflight.resolveDriverDirectory(
                explicit: nil, beside: emptyDir.appending(path: "win.iso"),
                autoDownload: false, requireDrivers: true,
                bootstrapService: WindowsImageBootstrapService()
            )
            XCTFail("Expected missing drivers to be blocked upfront")
        } catch {
            XCTAssertTrue(error.localizedDescription.contains("驱动包"))
        }
    }

    func testStoragePreflightRejectsInsufficientFreeSpace() throws {
        XCTAssertThrowsError(
            try ContainerBootstrapPreflight.validateStorageTarget(
                directory: tempDir, minimumFreeBytes: Int64.max / 2
            )
        ) { error in
            XCTAssertTrue(error.localizedDescription.contains("可用空间不足"))
        }
        XCTAssertNoThrow(
            try ContainerBootstrapPreflight.validateStorageTarget(
                directory: tempDir, minimumFreeBytes: 1_048_576
            )
        )
    }

    func testOfficialGuestToolsUses3DReleaseAndPrioritizes3DDriverISO() throws {
        XCTAssertTrue(
            ContainerBootstrapPreflight.officialGuestToolsISOURL.absoluteString.contains("utm-guest-tools-3d-latest")
        )
        let cacheDir = tempDir.appending(path: "drv-cache", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: cacheDir, withIntermediateDirectories: true)
        for name in ["utm-guest-tools-0.1.271.iso", "utm-guest-tools-3d-latest.iso"] {
            let file = cacheDir.appending(path: name)
            FileManager.default.createFile(atPath: file.path(percentEncoded: false), contents: nil)
            let handle = try FileHandle(forWritingTo: file)
            try handle.truncate(atOffset: UInt64(ContainerBootstrapPreflight.minimumDriverISOSizeBytes))
            try handle.close()
        }
        let picked = ContainerBootstrapPreflight.discoverLocalDriverSource(
            beside: nil, cacheDirectoryOverride: cacheDir, downloadsDirectoryOverride: tempDir
        )
        XCTAssertEqual(picked?.lastPathComponent, "utm-guest-tools-3d-latest.iso")
    }

    func testStageDriverDirectorySkipsLegacyViogpudoWhenViogpu3dIsPresent() async throws {
        let drvRoot = tempDir.appending(path: "mock-3d-iso", directoryHint: .isDirectory)
        for rel in ["Drivers/viogpu3d/w11/ARM64", "Drivers/viogpudo/w11/ARM64", "Drivers/viostor/w11/ARM64"] {
            let dir = drvRoot.appending(path: rel, directoryHint: .isDirectory)
            try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
            try Data("INF".utf8).write(to: dir.appending(path: "driver.inf"))
        }
        try Data("EXE".utf8).write(to: drvRoot.appending(path: "utm-guest-tools.exe"))

        let verified = LockedFlagBox()
        let bootstrap = WindowsImageBootstrapService(commandRunner: { _, args, _ in
            if let stagePath = args.last {
                let stage = URL(filePath: stagePath)
                let fileMgr = FileManager.default
                let has3d = fileMgr.fileExists(
                    atPath: stage.appending(path: "PostDrivers/viogpu3d/driver.inf").path(percentEncoded: false)
                )
                let hasDod = fileMgr.fileExists(
                    atPath: stage.appending(path: "PostDrivers/viogpudo").path(percentEncoded: false)
                ) || fileMgr.fileExists(
                    atPath: stage.appending(path: "Drivers/viogpudo").path(percentEncoded: false)
                )
                let hasStor = fileMgr.fileExists(
                    atPath: stage.appending(path: "Drivers/viostor/driver.inf").path(percentEncoded: false)
                )
                let hasExe = fileMgr.fileExists(
                    atPath: stage.appending(path: "utm-guest-tools.exe").path(percentEncoded: false)
                )
                verified.set(has3d && !hasDod && hasStor && hasExe)
            }
            return OrchestratorCommandResult(exitCode: 0)
        })
        _ = try await bootstrap.buildBootstrapISO(
            outputURL: tempDir.appending(path: "out.iso"), driverDirectory: drvRoot
        )
        XCTAssertTrue(verified.get())
    }
}

private final class LockedFlagBox: @unchecked Sendable {
    private let lock = NSLock()
    private var value = false

    func set(_ next: Bool) {
        lock.lock()
        defer { lock.unlock() }
        value = next
    }

    func get() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return value
    }
}
