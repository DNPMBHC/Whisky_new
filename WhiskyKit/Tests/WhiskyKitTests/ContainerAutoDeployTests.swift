// SPDX-License-Identifier: GPL-3.0-or-later

import Foundation
import XCTest

@testable import WhiskyKit

final class ContainerAutoDeployTests: XCTestCase {
    private var tempDir = FileManager.default.temporaryDirectory.resolvingSymlinksInPath()
        .appending(path: "malt-autodeploy-tests-\(UUID().uuidString)")

    override func setUpWithError() throws {
        try super.setUpWithError()
        tempDir = FileManager.default.temporaryDirectory.resolvingSymlinksInPath()
            .appending(path: "malt-autodeploy-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: tempDir)
        try super.tearDownWithError()
    }

    func testCreateSparseQCow2PassesCompat11AndPreallocationOff() async throws {
        let recorded = LockedBox<[[String]]>([])
        let fakeHelper = try makeFakeHelperApp()
        let compactor = ContainerDiskCompactor(
            helperAppPath: fakeHelper.path(percentEncoded: false),
            commandRunner: { _, args, _ in
                recorded.withValue { $0.append(args) }
                return OrchestratorCommandResult(exitCode: 0)
            }
        )
        let diskURL = tempDir.appending(path: "Data/system.qcow2")
        try await compactor.createSparseQCow2(at: diskURL, sizeGiB: 64)

        let calls = recorded.withValue { $0 }
        XCTAssertEqual(calls.count, 1)
        let flattened = calls[0].joined(separator: " ")
        XCTAssertTrue(flattened.contains("create -f qcow2 -o compat=1.1,cluster_size=65536,preallocation=off"))
        XCTAssertTrue(flattened.contains("64G"))
    }

    func testCompactRejectsProtectedGoldenAndColdBackupContainers() async throws {
        let fakeHelper = try makeFakeHelperApp()
        let compactor = ContainerDiskCompactor(
            helperAppPath: fakeHelper.path(percentEncoded: false),
            commandRunner: { _, _, _ in OrchestratorCommandResult(exitCode: 0) },
            stopVerifier: { _, _ in }
        )
        for name in ["golden-win11-arm64-v1.utm", "Windows11-ARM64.utm"] {
            let bundle = try makeDummyPlayableBundle(name: name, diskPayloadBytes: 4096)
            do {
                _ = try await compactor.compactContainerSystemDisk(bundlePath: bundle.path(percentEncoded: false))
                XCTFail("Expected protected container \(name) to be rejected")
            } catch {
                XCTAssertTrue(error.localizedDescription.contains("母盘") || error.localizedDescription.contains("冷备"))
            }
        }
    }

    func testCompactReplacesDiskAtomicallyAndComputesReclaimedBytes() async throws {
        let bundle = try makeDummyPlayableBundle(name: "playable-compact.utm", diskPayloadBytes: 262_144)
        let fakeHelper = try makeFakeHelperApp()
        let compactor = ContainerDiskCompactor(
            helperAppPath: fakeHelper.path(percentEncoded: false),
            commandRunner: { _, args, _ in
                if let convertIdx = args.firstIndex(of: "convert"), convertIdx + 7 < args.count {
                    let tempOutput = URL(filePath: args[args.count - 1])
                    try Data(repeating: 0x5A, count: 4096).write(to: tempOutput)
                }
                return OrchestratorCommandResult(exitCode: 0, stdout: "No errors were found on the image.\n")
            },
            stopVerifier: { _, _ in }
        )

        let report = try await compactor.compactContainerSystemDisk(bundlePath: bundle.path(percentEncoded: false))
        XCTAssertEqual(report.diskFilename, "system.qcow2")
        XCTAssertGreaterThan(report.beforeBytes, report.afterBytes)
        XCTAssertEqual(report.reclaimedBytes, report.beforeBytes - report.afterBytes)

        let dataDir = bundle.appending(path: "Data")
        let files = try FileManager.default.contentsOfDirectory(atPath: dataDir.path(percentEncoded: false))
        XCTAssertFalse(files.contains { $0.contains("compact-tmp") })
    }

    func testValidateISOAcceptsISO9660AndUDFAndRejectsInvalidImages() throws {
        let service = WindowsImageBootstrapService()
        let iso9660 = try makeDummyISO(name: "win11-arm64-iso9660.iso", signature: "CD001", offset: 0x8001)
        let res1 = try service.validateWindowsARM64ISO(at: iso9660, minimumSizeBytes: 65_536)
        XCTAssertEqual(res1.formatSignature, "ISO9660")

        let udfISO = try makeDummyISO(name: "win11-arm64-udf.iso", signature: "NSR02", offset: 0x8801)
        let res2 = try service.validateWindowsARM64ISO(at: udfISO, minimumSizeBytes: 65_536)
        XCTAssertEqual(res2.formatSignature, "UDF")

        let corruptISO = try makeDummyISO(name: "corrupt.iso", signature: "ZERO0", offset: 0x8001)
        XCTAssertThrowsError(try service.validateWindowsARM64ISO(at: corruptISO, minimumSizeBytes: 65_536))

        let wrongExt = tempDir.appending(path: "not-an-iso.dmg")
        try Data(repeating: 0, count: 70_000).write(to: wrongExt)
        XCTAssertThrowsError(try service.validateWindowsARM64ISO(at: wrongExt, minimumSizeBytes: 65_536))
    }

    func testGenerateUnattendXMLPreservesComplianceAndInjectsDriversAndMPOFix() {
        let service = WindowsImageBootstrapService()
        let xml = service.generateUnattendXML(config: UnattendedWindowsConfig(username: "maltplayer"))

        XCTAssertTrue(xml.contains(#"processorArchitecture="arm64""#))
        XCTAssertTrue(xml.contains("<DriverPaths>"))
        XCTAssertTrue(xml.contains("BypassNRO"))
        XCTAssertTrue(xml.contains("OverlayTestMode") && xml.contains("DisableOverlays"))
        XCTAssertTrue(xml.contains("DisableFileSyncNGSC") && xml.contains("bootstrap.ps1"))
        XCTAssertTrue(xml.contains("<Name>maltplayer</Name>"))
        XCTAssertFalse(xml.contains("HideLocalAccountScreen") || xml.contains("BypassTPMCheck"))
        XCTAssertFalse(xml.contains("BypassSecureBootCheck"))
        let script = WindowsUnattendXMLBuilder.bootstrapScript()
        XCTAssertTrue(script.contains("utm-guest-tools*.exe") && script.contains("qemu-ga*.msi"))
        XCTAssertTrue(script.contains("malt-cursor-bridge.ps1") && script.contains("bootstrap.done"))
    }

    func testBuildBootstrapISOStagesFilesAndInvokesHdiutil() async throws {
        let driverDir = tempDir.appending(path: "mock-drivers", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: driverDir, withIntermediateDirectories: true)
        try "INF".write(to: driverDir.appending(path: "viogpu3d.inf"), atomically: true, encoding: .utf8)
        let optFile = tempDir.appending(path: "apply-optimizer.ps1")
        try "Write-Output 'ok'".write(to: optFile, atomically: true, encoding: .utf8)

        let stagedFiles = LockedBox<[String]>([])
        let service = WindowsImageBootstrapService(commandRunner: { executable, args, _ in
            XCTAssertEqual(executable, "/usr/bin/hdiutil")
            XCTAssertTrue(args.contains("makehybrid"))
            XCTAssertTrue(args.contains("MALTBOOT"))
            if let stagePath = args.last {
                let stageURL = URL(filePath: stagePath)
                let hasXML = FileManager.default.fileExists(
                    atPath: stageURL.appending(path: "autounattend.xml").path(percentEncoded: false)
                )
                let hasDrv = FileManager.default.fileExists(
                    atPath: stageURL.appending(path: "Drivers/viogpu3d.inf").path(percentEncoded: false)
                )
                let hasOpt = FileManager.default.fileExists(
                    atPath: stageURL.appending(path: "GuestOptimizer/apply-optimizer.ps1").path(percentEncoded: false)
                )
                stagedFiles.withValue { $0 = ["xml:\(hasXML)", "drv:\(hasDrv)", "opt:\(hasOpt)"] }
            }
            if let outIdx = args.firstIndex(of: "-o"), outIdx + 1 < args.count {
                try Data("BOOTISO".utf8).write(to: URL(filePath: args[outIdx + 1]))
            }
            return OrchestratorCommandResult(exitCode: 0)
        })

        let outputISO = tempDir.appending(path: "malt-bootstrap.iso")
        let built = try await service.buildBootstrapISO(
            outputURL: outputISO, driverDirectory: driverDir, optimizerFiles: [optFile]
        )
        XCTAssertEqual(built, outputISO.standardizedFileURL)
        XCTAssertEqual(stagedFiles.withValue { $0 }, ["xml:true", "drv:true", "opt:true"])
    }

    func testDownloadOfficialISORejectsPlainHTTP() async {
        let service = WindowsImageBootstrapService()
        do {
            _ = try await service.downloadOfficialISO(from: URL(string: "http://example.com/win11.iso")!)
            XCTFail("Expected plain HTTP URL to be rejected")
        } catch { XCTAssertTrue(error.localizedDescription.contains("HTTPS")) }
    }

    func testCreateContainerSkeletonAndEjectInstallMedia() async throws {
        let winISO = try makeDummyISO(name: "win11.iso", signature: "CD001", offset: 0x8001)
        let bootISO = try makeDummyISO(name: "boot.iso", signature: "CD001", offset: 0x8001)
        let fakeHelper = try makeFakeHelperApp()

        let compactor = ContainerDiskCompactor(
            helperAppPath: fakeHelper.path(percentEncoded: false),
            commandRunner: { _, args, _ in
                if let createIdx = args.firstIndex(of: "create"), createIdx + 6 < args.count {
                    let diskPath = args[args.count - 2]
                    try Data(repeating: 0x11, count: 8192).write(to: URL(filePath: diskPath))
                }
                return OrchestratorCommandResult(exitCode: 0)
            }
        )
        let service = ContainerAutoDeployService(
            hardwareProfileProvider: { Self.makeHardware() },
            diskCompactor: compactor
        )
        let bundleURL = tempDir.appending(path: "malt-new-win11.utm")
        let vmUUID = try await service.createContainerSkeleton(
            at: bundleURL, diskSizeGiB: 64, windowsISOURL: winISO, bootstrapISOURL: bootISO
        )
        XCTAssertNotNil(UUID(uuidString: vmUUID))

        let config = try readPlist(at: bundleURL.appending(path: "config.plist"))
        XCTAssertEqual(config["Backend"] as? String, "QEMU")
        let qemu = config["QEMU"] as? [String: Any]
        XCTAssertEqual(qemu?["UEFIBoot"] as? Bool, true)
        XCTAssertEqual(qemu?["TPMDevice"] as? Bool, true)
        XCTAssertEqual(qemu?["DirectXDriver"] as? Int, 2)
        let displays = config["Display"] as? [[String: Any]]
        XCTAssertEqual(displays?.first?["Hardware"] as? String, "virtio-ramfb-gl")
        let drivesBefore = config["Drive"] as? [[String: Any]] ?? []
        XCTAssertEqual(drivesBefore.count, 4)

        try service.ejectInstallMedia(in: bundleURL)
        let afterConfig = try readPlist(at: bundleURL.appending(path: "config.plist"))
        let drivesAfter = afterConfig["Drive"] as? [[String: Any]] ?? []
        XCTAssertEqual(drivesAfter.count, 2)
        XCTAssertFalse(
            FileManager.default.fileExists(
                atPath: bundleURL.appending(path: "Data/win11-arm64-install.iso").path(percentEncoded: false)
            )
        )
    }

    func testFullSixStageAutoDeployPipelineSucceeds() async throws {
        let winISO = try makeDummyISO(name: "win11-arm64.iso", signature: "CD001", offset: 0x8001)
        let runtime = try makeFakeAppRuntime()
        let shaderDir = tempDir.appending(path: "shader-cache")
        let config = UnifiedOrchestratorConfiguration(
            appBundleURL: runtime.appBundle,
            containerControlBinaryURL: runtime.controlBinary
        )
        let runner: UnifiedRuntimeOrchestrator.CommandRunner = { executable, args, _ in
            return try Self.handleEndToEndMockCommand(executable: executable, args: args)
        }
        let compactor = ContainerDiskCompactor(
            helperAppPath: runtime.helperApp.path(percentEncoded: false),
            commandRunner: runner,
            stopVerifier: { _, _ in }
        )
        let provisioning = ContainerProvisioningService(
            configuration: config,
            commandRunner: runner,
            hardwareProfileProvider: { Self.makeHardware() },
            vmnetStatusProvider: {
                NativeVMNetStatus(
                    daemonInstalled: true, socketActive: true, socketPath: "/tmp/s", activeMode: .vmnetKernelDirect
                )
            },
            shaderCacheOverrideURL: shaderDir,
            stopVerifier: { _, _ in },
            guestReadinessVerifier: { _, _ in }
        )
        let service = ContainerAutoDeployService(
            configuration: config,
            commandRunner: runner,
            hardwareProfileProvider: { Self.makeHardware() },
            bootstrapService: WindowsImageBootstrapService(commandRunner: runner),
            diskCompactor: compactor,
            provisioningService: provisioning
        )

        let request = AutoDeployRequest(
            imageSource: .localISO(winISO),
            destinationDirectory: tempDir,
            containerName: "malt-auto-e2e",
            diskSizeGiB: 64,
            minimumISOSizeBytes: 65_536,
            installTimeoutSeconds: 10,
            pollIntervalSeconds: 0.05
        )
        let report = try await service.deployNewContainer(request: request)
        XCTAssertTrue(report.allPassed)
        XCTAssertEqual(report.steps.count, 6)
        XCTAssertTrue(report.steps.allSatisfy { $0.state == .succeeded })
        XCTAssertGreaterThan(report.compactionReport?.reclaimedBytes ?? 0, 0)
    }
}

private extension ContainerAutoDeployTests {
    static func handleEndToEndMockCommand(
        executable: String, args: [String]
    ) throws -> OrchestratorCommandResult {
        if executable == "/usr/bin/hdiutil", let outIdx = args.firstIndex(of: "-o"), outIdx + 1 < args.count {
            try Data("MALTBOOT_ISO".utf8).write(to: URL(filePath: args[outIdx + 1]))
            return OrchestratorCommandResult(exitCode: 0)
        }
        if args.contains("create"), args.contains("qcow2"), args.count >= 2 {
            try Data(repeating: 0x33, count: 131_072).write(to: URL(filePath: args[args.count - 2]))
            return OrchestratorCommandResult(exitCode: 0)
        }
        if args.contains("convert"), args.contains("qcow2"), let output = args.last {
            try Data(repeating: 0x33, count: 4096).write(to: URL(filePath: output))
            return OrchestratorCommandResult(exitCode: 0)
        }
        if executable.hasSuffix("utmctl") {
            let joined = args.joined(separator: " ")
            if joined.contains("bootstrap.done") {
                return OrchestratorCommandResult(exitCode: 0, stdout: "MALT_BOOTSTRAP_DONE\n")
            }
            if joined.hasPrefix("status") {
                return OrchestratorCommandResult(exitCode: 0, stdout: "stopped\n")
            }
            if joined.contains("powershell.exe"),
               let encIdx = args.firstIndex(of: "-EncodedCommand"), encIdx + 1 < args.count,
               let raw = Data(base64Encoded: args[encIdx + 1]),
               let script = String(data: raw, encoding: .utf16LittleEndian) {
                if script.contains("MALT_OPT_APPLY_V1=") {
                    return OrchestratorCommandResult(
                        exitCode: 0,
                        stdout: #"MALT_OPT_APPLY_V1={"applied":true,"dry_run":false,"secure_boot_enabled":true,"#
                            + #""bcd_safe":true,"prism_signatures_valid":true,"ui_language":"zh-CN"}"#
                    )
                }
                if script.contains("MALT_GFX_PROBE_V1=") {
                    return OrchestratorCommandResult(
                        exitCode: 0,
                        stdout: #"MALT_GFX_PROBE_V1={"viogpu3dPresent":true,"#
                            + #""driverName":"viogpu3d","secureBootEnabled":true}"#
                    )
                }
            }
        }
        return OrchestratorCommandResult(exitCode: 0)
    }

    static func makeHardware() -> HardwareProfileSnapshot {
        HardwareProfileSnapshot(
            chipName: "Apple M4", totalCores: 10, performanceCores: 4, efficiencyCores: 6,
            physicalMemoryGiB: 16, displayRefreshRateHz: 120, recommendedStoragePath: "/tmp"
        )
    }

    func makeFakeHelperApp() throws -> URL {
        let helper = tempDir.appending(path: "MaltContainerHelper.app", directoryHint: .isDirectory)
        let img = helper.appending(path: "Contents/Frameworks/qemu-img.framework/Versions/A/qemu-img")
        try FileManager.default.createDirectory(at: img.deletingLastPathComponent(), withIntermediateDirectories: true)
        try Data("ELF".utf8).write(to: img)
        return helper
    }

    func makeFakeAppRuntime() throws -> FakeAutoDeployRuntime {
        let app = tempDir.appending(path: "Malt.app", directoryHint: .isDirectory)
        let helper = app.appending(path: "Contents/Helpers/MaltContainerHelper.app", directoryHint: .isDirectory)
        let binaries = [
            helper.appending(path: "Contents/MacOS/UTM"),
            helper.appending(path: "Contents/MacOS/utmctl"),
            helper.appending(path: "Contents/Frameworks/qemu-img.framework/Versions/A/qemu-img"),
            app.appending(path: "Contents/Helpers/malt-net-proxy")
        ]
        let fileMgr = FileManager.default
        for url in binaries {
            try fileMgr.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            try Data("#!/bin/sh\nexit 0\n".utf8).write(to: url)
            try fileMgr.setAttributes([.posixPermissions: 0o755], ofItemAtPath: url.path(percentEncoded: false))
        }
        let optDir = app.appending(path: "Contents/Resources/RuntimeScripts")
        try FileManager.default.createDirectory(at: optDir, withIntermediateDirectories: true)
        try Data("ok".utf8).write(to: optDir.appending(path: "apply-optimizer.ps1"))
        try Data("{}".utf8).write(to: optDir.appending(path: "anticheat-minimal-win11-arm64.json"))
        return FakeAutoDeployRuntime(appBundle: app, helperApp: helper, controlBinary: binaries[1])
    }

    func makeDummyISO(name: String, signature: String, offset: Int) throws -> URL {
        var bytes = Data(repeating: 0, count: 65_536)
        bytes.replaceSubrange(offset..<(offset + signature.utf8.count), with: Data(signature.utf8))
        let url = tempDir.appending(path: name)
        try bytes.write(to: url)
        return url
    }

    func makeDummyPlayableBundle(name: String, diskPayloadBytes: Int) throws -> URL {
        let bundle = tempDir.appending(path: name, directoryHint: .isDirectory)
        let dataDir = bundle.appending(path: "Data", directoryHint: .isDirectory)
        try FileManager.default.createDirectory(at: dataDir, withIntermediateDirectories: true)
        try Data(repeating: 0xAA, count: diskPayloadBytes).write(to: dataDir.appending(path: "system.qcow2"))
        let config: [String: Any] = [
            "Backend": "QEMU", "Information": ["UUID": UUID().uuidString.uppercased(), "Name": name],
            "System": ["UEFIBoot": true, "CPUCount": 6, "MemorySize": 8192],
            "Drive": [["Identifier": "SYS", "ImageName": "system.qcow2",
                       "ImageType": "Disk", "Interface": "VirtIO", "ReadOnly": false]]
        ]
        try PropertyListSerialization.data(fromPropertyList: config, format: .xml, options: 0)
            .write(to: bundle.appending(path: "config.plist"))
        return bundle
    }

    func readPlist(at url: URL) throws -> [String: Any] {
        let parsed = try PropertyListSerialization.propertyList(from: Data(contentsOf: url), options: [], format: nil)
        return (parsed as? [String: Any]) ?? [:]
    }
}

private struct FakeAutoDeployRuntime {
    let appBundle: URL
    let helperApp: URL
    let controlBinary: URL
}

private final class LockedBox<Value>: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: Value

    init(_ initial: Value) { self.storage = initial }
    func withValue<Result>(_ body: (inout Value) -> Result) -> Result { lock.withLock { body(&storage) } }
}
