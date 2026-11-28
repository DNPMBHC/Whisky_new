// SPDX-License-Identifier: GPL-3.0-or-later
// Standard UTM v5 ARM64 config.plist builder and install-media ejector for automated container deployment.

import Foundation

/// Stages of the new-user one-click Windows 11 ARM64 container deployment pipeline.
public enum AutoDeployStage: String, Codable, CaseIterable, Sendable {
    case prepareWindowsImage
    case buildBootstrapMedia
    case createContainerSkeleton
    case runUnattendedInstall
    case injectOptimizationAndTrim
    case compactAndRegister

    public var displayTitle: String {
        switch self {
        case .prepareWindowsImage:
            return "校验或下载官方 Windows 11 ARM64 镜像"
        case .buildBootstrapMedia:
            return "生成无人值守驱动与优化引导介质"
        case .createContainerSkeleton:
            return "创建 UEFI/TPM 2.0 容器与精简虚拟盘"
        case .runUnattendedInstall:
            return "执行无人值守安装并等待来宾工具就绪"
        case .injectOptimizationAndTrim:
            return "注入 v3.3 驱动优化、清晰渲染、光标桥接与系统瘦身"
        case .compactAndRegister:
            return "卸载安装介质并执行容器磁盘离线瘦身"
        }
    }
}

/// Per-stage status reported during automated container deployment.
public struct AutoDeployStepReport: Identifiable, Codable, Equatable, Sendable {
    public var id: AutoDeployStage { stage }
    public let stage: AutoDeployStage
    public let state: ProvisioningStepState
    public let detail: String

    public init(stage: AutoDeployStage, state: ProvisioningStepState, detail: String) {
        self.stage = stage
        self.state = state
        self.detail = detail
    }
}

/// Source of the legal official Windows 11 ARM64 ISO image provided by the user.
public enum AutoDeployImageSource: Equatable, Sendable {
    case localISO(URL)
    case officialDownloadURL(URL, expectedSHA256: String?)
}

/// User request parameters for one-click Windows 11 ARM64 container creation and optimization.
public struct AutoDeployRequest: Equatable, Sendable {
    public let imageSource: AutoDeployImageSource
    public let destinationDirectory: URL
    public let containerName: String
    public let diskSizeGiB: Int
    public let driverDirectory: URL?
    public let autoDownloadDrivers: Bool
    public let unattendedConfig: UnattendedWindowsConfig
    public let launchSettings: UnifiedLaunchSettings
    public let minimumISOSizeBytes: Int64
    public let installTimeoutSeconds: TimeInterval
    public let pollIntervalSeconds: TimeInterval

    public init(
        imageSource: AutoDeployImageSource,
        destinationDirectory: URL,
        containerName: String = "malt-win11-arm64",
        diskSizeGiB: Int = 64,
        driverDirectory: URL? = nil,
        autoDownloadDrivers: Bool = true,
        unattendedConfig: UnattendedWindowsConfig = UnattendedWindowsConfig(),
        launchSettings: UnifiedLaunchSettings = UnifiedLaunchSettings(),
        minimumISOSizeBytes: Int64 = 1_073_741_824,
        installTimeoutSeconds: TimeInterval = 2700,
        pollIntervalSeconds: TimeInterval = 5
    ) {
        self.imageSource = imageSource
        self.destinationDirectory = destinationDirectory
        self.containerName = containerName
        self.diskSizeGiB = diskSizeGiB
        self.driverDirectory = driverDirectory
        self.autoDownloadDrivers = autoDownloadDrivers
        self.unattendedConfig = unattendedConfig
        self.launchSettings = launchSettings
        self.minimumISOSizeBytes = minimumISOSizeBytes
        self.installTimeoutSeconds = installTimeoutSeconds
        self.pollIntervalSeconds = pollIntervalSeconds
    }
}

/// Final outcome of an automated deployment run.
public struct AutoDeployReport: Codable, Equatable, Sendable {
    public let containerPath: String
    public let vmUUID: String
    public let steps: [AutoDeployStepReport]
    public let compactionReport: ContainerDiskCompactionReport?
    public let allPassed: Bool
    public let completedAt: Date

    public init(
        containerPath: String,
        vmUUID: String,
        steps: [AutoDeployStepReport],
        compactionReport: ContainerDiskCompactionReport?,
        allPassed: Bool,
        completedAt: Date = Date()
    ) {
        self.containerPath = containerPath
        self.vmUUID = vmUUID
        self.steps = steps
        self.compactionReport = compactionReport
        self.allPassed = allPassed
        self.completedAt = completedAt
    }
}

/// Builds compliant Apple Silicon Windows 11 ARM64 `.utm` configuration dictionaries
/// and cleanly strips temporary optical installation media after unattended setup.
enum ContainerAutoDeployConfigBuilder {
    static let windowsInstallDriveID = "MALT-WIN11-ISO"
    static let bootstrapDriveID = "MALT-BOOTSTRAP-ISO"
    static let usbTransferDriveID = "MALT-USB-TRANSFER-SLOT"
    static let windowsInstallFilename = "win11-arm64-install.iso"
    static let bootstrapFilename = "malt-bootstrap.iso"

    struct Spec: Sendable {
        let vmUUID: String
        let diskUUID: String
        let containerName: String
        let cpuCount: Int
        let memoryMiB: Int
        let fpsLimit: Int
        let virtioBlkQueues: Int

        init(
            vmUUID: String,
            diskUUID: String,
            containerName: String,
            cpuCount: Int,
            memoryMiB: Int,
            fpsLimit: Int = ContainerProvisioningConstants.fpsLimitDefault,
            virtioBlkQueues: Int = 4
        ) {
            self.vmUUID = vmUUID
            self.diskUUID = diskUUID
            self.containerName = containerName
            self.cpuCount = cpuCount
            self.memoryMiB = memoryMiB
            self.fpsLimit = fpsLimit
            self.virtioBlkQueues = virtioBlkQueues
        }
    }

    static func makeConfigDictionary(spec: Spec) -> [String: Any] {
        [
            "Backend": "QEMU",
            "ConfigurationVersion": 4,
            "Information": [
                "IconCustom": false,
                "Name": spec.containerName,
                "UUID": spec.vmUUID
            ],
            "System": [
                "Architecture": "aarch64",
                "CPU": "default",
                "CPUCount": spec.cpuCount,
                "CPUFlagsAdd": [String](),
                "CPUFlagsRemove": [String](),
                "ForceMulticore": false,
                "JITCacheSize": 0,
                "MemorySize": spec.memoryMiB,
                "Target": "virt",
                "UEFIBoot": true
            ],
            "QEMU": makeQEMUSection(fpsLimit: spec.fpsLimit, queues: spec.virtioBlkQueues),
            "Display": [[
                "DownscalingFilter": "Linear",
                "DynamicResolution": false,
                "Hardware": "virtio-ramfb-gl",
                "IOSurfaceDirectPresent": true,
                "NativeResolution": false,
                "UpscalingFilter": "Linear"
            ]],
            "Input": [
                "DisableUsbRedir": true,
                "MaximumUsbShare": 0,
                "PureRelativeMouse": true,
                "UsbBusSupport": "3.0",
                "UsbSharing": false,
                "VirtioMouse": true
            ],
            "Drive": makeInstallDrives(diskUUID: spec.diskUUID),
            "Network": [[String: Any]](),
            "Serial": [["Mode": "Ptty", "Target": "Auto"]],
            "Sharing": [
                "ClipboardSharing": false,
                "DirectoryShareMode": "None",
                "DirectoryShareReadOnly": true
            ],
            "Sound": [["Hardware": "intel-hda"]]
        ]
    }

    static func writeSkeletonConfigAndMetadata(
        spec: Spec, bundleURL: URL, fileManager: FileManager
    ) throws {
        let config = makeConfigDictionary(spec: spec)
        let plistData = try PropertyListSerialization.data(fromPropertyList: config, format: .xml, options: 0)
        try plistData.write(to: bundleURL.appending(path: "config.plist"), options: .atomic)
        try writePlayableMetadata(vmUUID: spec.vmUUID, bundleURL: bundleURL, fileManager: fileManager)
        let checkpoint = ContainerProvisioningCheckpoint(
            schemaVersion: 1,
            containerUUID: spec.vmUUID,
            succeededStages: [ContainerProvisioningStage.configureHardwarePipeline.rawValue]
        )
        ContainerProvisioningPipeline.saveCheckpoint(
            checkpoint, at: bundleURL.path(percentEncoded: false), fileManager: fileManager
        )
    }

    static func writePlayableMetadata(vmUUID: String, bundleURL: URL, fileManager: FileManager) throws {
        let meta: [String: Any] = [
            "schema_version": 1,
            "role": "playable_working_vm",
            "vm_uuid": vmUUID
        ]
        let metaURL = bundleURL.appending(path: ".playable-meta.json")
        let data = try JSONSerialization.data(withJSONObject: meta, options: [.sortedKeys])
        try data.write(to: metaURL, options: .atomic)
        try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: metaURL.path(percentEncoded: false))
    }

    static func ejectInstallMedia(in bundleURL: URL, fileManager: FileManager) throws {
        let configURL = bundleURL.appending(path: "config.plist")
        var format = PropertyListSerialization.PropertyListFormat.xml
        let raw = try Data(contentsOf: configURL)
        guard var root = try PropertyListSerialization.propertyList(
            from: raw, options: [], format: &format
        ) as? [String: Any] else {
            throw UnifiedOrchestrationError.backendUnavailable("无法解析容器 config.plist 以卸载安装介质。")
        }
        let removableIDs: Set<String> = [windowsInstallDriveID, bootstrapDriveID]
        if let drives = root["Drive"] as? [[String: Any]] {
            root["Drive"] = drives.filter { drive in
                let identifier = drive["Identifier"] as? String ?? ""
                return !removableIDs.contains(identifier)
            }
        }
        let encoded = try PropertyListSerialization.data(fromPropertyList: root, format: format, options: 0)
        try encoded.write(to: configURL, options: .atomic)

        let dataDir = bundleURL.appending(path: "Data", directoryHint: .isDirectory)
        try? fileManager.removeItem(at: dataDir.appending(path: windowsInstallFilename))
        try? fileManager.removeItem(at: dataDir.appending(path: bootstrapFilename))
    }

    private static func makeQEMUSection(fpsLimit: Int, queues: Int) -> [String: Any] {
        [
            "AdditionalArguments": [
                "-object", "iothread,id=iothread0",
                "-global", "virtio-blk-pci.iothread=iothread0",
                "-global", "virtio-blk-pci.num-queues=\(queues)"
            ],
            "BalloonDevice": false,
            "DebugLog": false,
            "DirectXDriver": 2,
            "Hypervisor": true,
            "InterruptRemapping": true,
            "MemoryLock": false,
            "PS2Controller": false,
            "QEMURendererFPSLimit": fpsLimit,
            "RendererFPSLimit": fpsLimit,
            "RNGDevice": true,
            "RTCLocalTime": true,
            "TPMDevice": true,
            "TripleBuffering": true,
            "TSO": false,
            "UEFIBoot": true
        ]
    }

    private static func makeInstallDrives(diskUUID: String) -> [[String: Any]] {
        [
            [
                "Identifier": diskUUID,
                "ImageName": "\(diskUUID).qcow2",
                "ImageType": "Disk",
                "Interface": "VirtIO",
                "InterfaceVersion": 1,
                "ReadOnly": false
            ],
            [
                "Identifier": windowsInstallDriveID,
                "ImageName": windowsInstallFilename,
                "ImageType": "CD",
                "Interface": "USB",
                "InterfaceVersion": 1,
                "ReadOnly": true
            ],
            [
                "Identifier": bootstrapDriveID,
                "ImageName": bootstrapFilename,
                "ImageType": "CD",
                "Interface": "USB",
                "InterfaceVersion": 1,
                "ReadOnly": true
            ],
            [
                "Identifier": usbTransferDriveID,
                "ImageType": "CD",
                "Interface": "USB",
                "InterfaceVersion": 1,
                "ReadOnly": true
            ]
        ]
    }
}
