// SPDX-License-Identifier: GPL-3.0-or-later
// Hardware pipeline, APFS CoW derivation, and guest optimization helpers for ContainerProvisioningService.

import Foundation

enum ContainerProvisioningConstants {
    static let hardwareBackupName = ".provisioning-hardware-backup.plist"
    static let checkpointName = ".provisioning-checkpoint.json"
    static let guestOptimizerDir = #"C:\ProgramData\Malt\GuestOptimizer"#
    static let guestStateDir = #"C:\graphics-lab\guest-optimizer"#
    static let fpsLimitDefault = 120
    static let allowedQEMUFlags: Set<String> = ["-object", "-global", "-netdev", "-device"]
    static let allowedQEMUValuePrefixes: [String] = [
        "iothread,", "virtio-blk-pci.", "virtio-net-pci.", "virtio-net-pci,", "stream,id=net0,"
    ]
}

struct ContainerHardwarePipelineResult: Sendable {
    let cpuCount, memoryMiB, virtioBlkQueues, fpsLimit: Int
    let summary: String
}

struct ContainerGuestOptimizationReport: Decodable, Sendable {
    let applied, dryRun, secureBootEnabled, bcdSafe, prismSignaturesValid, rollbackConsistent: Bool?
    let uiLanguage: String?

    enum CodingKeys: String, CodingKey {
        case applied, dryRun = "dry_run", secureBootEnabled = "secure_boot_enabled"
        case bcdSafe = "bcd_safe", prismSignaturesValid = "prism_signatures_valid"
        case uiLanguage = "ui_language", rollbackConsistent = "rollback_consistent"
    }
}

struct ContainerGraphicsNetworkProbe: Decodable, Sendable {
    let viogpu3dPresent, secureBootEnabled: Bool
    let driverName: String
    let overlayDisabled, userTransparencyDisabled, fseDisabled, cursorBridgeInstalled: Bool?
}

struct ContainerProvisioningCheckpoint: Codable, Equatable, Sendable {
    let schemaVersion: Int
    let containerUUID: String
    var succeededStages: [String]
}

enum ContainerProvisioningPipeline {
    static func isProtectedBundle(_ url: URL, fileManager: FileManager) -> Bool {
        let standardized = url.standardizedFileURL
        let canonical = standardized.resolvingSymlinksInPath()
        let names = [standardized.lastPathComponent.lowercased(), canonical.lastPathComponent.lowercased()]
        for name in names where name.contains("golden") || name == "vm-a.utm"
            || name.hasPrefix("vm-a-") || name == "windows11-arm64.utm" {
            return true
        }
        let goldenManifest = canonical.appending(path: ".golden-manifest.json").path(percentEncoded: false)
        return fileManager.fileExists(atPath: goldenManifest)
    }

    static func verifySourceContainer(
        at bundlePath: String, fileManager: FileManager
    ) throws -> String {
        let url = URL(filePath: bundlePath).standardizedFileURL
        let path = url.path(percentEncoded: false)
        guard !path.isEmpty, url.pathExtension.lowercased() == "utm" else {
            throw UnifiedOrchestrationError.backendUnavailable("请选择有效的 .utm 容器目录。")
        }
        guard !isProtectedBundle(url, fileManager: fileManager) else {
            throw UnifiedOrchestrationError.backendUnavailable(
                "禁止直接修改只读母盘或冷备容器，请先派生独立受管游玩副本。"
            )
        }
        guard UnifiedRuntimeDiscovery.isUsablePlayableVMBundle(path, fileManager: fileManager) else {
            throw UnifiedOrchestrationError.backendUnavailable("所选容器不可写或缺少有效 config.plist。")
        }
        let configURL = url.appending(path: "config.plist")
        guard (try? configURL.resourceValues(forKeys: [.isSymbolicLinkKey]).isSymbolicLink) == false else {
            throw UnifiedOrchestrationError.backendUnavailable("容器配置文件为符号链接，已拒绝修改。")
        }
        let data = try Data(contentsOf: configURL)
        guard let config = try PropertyListSerialization.propertyList(
            from: data, options: [], format: nil) as? [String: Any],
            (config["Backend"] as? String) == "QEMU",
            let info = config["Information"] as? [String: Any],
            let uuid = info["UUID"] as? String, UUID(uuidString: uuid) != nil
        else {
            throw UnifiedOrchestrationError.backendUnavailable("容器 config.plist 缺少有效的 QEMU 配置或 UUID。")
        }
        if let system = config["System"] as? [String: Any],
           let uefi = system["UEFIBoot"] as? Bool, !uefi {
            throw UnifiedOrchestrationError.backendUnavailable("容器未启用 UEFI / Secure Boot，已拒绝部署。")
        }
        let drives = config["Drive"] as? [[String: Any]] ?? []
        let hasDisk = drives.contains { ($0["ImageType"] as? String) == "Disk" }
        guard hasDisk else {
            throw UnifiedOrchestrationError.backendUnavailable("容器缺少系统磁盘配置，无法作为可游玩副本。")
        }
        return uuid
    }

    static func configureHardwarePipeline(
        bundlePath: String,
        settings: UnifiedLaunchSettings,
        hardware: HardwareProfileSnapshot,
        fileManager: FileManager
    ) throws -> ContainerHardwarePipelineResult {
        let bundle = URL(filePath: bundlePath).standardizedFileURL
        let uuid = try verifySourceContainer(at: bundlePath, fileManager: fileManager)
        let configURL = bundle.appending(path: "config.plist")
        let original = try Data(contentsOf: configURL)
        var format = PropertyListSerialization.PropertyListFormat.xml
        guard var config = try PropertyListSerialization.propertyList(
            from: original, options: [], format: &format) as? [String: Any] else {
            throw UnifiedOrchestrationError.backendUnavailable("无法解析容器配置。")
        }

        let target = resolveSafeResources(settings: settings, hardware: hardware)
        let queues = HardwareAutoTuner.recommendedVirtIOBlockQueues(forVCPUCount: target.cpu)
        let fpsLimit = min(ContainerProvisioningConstants.fpsLimitDefault, max(60, hardware.displayRefreshRateHz))
        try mutateHardwareConfig(
            &config, cpu: target.cpu, memoryMiB: target.memoryMiB, queues: queues, fpsLimit: fpsLimit
        )
        let backupURL = bundle.appending(path: ContainerProvisioningConstants.hardwareBackupName)
        let backupPath = backupURL.path(percentEncoded: false)
        if !fileManager.fileExists(atPath: backupPath) {
            try original.write(to: backupURL, options: .atomic)
            try? fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: backupPath)
        }
        let encoded = try PropertyListSerialization.data(fromPropertyList: config, format: format, options: 0)
        try encoded.write(to: configURL, options: .atomic)
        do {
            try verifyHardwareConfig(
                at: configURL, expectedUUID: uuid, cpu: target.cpu, memoryMiB: target.memoryMiB, fpsLimit: fpsLimit
            )
        } catch {
            try? original.write(to: configURL, options: .atomic)
            throw error
        }
        return ContainerHardwarePipelineResult(
            cpuCount: target.cpu, memoryMiB: target.memoryMiB, virtioBlkQueues: queues, fpsLimit: fpsLimit,
            summary: "已配置 \(target.cpu) vCPU / \(target.memoryMiB / 1024) GiB、VirtIO-Blk \(queues) 队列、"
                + "WHQL virtio-mouse、清零 usb-redir、保留 intel-hda 与 \(fpsLimit) FPS 三重缓冲。"
        )
    }

    static func restoreHardwareBackupIfPresent(bundlePath: String, fileManager: FileManager) throws -> Bool {
        let bundle = URL(filePath: bundlePath).standardizedFileURL
        guard !isProtectedBundle(bundle, fileManager: fileManager) else {
            throw UnifiedOrchestrationError.backendUnavailable("禁止对受保护母盘或冷备执行回滚操作。")
        }
        let backupURL = bundle.appending(path: ContainerProvisioningConstants.hardwareBackupName)
        guard fileManager.fileExists(atPath: backupURL.path(percentEncoded: false)) else {
            return false
        }
        let backupData = try Data(contentsOf: backupURL)
        guard (try? PropertyListSerialization.propertyList(
            from: backupData, options: [], format: nil) as? [String: Any]) != nil else {
            throw UnifiedOrchestrationError.backendUnavailable("硬件配置备份损坏，未覆盖当前配置。")
        }
        try backupData.write(to: bundle.appending(path: "config.plist"), options: .atomic)
        try? fileManager.removeItem(at: backupURL)
        return true
    }

    static func deriveManagedCopy(
        fromGoldenPath goldenPath: String, destinationPath: String,
        fileManager: FileManager, commandRunner: UnifiedRuntimeOrchestrator.CommandRunner
    ) async throws -> String {
        let source = URL(filePath: goldenPath).standardizedFileURL
        let destination = URL(filePath: destinationPath).standardizedFileURL
        guard source.pathExtension.lowercased() == "utm",
              destination.pathExtension.lowercased() == "utm" else {
            throw UnifiedOrchestrationError.backendUnavailable("母盘与目标路径必须均为 .utm 容器目录。")
        }
        guard !isProtectedBundle(destination, fileManager: fileManager) else {
            throw UnifiedOrchestrationError.backendUnavailable("目标副本名称不得使用受保护母盘或冷备标识。")
        }
        guard fileManager.fileExists(atPath: source.appending(path: "config.plist").path(percentEncoded: false)) else {
            throw UnifiedOrchestrationError.missingVMBundle(goldenPath)
        }
        guard !fileManager.fileExists(atPath: destination.path(percentEncoded: false)) else {
            throw UnifiedOrchestrationError.backendUnavailable("目标副本目录已存在，请先清理或更换目标名称。")
        }
        try fileManager.createDirectory(at: destination.deletingLastPathComponent(), withIntermediateDirectories: true)
        let copyResult = try await commandRunner(
            "/bin/cp", ["-cR", source.path(percentEncoded: false), destination.path(percentEncoded: false)],
            ["__DEMOAPP_TIMEOUT_SECONDS": "120"])
        guard copyResult.exitCode == 0 else {
            try? fileManager.removeItem(at: destination)
            throw UnifiedOrchestrationError.commandFailed("APFS CoW 派生受管副本失败，请检查磁盘空间与文件系统支持。")
        }
        do { try prepareDerivedBundleMetadata(at: destination, fileManager: fileManager) } catch {
            try? fileManager.removeItem(at: destination)
            throw error
        }
        return destination.path(percentEncoded: false)
    }

    static func loadCheckpoint(at bundlePath: String, expectedUUID: String) -> ContainerProvisioningCheckpoint? {
        let url = URL(filePath: bundlePath).appending(path: ContainerProvisioningConstants.checkpointName)
        guard let data = try? Data(contentsOf: url),
              let decoded = try? JSONDecoder().decode(ContainerProvisioningCheckpoint.self, from: data),
              decoded.schemaVersion == 1,
              decoded.containerUUID.caseInsensitiveCompare(expectedUUID) == .orderedSame
        else { return nil }
        return decoded
    }

    static func saveCheckpoint(
        _ checkpoint: ContainerProvisioningCheckpoint, at bundlePath: String, fileManager: FileManager
    ) {
        let url = URL(filePath: bundlePath).appending(path: ContainerProvisioningConstants.checkpointName)
        guard let data = try? JSONEncoder().encode(checkpoint) else { return }
        try? data.write(to: url, options: .atomic)
        try? fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path(percentEncoded: false))
    }

    static func clearCheckpoint(at bundlePath: String, fileManager: FileManager) {
        let name = ContainerProvisioningConstants.checkpointName
        try? fileManager.removeItem(at: URL(filePath: bundlePath).appending(path: name))
    }

    static func ensureShaderCacheDirectory(fileManager: FileManager, overrideURL: URL? = nil) throws -> URL {
        let base = overrideURL
            ?? fileManager.urls(for: .cachesDirectory, in: .userDomainMask).first?.appending(path: "dxmt-shader-cache")
            ?? fileManager.temporaryDirectory.appending(path: "dxmt-shader-cache")
        try fileManager.createDirectory(at: base, withIntermediateDirectories: true)
        guard fileManager.isWritableFile(atPath: base.path(percentEncoded: false)) else {
            throw UnifiedOrchestrationError.backendUnavailable("DXMT 着色器缓存目录不可写。")
        }
        return base
    }
}

private extension ContainerProvisioningPipeline {
    static func mutateHardwareConfig(
        _ config: inout [String: Any], cpu: Int, memoryMiB: Int, queues: Int, fpsLimit: Int
    ) throws {
        var system = config["System"] as? [String: Any] ?? [:]
        system["CPUCount"] = cpu
        system["MemorySize"] = memoryMiB
        system["UEFIBoot"] = true
        config["System"] = system

        var input = config["Input"] as? [String: Any] ?? [:]
        input["VirtioMouse"] = true
        input["PureRelativeMouse"] = true
        input["DisableUsbRedir"] = true
        input["UsbSharing"] = false
        input["MaximumUsbShare"] = 0
        config["Input"] = input

        if var drives = config["Drive"] as? [[String: Any]] {
            for idx in drives.indices where (drives[idx]["ImageType"] as? String) == "Disk" {
                drives[idx]["Interface"] = "VirtIO"
            }
            config["Drive"] = drives
        }

        var sounds = config["Sound"] as? [[String: Any]] ?? []
        if !sounds.contains(where: { ($0["Hardware"] as? String) == "intel-hda" }) {
            sounds.append(["Hardware": "intel-hda"])
        }
        config["Sound"] = sounds

        var qemu = config["QEMU"] as? [String: Any] ?? [:]
        qemu["BalloonDevice"] = false
        qemu["RendererFPSLimit"] = fpsLimit
        qemu["QEMURendererFPSLimit"] = fpsLimit
        qemu["TripleBuffering"] = true
        let updatedArgs = mergeHardwareArguments(extractAdditionalArguments(from: qemu), queues: queues)
        try assertSafeQEMUArguments(updatedArgs)
        qemu["AdditionalArguments"] = updatedArgs
        config["QEMU"] = qemu
    }

    static func resolveSafeResources(
        settings: UnifiedLaunchSettings, hardware: HardwareProfileSnapshot
    ) -> (cpu: Int, memoryMiB: Int) {
        let preset = UnifiedLaunchSettings.containerPreset(settings.presetTier, hardware: hardware)
        let safeCPUs = HardwareAutoTuner.safeVCPUOptions(for: hardware)
        let safeRAMs = UnifiedLaunchSettings.supportedContainerMemoryOptionsGiB(for: hardware).map { $0 * 1024 }
        let cpu = settings.virtualCPUCount.flatMap { safeCPUs.contains($0) ? $0 : nil } ?? preset.virtualCPUCount
        let memory = settings.memoryMiB.flatMap { safeRAMs.contains($0) ? $0 : nil } ?? preset.memoryMiB
        return (cpu, memory)
    }

    static func extractAdditionalArguments(from qemu: [String: Any]) -> [String] {
        if let strings = qemu["AdditionalArguments"] as? [String] { return strings }
        if let dicts = qemu["AdditionalArguments"] as? [[String: Any]] {
            return dicts.compactMap { $0["Argument"] as? String }
        }
        return []
    }

    static func mergeHardwareArguments(_ existing: [String], queues: Int) -> [String] {
        let pairs = [
            ("-object", "iothread,id=iothread0", "iothread,"),
            ("-global", "virtio-blk-pci.num-queues=\(queues)", "virtio-blk-pci.num-queues="),
            ("-global", "virtio-blk-pci.iothread=iothread0", "virtio-blk-pci.iothread=")
        ]
        return pairs.reduce(existing) { acc, item in
            upsertArgumentPair(acc, flag: item.0, value: item.1, matchPrefix: item.2)
        }
    }

    static func upsertArgumentPair(_ args: [String], flag: String, value: String, matchPrefix: String) -> [String] {
        var output: [String] = []
        var index = 0
        var replaced = false
        while index < args.count {
            if index + 1 < args.count && args[index] == flag && args[index + 1].hasPrefix(matchPrefix) {
                if !replaced {
                    output.append(contentsOf: [flag, value])
                    replaced = true
                }
                index += 2
                continue
            }
            output.append(args[index])
            index += 1
        }
        if !replaced {
            output.append(contentsOf: [flag, value])
        }
        return output
    }

    static func assertSafeQEMUArguments(_ args: [String]) throws {
        var idx = 0
        while idx < args.count {
            guard args[idx].hasPrefix("-"),
                  ContainerProvisioningConstants.allowedQEMUFlags.contains(args[idx]),
                  idx + 1 < args.count else {
                throw UnifiedOrchestrationError.backendUnavailable("检测到非白名单 QEMU 参数，已终止配置写入。")
            }
            let val = args[idx + 1]
            guard ContainerProvisioningConstants.allowedQEMUValuePrefixes.contains(where: { val.hasPrefix($0) }) else {
                throw UnifiedOrchestrationError.backendUnavailable("检测到非白名单设备参数，已终止配置写入。")
            }
            idx += 2
        }
    }

    static func verifyHardwareConfig(
        at configURL: URL, expectedUUID: String, cpu: Int, memoryMiB: Int, fpsLimit: Int
    ) throws {
        guard let readBack = try PropertyListSerialization.propertyList(
            from: Data(contentsOf: configURL), options: [], format: nil) as? [String: Any],
            let info = readBack["Information"] as? [String: Any],
            (info["UUID"] as? String) == expectedUUID,
            let system = readBack["System"] as? [String: Any],
            (system["CPUCount"] as? Int) == cpu,
            (system["MemorySize"] as? Int) == memoryMiB,
            let input = readBack["Input"] as? [String: Any],
            (input["VirtioMouse"] as? Bool) == true,
            (input["DisableUsbRedir"] as? Bool) == true,
            (input["MaximumUsbShare"] as? Int) == 0,
            let qemu = readBack["QEMU"] as? [String: Any],
            (qemu["QEMURendererFPSLimit"] as? Int) == fpsLimit
        else {
            throw UnifiedOrchestrationError.backendUnavailable("硬件管线配置回读校验失败，已自动回滚。")
        }
    }

    static func prepareDerivedBundleMetadata(at bundle: URL, fileManager: FileManager) throws {
        if let enumerator = fileManager.enumerator(at: bundle, includingPropertiesForKeys: [.isDirectoryKey]) {
            try? fileManager.setAttributes([.posixPermissions: 0o755], ofItemAtPath: bundle.path(percentEncoded: false))
            for case let item as URL in enumerator {
                let isDir = (try? item.resourceValues(forKeys: [.isDirectoryKey]).isDirectory) ?? false
                let path = item.path(percentEncoded: false)
                try? fileManager.setAttributes([.posixPermissions: isDir ? 0o755 : 0o644], ofItemAtPath: path)
            }
        }
        try? fileManager.removeItem(at: bundle.appending(path: ".golden-manifest.json"))
        let configURL = bundle.appending(path: "config.plist")
        var format = PropertyListSerialization.PropertyListFormat.xml
        guard var config = try PropertyListSerialization.propertyList(
            from: Data(contentsOf: configURL), options: [], format: &format) as? [String: Any] else {
            throw UnifiedOrchestrationError.backendUnavailable("派生副本 config.plist 无效。")
        }
        let newUUID = UUID().uuidString.uppercased()
        var info = config["Information"] as? [String: Any] ?? [:]
        info["UUID"] = newUUID
        info["Name"] = bundle.deletingPathExtension().lastPathComponent
        config["Information"] = info
        try PropertyListSerialization.data(fromPropertyList: config, format: format, options: 0)
            .write(to: configURL, options: .atomic)
        let meta: [String: Any] = ["schema_version": 1, "role": "playable_working_vm", "vm_uuid": newUUID]
        let metaURL = bundle.appending(path: ".playable-meta.json")
        try JSONSerialization.data(withJSONObject: meta, options: [.sortedKeys]).write(to: metaURL, options: .atomic)
        try fileManager.setAttributes([.posixPermissions: 0o600], ofItemAtPath: metaURL.path(percentEncoded: false))
    }
}
