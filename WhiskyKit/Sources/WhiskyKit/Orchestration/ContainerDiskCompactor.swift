// SPDX-License-Identifier: GPL-3.0-or-later
// Isolated qcow2 image creation, integrity check, and offline sparse compaction for Malt containers.

import Foundation

/// Outcome of an offline qcow2 container disk compaction pass.
public struct ContainerDiskCompactionReport: Codable, Equatable, Sendable {
    public let diskFilename: String
    public let beforeBytes: Int64
    public let afterBytes: Int64
    public let reclaimedBytes: Int64

    public var beforeGiB: Double { Double(beforeBytes) / 1_073_741_824.0 }
    public var afterGiB: Double { Double(afterBytes) / 1_073_741_824.0 }
    public var reclaimedGiB: Double { Double(max(0, reclaimedBytes)) / 1_073_741_824.0 }
}

/// Executes qemu-img operations in an isolated child process using either a host qemu-img binary
/// or Malt's embedded qemu-img.framework without risking host process termination.
public struct ContainerDiskCompactor: Sendable {
    public typealias CommandRunner = UnifiedRuntimeOrchestrator.CommandRunner
    public typealias StopVerifier = @Sendable (String, String) async throws -> Void

    private let helperAppPath: String?
    private let pythonExecutablePath: String?
    private let commandRunner: CommandRunner
    private let stopVerifier: StopVerifier?

    public init(
        helperAppPath: String? = nil,
        pythonExecutablePath: String? = nil,
        commandRunner: CommandRunner? = nil,
        stopVerifier: StopVerifier? = nil
    ) {
        self.helperAppPath = helperAppPath
        self.pythonExecutablePath = pythonExecutablePath
        self.commandRunner = commandRunner ?? { executable, arguments, environment in
            try await OrchestratorProcessRunner.run(
                executable: executable,
                arguments: arguments,
                environment: environment
            )
        }
        self.stopVerifier = stopVerifier
    }

    /// Creates a sparse qcow2 virtual disk (`compat=1.1, cluster_size=65536, preallocation=off`).
    public func createSparseQCow2(at imageURL: URL, sizeGiB: Int = 64) async throws {
        let clampedGiB = max(32, min(512, sizeGiB))
        let parentDir = imageURL.deletingLastPathComponent()
        try FileManager.default.createDirectory(at: parentDir, withIntermediateDirectories: true)
        let args = [
            "create", "-f", "qcow2",
            "-o", "compat=1.1,cluster_size=65536,preallocation=off",
            imageURL.path(percentEncoded: false),
            "\(clampedGiB)G"
        ]
        try await runQemuImg(arguments: args)
    }

    /// Runs a read-only `qemu-img check` on a qcow2 disk image.
    public func checkQCow2(at imageURL: URL) async throws -> String {
        let result = try await executeQemuImg(arguments: ["check", imageURL.path(percentEncoded: false)])
        guard result.exitCode == 0 else {
            throw UnifiedOrchestrationError.backendUnavailable(
                "磁盘镜像一致性检查未通过（exit \(result.exitCode)）。"
            )
        }
        return result.stdout
    }

    /// Compacts the primary writable qcow2 system disk inside a stopped, managed `.utm` container.
    public func compactContainerSystemDisk(
        bundlePath: String,
        fileManager: FileManager = .default
    ) async throws -> ContainerDiskCompactionReport {
        let vmUUID = try ContainerProvisioningPipeline.verifySourceContainer(at: bundlePath, fileManager: fileManager)
        try await verifyContainerStopped(bundlePath: bundlePath, vmUUID: vmUUID)
        let bundleURL = URL(filePath: bundlePath).standardizedFileURL
        let diskURL = try resolvePrimaryQCow2URL(in: bundleURL, fileManager: fileManager)
        let beforeBytes = allocatedDiskBytes(at: diskURL)
        try ContainerBootstrapPreflight.validateStorageTarget(
            directory: diskURL.deletingLastPathComponent(),
            minimumFreeBytes: beforeBytes + 1_073_741_824,
            fileManager: fileManager
        )
        let tempURL = diskURL.deletingLastPathComponent()
            .appending(path: ".\(diskURL.deletingPathExtension().lastPathComponent)-compact-tmp.qcow2")
        try? fileManager.removeItem(at: tempURL)

        defer { try? fileManager.removeItem(at: tempURL) }

        let convertArgs = [
            "convert", "-f", "qcow2", "-O", "qcow2",
            "-o", "compat=1.1,cluster_size=65536,preallocation=off",
            diskURL.path(percentEncoded: false),
            tempURL.path(percentEncoded: false)
        ]
        try await runQemuImg(arguments: convertArgs, timeoutSeconds: 600)
        _ = try await checkQCow2(at: tempURL)

        _ = try fileManager.replaceItemAt(diskURL, withItemAt: tempURL)
        let afterBytes = allocatedDiskBytes(at: diskURL)
        return ContainerDiskCompactionReport(
            diskFilename: diskURL.lastPathComponent,
            beforeBytes: beforeBytes,
            afterBytes: afterBytes,
            reclaimedBytes: max(0, beforeBytes - afterBytes)
        )
    }

    func resolvePrimaryQCow2URL(in bundleURL: URL, fileManager: FileManager) throws -> URL {
        let configURL = bundleURL.appending(path: "config.plist")
        let data = try Data(contentsOf: configURL)
        guard let root = try PropertyListSerialization.propertyList(
            from: data, options: [], format: nil
        ) as? [String: Any],
            let drives = root["Drive"] as? [[String: Any]]
        else {
            throw UnifiedOrchestrationError.backendUnavailable("无法解析容器磁盘列表。")
        }
        let dataDir = bundleURL.appending(path: "Data", directoryHint: .isDirectory)
        for drive in drives {
            let isDisk = (drive["ImageType"] as? String) == "Disk"
            let isReadOnly = (drive["ReadOnly"] as? Bool) ?? false
            guard isDisk, !isReadOnly, let imageName = drive["ImageName"] as? String,
                  imageName.lowercased().hasSuffix(".qcow2") else {
                continue
            }
            let candidate = dataDir.appending(path: imageName)
            if fileManager.fileExists(atPath: candidate.path(percentEncoded: false)) {
                return candidate
            }
        }
        throw UnifiedOrchestrationError.backendUnavailable("容器内未找到可压缩的 qcow2 系统磁盘。")
    }

    private func allocatedDiskBytes(at url: URL) -> Int64 {
        let values = try? url.resourceValues(forKeys: [.fileAllocatedSizeKey, .fileSizeKey])
        if let allocated = values?.fileAllocatedSize, allocated > 0 {
            return Int64(allocated)
        }
        return Int64(values?.fileSize ?? 0)
    }

    private func verifyContainerStopped(bundlePath: String, vmUUID: String) async throws {
        if let stopVerifier {
            try await stopVerifier(bundlePath, vmUUID)
            return
        }
        let checkResult = try await commandRunner(
            "/usr/bin/pgrep", ["-f", vmUUID], ["__DEMOAPP_TIMEOUT_SECONDS": "5"]
        )
        if checkResult.exitCode == 0 {
            throw UnifiedOrchestrationError.backendUnavailable(
                "容器仍在运行中，请先在 Windows 内正常关机后再执行磁盘瘦身。"
            )
        }
    }

    private func runQemuImg(arguments: [String], timeoutSeconds: Int = 180) async throws {
        let result = try await executeQemuImg(arguments: arguments, timeoutSeconds: timeoutSeconds)
        guard result.exitCode == 0 else {
            let detail = result.stderr.trimmingCharacters(in: .whitespacesAndNewlines)
            throw UnifiedOrchestrationError.backendUnavailable(
                "磁盘引擎操作失败（exit \(result.exitCode)）：\(detail.isEmpty ? "未知错误" : detail)"
            )
        }
    }

    private func executeQemuImg(
        arguments: [String],
        timeoutSeconds: Int = 180
    ) async throws -> OrchestratorCommandResult {
        let timeoutEnv = ["__DEMOAPP_TIMEOUT_SECONDS": String(timeoutSeconds)]
        if let directBinary = resolveHostQemuImgBinary() {
            return try await commandRunner(directBinary, arguments, timeoutEnv)
        }
        guard let frameworkDir = resolveEmbeddedFrameworksDirectory() else {
            throw UnifiedOrchestrationError.backendUnavailable(
                "未找到内嵌 qemu-img.framework 或系统 qemu-img 工具。"
            )
        }
        let frameworkBinary = frameworkDir
            .appending(path: "qemu-img.framework/Versions/A/qemu-img")
            .path(percentEncoded: false)
        let pythonBridge = """
        import ctypes, sys
        lib = ctypes.CDLL(sys.argv[1])
        fn = getattr(lib, "main", None) or getattr(lib, "qemu_img_main")
        fn.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_char_p)]
        fn.restype = ctypes.c_int
        argv = [b"qemu-img"] + [arg.encode("utf-8") for arg in sys.argv[2:]]
        arr = (ctypes.c_char_p * len(argv))(*argv)
        sys.exit(fn(len(argv), arr))
        """
        var env = timeoutEnv
        env["DYLD_FRAMEWORK_PATH"] = frameworkDir.path(percentEncoded: false)
        env["PYTHONNOUSERSITE"] = "1"
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        let pythonBinary = resolveNonSIPPythonBinary()
        return try await commandRunner(
            pythonBinary,
            ["-I", "-c", pythonBridge, frameworkBinary] + arguments,
            env
        )
    }

    private func resolveNonSIPPythonBinary() -> String {
        var candidates: [String] = []
        if let pythonExecutablePath, !pythonExecutablePath.isEmpty {
            candidates.append(pythonExecutablePath)
        }
        let mainPython = Bundle.main.bundleURL
            .appending(path: "Contents/Frameworks/Python.framework/Versions/Current/bin/python3")
            .path(percentEncoded: false)
        candidates.append(mainPython)
        candidates.append("/Applications/Malt.app/Contents/Frameworks/Python.framework/Versions/Current/bin/python3")
        candidates.append("/opt/homebrew/bin/python3")
        candidates.append("/usr/local/bin/python3")
        for candidate in candidates where FileManager.default.isExecutableFile(atPath: candidate) {
            return candidate
        }
        return "/usr/bin/python3"
    }

    private func resolveHostQemuImgBinary() -> String? {
        let candidates = ["/opt/homebrew/bin/qemu-img", "/usr/local/bin/qemu-img"]
        return candidates.first { FileManager.default.isExecutableFile(atPath: $0) }
    }

    private func resolveEmbeddedFrameworksDirectory() -> URL? {
        var candidates: [URL] = []
        if let helperAppPath, !helperAppPath.isEmpty {
            candidates.append(URL(filePath: helperAppPath).appending(path: "Contents/Frameworks"))
        }
        candidates.append(
            Bundle.main.bundleURL.appending(path: "Contents/Helpers/MaltContainerHelper.app/Contents/Frameworks")
        )
        candidates.append(
            URL(filePath: "/Applications/Malt.app/Contents/Helpers/MaltContainerHelper.app/Contents/Frameworks")
        )
        candidates.append(URL(filePath: "/Applications/UTM.app/Contents/Frameworks"))
        for directory in candidates {
            let imgBin = directory.appending(path: "qemu-img.framework/Versions/A/qemu-img")
            if FileManager.default.fileExists(atPath: imgBin.path(percentEncoded: false)) {
                return directory
            }
        }
        return nil
    }
}
