// SPDX-License-Identifier: GPL-3.0-or-later
// Official Windows 11 ARM64 ISO validation, resumable HTTPS download, and unattended bootstrap ISO builder.

import CryptoKit
import Foundation

/// Verified metadata for a local Windows 11 ARM64 ISO image.
public struct WindowsImageValidationResult: Equatable, Sendable {
    public let isoURL: URL
    public let sizeBytes: Int64
    public let formatSignature: String

    public init(isoURL: URL, sizeBytes: Int64, formatSignature: String) {
        self.isoURL = isoURL
        self.sizeBytes = sizeBytes
        self.formatSignature = formatSignature
    }
}

/// Progress snapshot emitted while downloading an official Windows 11 ARM64 ISO.
public struct WindowsImageDownloadProgress: Equatable, Sendable {
    public let receivedBytes: Int64
    public let expectedBytes: Int64

    public var fractionCompleted: Double {
        guard expectedBytes > 0 else { return 0 }
        return min(1.0, max(0.0, Double(receivedBytes) / Double(expectedBytes)))
    }

    public init(receivedBytes: Int64, expectedBytes: Int64) {
        self.receivedBytes = receivedBytes
        self.expectedBytes = expectedBytes
    }
}

/// Parameters for generating a compliant ARM64 Windows 11 `autounattend.xml`.
public struct UnattendedWindowsConfig: Codable, Equatable, Sendable {
    public var computerName: String
    public var username: String
    public var setupUILanguage: String
    public var autoDetectSetupLanguage: Bool
    public var locale: String
    public var timeZone: String
    public var imageIndex: Int

    public init(
        computerName: String = "MALT-WIN11",
        username: String = "malt",
        setupUILanguage: String = "en-US",
        autoDetectSetupLanguage: Bool = true,
        locale: String = "zh-CN",
        timeZone: String = "China Standard Time",
        imageIndex: Int = 1
    ) {
        self.computerName = computerName
        self.username = username
        self.setupUILanguage = setupUILanguage
        self.autoDetectSetupLanguage = autoDetectSetupLanguage
        self.locale = locale
        self.timeZone = timeZone
        self.imageIndex = max(1, imageIndex)
    }
}

/// Validates official Windows 11 ARM64 ISOs, performs resumable HTTPS downloads with optional SHA-256 checks,
/// and builds native macOS `hdiutil` unattended bootstrap ISOs (`MALTBOOT`) without bundling OS images.
public struct WindowsImageBootstrapService: Sendable {
    public typealias CommandRunner = UnifiedRuntimeOrchestrator.CommandRunner

    private let commandRunner: CommandRunner

    public init(commandRunner: CommandRunner? = nil) {
        self.commandRunner = commandRunner ?? { exe, args, env in
            try await OrchestratorProcessRunner.run(executable: exe, arguments: args, environment: env)
        }
    }

    public static func defaultISOCacheDirectory(fileManager: FileManager = .default) -> URL {
        let caches = fileManager.urls(for: .cachesDirectory, in: .userDomainMask).first
            ?? fileManager.temporaryDirectory
        return caches.appending(path: "Malt/ISOs", directoryHint: .isDirectory)
    }

    /// Validates that a local file is a readable, non-trivial ISO9660 or UDF disk image.
    public func validateWindowsARM64ISO(
        at isoURL: URL,
        minimumSizeBytes: Int64 = 1_073_741_824,
        fileManager: FileManager = .default
    ) throws -> WindowsImageValidationResult {
        let standardized = isoURL.standardizedFileURL
        let path = standardized.path(percentEncoded: false)
        guard standardized.pathExtension.lowercased() == "iso" else {
            throw UnifiedOrchestrationError.backendUnavailable("请选择扩展名为 .iso 的官方 Windows 11 ARM64 镜像文件。")
        }
        guard fileManager.isReadableFile(atPath: path) else {
            throw UnifiedOrchestrationError.backendUnavailable("无法读取所选 ISO 镜像，请检查文件是否存在及读取权限。")
        }
        let attrs = try fileManager.attributesOfItem(atPath: path)
        let sizeBytes = (attrs[.size] as? NSNumber)?.int64Value ?? 0
        guard sizeBytes >= minimumSizeBytes else {
            throw UnifiedOrchestrationError.backendUnavailable(
                "ISO 镜像体积异常过小，请确认已完整下载官方 Windows 11 ARM64 镜像。"
            )
        }
        let header = try readHeaderBytes(from: standardized, maxBytes: 65_536)
        guard let signature = detectOpticalSignature(in: header) else {
            throw UnifiedOrchestrationError.backendUnavailable(
                "文件头未检测到有效的 ISO9660 / UDF 卷标识，请重新下载官方 Windows 11 ARM64 ISO。"
            )
        }
        return WindowsImageValidationResult(isoURL: standardized, sizeBytes: sizeBytes, formatSignature: signature)
    }

    /// Downloads an official HTTPS ISO with HTTP Range resume and optional SHA-256 verification.
    public func downloadOfficialISO(
        from sourceURL: URL,
        expectedSHA256: String? = nil,
        destinationDirectory: URL? = nil,
        minimumSizeBytes: Int64 = 1_073_741_824,
        fileManager: FileManager = .default,
        onProgress: (@Sendable (WindowsImageDownloadProgress) -> Void)? = nil
    ) async throws -> URL {
        guard sourceURL.scheme?.lowercased() == "https", sourceURL.host != nil else {
            throw UnifiedOrchestrationError.backendUnavailable("仅支持通过 HTTPS 官方直链下载 Windows 11 ARM64 镜像。")
        }
        let targetDir = destinationDirectory ?? Self.defaultISOCacheDirectory(fileManager: fileManager)
        try fileManager.createDirectory(at: targetDir, withIntermediateDirectories: true)
        let filename = sanitizedISOFilename(from: sourceURL)
        let finalURL = targetDir.appending(path: filename)
        let partURL = targetDir.appending(path: filename + ".part")

        var existingBytes: Int64 = 0
        if fileManager.fileExists(atPath: partURL.path(percentEncoded: false)) {
            let attrs = try? fileManager.attributesOfItem(atPath: partURL.path(percentEncoded: false))
            existingBytes = (attrs?[.size] as? NSNumber)?.int64Value ?? 0
        }

        var request = URLRequest(url: sourceURL)
        request.timeoutInterval = 60
        if existingBytes > 0 {
            request.setValue("bytes=\(existingBytes)-", forHTTPHeaderField: "Range")
        }

        let (byteStream, response) = try await URLSession.shared.bytes(for: request)
        guard let http = response as? HTTPURLResponse, (200...299).contains(http.statusCode) else {
            throw UnifiedOrchestrationError.backendUnavailable("官方镜像下载请求未成功，请确认下载链接有效且未过期。")
        }

        let isResuming = http.statusCode == 206 && existingBytes > 0
        let contentLength = http.expectedContentLength > 0 ? http.expectedContentLength : 0
        let totalExpected = isResuming ? (existingBytes + contentLength) : contentLength
        let handle = try openPartFileHandle(at: partURL, resuming: isResuming, fileManager: fileManager)
        defer { try? handle.close() }

        var received: Int64 = isResuming ? existingBytes : 0
        try await streamDownloadBytes(
            byteStream, to: handle, received: &received, expected: totalExpected, onProgress: onProgress
        )

        if let expectedHash = expectedSHA256?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased(),
           !expectedHash.isEmpty {
            let actualHash = try computeFileSHA256(at: partURL)
            guard actualHash == expectedHash else {
                throw UnifiedOrchestrationError.backendUnavailable("下载文件的 SHA-256 校验值不匹配，请重新获取官方镜像。")
            }
        }
        if fileManager.fileExists(atPath: finalURL.path(percentEncoded: false)) {
            try fileManager.removeItem(at: finalURL)
        }
        try fileManager.moveItem(at: partURL, to: finalURL)
        _ = try validateWindowsARM64ISO(at: finalURL, minimumSizeBytes: minimumSizeBytes, fileManager: fileManager)
        return finalURL
    }

    /// Downloads and caches the official open-source UTM guest tools ISO if no local copy is present.
    public func ensureOfficialGuestToolsISO(
        beside windowsISO: URL? = nil, fileManager: FileManager = .default,
        onProgress: (@Sendable (WindowsImageDownloadProgress) -> Void)? = nil
    ) async throws -> URL {
        if let local = ContainerBootstrapPreflight.discoverLocalDriverSource(
            beside: windowsISO, fileManager: fileManager
        ) { return local }
        return try await downloadOfficialISO(
            from: ContainerBootstrapPreflight.officialGuestToolsISOURL,
            destinationDirectory: ContainerBootstrapPreflight.defaultDriverCacheDirectory(fileManager: fileManager),
            minimumSizeBytes: ContainerBootstrapPreflight.minimumDriverISOSizeBytes,
            fileManager: fileManager, onProgress: onProgress
        )
    }

    /// Generates an anti-cheat compliant ARM64 Windows 11 `autounattend.xml` preserving Secure Boot and TPM 2.0.
    public func generateUnattendXML(config: UnattendedWindowsConfig = UnattendedWindowsConfig()) -> String {
        WindowsUnattendXMLBuilder.generate(config: config)
    }

    /// Packages `autounattend.xml`, optional WHQL driver folders, and guest-optimizer assets into `MALTBOOT` ISO.
    public func buildBootstrapISO(
        outputURL: URL,
        config: UnattendedWindowsConfig = UnattendedWindowsConfig(),
        driverDirectory: URL? = nil,
        optimizerFiles: [URL] = [],
        fileManager: FileManager = .default
    ) async throws -> URL {
        let staging = fileManager.temporaryDirectory.appending(
            path: "malt-bootstrap-stage-\(UUID().uuidString)", directoryHint: .isDirectory
        )
        try fileManager.createDirectory(at: staging, withIntermediateDirectories: true)
        defer { try? fileManager.removeItem(at: staging) }

        try generateUnattendXML(config: config)
            .write(to: staging.appending(path: "autounattend.xml"), atomically: true, encoding: .utf8)
        try WindowsUnattendXMLBuilder.bootstrapScript()
            .write(to: staging.appending(path: "bootstrap.ps1"), atomically: true, encoding: .utf8)
        try WindowsUnattendXMLBuilder.startupScript()
            .write(to: staging.appending(path: "startup.nsh"), atomically: true, encoding: .utf8)

        if let driverSource = driverDirectory,
           fileManager.fileExists(atPath: driverSource.path(percentEncoded: false)) {
            try await stageDriverSource(driverSource, into: staging, fileManager: fileManager)
        }
        if !optimizerFiles.isEmpty {
            let optDir = staging.appending(path: "GuestOptimizer", directoryHint: .isDirectory)
            try fileManager.createDirectory(at: optDir, withIntermediateDirectories: true)
            for fileURL in optimizerFiles {
                guard fileManager.isReadableFile(atPath: fileURL.path(percentEncoded: false)) else { continue }
                try fileManager.copyItem(at: fileURL, to: optDir.appending(path: fileURL.lastPathComponent))
            }
        }

        let targetISO = outputURL.standardizedFileURL
        try fileManager.createDirectory(at: targetISO.deletingLastPathComponent(), withIntermediateDirectories: true)
        try? fileManager.removeItem(at: targetISO)

        let result = try await commandRunner(
            "/usr/bin/hdiutil",
            [
                "makehybrid", "-iso", "-joliet", "-udf",
                "-default-volume-name", "MALTBOOT",
                "-o", targetISO.path(percentEncoded: false),
                staging.path(percentEncoded: false)
            ],
            ["__DEMOAPP_TIMEOUT_SECONDS": "120"]
        )
        guard result.exitCode == 0 else {
            throw UnifiedOrchestrationError.commandFailed(
                "生成无人值守引导 ISO 失败（exit \(result.exitCode)）。"
            )
        }
        return targetISO
    }
}

private extension WindowsImageBootstrapService {
    func stageDriverSource(_ source: URL, into staging: URL, fileManager: FileManager) async throws {
        if source.pathExtension.lowercased() == "iso" {
            let mountPoint = fileManager.temporaryDirectory
                .appending(path: "malt-drv-mnt-\(UUID().uuidString)", directoryHint: .isDirectory)
            try fileManager.createDirectory(at: mountPoint, withIntermediateDirectories: true)
            let mountPath = mountPoint.path(percentEncoded: false)
            let attach = try await commandRunner(
                "/usr/bin/hdiutil",
                ["attach", "-readonly", "-nobrowse", "-mountpoint", mountPath, source.path(percentEncoded: false)],
                ["__DEMOAPP_TIMEOUT_SECONDS": "60"]
            )
            guard attach.exitCode == 0 else {
                try? fileManager.removeItem(at: mountPoint)
                throw UnifiedOrchestrationError.commandFailed("挂载驱动 ISO 失败（exit \(attach.exitCode)）。")
            }
            defer {
                Task.detached { [commandRunner] in
                    _ = try? await commandRunner("/usr/sbin/diskutil", ["eject", mountPath], [:])
                    try? FileManager.default.removeItem(at: mountPoint)
                }
            }
            try stageDriverDirectoryContents(from: mountPoint, into: staging, fileManager: fileManager)
            _ = try? await commandRunner(
                "/usr/sbin/diskutil", ["eject", mountPath], ["__DEMOAPP_TIMEOUT_SECONDS": "20"]
            )
            try? fileManager.removeItem(at: mountPoint)
            return
        }
        try stageDriverDirectoryContents(from: source, into: staging, fileManager: fileManager)
    }

    func stageDriverDirectoryContents(from root: URL, into staging: URL, fileManager: FileManager) throws {
        let destDrivers = staging.appending(path: "Drivers", directoryHint: .isDirectory)
        let postDrivers = staging.appending(path: "PostDrivers", directoryHint: .isDirectory)
        let nestedDriversRoot = root.appending(path: "Drivers", directoryHint: .isDirectory)
        let searchRoot = fileManager.fileExists(atPath: nestedDriversRoot.path(percentEncoded: false))
            ? nestedDriversRoot : root
        var copiedARM64 = false
        if let children = try? fileManager.contentsOfDirectory(at: searchRoot, includingPropertiesForKeys: nil) {
            let hasVioGpu3d = children.contains { child in
                child.lastPathComponent.lowercased() == "viogpu3d"
                    && fileManager.fileExists(atPath: child.appending(path: "w11/ARM64").path(percentEncoded: false))
            }
            for child in children {
                let lowerName = child.lastPathComponent.lowercased()
                if hasVioGpu3d && lowerName == "viogpudo" { continue }
                let arm64Dir = child.appending(path: "w11/ARM64", directoryHint: .isDirectory)
                if fileManager.fileExists(atPath: arm64Dir.path(percentEncoded: false)) {
                    let isGPUDriver = lowerName == "viogpu3d" || lowerName == "viogpudo"
                    let targetBase = isGPUDriver ? postDrivers : destDrivers
                    try fileManager.createDirectory(at: targetBase, withIntermediateDirectories: true)
                    try fileManager.copyItem(at: arm64Dir, to: targetBase.appending(path: child.lastPathComponent))
                    copiedARM64 = true
                }
            }
        }
        if !copiedARM64 {
            try fileManager.copyItem(at: root, to: destDrivers)
        }
        if let topItems = try? fileManager.contentsOfDirectory(at: root, includingPropertiesForKeys: nil) {
            for item in topItems {
                let lower = item.lastPathComponent.lowercased()
                if lower.hasPrefix("utm-guest-tools") && lower.hasSuffix(".exe")
                    || lower.hasPrefix("qemu-ga") && lower.hasSuffix(".msi") {
                    try? fileManager.copyItem(at: item, to: staging.appending(path: item.lastPathComponent))
                }
            }
        }
    }

    func readHeaderBytes(from url: URL, maxBytes: Int) throws -> Data {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        return try handle.read(upToCount: maxBytes) ?? Data()
    }

    func detectOpticalSignature(in header: Data) -> String? {
        if header.range(of: Data("CD001".utf8)) != nil {
            return "ISO9660"
        }
        for marker in ["BEA01", "NSR02", "NSR03"] where header.range(of: Data(marker.utf8)) != nil {
            return "UDF"
        }
        return nil
    }

    func sanitizedISOFilename(from sourceURL: URL) -> String {
        let raw = sourceURL.lastPathComponent
        let cleaned = raw.replacingOccurrences(of: "[^A-Za-z0-9._-]", with: "_", options: .regularExpression)
        if cleaned.lowercased().hasSuffix(".iso") && cleaned.count > 4 {
            return cleaned
        }
        return "Win11_ARM64_Official.iso"
    }

    func openPartFileHandle(at url: URL, resuming: Bool, fileManager: FileManager) throws -> FileHandle {
        let path = url.path(percentEncoded: false)
        if !fileManager.fileExists(atPath: path) || !resuming {
            fileManager.createFile(atPath: path, contents: nil)
        }
        let handle = try FileHandle(forWritingTo: url)
        if resuming {
            try handle.seekToEnd()
        } else {
            try handle.truncate(atOffset: 0)
        }
        return handle
    }

    func streamDownloadBytes(
        _ stream: URLSession.AsyncBytes,
        to handle: FileHandle,
        received: inout Int64,
        expected: Int64,
        onProgress: (@Sendable (WindowsImageDownloadProgress) -> Void)?
    ) async throws {
        var buffer = Data()
        buffer.reserveCapacity(262_144)
        for try await byte in stream {
            try Task.checkCancellation()
            buffer.append(byte)
            if buffer.count >= 262_144 {
                try handle.write(contentsOf: buffer)
                received += Int64(buffer.count)
                buffer.removeAll(keepingCapacity: true)
                onProgress?(WindowsImageDownloadProgress(receivedBytes: received, expectedBytes: expected))
            }
        }
        if !buffer.isEmpty {
            try handle.write(contentsOf: buffer)
            received += Int64(buffer.count)
            onProgress?(WindowsImageDownloadProgress(receivedBytes: received, expectedBytes: expected))
        }
    }

    func computeFileSHA256(at url: URL) throws -> String {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        var hasher = SHA256()
        while let chunk = try handle.read(upToCount: 1_048_576), !chunk.isEmpty {
            hasher.update(data: chunk)
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }
}
