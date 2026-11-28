// SPDX-License-Identifier: GPL-3.0-or-later
// Pre-flight storage, ISO language detection, open-source VirtIO driver caching, and logon readiness helpers.

import Darwin
import Foundation

/// Pre-flight checks and automatic asset helpers ensuring reliable container setup across all Apple Silicon Macs.
public enum ContainerBootstrapPreflight {
    /// Official open-source UTM v5 3D guest tools ISO (viogpu3d WDDM 3D, viostor, vioserial, NetKVM, QGA).
    public static let officialGuestToolsISOURL = URL(
        string: "https://getutm.app/downloads/utm-guest-tools-3d-latest.iso"
    ) ?? URL(filePath: "/")

    /// Minimum free space required before creating a new Windows 11 ARM64 sparse container (25 GiB).
    public static let minimumNewContainerFreeBytes: Int64 = 25 * 1_073_741_824
    /// Minimum valid size for a VirtIO / UTM guest tools ISO (8 MiB).
    public static let minimumDriverISOSizeBytes: Int64 = 8 * 1_048_576

    public static func defaultDriverCacheDirectory(fileManager: FileManager = .default) -> URL {
        let caches = fileManager.urls(for: .cachesDirectory, in: .userDomainMask).first
            ?? fileManager.temporaryDirectory
        return caches.appending(path: "Malt/Drivers", directoryHint: .isDirectory)
    }

    /// Searches alongside the Windows ISO, Malt's local driver cache, and Downloads for an existing VirtIO driver ISO.
    public static func discoverLocalDriverSource(
        beside windowsISO: URL?,
        fileManager: FileManager = .default,
        cacheDirectoryOverride: URL? = nil,
        downloadsDirectoryOverride: URL? = nil
    ) -> URL? {
        var searchDirs: [URL] = []
        if let windowsISO {
            searchDirs.append(windowsISO.deletingLastPathComponent())
        }
        searchDirs.append(cacheDirectoryOverride ?? defaultDriverCacheDirectory(fileManager: fileManager))
        if let downloads = downloadsDirectoryOverride
            ?? fileManager.urls(for: .downloadsDirectory, in: .userDomainMask).first {
            searchDirs.append(downloads)
        }
        for directory in searchDirs {
            if let match = findDriverISO(in: directory, fileManager: fileManager) {
                return match
            }
        }
        return nil
    }

    /// Resolves a usable VirtIO/QGA driver source: explicit path -> local cache/Downloads -> optional HTTPS download.
    public static func resolveDriverDirectory(
        explicit: URL?,
        beside windowsISO: URL?,
        autoDownload: Bool,
        requireDrivers: Bool,
        bootstrapService: WindowsImageBootstrapService,
        fileManager: FileManager = .default,
        onProgress: (@Sendable (WindowsImageDownloadProgress) -> Void)? = nil
    ) async throws -> (url: URL?, sourceLabel: String) {
        if let explicit, fileManager.fileExists(atPath: explicit.path(percentEncoded: false)) {
            return (explicit, "已选用自定义驱动包 \(explicit.lastPathComponent)")
        }
        if let local = discoverLocalDriverSource(beside: windowsISO, fileManager: fileManager) {
            return (local, "已自动复用本地驱动包 \(local.lastPathComponent)")
        }
        if autoDownload {
            do {
                let downloaded = try await bootstrapService.ensureOfficialGuestToolsISO(
                    beside: windowsISO, fileManager: fileManager, onProgress: onProgress
                )
                return (downloaded, "已自动下载开源官方驱动包 \(downloaded.lastPathComponent)")
            } catch {
                if requireDrivers {
                    throw UnifiedOrchestrationError.backendUnavailable(
                        "自动获取官方开源 VirtIO 驱动包失败（\(error.localizedDescription)）。"
                            + "请检查网络或手动选择 utm-guest-tools / virtio-win ISO 驱动包。"
                    )
                }
            }
        }
        if requireDrivers {
            throw UnifiedOrchestrationError.backendUnavailable(
                "缺少 VirtIO / viogpu3d 驱动包，WinPE 将无法识别虚拟磁盘。请勾选自动下载官方驱动包或手动选择驱动 ISO。"
            )
        }
        return (nil, "测试模式跳过驱动注入")
    }

    /// Infers the Windows Setup UI language from filename conventions or ISO9660 volume label markers.
    public static func detectSetupUILanguage(
        for isoURL: URL,
        fileManager: FileManager = .default
    ) -> String? {
        if let fromName = matchLanguageToken(in: isoURL.lastPathComponent) {
            return fromName
        }
        let path = isoURL.standardizedFileURL.path(percentEncoded: false)
        guard fileManager.isReadableFile(atPath: path),
              let handle = try? FileHandle(forReadingFrom: isoURL) else {
            return nil
        }
        defer { try? handle.close() }
        guard let header = try? handle.read(upToCount: 65_536), header.count >= 0x8048 else {
            return nil
        }
        let volumeSlice = header[0x8028..<0x8048]
        if let volumeLabel = String(bytes: volumeSlice, encoding: .ascii),
           let fromLabel = matchLanguageToken(in: volumeLabel) {
            return fromLabel
        }
        return nil
    }

    /// Returns a copy of `config` whose `setupUILanguage` automatically matches the chosen Windows ISO when enabled.
    public static func resolvedUnattendedConfig(
        _ config: UnattendedWindowsConfig,
        for isoURL: URL,
        fileManager: FileManager = .default
    ) -> UnattendedWindowsConfig {
        guard config.autoDetectSetupLanguage,
              let detected = detectSetupUILanguage(for: isoURL, fileManager: fileManager) else {
            return config
        }
        var updated = config
        updated.setupUILanguage = detected
        return updated
    }

    /// Validates that the destination volume is writable, supports >4 GiB files (not FAT32), and has enough free space.
    public static func validateStorageTarget(
        directory: URL,
        minimumFreeBytes: Int64,
        fileManager: FileManager = .default
    ) throws {
        let probeURL = nearestExistingDirectory(for: directory.standardizedFileURL, fileManager: fileManager)
        let probePath = probeURL.path(percentEncoded: false)
        guard fileManager.isWritableFile(atPath: probePath) else {
            throw UnifiedOrchestrationError.backendUnavailable(
                "目标存储目录不可写，请更换有写入权限的本地目录或外置 SSD。"
            )
        }
        let fsType = filesystemTypeName(atPath: probePath).lowercased()
        if fsType == "msdos" || fsType.contains("fat32") || fsType.contains("fat16") {
            throw UnifiedOrchestrationError.backendUnavailable(
                "目标磁盘为 FAT32 格式（单文件上限 4 GiB），无法存放 Windows 镜像与虚拟盘，请改用 APFS 或 exFAT 磁盘。"
            )
        }
        if let freeBytes = availableCapacityBytes(at: probeURL), freeBytes < minimumFreeBytes {
            let haveGiB = String(format: "%.1f", Double(freeBytes) / 1_073_741_824.0)
            let needGiB = String(format: "%.1f", Double(minimumFreeBytes) / 1_073_741_824.0)
            throw UnifiedOrchestrationError.backendUnavailable(
                "目标磁盘可用空间不足（当前剩余 \(haveGiB) GiB，至少需要 \(needGiB) GiB），请清理空间或更换外置 SSD。"
            )
        }
    }

    /// Waits briefly after `bootstrap.done` until an interactive Windows desktop user session is logged on.
    static func waitForInteractiveUserLogon(
        controlBinary: String,
        vmUUID: String,
        timeoutSeconds: TimeInterval = 60,
        pollIntervalSeconds: TimeInterval = 2,
        commandRunner: UnifiedRuntimeOrchestrator.CommandRunner
    ) async {
        let deadline = Date().addingTimeInterval(max(1, timeoutSeconds))
        let nanos = UInt64(max(0.05, pollIntervalSeconds) * 1_000_000_000)
        while Date() < deadline {
            let res = try? await commandRunner(
                controlBinary,
                [
                    "exec", "--hide", vmUUID, "--cmd", "powershell.exe",
                    "-NoProfile", "-Command", "(Get-CimInstance Win32_ComputerSystem).UserName"
                ],
                ["__DEMOAPP_TIMEOUT_SECONDS": "10"]
            )
            let out = res?.stdout.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            if res?.exitCode == 0 && !out.isEmpty { return }
            try? await Task.sleep(nanoseconds: nanos)
        }
    }

    /// Gracefully restarts Windows inside a running VM and waits for the interactive user desktop to return.
    static func rebootAndWaitForLogon(
        controlBinary: String,
        vmUUID: String,
        commandRunner: UnifiedRuntimeOrchestrator.CommandRunner
    ) async {
        _ = try? await commandRunner(
            controlBinary,
            ["exec", "--hide", vmUUID, "--cmd", "shutdown.exe", "/r", "/t", "1", "/f"],
            ["__DEMOAPP_TIMEOUT_SECONDS": "15"]
        )
        try? await Task.sleep(nanoseconds: 12_000_000_000)
        await waitForInteractiveUserLogon(
            controlBinary: controlBinary, vmUUID: vmUUID,
            timeoutSeconds: 90, pollIntervalSeconds: 2, commandRunner: commandRunner
        )
    }

    static func triggerOpticalBootKeypresses(
        commandRunner: UnifiedRuntimeOrchestrator.CommandRunner
    ) async {
        let safeSpace = "tell application \"System Events\" to if (name of first application process "
            + "whose frontmost is true) is \"UTM\" then tell process \"UTM\" to key code 49"
        for _ in 0..<8 {
            try? await Task.sleep(nanoseconds: 1_500_000_000)
            _ = try? await commandRunner("/usr/bin/osascript", ["-e", safeSpace], ["__DEMOAPP_TIMEOUT_SECONDS": "5"])
        }
    }

    static func gracefulShutdownAndWait(
        controlBinary: String, vmUUID: String, pollIntervalSeconds: TimeInterval,
        commandRunner: UnifiedRuntimeOrchestrator.CommandRunner
    ) async throws {
        _ = try? await commandRunner(
            controlBinary, ["exec", "--hide", vmUUID, "--cmd", "shutdown.exe", "/s", "/t", "2"],
            ["__DEMOAPP_TIMEOUT_SECONDS": "15"]
        )
        let deadline = Date().addingTimeInterval(120)
        let pollNanos = UInt64(max(0.05, min(2.0, pollIntervalSeconds)) * 1_000_000_000)
        while Date() < deadline {
            try Task.checkCancellation()
            let status = try? await commandRunner(
                controlBinary, ["status", "--hide", vmUUID], ["__DEMOAPP_TIMEOUT_SECONDS": "5"]
            )
            let state = status?.stdout.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() ?? ""
            if status?.exitCode == 0 && (state == "stopped" || state.isEmpty) { return }
            try await Task.sleep(nanoseconds: pollNanos)
        }
        throw UnifiedOrchestrationError.commandFailed("等待容器正常关机超时，未能执行离线磁盘瘦身。")
    }

    static func stageMediaFile(
        from source: URL, to destination: URL,
        fileManager: FileManager, commandRunner: UnifiedRuntimeOrchestrator.CommandRunner
    ) async throws {
        let srcPath = source.standardizedFileURL.path(percentEncoded: false)
        let dstPath = destination.standardizedFileURL.path(percentEncoded: false)
        let clone = try? await commandRunner("/bin/cp", ["-c", srcPath, dstPath], ["__DEMOAPP_TIMEOUT_SECONDS": "60"])
        if clone?.exitCode == 0 && fileManager.fileExists(atPath: dstPath) { return }
        try? fileManager.removeItem(at: destination)
        try fileManager.copyItem(at: source, to: destination)
    }

    /// Reads available bytes on the volume containing `url`.
    public static func availableCapacityBytes(at url: URL) -> Int64? {
        let keys: Set<URLResourceKey> = [
            .volumeAvailableCapacityForImportantUsageKey,
            .volumeAvailableCapacityKey
        ]
        guard let values = try? url.resourceValues(forKeys: keys) else { return nil }
        if let important = values.volumeAvailableCapacityForImportantUsage, important > 0 {
            return important
        }
        if let regular = values.volumeAvailableCapacity {
            return Int64(regular)
        }
        return nil
    }
}

private extension ContainerBootstrapPreflight {
    static func findDriverISO(in directory: URL, fileManager: FileManager) -> URL? {
        guard let items = try? fileManager.contentsOfDirectory(
            at: directory,
            includingPropertiesForKeys: [.fileSizeKey],
            options: [.skipsHiddenFiles]
        ) else {
            return nil
        }
        let candidates = items.filter { item in
            let lower = item.lastPathComponent.lowercased()
            guard lower.hasSuffix(".iso"),
                  lower.contains("utm-guest-tools") || lower.contains("virtio-win") else {
                return false
            }
            let size = (try? item.resourceValues(forKeys: [.fileSizeKey]).fileSize) ?? 0
            return Int64(size) >= minimumDriverISOSizeBytes
        }
        return candidates.sorted { lhs, rhs in
            let rank: (URL) -> Int = { url in
                let name = url.lastPathComponent.lowercased()
                if name.contains("utm-guest-tools-3d") { return 3 }
                if name.contains("utm-guest-tools") { return 2 }
                return 1
            }
            let lhsRank = rank(lhs)
            let rhsRank = rank(rhs)
            if lhsRank != rhsRank { return lhsRank > rhsRank }
            return lhs.lastPathComponent > rhs.lastPathComponent
        }.first
    }

    static func matchLanguageToken(in raw: String) -> String? {
        let norm = raw.lowercased()
            .replacingOccurrences(of: "_", with: "-")
            .replacingOccurrences(of: " ", with: "-")
        let rules: [([String], String)] = [
            (["chinese-simplified", "zh-cn", "-chs-"], "zh-CN"),
            (["chinese-traditional", "zh-tw", "-cht-"], "zh-TW"),
            (["japanese", "ja-jp", "-jpn-"], "ja-JP"),
            (["korean", "ko-kr", "-kor-"], "ko-KR"),
            (["englishinternational", "english-international", "en-gb"], "en-GB"),
            (["english", "en-us", "-enu-"], "en-US")
        ]
        for (tokens, bcp47) in rules where tokens.contains(where: { norm.contains($0) }) {
            return bcp47
        }
        return nil
    }

    static func nearestExistingDirectory(for url: URL, fileManager: FileManager) -> URL {
        var cursor = url
        while !fileManager.fileExists(atPath: cursor.path(percentEncoded: false)) {
            let parent = cursor.deletingLastPathComponent()
            if parent == cursor { break }
            cursor = parent
        }
        return cursor
    }

    static func filesystemTypeName(atPath path: String) -> String {
        var stat = statfs()
        guard statfs(path, &stat) == 0 else { return "" }
        return withUnsafePointer(to: &stat.f_fstypename) { ptr in
            ptr.withMemoryRebound(to: CChar.self, capacity: Int(MFSTYPENAMELEN)) { cStr in
                String(cString: cStr)
            }
        }
    }
}
