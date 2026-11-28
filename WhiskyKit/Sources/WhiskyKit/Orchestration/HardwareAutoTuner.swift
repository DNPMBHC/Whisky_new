// SPDX-License-Identifier: GPL-3.0-or-later
// Apple Silicon hardware probing, safe tuning bounds, and non-blocking lightweight benchmark.

import AppKit
import Darwin
import Foundation

/// Real-time snapshot of local macOS hardware capabilities.
public struct HardwareProfileSnapshot: Codable, Equatable, Sendable {
    public let chipName: String
    public let totalCores: Int
    public let performanceCores: Int
    public let efficiencyCores: Int
    public let physicalMemoryGiB: Int
    public let displayRefreshRateHz: Int
    public let recommendedStoragePath: String

    public init(
        chipName: String,
        totalCores: Int,
        performanceCores: Int,
        efficiencyCores: Int,
        physicalMemoryGiB: Int,
        displayRefreshRateHz: Int,
        recommendedStoragePath: String
    ) {
        self.chipName = chipName
        self.totalCores = totalCores
        self.performanceCores = performanceCores
        self.efficiencyCores = efficiencyCores
        self.physicalMemoryGiB = physicalMemoryGiB
        self.displayRefreshRateHz = displayRefreshRateHz
        self.recommendedStoragePath = recommendedStoragePath
    }
}

/// Optimal runtime configuration produced from hardware profile and quick micro-benchmark.
public struct AutoTuneRecommendation: Codable, Equatable, Sendable {
    public let hardware: HardwareProfileSnapshot
    public let recommendedTier: PerformancePresetTier
    public let recommendedVCPU: Int
    public let recommendedRAMMiB: Int
    public let recommendedResolution: String
    public let enableGameMode: Bool
    public let mouseCoalesceMicros: Int
    public let blockAccidentalShortcuts: Bool
    public let benchmarkScore: Double
    public let durationSeconds: Double

    public var recommendedRAMGiB: Int {
        max(4, recommendedRAMMiB / 1024)
    }

    public init(
        hardware: HardwareProfileSnapshot,
        recommendedTier: PerformancePresetTier,
        recommendedVCPU: Int,
        recommendedRAMMiB: Int,
        recommendedResolution: String,
        enableGameMode: Bool,
        mouseCoalesceMicros: Int,
        blockAccidentalShortcuts: Bool,
        benchmarkScore: Double,
        durationSeconds: Double
    ) {
        self.hardware = hardware
        self.recommendedTier = recommendedTier
        self.recommendedVCPU = recommendedVCPU
        self.recommendedRAMMiB = recommendedRAMMiB
        self.recommendedResolution = recommendedResolution
        self.enableGameMode = enableGameMode
        self.mouseCoalesceMicros = mouseCoalesceMicros
        self.blockAccidentalShortcuts = blockAccidentalShortcuts
        self.benchmarkScore = benchmarkScore
        self.durationSeconds = durationSeconds
    }
}

/// Detects host hardware and runs a non-blocking micro-benchmark to recommend VM and Wine settings.
public final class HardwareAutoTuner: Sendable {
    private let benchmarkDurationSeconds: Double

    public init(benchmarkDurationSeconds: Double = 11.0) {
        self.benchmarkDurationSeconds = max(0.05, benchmarkDurationSeconds)
    }

    public func detectHardwareProfile() -> HardwareProfileSnapshot {
        let chipName = Self.sysctlString("machdep.cpu.brand_string") ?? "Apple Silicon"
        let totalCores = max(1, ProcessInfo.processInfo.processorCount)
        let perfCores = Self.sysctlInt("hw.perflevel0.physicalcpu") ?? max(1, totalCores / 2)
        let effCores = Self.sysctlInt("hw.perflevel1.physicalcpu") ?? max(0, totalCores - perfCores)
        let memBytes = ProcessInfo.processInfo.physicalMemory
        let memGiB = max(1, Int((Double(memBytes) / 1_073_741_824.0).rounded()))
        let refreshHz = Self.detectDisplayRefreshRateHz()
        let storagePath = Self.detectRecommendedStoragePath()

        return HardwareProfileSnapshot(
            chipName: chipName,
            totalCores: totalCores,
            performanceCores: perfCores,
            efficiencyCores: effCores,
            physicalMemoryGiB: memGiB,
            displayRefreshRateHz: refreshHz,
            recommendedStoragePath: storagePath
        )
    }

    /// Returns safe selectable container memory options in whole GiB for the detected Mac.
    public static func safeMemoryOptionsGiB(for hardware: HardwareProfileSnapshot) -> [Int] {
        switch hardware.physicalMemoryGiB {
        case 32...:
            return [8, 12, 16, 20]
        case 24..<32:
            return [8, 12, 16]
        case 16..<24:
            return [6, 8, 10, 12]
        case 12..<16:
            return [4, 6, 8]
        default:
            return [4, 6]
        }
    }

    /// Returns the highlighted default memory tier in whole GiB for the detected Mac.
    public static func recommendedMemoryGiB(for hardware: HardwareProfileSnapshot) -> Int {
        switch hardware.physicalMemoryGiB {
        case 32...:
            return 16
        case 24..<32:
            return 12
        case 16..<24:
            return 10
        case 12..<16:
            return 6
        default:
            return 4
        }
    }

    /// Adaptive virgl/venus GPU hostmem budget across all Apple Silicon RAM tiers (8 GiB to 128+ GiB).
    public static func recommendedVirglHostmem(forPhysicalMemoryBytes bytes: UInt64) -> String {
        if bytes <= 10_737_418_240 {
            return "2G"
        }
        if bytes <= 21_474_836_480 {
            return "4G"
        }
        return "8G"
    }

    /// Adaptive VirtIO-Blk queue count bounded to allocated vCPU count so 4-core M1/M2 configs avoid contention.
    public static func recommendedVirtIOBlockQueues(forVCPUCount cpuCount: Int) -> Int {
        min(4, max(2, cpuCount))
    }

    /// Clamps any persisted or requested GiB memory choice into the hardware's safe GiB choices.
    public static func clampedMemoryGiB(
        _ requestedGiB: Int,
        for hardware: HardwareProfileSnapshot
    ) -> Int {
        let options = safeMemoryOptionsGiB(for: hardware)
        if options.contains(requestedGiB) {
            return requestedGiB
        }
        return options.min(by: { abs($0 - requestedGiB) < abs($1 - requestedGiB) })
            ?? recommendedMemoryGiB(for: hardware)
    }

    /// Returns safe selectable vCPU core counts leaving host macOS headroom.
    public static func safeVCPUOptions(for hardware: HardwareProfileSnapshot) -> [Int] {
        let maxSafe: Int
        if hardware.totalCores >= 12 {
            maxSafe = min(10, hardware.totalCores - 2)
        } else if hardware.totalCores >= 6 {
            maxSafe = hardware.totalCores - 2
        } else {
            maxSafe = max(2, hardware.totalCores - 1)
        }

        let minSafe = min(4, maxSafe)
        var candidates: [Int] = []
        var value = minSafe
        while value <= maxSafe {
            candidates.append(value)
            value += 2
        }
        let recommended = recommendedVCPUCount(for: hardware)
        if !candidates.contains(recommended) && recommended <= maxSafe {
            candidates.append(recommended)
        }
        if !candidates.contains(maxSafe) {
            candidates.append(maxSafe)
        }
        return Array(Set(candidates)).sorted()
    }

    /// Clamps any persisted vCPU count into the hardware's safe vCPU options.
    public static func clampedVCPU(_ requestedVCPU: Int, for hardware: HardwareProfileSnapshot) -> Int {
        let options = safeVCPUOptions(for: hardware)
        if options.contains(requestedVCPU) {
            return requestedVCPU
        }
        return options.min(by: { abs($0 - requestedVCPU) < abs($1 - requestedVCPU) })
            ?? recommendedVCPUCount(for: hardware)
    }

    public func runQuickBenchmarkAndRecommend() async -> AutoTuneRecommendation {
        let profile = detectHardwareProfile()
        let start = CFAbsoluteTimeGetCurrent()
        let cpuScore = await Self.runMulticoreCPUBenchmark(
            workerCount: max(2, min(profile.totalCores, 8)),
            durationSeconds: benchmarkDurationSeconds * 0.72
        )
        let ioScore = await Self.runDiskIOBenchmark(durationSeconds: benchmarkDurationSeconds * 0.28)
        let elapsed = max(0.01, CFAbsoluteTimeGetCurrent() - start)
        let compositeScore = ((cpuScore * 0.7) + (ioScore * 0.3)).rounded()
        return Self.recommend(for: profile, benchmarkScore: compositeScore, durationSeconds: elapsed)
    }

    /// Deterministic recommendation engine grounded in Phase 11–14 empirical VM benchmarks.
    public static func recommend(
        for hardware: HardwareProfileSnapshot,
        benchmarkScore: Double,
        durationSeconds: Double
    ) -> AutoTuneRecommendation {
        let recommendedGiB = recommendedMemoryGiB(for: hardware)
        let recommendedRAMMiB = recommendedGiB * 1024
        let recommendedTier: PerformancePresetTier
        let recommendedResolution: String

        if hardware.physicalMemoryGiB >= 24 {
            recommendedTier = benchmarkScore >= 65.0 ? .maxPerformance : .balanced
            recommendedResolution = hardware.physicalMemoryGiB >= 32 ? "2560x1440" : "1920x1080"
        } else if hardware.physicalMemoryGiB >= 16 {
            recommendedTier = benchmarkScore >= 25.0 ? .balanced : .lowSpecCompatible
            recommendedResolution = "1920x1080"
        } else {
            recommendedTier = .lowSpecCompatible
            recommendedResolution = "1280x720"
        }

        let recommendedVCPU = recommendedVCPUCount(for: hardware)
        let roundedDuration = (durationSeconds * 100.0).rounded() / 100.0
        return AutoTuneRecommendation(
            hardware: hardware,
            recommendedTier: recommendedTier,
            recommendedVCPU: recommendedVCPU,
            recommendedRAMMiB: recommendedRAMMiB,
            recommendedResolution: recommendedResolution,
            enableGameMode: true,
            mouseCoalesceMicros: 1500,
            blockAccidentalShortcuts: true,
            benchmarkScore: max(1.0, benchmarkScore),
            durationSeconds: roundedDuration
        )
    }

    public static func recommendedVCPUCount(for hardware: HardwareProfileSnapshot) -> Int {
        if hardware.totalCores >= 12 {
            return min(10, hardware.totalCores - 2)
        }
        if hardware.totalCores >= 10 {
            return 8
        }
        if hardware.totalCores >= 8 {
            return 6
        }
        return max(2, hardware.totalCores - 1)
    }

    private static func runMulticoreCPUBenchmark(
        workerCount: Int,
        durationSeconds: Double
    ) async -> Double {
        let deadline = CFAbsoluteTimeGetCurrent() + durationSeconds
        return await withTaskGroup(of: UInt64.self) { group in
            for workerIndex in 0..<workerCount {
                group.addTask {
                    var state: UInt64 = 0x9E37_79B9_7F4A_7C15 ^ UInt64(workerIndex &+ 1)
                    var iterations: UInt64 = 0
                    while CFAbsoluteTimeGetCurrent() < deadline {
                        for _ in 0..<4096 {
                            state ^= state << 13
                            state ^= state >> 7
                            state ^= state << 17
                            state = state &* 0x2545_F491_4F6C_DD1D
                        }
                        iterations &+= 1
                    }
                    return iterations ^ (state & 1)
                }
            }
            var totalIterations: UInt64 = 0
            for await count in group {
                totalIterations &+= count
            }
            let rate = Double(totalIterations) / max(0.05, durationSeconds)
            return min(100.0, max(10.0, (rate / 500.0) * 100.0))
        }
    }

    /// Runs disk I/O micro-benchmark off the caller actor so UI animations never stall.
    private static func runDiskIOBenchmark(durationSeconds: Double) async -> Double {
        await Task.detached(priority: .utility) {
            let tempDir = FileManager.default.temporaryDirectory
            let probeFile = tempDir.appending(path: "whisky-autotune-\(UUID().uuidString).tmp")
            defer { try? FileManager.default.removeItem(at: probeFile) }

            let payload = Data(repeating: 0x5A, count: 1_048_576)
            let deadline = CFAbsoluteTimeGetCurrent() + durationSeconds
            var completedMiB: Double = 0

            while CFAbsoluteTimeGetCurrent() < deadline {
                do {
                    try payload.write(to: probeFile, options: .atomic)
                    _ = try Data(contentsOf: probeFile)
                    completedMiB += 2.0
                } catch {
                    break
                }
            }
            let throughputMBps = completedMiB / max(0.05, durationSeconds)
            return min(100.0, max(10.0, (throughputMBps / 800.0) * 100.0))
        }.value
    }
}

private extension HardwareAutoTuner {
    static func sysctlString(_ name: String) -> String? {
        var size: Int = 0
        guard sysctlbyname(name, nil, &size, nil, 0) == 0, size > 1 else {
            return nil
        }
        var buffer = [CChar](repeating: 0, count: size)
        guard sysctlbyname(name, &buffer, &size, nil, 0) == 0 else {
            return nil
        }
        let bytes = buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
        return String(bytes: bytes, encoding: .utf8)
    }

    static func sysctlInt(_ name: String) -> Int? {
        var value: Int32 = 0
        var size = MemoryLayout<Int32>.size
        guard sysctlbyname(name, &value, &size, nil, 0) == 0 else {
            return nil
        }
        return Int(value)
    }

    static func detectDisplayRefreshRateHz() -> Int {
        if Thread.isMainThread {
            let rate = MainActor.assumeIsolated { NSScreen.main?.maximumFramesPerSecond ?? 60 }
            return max(60, rate)
        }
        if let mode = CGDisplayCopyDisplayMode(CGMainDisplayID()), mode.refreshRate >= 59.0 {
            return max(60, Int(mode.refreshRate.rounded()))
        }
        return 60
    }

    static func detectRecommendedStoragePath() -> String {
        let fileManager = FileManager.default
        let skipped = Set(["Macintosh HD", "Recovery", "Preboot", "VM", "Update", "DATA"])
        if let volumes = try? fileManager.contentsOfDirectory(
            at: URL(filePath: "/Volumes"),
            includingPropertiesForKeys: [.volumeIsInternalKey, .volumeIsReadOnlyKey],
            options: [.skipsHiddenFiles]
        ) {
            for volume in volumes.sorted(by: { $0.lastPathComponent < $1.lastPathComponent })
            where !skipped.contains(volume.lastPathComponent) {
                let maltDir = volume.appending(path: "MaltContainers")
                if fileManager.isWritableFile(atPath: maltDir.path(percentEncoded: false)) {
                    return maltDir.path(percentEncoded: false)
                }
                if fileManager.isWritableFile(atPath: volume.path(percentEncoded: false)) {
                    return volume.path(percentEncoded: false)
                }
            }
        }
        let docs = fileManager.urls(for: .documentDirectory, in: .userDomainMask).first
            ?? fileManager.homeDirectoryForCurrentUser
        return docs.appending(path: "MaltContainers").path(percentEncoded: false)
    }
}
